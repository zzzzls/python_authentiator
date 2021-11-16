import base64
import time
import hmac
import struct
from hashlib import sha1
from urllib.parse import urlencode, quote

class TOTP:
    def __init__(self, origin_secret:str, label:str=None, account:str=None) -> None:
        """
        :param origin_secret: 生成密钥的字符串
        :param label: [可选]标识平台
        :param account: [可选]标识账号
        """
        self.origin_secret = origin_secret
        self.label = label
        self.account = account

        # Google Authenticator URI
        self.base_uri = 'otpauth://totp/{prefix}?{ends}'
        # 草料二维码 生成api
        self.caoliao_qrcode_url = 'https://api.pwmqr.com/qrcode/create/?url={qr_content}'

    def generate_secret(self) -> tuple:
        """
        生成密钥
        """
        base32_obj = base64.b32encode(self.origin_secret.encode())
        # 由于编码后的=, 后续生成二维码时会出现问题, 此处将其全部转换为 A
        secret = base32_obj.decode().replace('=', 'A')
        return secret

    def _generate_timestamp_bytestring(self) -> bytes:
        """
        生成字节时间片
        """
        ts = int(time.time()) // 30
        return struct.pack(">Q", ts)

    def _truncate(self, hmac_hash:bytes) -> str:
        """
        将 hmac结果 转换为 6位数字
        """
        offset = hmac_hash[19] & 0xf
        google_code = (struct.unpack(">I", hmac_hash[offset: offset+4])[0] & 0x7fffffff) % 10**6
        # 若计算后结果不足6位, 则在左侧补0
        google_code = f'{google_code:>06}'
        return google_code

    def generate_code(self, secret) -> str:
        """
        生成 google 一次性密码
        
        :returns: 6位数字密码
        """
        k = base64.b32decode(secret)
        c = self._generate_timestamp_bytestring()
        hmac_hash = hmac.new(k, c, sha1).digest()
        google_code = self._truncate(hmac_hash)
        return google_code

    def generate_qrcode(self, secret) -> str:
        """
        生成 TOTP 配置 URI, 将其转换为二维码;
        可通过 Google Authenticator 扫码添加

        :returns: 二维码图片url
        """
        
        prefix = ''
        ends = {
            'secret': secret,
        }
        
        if self.label:
            prefix += self.label
            ends['issuer'] = self.label

        if self.account:
            prefix += f':{self.account}'
        
        totp_uri = self.base_uri.format(prefix=prefix, ends=urlencode(ends))
        return self.caoliao_qrcode_url.format(qr_content=quote(totp_uri))
