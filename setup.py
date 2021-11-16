import setuptools

with open("README.md", "r", encoding='utf-8') as fh:
    long_description = fh.read()

setuptools.setup(
    name="python-authentiator",
    version="0.55.1",
    author="zzzzls",
    author_email="245129129@qq.com",
    description="TOTP based on python",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/zzzzls/python_authentiator",
    packages=setuptools.find_packages(),
    license='MIT',
    keywords=['Goole authentiator', 'totp', 'hotp']
)
