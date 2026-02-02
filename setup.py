from setuptools import setup, find_packages

setup(
    name="cobrax",
    version="5.1.0",
    description="Cobra X - Ultra Stealth Offensive Security Framework",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="COBRA DEV",
    packages=find_packages(),
    install_requires=[
        "httpx[socks]>=0.24.0",
        "dnspython>=2.3.0",
    ],
    entry_points={
        "console_scripts": [
            "cobrax=cobrax.core:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
    ],
)
