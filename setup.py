from setuptools import setup, find_packages
import subprocess
import sys

subprocess.check_call(
    [sys.executable, "-m", "pip", "install", "grpcio-tools==1.50.0"]
)
subprocess.check_call(
    [sys.executable, "./colink/proto/proto_gen.py", "v4"]
)
subprocess.check_call(
    [sys.executable, "-m", "pip", "install", "grpcio-tools==1.46.3"]
)
subprocess.check_call(
    [sys.executable, "./colink/proto/proto_gen.py", "v3"]
)
subprocess.check_call(
    [sys.executable, "-m", "pip", "uninstall", "-y", "grpcio", "grpcio-tools", "protobuf"]
)

desc_file = open("README.md", "r")
long_description = desc_file.read()
desc_file.close()

setup(
    name="colink",
    version="0.3.2",
    description="colink python module",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Wenjie Qu",
    author_email="",
    packages=find_packages(include=["colink", "colink.*"]),
    install_requires=[
        "grpcio>=1.27.2",
        "protobuf>=3.19.0,<5.0dev",
        "coincurve>=18.0.0",
        "cryptography>=39.0.1",
        "pika>=1.2.0",
        "pyjwt>=2.6.0",
        "requests>=2.28.1",
        "requests_toolbelt>=0.10.1",
        "redis>=4.5.4"
    ],  # external packages as dependencies
)
