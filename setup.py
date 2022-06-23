from setuptools import setup
import pip
import os


pip.main(["install", "grpcio-tools==1.45.0"])
import grpc_tools.protoc

grpc_tools.protoc.main(
    [
        "grpc_tools.protoc",
        "-I./proto",
        "--python_out=./colink",
        "--grpc_python_out=./colink",
        "./proto/colink.proto",
    ]
)


def update_import_path_in_pb2_grpc():
    with open("./colink/colink_pb2_grpc.py", "r") as f:
        lines = f.readlines()
    with open("./colink/colink_pb2_grpc.py", "w") as f:
        for line in lines:
            if "import colink_pb2 as colink__pb2" in line:
                line = line.replace("colink_pb2", "colink.colink_pb2")
            f.write(line)


update_import_path_in_pb2_grpc()
setup(
    name="colink",
    version="0.1.0",
    description="colink python module",
    author="Wenjie Qu",
    author_email="",
    packages=["colink"],  # same as name
    install_requires=[
        "secp256k1==0.14.0",
        "pika==1.2.0",
    ],  # external packages as dependencies
)
