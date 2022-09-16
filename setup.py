from setuptools import setup
import pip
import os
import pkg_resources

pip.main(["install", "grpcio-tools==1.45.0"])
import grpc_tools.protoc


def generate_grpc_template(
    proto_file, proto_dir="./proto", python_out="./colink", grpc_out="./colink"
):
    proto_include = pkg_resources.resource_filename("grpc_tools", "_proto")
    grpc_tools.protoc.main(
        (
            ".",
            "-I{}".format(proto_include),  # import well known protos
            "-I{}".format(proto_dir),
            "--python_out={}".format(python_out),
            "--grpc_python_out={}".format(grpc_out),
            "{}/{}".format(proto_dir, proto_file),
        )
    )


generate_grpc_template("colink.proto")
generate_grpc_template("colink_remote_storage.proto")
generate_grpc_template("colink_policy_module.proto")
generate_grpc_template("colink_registry.proto")


def update_import_path_in_pb2_grpc():
    with open("./colink/colink_pb2_grpc.py", "r") as f:
        lines = f.readlines()
    with open("./colink/colink_pb2_grpc.py", "w") as f:
        for line in lines:
            if "import colink_pb2 as colink__pb2" in line:
                line = line.replace("colink_pb2", "colink.colink_pb2")
            f.write(line)


update_import_path_in_pb2_grpc()

desc_file=open("README.md",'r')
long_description = desc_file.read()
desc_file.close()

setup(
    name="colink",
    version="0.1.10",
    description="colink python module",
    long_description=long_description,
    long_description_content_type='text/markdown',
    author="Wenjie Qu",
    author_email="",
    packages=["colink"],  # same as name
    install_requires=[
        "secp256k1==0.14.0",
        "pika==1.2.0",
    ],  # external packages as dependencies
)


