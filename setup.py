from setuptools import setup
import subprocess
import sys
import pkg_resources

grpc_tools_version = "grpcio-tools==1.50.0"
subprocess.check_call(
    [sys.executable, "-m", "pip", "install", grpc_tools_version]
)  # in order to generate grpc template we must first install grpcio-tools here
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

desc_file = open("README.md", "r")
long_description = desc_file.read()
desc_file.close()

setup(
    name="colink",
    version="0.2.6",
    description="colink python module",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Wenjie Qu",
    author_email="",
    packages=["colink"],  # same as name
    install_requires=[
        grpc_tools_version,
        "secp256k1==0.14.0",
        "pika==1.2.0",
        "cryptography==39.0.1",
        "pyjwt==2.6.0",
        "requests==2.28.1"
    ],  # external packages as dependencies
)
