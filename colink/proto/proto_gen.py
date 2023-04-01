import sys
import pkg_resources
import grpc_tools.protoc

version = sys.argv[1]

def generate_grpc_template(
    proto_file, proto_dir="./proto"
):
    proto_include = pkg_resources.resource_filename("grpc_tools", "_proto")
    grpc_tools.protoc.main(
        (
            ".",
            "-I{}".format(proto_include),
            "-I{}".format(proto_dir),
            "--python_out=./colink/proto/{}".format(version),
            "--grpc_python_out=./colink/proto/{}".format(version),
            "{}/{}".format(proto_dir, proto_file),
        )
    )


def generate_proto_template(
    proto_file, proto_dir="./proto"
):
    proto_include = pkg_resources.resource_filename("grpc_tools", "_proto")
    grpc_tools.protoc.main(
        (
            ".",
            "-I{}".format(proto_include),
            "-I{}".format(proto_dir),
            "--python_out=./colink/proto/{}".format(version),
            "{}/{}".format(proto_dir, proto_file),
        )
    )


generate_grpc_template("colink.proto")
generate_proto_template("colink_remote_storage.proto")
generate_proto_template("colink_policy_module.proto")
generate_proto_template("colink_registry.proto")


def update_import_path_in_pb2_grpc():
    with open("./colink/proto/{}/colink_pb2_grpc.py".format(version), "r") as f:
        lines = f.readlines()
    with open("./colink/proto/{}/colink_pb2_grpc.py".format(version), "w") as f:
        for line in lines:
            if "import colink_pb2 as colink__pb2" in line:
                line = line.replace("colink_pb2", "colink.proto.colink_pb2")
            f.write(line)


update_import_path_in_pb2_grpc()
