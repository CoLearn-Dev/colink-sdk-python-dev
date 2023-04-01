import google.protobuf

protobuf_version = google.protobuf.__version__[0]

if protobuf_version == "3":
    from colink.proto.v3.colink_remote_storage_pb2 import *
elif protobuf_version == "4":
    from colink.proto.v4.colink_remote_storage_pb2 import *
