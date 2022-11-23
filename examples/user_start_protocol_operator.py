import sys
from colink import CoLink, decode_jwt_without_validation

if __name__ == "__main__":
    addr = sys.argv[1]
    jwt = sys.argv[2]
    protocol_name = sys.argv[3]
    user_id = decode_jwt_without_validation(jwt).user_id
    cl = CoLink(addr, jwt)
    instance_id = cl.start_protocol_operator(protocol_name, user_id)
    print("Instance id: {}".format(instance_id))
