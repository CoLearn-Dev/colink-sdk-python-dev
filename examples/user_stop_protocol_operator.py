import sys
from colink.sdk_a import CoLink
if __name__ == "__main__":
    addr = sys.argv[1]
    jwt = sys.argv[2]
    instance_id = sys.argv[3]
    cl = CoLink(addr, jwt)
    instance_id = cl.stop_protocol_operator(instance_id)
