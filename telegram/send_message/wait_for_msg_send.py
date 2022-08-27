import queue
import sys
import colink as CL
from colink.sdk_a import CoLink, byte_to_str

if __name__ == "__main__":
    addr = sys.argv[1]
    jwt = sys.argv[2]
    cl = CoLink(addr, jwt)
    latest_key = "_internal:protocols:telegram/send_msg:finished:latest"
    message = cl.read_or_wait(latest_key)
