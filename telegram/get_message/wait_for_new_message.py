import queue
import sys
import colink as CL
from colink.sdk_a import CoLink, byte_to_str

if __name__ == "__main__":
    addr = sys.argv[1]
    jwt = sys.argv[2]
    cl = CoLink(addr, jwt)
    message = cl.read_or_wait("telegram_message")