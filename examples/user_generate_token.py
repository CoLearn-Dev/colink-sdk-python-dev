import sys
import logging
from colink.sdk_a import CoLink

if __name__ == "__main__":
    logging.basicConfig(
        filename="user_generate_token.log", filemode="a", level=logging.INFO
    )
    addr = sys.argv[1]
    jwt = sys.argv[2]
    cl = CoLink(addr, jwt)
    new_jwt = cl.generate_token("user")
    cl.update_jwt(new_jwt)
    guest_jwt = cl.generate_token("guest")
    print(f"{new_jwt}\n{guest_jwt}")
