import queue
import sys
import colink as CL
from colink.sdk_a import CoLink, byte_to_str

if __name__ == "__main__":
    
    addr = sys.argv[1]
    jwt = sys.argv[2]
    cl = CoLink(addr, jwt)

    keys = ["telegram_api_key", "telegram_chat_id"]
    api_key, chat_id = list(map(lambda key: byte_to_str(cl.read_or_wait(key)), keys))
        
    print(
        (api_key, chat_id), end=""
    )  # send credentials to pipe
