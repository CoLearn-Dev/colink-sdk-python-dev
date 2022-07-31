import sys
import logging
from colink.sdk_a import (
    CoLink,
    get_time_stamp,
    generate_user,
    prepare_import_user_signature
)

if __name__ == "__main__":
    core_jwt = open("./colink-server/host_token.txt", "r").readline()
    addr = "127.0.0.1:8080"
    expiration_timestamp = get_time_stamp() + 86400 * 31
    cl = CoLink(addr, core_jwt)
    pub_key, sec_key = generate_user()
    _, core_pub_key = cl.request_core_info()
    signature_timestamp, sig = prepare_import_user_signature(
        pub_key, sec_key, core_pub_key, expiration_timestamp
    )
    jwt = cl.import_user(pub_key, signature_timestamp, expiration_timestamp, sig)
    logging.info("import user success! (jwt): %s", jwt)
