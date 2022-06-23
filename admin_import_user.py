import sys
import logging
from colink.sdk_a import (
    Dds,
    get_time_stamp,
    generate_user,
    prepare_import_user_signature
)

if __name__ == "__main__":
    addr = sys.argv[1]
    core_jwt = sys.argv[2]
    #core_jwt = open("./colink-server/admin_token.txt", "r").readline()
    #addr = "127.0.0.1:8080"
    expiration_timestamp = get_time_stamp() + 86400 * 31
    dds = Dds(addr, core_jwt)
    pub_key, sec_key = generate_user()
    _, core_pub_key = dds.request_core_info()
    signature_timestamp, sig = prepare_import_user_signature(
        pub_key, sec_key, core_pub_key, expiration_timestamp
    )
    jwt = dds.import_user(pub_key, signature_timestamp, expiration_timestamp, sig)
    logging.info("import user success! (jwt): %s", jwt)
