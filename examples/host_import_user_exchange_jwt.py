import sys
from colink.sdk_a import (
    Dds,
    get_time_stamp,
    generate_user,
    prepare_import_user_signature,
    decode_jwt_without_validation,
)

if __name__ == "__main__":
    addr = sys.argv[1]
    core_jwt = sys.argv[2]
    expiration_timestamp = get_time_stamp() + 86400 * 31
    dds = Dds(addr, core_jwt)
    num = int(sys.argv[3])
    users = []
    for i in range(num):
        pub_key, sec_key = generate_user()
        _, core_pub_key = dds.request_core_info()
        signature_timestamp, sig = prepare_import_user_signature(
            pub_key, sec_key, core_pub_key, expiration_timestamp
        )
        jwt = dds.import_user(pub_key, signature_timestamp, expiration_timestamp, sig)
        users.append(jwt)
    for i in range(num):
        for j in range(num):
            if i != j:
                dds = Dds(addr, users[i])
                dds.import_guest_jwt(users[j])
                jwt = decode_jwt_without_validation(users[j])
                dds.import_core_addr(jwt.user_id, addr)
    for i in range(num):
        print(users[i])