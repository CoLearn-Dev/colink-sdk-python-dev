import sys
from colink import (
    CoLink,
    get_time_stamp,
    generate_user,
    prepare_import_user_signature,
    decode_jwt_without_validation,
)

if __name__ == "__main__":
    addr = sys.argv[1]
    core_jwt = sys.argv[2]
    expiration_timestamp = get_time_stamp() + 86400 * 31
    cl = CoLink(addr, core_jwt)
    num = int(sys.argv[3])
    users = []
    for i in range(num):
        pub_key, sec_key = generate_user()
        core_pub_key = cl.request_info().core_public_key
        signature_timestamp, sig = prepare_import_user_signature(
            pub_key, sec_key, core_pub_key, expiration_timestamp
        )
        jwt = cl.import_user(pub_key, signature_timestamp, expiration_timestamp, sig)
        users.append(jwt)

    for i in range(num):
        for j in range(num):
            if i != j:
                cl = CoLink(addr, users[i])
                cl.import_guest_jwt(users[j])
                jwt = decode_jwt_without_validation(users[j])
                cl.import_core_addr(jwt.user_id, addr)
    for i in range(num):
        print(users[i])
