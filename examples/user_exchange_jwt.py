import sys
from colink.sdk_a import (
    CoLink,
    get_time_stamp,
    generate_user,
    prepare_import_user_signature,
    decode_jwt_without_validation,
)

if __name__ == "__main__":
    addr = sys.argv[1]
    users = sys.argv[2:]
    num = len(users)
    for i in range(num):
        for j in range(num):
            if i != j:
                cl = CoLink(addr, users[i])
                cl.import_guest_jwt(users[j])
                jwt = decode_jwt_without_validation(users[j])
                cl.import_core_addr(jwt.user_id, addr)
    for i in range(num):
        print(users[i])
