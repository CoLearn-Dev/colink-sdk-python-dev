import sys
import logging
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from colink import (
    CoLink,
    public_key_to_vec,
    InstantServer,
    get_time_stamp,
    generate_user,
    prepare_import_user_signature,
    decode_jwt_without_validation,
)

if __name__ == "__main__":
    is0 = InstantServer()
    cl = is0.get_colink()
    expiration_timestamp = get_time_stamp() + 86400 * 31
    num = 3
    users = []
    for i in range(num):
        pub_key, sec_key = generate_user()
        core_pub_key = cl.request_info().core_public_key
        signature_timestamp, sig = prepare_import_user_signature(
            pub_key, sec_key, core_pub_key, expiration_timestamp
        )
        pub_key_to_vec=public_key_to_vec(pub_key)
        jwt = cl.import_user(pub_key_to_vec, signature_timestamp, expiration_timestamp, sig)
        users.append(jwt)

    for i in range(num):
        for j in range(num):
            if i != j:
                clx = CoLink(cl.core_addr, users[i])
                clx.import_guest_jwt(users[j])
                jwt = decode_jwt_without_validation(users[j])
                clx.import_core_addr(jwt.user_id, cl.core_addr)
    for i in range(num):
        print(users[i])
