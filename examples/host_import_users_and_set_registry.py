import sys
import logging
import colink as CL
from colink import CoLink, get_time_stamp, generate_user, prepare_import_user_signature

if __name__ == "__main__":
    logging.basicConfig(
        filename="host_import_users_and_set_registry.log",
        filemode="a",
        level=logging.INFO,
    )
    addr = sys.argv[1]
    host_jwt = sys.argv[2]
    num = int(sys.argv[3])
    if len(sys.argv) > 4:
        expiration_timestamp = int(sys.argv[4])
    else:
        expiration_timestamp = get_time_stamp() + 86400 * 31
    cl = CoLink(addr, host_jwt)
    users = []
    pk, sk = generate_user()
    core_pub_key = cl.request_info().core_public_key
    signature_timestamp, sig = prepare_import_user_signature(
        pk, sk, core_pub_key, expiration_timestamp
    )
    registry_user = cl.import_user(pk, signature_timestamp, expiration_timestamp, sig)

    print("registry_user:")
    print(registry_user)
    clt = CoLink(addr, registry_user)
    registry_jwt = clt.generate_token_with_expiration_time(
        expiration_timestamp, "guest"
    )

    registry = CL.Registry(address=addr, guest_jwt=registry_jwt)
    registries = CL.Registries(
        registries=[registry],
    )
    clt.update_registries(registries)
    for i in range(num):
        pk, sk = generate_user()
        core_pub_key = cl.request_info().core_public_key
        signature_timestamp, sig = prepare_import_user_signature(
            pk, sk, core_pub_key, expiration_timestamp
        )
        users.append(cl.import_user(pk, signature_timestamp, expiration_timestamp, sig))
        clu = CoLink(addr, users[i])
        clu.update_registries(registries)
    print("user:")
    for i in range(num):
        print(users[i])
