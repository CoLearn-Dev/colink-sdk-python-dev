from colink import (
    CoLink,
    InstantServer,
    InstantRegistry,
    prepare_import_user_signature,
    decode_jwt_without_validation,
    get_time_stamp,
    generate_user,
)


def test_user_management():
    _ir = InstantRegistry()
    _is = InstantServer()
    cl = _is.get_colink()
    core_addr = cl.get_core_addr()
    expiration_timestamp = get_time_stamp() + 86400 * 31
    pk, sk = generate_user()
    core_pub_key = cl.request_info().core_public_key
    signature_timestamp, sig = prepare_import_user_signature(
        pk, sk, core_pub_key, expiration_timestamp
    )
    user_jwt = cl.import_user(pk, signature_timestamp, expiration_timestamp, sig)
    user_id = decode_jwt_without_validation(user_jwt).user_id
    cl = CoLink(core_addr, user_jwt)
    new_expiration_timestamp = get_time_stamp() + 86400 * 60
    guest_jwt = cl.generate_token_with_expiration_time(
        new_expiration_timestamp, "guest"
    )
    guest_auth_content = decode_jwt_without_validation(guest_jwt)
    assert guest_auth_content.user_id == user_id
    assert guest_auth_content.privilege == "guest"
    assert guest_auth_content.exp == new_expiration_timestamp
    cl = CoLink(core_addr, "")
    new_signature_timestamp, new_sig = prepare_import_user_signature(
        pk, sk, core_pub_key, new_expiration_timestamp
    )
    new_user_jwt = cl.generate_token_with_signature(
        pk,
        new_signature_timestamp,
        new_expiration_timestamp,
        new_sig,
    )
    user_auth_content = decode_jwt_without_validation(new_user_jwt)
    assert user_auth_content.user_id == user_id
    assert user_auth_content.privilege == "user"
    assert user_auth_content.exp == new_expiration_timestamp


if __name__ == "__main__":
    test_user_management()
