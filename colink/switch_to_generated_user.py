from .application import (
    decode_jwt_without_validation,
    generate_user,
    prepare_import_user_signature,
)


def generate_user_and_import(self) -> str:
    auth_content = decode_jwt_without_validation(self.jwt)
    expiration_timestamp = auth_content.exp
    pk, sk = generate_user()
    core_pub_key = self.request_info().core_public_key
    signature_timestamp, sig = prepare_import_user_signature(
        pk, sk, core_pub_key, expiration_timestamp
    )
    return self.import_user(pk, signature_timestamp, expiration_timestamp, sig)


def switch_to_generated_user(self):
    self.update_jwt(self.generate_user_and_import())
    self.wait_user_init()
    return self
