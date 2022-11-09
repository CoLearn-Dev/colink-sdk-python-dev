from colink import CoLink
from colink.sdk_a import decode_jwt_without_validation, generate_user, prepare_import_user_signature
def generate_user_and_import(self) -> str:
    auth_content = decode_jwt_without_validation(self.jwt)
    expiration_timestamp = auth_content.exp
    pk, sk = generate_user()
    _, core_pub_key, _ = self.request_info()
    signature_timestamp, sig = prepare_import_user_signature(pk, sk, core_pub_key, expiration_timestamp)
    self.import_user(pk, signature_timestamp, expiration_timestamp, sig)
            
def switch_to_generated_user(self) :
    cl = CoLink(self.core_addr, self.generate_user_and_import())
    cl.wait_user_init()
    return cl
