import logging
import json
import time
import base64
from typing import Tuple, List
import sys
import pika
import grpc
import secp256k1
import random
import copy
from colink import CoLinkStub
import colink as CL


class JWT:
    def __init__(self, role: str, user_id: str, exp: int):
        self.role = role
        self.user_id = user_id
        self.exp = exp


class CoLinkSubscriber:
    def __init__(self, mq_uri: str, queue_name: str):
        self.uri = mq_uri
        self.queue_name = queue_name
        param = pika.connection.URLParameters(url=self.uri)
        mq = pika.BlockingConnection(param)  # establish rabbitmq connection
        self.channel = mq.channel()

    def get_next(self) -> bytes:
        for method, properties, body in self.channel.consume(
            self.queue_name
        ):  # get the first package from queue then return
            self.channel.basic_ack(
                method.delivery_tag
            )  # ack this package before return
            return body


class CoLink:
    def __init__(
        self, coreaddr: str, jwt: str, ca_certificate: str = None, identity: str = None
    ):
        self.core_addr = str(coreaddr)
        self.jwt = str(jwt)
        self.task_id = ""
        self.ca_cert = ca_certificate
        self.identity = identity

    def request_core_info(self) -> Tuple[str, str]:
        client = self._grpc_connect(self.core_addr)
        try:
            response = client.RequestCoreInfo(
                request=CL.Empty(),
                metadata=get_jwt_auth(self.jwt),
            )
        except grpc.RpcError as e:
            logging.error(
                f"Request CoreInfo Received exception: code={e.code()} message={e.details()}"
            )
            raise e
        else:
            return response.mq_uri, response.core_public_key

    def import_guest_jwt(self, jwt: str):
        jwt_decoded = decode_jwt_without_validation(
            jwt
        )  # want user_id from jwt, decode it to get
        self.create_entry(
            "_internal:known_users:{}:guest_jwt".format(jwt_decoded.user_id),
            str_to_byte(jwt),
        )

    def import_core_addr(
        self,
        user_id: str,
        core_addr: str,
    ):
        self.create_entry(
            "_internal:known_users:{}:core_addr".format(user_id),
            str_to_byte(core_addr),
        )

    def set_task_id(self, task_id: str):
        self.task_id = task_id

    def get_task_id(self) -> Tuple[str, str]:
        if len(self.task_id) == 0:
            logging.error("task_id not found")
            return None
        return copy.deepcopy(self.task_id)

    def import_user(
        self,
        public_key: secp256k1.PublicKey,
        signature_timestamp: int,
        expiration_timestamp: int,
        signature: str,
    ) -> str:
        public_key_vec = public_key_to_vec(public_key)
        client = self._grpc_connect(self.core_addr)
        try:
            response = client.ImportUser(
                request=CL.UserConsent(
                    public_key=public_key_vec,
                    signature_timestamp=signature_timestamp,
                    expiration_timestamp=expiration_timestamp,
                    signature=signature,
                ),
                metadata=get_jwt_auth(self.jwt),
            )
        except grpc.RpcError as e:
            logging.error(
                f"ImportUser Received RPC exception: code={e.code()} message={e.details()}"
            )
            raise e
        else:
            return response.jwt

    def generate_token(self, privilege: str) -> str:
        return self.generate_token_with_expiration_time(
            get_time_stamp() + 86400, privilege
        )

    def generate_token_with_expiration_time(
        self,
        expiration_time: int,
        privilege: str,
    ) -> str:
        client = self._grpc_connect(self.core_addr)
        response = client.GenerateToken(
            request=CL.GenerateTokenRequest(
                expiration_time=expiration_time,
                privilege=privilege,
            ),
            metadata=get_jwt_auth(self.jwt),
        )
        return response.jwt

    def create_entry(self, key_name: str, payload: bytes) -> str:
        client = self._grpc_connect(self.core_addr)
        try:
            response = client.CreateEntry(
                CL.StorageEntry(
                    key_name=key_name,
                    payload=payload,
                ),
                metadata=get_jwt_auth(self.jwt),
            )
        except grpc.RpcError as e:
            logging.error(
                f"CreateEntry Received RPC exception: code={e.code()} message={e.details()}"
            )
            raise e
        else:
            return response.key_path

    def read_entries(self, entries: List[CL.StorageEntry]) -> List[CL.StorageEntry]:
        client = self._grpc_connect(self.core_addr)
        try:
            response = client.ReadEntries(
                CL.StorageEntries(entries=entries),
                metadata=get_jwt_auth(self.jwt),
            )
        except grpc.RpcError as e:
            return None
        else:
            return response.entries

    def update_entry(self, key_name: str, payload: bytes) -> str:
        client = self._grpc_connect(self.core_addr)
        try:
            response = client.UpdateEntry(
                CL.StorageEntry(
                    key_name=key_name,
                    payload=payload,
                ),
                metadata=get_jwt_auth(self.jwt),
            )
        except grpc.RpcError as e:
            logging.error(
                f"Update Entry Received RPC exception: code={e.code()} message={e.details()}"
            )
            raise e
        else:
            return response.key_path

    def delete_entry(self, key_name: str) -> str:
        client = self._grpc_connect(self.core_addr)
        try:
            response = client.DeleteEntry(
                CL.StorageEntry(
                    key_name=key_name,
                ),
                metadata=get_jwt_auth(self.jwt),
            )
        except grpc.RpcError as e:
            logging.error(
                f"DeleteEntry Received RPC exception: code={e.code()} message={e.details()}"
            )
            raise e
        else:
            return response.key_path

    def refresh_token(self) -> str:
        return self.refresh_token_with_expiration_time(get_time_stamp() + 86400)

    def refresh_token_with_expiration_time(self, expiration_time: int) -> str:
        client = self._grpc_connect(self.core_addr)
        try:
            response = client.RefreshToken(
                request=CL.RefreshTokenRequest(expiration_time=expiration_time),
                metadata=get_jwt_auth(self.jwt),
            )
        except grpc.RpcError as e:
            logging.error(
                f"RefreshToken Received RPC exception: code={e.code()} message={e.details()}"
            )
            raise e
        else:
            self.jwt = response.jwt
            return self.jwt

    # The default expiration time is 1 day later. If you want to specify an expiration time, use run_task_with_expiration_time instead.
    def run_task(
        self,
        protocol_name: str,
        protocol_param: bytes,
        participants: List[CL.Participant],
        require_agreement: bool,
    ) -> str:
        return self.run_task_with_expiration_time(
            protocol_name,
            protocol_param,
            participants,
            require_agreement,
            get_time_stamp() + 86400,
        )

    def run_task_with_expiration_time(
        self,
        protocol_name: str,
        protocol_param: bytes,
        participants: List[CL.Participant],
        require_agreement: bool,
        expiration_time: int,
    ) -> str:
        client = self._grpc_connect(self.core_addr)
        task = CL.Task(
            protocol_name=protocol_name,
            protocol_param=protocol_param,
            participants=participants,
            parent_task=self.task_id,
            expiration_time=expiration_time,
            require_agreement=require_agreement,
        )
        response = client.CreateTask(
            request=task,
            metadata=get_jwt_auth(self.jwt),
        )
        logging.info("create task {}".format(response.task_id))
        return response.task_id

    def confirm_task(
        self,
        task_id: str,
        is_approved: bool,
        is_rejected: bool,
        reason: str,
    ):
        client = self._grpc_connect(self.core_addr)
        response = client.ConfirmTask(
            request=CL.ConfirmTaskRequest(
                task_id=task_id,
                decision=CL.Decision(
                    is_approved=is_approved, is_rejected=is_rejected, reason=reason
                ),
            ),
            metadata=get_jwt_auth(self.jwt),
        )

    def finish_task(self, task_id: str):
        client = self._grpc_connect(self.core_addr)
        response = client.FinishTask(
            request=CL.Task(
                task_id=task_id,
            ),
            metadata=get_jwt_auth(self.jwt),
        )

    def subscribe(self, key_name: str, start_timestamp: int) -> str:
        if start_timestamp is None:
            start_timestamp = time.time_ns()
        client = self._grpc_connect(self.core_addr)
        response = client.Subscribe(
            request=CL.SubscribeRequest(
                key_name=key_name,
                start_timestamp=start_timestamp,
            ),
            metadata=get_jwt_auth(self.jwt),
        )
        return response.queue_name

    def unsubscribe(self, queue_name: str):
        client = self._grpc_connect(self.core_addr)
        response = client.Unsubscribe(
            CL.MQQueueName(
                queue_name=queue_name,
            ),
            metadata=get_jwt_auth(self.jwt),
        )

    def new_subscriber(self, queue_name: str) -> CoLinkSubscriber:
        (mq_uri, _) = self.request_core_info()
        subscriber = CoLinkSubscriber(mq_uri, queue_name)
        return subscriber

    def _grpc_connect(
        self, addr: str
    ) -> CoLinkStub:  # give string addr, return grpc client object, currently non TLS
        try:
            if self.ca_cert is None:
                channel = grpc.insecure_channel(
                    addr.replace("http://", "")
                )  # without TLS, remove http:// prefix to deal with domain problem
            else:  # this part has not been tested currently
                root_certs = open(self.ca_cert).read()
                credentials = grpc.ssl_channel_credentials(root_certs)
                channel = grpc.secure_channel(addr.replace("http://", ""), credentials)
            stub = CoLinkStub(channel)
        except grpc.RpcError as e:
            logging.error(
                f"grpc connect Received RPC exception: code={e.code()} message={e.details()}"
            )
            raise e
        else:
            return stub

    def read_entry(self, key: str) -> bytes:
        if "::" in key:
            storage_entry = CL.StorageEntry(key_path=key)
        else:
            storage_entry = CL.StorageEntry(key_name=key)
        res = self.read_entries([storage_entry])
        if res is None:
            return None
        else:
            return res[0].payload

    def read_or_wait(self, key: str) -> bytes:
        res = self.read_entry(key)
        if res is not None:
            return res
        else:
            queue_name = self.subscribe(key, None)
            mut_subscriber = self.new_subscriber(queue_name)
            data = mut_subscriber.get_next()
            logging.info("Received [{}]".format(data))
            self.unsubscribe(queue_name)
            message = CL.SubscriptionMessage().FromString(data)
            if message.change_type != "delete":
                return message.payload
            else:
                logging.warning("Subscribe {} got delete event".format(key))
                return None

    def get_user_id(self) -> str:
        auth_content = decode_jwt_without_validation(self.jwt)
        return auth_content.user_id

    def set_variable(self, key: str, payload: bytes, receivers: List[CL.Participant]):
        if self.task_id is None:
            logging.error("set_variable task_id not found")
        new_participants = [
            CL.Participant(user_id=self.get_user_id(), role="requester")
        ]
        for p in receivers:
            if p.user_id == self.get_user_id():
                self.create_entry(
                    "_remote_storage:private:{}:_variable_transfer:{}:{}".format(
                        p.user_id, self.get_task_id(), key
                    ),
                    payload,
                )
            else:
                new_participants.append(
                    CL.Participant(
                        user_id=p.user_id,
                        role="provider",
                    )
                )
        params = CL.CreateParams(
            remote_key_name="_variable_transfer:{}:{}".format(self.get_task_id(), key),
            payload=payload,
        )
        payload = params.SerializeToString()
        self.run_task("remote_storage.create", payload, new_participants, False)

    def get_variable(self, key: str, sender: CL.Participant) -> bytes:
        if self.task_id is None:
            logging.error("get_variable task_id not found")
        key = "_remote_storage:private:{}:_variable_transfer:{}:{}".format(
            sender.user_id, self.get_task_id(), key
        )
        res = self.read_or_wait(key)
        return res

    def get_participant_id(self, participants: List[CL.Participant]) -> int:
        for i, participant in enumerate(participants):
            if participant.user_id == self.get_user_id():
                return i
        return None

    def remote_storage_create(
        self,
        providers: List[str],
        key: str,
        payload: bytes,
        is_public: bool,
    ):
        participants = [
            CL.Participant(
                user_id=self.get_user_id(),
                role="requester",
            )
        ]
        for provider in providers:
            participants.append(
                CL.Participant(
                    user_id=provider,
                    role="provider",
                )
            )
        params = CL.CreateParams(
            remote_key_name=key, payload=payload, is_public=is_public
        )
        payload = params.SerializeToString()

        self.run_task("remote_storage.create", payload, participants, False)

    def remote_storage_read(
        self,
        provider: str,
        key: str,
        is_public: bool,
        holder_id: str,
    ) -> bytes:
        participants = [
            CL.Participant(
                user_id=self.get_user_id(),
                role="requester",
            ),
            CL.Participant(user_id=provider, role="provider"),
        ]
        params = CL.ReadParams(
            remote_key_name=key, is_public=is_public, holder_id=holder_id
        )
        payload = params.SerializeToString()
        task_id = self.run_task("remote_storage.read", payload, participants, False)
        status = self.read_or_wait("tasks:{}:status".format(task_id))
        if status[0] == 0:
            data = self.read_or_wait("tasks:{}:output".format(task_id))
            return data
        else:
            logging.error("remote_storage.read: status_code: {}".format(status[0]))
            return None

    def remote_storage_update(
        self,
        providers: List[str],
        key: str,
        payload: bytes,
        is_public: bool,
    ):
        participants = [
            CL.Participant(
                user_id=self.get_user_id(),
                role="requester",
            )
        ]
        for provider in providers:
            participants.append(CL.Participant(user_id=provider, role="provider"))
        params = CL.UpdateParams(
            remote_key_name=key, payload=payload, is_public=is_public
        )
        payload = params.SerializeToString()
        self.run_task("remote_storage.update", payload, participants, False)

    def remote_storage_delete(
        self,
        providers: List[str],
        key: str,
        is_public: bool,
    ):
        participants = [
            CL.Participant(
                user_id=self.get_user_id(),
                role="requester",
            )
        ]
        for provider in providers:
            participants.append(
                CL.Participant(
                    user_id=provider,
                    role="provider",
                )
            )
        params = CL.DeleteParams(
            remote_key_name=key,
            is_public=is_public,
        )
        payload = params.SerializeToString()
        self.run_task("remote_storage.delete", payload, participants, False)

    def update_registries(self, registries: CL.Registries):
        participants = [
            CL.Participant(
                user_id=self.get_user_id(),
                role="update_registries",
            )
        ]
        payload = registries.SerializeToString()
        self.run_task("registry", payload, participants, False)

    def lock(self, key: str) -> Tuple[str, int]:
        return self.lock_with_retry_time(key, 100)

    def lock_with_retry_time(
        self,
        key: str,
        retry_time_cap_in_ms: int,
    ) -> Tuple[str, int]:
        sleep_time_cap = 1
        rnd_num = random.getrandbits(32)
        while True:
            payload = rnd_num.to_bytes(length=32, byteorder="little", signed=False)
            try:
                ret = self.create_entry("_lock:{}".format(key), payload)
            except grpc.RpcError as e:
                pass
            else:
                break
            st = random.randint(0, sleep_time_cap - 1)
            time.sleep(st / 1000)  # st is in milli-second
            sleep_time_cap *= 2
            if sleep_time_cap > retry_time_cap_in_ms:
                sleep_time_cap = retry_time_cap_in_ms
        return (key, rnd_num)

    def unlock(self, lock_token: Tuple[str, int]):
        key, rnd_num = lock_token
        rnd_num_in_storage = self.read_entry("_lock:{}".format(key))
        rnd_num_in_storage = int().from_bytes(
            rnd_num_in_storage, byteorder="little", signed=False
        )
        if rnd_num_in_storage == rnd_num:
            self.delete_entry("_lock:{}".format(key))
        else:
            logging.error("Invalid token.")


def generate_user() -> Tuple[
    secp256k1.PublicKey, secp256k1.PrivateKey
]:  # generate key pair(pub key+secret key) by SECP256K1 algorithm
    private_key = secp256k1.PrivateKey()
    public_key = private_key.pubkey
    return public_key, private_key


def prepare_import_user_signature(
    user_pub_key: secp256k1.PublicKey,
    user_sec_key: secp256k1.PrivateKey,
    core_pub_key: str,  # directly use string because hard to construct string back to secp256k1.PublicKey
    expiration_timestamp: int,
) -> Tuple[int, str]:
    signature_timestamp = get_time_stamp()
    msg = (
        public_key_to_vec(user_pub_key)
        + signature_timestamp.to_bytes(8, byteorder="little")
        + expiration_timestamp.to_bytes(8, byteorder="little")
        + core_pub_key
    )  # connect them all
    ecdsax = user_sec_key.ecdsa_sign(msg)  # sign and get signature
    signature = user_sec_key.ecdsa_serialize_compact(
        ecdsax
    )  # serialize the signature to given format align rust
    return signature_timestamp, signature


def decode_jwt_without_validation(
    jwt: str,
) -> JWT:  # decode jwt string to get JWT object(with validation)
    split = jwt.split(".")
    try:
        payload = base64_decode(split[1])
    except Exception as res:
        logging.error("jwt base64 decode exception")
        raise res
    else:
        try:
            dic = json.loads(payload)
        except Exception as res:
            logging.error("json decode exception, decoding:{}".format(payload))
            raise res
        else:
            jwt = JWT(
                dic["privilege"], dic["user_id"], dic["exp"]
            )  # construct JWT from decoded result and return
            return jwt


def public_key_to_vec(key: secp256k1.PublicKey) -> str:
    return key.serialize()


def get_time_stamp():
    return int(time.time())


def base64_decode(sw):
    while len(sw) % 4 != 0:  # supplement missing padding '='
        sw += "="
    sw = bytes(sw, "utf-8")
    return base64.urlsafe_b64decode(sw)


def str_to_byte(s: str):
    return bytes(s, "utf-8")


def byte_to_str(b: bytes):
    return str(b, encoding="utf-8")


def get_timestamp(key_path: str) -> int:  # decode path name to get timestamp
    pos = key_path.rfind("@")
    return int(key_path[pos + 1 :])


def get_jwt_auth(
    jwt: str,
):  # duplicate functionality of creating metadata for authorization from jwt
    return [
        (
            "authorization",
            jwt,
        )
    ]
