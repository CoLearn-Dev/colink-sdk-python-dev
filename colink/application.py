import logging
import json
import time
import base64
from typing import Tuple, List, Union, Any
import pika
import grpc
import secp256k1
import copy
import redis
from urllib.parse import urlparse
import uuid
from colink.colink_pb2 import *
from colink.colink_pb2_grpc import CoLinkStub, CoLinkServicer
from colink.colink_remote_storage_pb2 import *
from colink.colink_remote_storage_pb2_grpc import *
from colink.colink_policy_module_pb2 import *
from colink.colink_policy_module_pb2_grpc import *
from colink.colink_registry_pb2 import *
from colink.colink_registry_pb2_grpc import *


class JWT:
    def __init__(self, privilege: str, user_id: str, exp: int):
        self.privilege = privilege
        self.user_id = user_id
        self.exp = exp


class CoLinkInfo:
    def __init__(
        self, mq_uri: str, core_public_key: bytes, requestor_ip: str, version: str
    ):
        self.mq_uri = mq_uri
        self.core_public_key = core_public_key
        self.requestor_ip = requestor_ip
        self.version = version


class CoLinkSubscriber:
    def __init__(self, mq_uri: str, queue_name: str):
        uri_parsed = urlparse(mq_uri)
        self.queue_name = queue_name
        if uri_parsed.scheme.startswith("redis"):
            r = redis.from_url(mq_uri)
            self.mq_type = "redis"
            self.rabbitmq_channel = None
            self.redis_connection = r
            # self.redis_connection.subscribe(queue_name)
        else:
            param = pika.connection.URLParameters(url=mq_uri)
            mq = pika.BlockingConnection(param)  # establish rabbitmq connection
            self.mq_type = "rabbitmq"
            self.rabbitmq_channel = mq.channel()
            self.redis_connection = None

    def get_next(self) -> bytes:
        if self.mq_type == "rabbitmq":
            print("go rabbit ",self.queue_name, file=open("1.txt", "a"))
            for method, _, body in self.rabbitmq_channel.consume(
                self.queue_name
            ):  # get the first package from queue then return
                self.rabbitmq_channel.basic_ack(
                    method.delivery_tag
                )  # ack this package before return
                print("acked", file=open("1.txt", "a"))
                print(body, file=open("1.txt", "a"))
                return body
        elif self.mq_type == "redis":
            # data=self.redis_connection.get_message()
            print("go redis",self.queue_name, file=open("1.txt", "a"))
            consumer_name = str(uuid.uuid4())
            res = self.redis_connection.xreadgroup(
                self.queue_name, consumer_name, {self.queue_name: ">"}, count=1, block=0
            )
            print("readed", file=open("1.txt", "a"))
            key, ids = res[0]
            id, _map = ids[0]
            data = _map[b"payload"]
            id = byte_to_str(id)
            self.redis_connection.xack(self.queue_name, self.queue_name, id)
            print("acked ", id, file=open("1.txt", "a"))
            self.redis_connection.xdel(self.queue_name, id)
            print("del", file=open("1.txt", "a"))
            print(data, file=open("1.txt", "a"))

            # p.subscribe('foo')
            return data
        else:
            raise Exception("Unsupported MQ type")


def request_info(self) -> CoLinkInfo:
    client = self._grpc_connect(self.core_addr)
    try:
        response = client.RequestInfo(
            request=Empty(),
            metadata=get_jwt_auth(self.jwt),
        )
    except grpc.RpcError as e:
        logging.error(
            f"Request CoreInfo Received exception: code={e.code()} message={e.details()}"
        )
        raise e
    else:
        return CoLinkInfo(
            response.mq_uri,
            response.core_public_key,
            response.requestor_ip,
            response.version,
        )


def import_guest_jwt(self, jwt: str):
    jwt_decoded = decode_jwt_without_validation(
        jwt
    )  # want user_id from jwt, decode it to get
    self.create_entry(
        "_internal:known_users:{}:guest_jwt".format(jwt_decoded.user_id),
        jwt,
    )


def import_core_addr(
    self,
    user_id: str,
    core_addr: str,
):
    self.create_entry(
        "_internal:known_users:{}:core_addr".format(user_id),
        core_addr,
    )


def set_task_id(self, task_id: str):
    self.task_id = task_id


def get_task_id(self) -> str:
    if self.task_id is None:
        logging.error("task_id not found")
        raise Exception("task_id not found")
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
            request=UserConsent(
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
    return self.generate_token_with_expiration_time(get_time_stamp() + 86400, privilege)


def generate_token_with_signature(
    self,
    public_key: secp256k1.PublicKey,
    signature_timestamp: int,
    expiration_timestamp: int,
    signature: bytes,
) -> str:
    public_key_vec = public_key_to_vec(public_key)
    client = self._grpc_connect(self.core_addr)
    response = client.GenerateToken(
        request=GenerateTokenRequest(
            expiration_time=expiration_timestamp,
            privilege="user",
            user_consent=UserConsent(
                public_key=public_key_vec,
                signature_timestamp=signature_timestamp,
                expiration_timestamp=expiration_timestamp,
                signature=signature,
            ),
        ),
        metadata=get_jwt_auth(self.jwt),
    )
    return response.jwt


def generate_token_with_expiration_time(
    self,
    expiration_time: int,
    privilege: str,
) -> str:
    client = self._grpc_connect(self.core_addr)
    response = client.GenerateToken(
        request=GenerateTokenRequest(
            expiration_time=expiration_time,
            privilege=privilege,
        ),
        metadata=get_jwt_auth(self.jwt),
    )
    return response.jwt


def create_entry(self, key_name: str, payload: Any) -> str:
    client = self._grpc_connect(self.core_addr)
    payload = try_convert_to_bytes(payload)
    try:
        response = client.CreateEntry(
            StorageEntry(
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


def read_entries(self, entries: List[StorageEntry]) -> List[StorageEntry]:
    client = self._grpc_connect(self.core_addr)
    try:
        response = client.ReadEntries(
            StorageEntries(entries=entries),
            metadata=get_jwt_auth(self.jwt),
        )
    except grpc.RpcError as e:
        return None
    else:
        return response.entries


def update_entry(self, key_name: str, payload: Any) -> str:
    client = self._grpc_connect(self.core_addr)
    payload = try_convert_to_bytes(payload)
    try:
        response = client.UpdateEntry(
            StorageEntry(
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
            StorageEntry(
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


# The default expiration time is 1 day later.
def run_task(
    self,
    protocol_name: str,
    protocol_param: Any,
    participants: List[Participant],
    require_agreement: bool,
    expiration_time: Union[int, None] = None,
) -> str:
    if expiration_time is None:
        expiration_time = get_time_stamp() + 86400
    client = self._grpc_connect(self.core_addr)
    protocol_param = try_convert_to_bytes(protocol_param)
    task = Task(
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
        request=ConfirmTaskRequest(
            task_id=task_id,
            decision=Decision(
                is_approved=is_approved, is_rejected=is_rejected, reason=reason
            ),
        ),
        metadata=get_jwt_auth(self.jwt),
    )


def finish_task(self, task_id: str):
    client = self._grpc_connect(self.core_addr)
    response = client.FinishTask(
        request=Task(
            task_id=task_id,
        ),
        metadata=get_jwt_auth(self.jwt),
    )


def subscribe(self, key_name: str, start_timestamp: int) -> str:
    if start_timestamp is None:
        start_timestamp = time.time_ns()
    client = self._grpc_connect(self.core_addr)
    response = client.Subscribe(
        request=SubscribeRequest(
            key_name=key_name,
            start_timestamp=start_timestamp,
        ),
        metadata=get_jwt_auth(self.jwt),
    )
    return response.queue_name


def unsubscribe(self, queue_name: str):
    client = self._grpc_connect(self.core_addr)
    response = client.Unsubscribe(
        MQQueueName(
            queue_name=queue_name,
        ),
        metadata=get_jwt_auth(self.jwt),
    )


def new_subscriber(self, queue_name: str) -> CoLinkSubscriber:
    mq_uri = self.request_info().mq_uri
    subscriber = CoLinkSubscriber(mq_uri, queue_name)
    return subscriber


def _grpc_connect(
    self, addr: str
) -> CoLinkStub:  # give string addr, return grpc client object, currently non TLS
    try:

        def address_filter(
            address,
        ):  # when address starts with 127.0.0.1/0.0.0.0 connect error, but using localhost works, due to domain cert
            if address.startswith("127.0.0.1"):
                return address.replace("127.0.0.1", "localhost")
            elif address.startswith("0.0.0.0"):
                return address.replace("0.0.0.0", "localhost")
            return address

        if addr.startswith("http://"):
            channel = grpc.insecure_channel(addr.replace("http://", ""))
        else:  # TLS case
            if self._identity is not None:
                client_cert, client_key = self._identity
            else:
                client_cert, client_key = None, None
            credentials = grpc.ssl_channel_credentials(
                root_certificates=self.ca_cert,
                private_key=client_key,
                certificate_chain=client_cert,
            )
            channel = grpc.secure_channel(
                address_filter(addr.replace("https://", "")), credentials
            )
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
        storage_entry = StorageEntry(key_path=key)
    else:
        storage_entry = StorageEntry(key_name=key)
    res = self.read_entries([storage_entry])
    if res is None:
        return None
    else:
        return res[0].payload


def read_keys(
    self,
    prefix: str,
    include_history: bool,
) -> List[StorageEntry]:
    client = self._grpc_connect(self.core_addr)
    request = ReadKeysRequest(prefix=prefix, include_history=include_history)
    response = client.ReadKeys(request, metadata=get_jwt_auth(self.jwt))
    return response.entries


def get_user_id(self) -> str:
    auth_content = decode_jwt_without_validation(self.jwt)
    return auth_content.user_id


def start_protocol_operator(self, protocol_name: str, user_id: str):
    client = self._grpc_connect(self.core_addr)
    request = StartProtocolOperatorRequest(protocol_name=protocol_name, user_id=user_id)
    response = client.StartProtocolOperator(
        request=request, metadata=get_jwt_auth(self.jwt)
    )
    return response.instance_id


def stop_protocol_operator(self, instance_id: str):
    client = self._grpc_connect(self.core_addr)
    request = ProtocolOperatorInstanceId(instance_id=instance_id)
    client.StopProtocolOperator(request=request, metadata=get_jwt_auth(self.jwt))


def get_core_addr(self) -> str:
    if self.core_addr is None:
        raise Exception("core_addr not found")
    return self.core_addr


def generate_user() -> Tuple[
    secp256k1.PublicKey, secp256k1.PrivateKey
]:  # generate key pair(pub key+secret key) by SECP256K1 algorithm
    private_key = secp256k1.PrivateKey()
    public_key = private_key.pubkey
    return public_key, private_key


def prepare_import_user_signature(
    user_pub_key: secp256k1.PublicKey,
    user_sec_key: secp256k1.PrivateKey,
    # directly use string because hard to construct string back to secp256k1.PublicKey
    core_pub_key: str,
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


def byte_to_str(b: bytes):
    return str(b, encoding="utf-8")


def get_path_timestamp(key_path: str) -> int:  # decode path name to get timestamp
    pos = key_path.rfind("@")
    return int(key_path[pos + 1 :])


def byte_to_int(b: bytes, byteorder: str = "little", signed: bool = "False"):
    return int().from_bytes(b, byteorder=byteorder, signed=signed)


def get_jwt_auth(
    jwt: str,
):  # duplicate functionality of creating metadata for authorization from jwt
    return [
        (
            "authorization",
            jwt,
        )
    ]


def try_convert_to_bytes(val: Any):
    if isinstance(val, str):
        return bytes(val, "utf-8")
    elif isinstance(val, int):
        return val.to_bytes(length=32, byteorder="little", signed=True)
    elif isinstance(val, bytes):
        return val
    else:
        raise NotImplementedError(
            f"{type(val)} automatic conversion to bytes not supported. Please serialize to bytes manually."
        )
