from typing import Mapping, Set
import colink as CL
import jwt
import json
import secrets
from http.client import HTTPSConnection
from http.server import HTTPServer, BaseHTTPRequestHandler
import ssl
import socket
import random
import threading
from queue import Queue
import time
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from .application import Mutex, RWLock
from tempfile import NamedTemporaryFile
from .tls_utils import gen_cert

class VTInbox:
    def __init__(self, addr: str, vt_jwt: str, tls_cert: bytes):
        self.addr = addr
        self.vt_jwt = vt_jwt
        self.tls_cert = tls_cert


Status_OK = 200
Status_BAD_REQUEST = 400
Status_UNAUTHORIZED = 401


class VTInBox_RequestHandler(BaseHTTPRequestHandler):
    def _send_response(self, resp: int):
        self.send_response_only(resp)
        self.send_header("Content-type", "text/plaintext")
        self.end_headers()

    def do_POST(self):
        data = self.server.data
        notification_channels = self.server.notification_channels
        user_id = self.headers.get("user_id", "")
        key = self.headers.get("key", "")
        token = self.headers.get("token")
        if not user_id or not key or not token:
            self._send_response(Status_BAD_REQUEST)
            return
        try:
            token = jwt.decode(token, self.server.jwt_secret, algorithms=["HS256"])
        except Exception as e:
            self._send_response(Status_UNAUTHORIZED)
            return

        if token["user_id"] != user_id:
            self._send_response(Status_UNAUTHORIZED)
            return
        # payload
        length = int(self.headers.get("content-length"))
        body = self.rfile.read(length)
        with data.write():
            data.update({(user_id, key): body})
        with notification_channels.read():
            nc = notification_channels.get((user_id, key), "")
            if nc:
                nc.put(1)  # send
            self._send_response(Status_OK)


def server_maintainer(server, q):
    while True:
        if not q.empty():
            server.shutdown()
            break
        time.sleep(0.01)


class VTInboxServer:
    def __init__(self):
        jwt_secret = secrets.token_bytes(32)
        # tls
        tls_cert_der, tls_cert_pem, priv_key_pem = gen_cert()
        cert_file, priv_key_file = NamedTemporaryFile(), NamedTemporaryFile()
        priv_key_file.write(priv_key_pem)
        priv_key_file.seek(0)
        cert_file.write(tls_cert_pem)
        cert_file.seek(0)
        # http server
        port = random.randint(10000, 30000)
        if socket.socket().connect_ex(("0.0.0.0", port)) == 0:
            port = random.randint(10000, 30000)
        httpd = HTTPServer(("0.0.0.0", port), VTInBox_RequestHandler)
        httpd.data = RWLock(dict())  # pass to http request handler
        httpd.notification_channels = RWLock(dict())
        httpd.jwt_secret = jwt_secret
        httpd.socket = ssl.wrap_socket(
            httpd.socket,
            keyfile=priv_key_file.name,
            certfile=cert_file.name,
            server_side=True,
        )
        cert_file.close()
        priv_key_file.close()
        shutdown_channel = Queue()
        thread_server = threading.Thread(target=httpd.serve_forever, args=())
        thread_server.start()
        thread_maintain = threading.Thread(
            target=server_maintainer,
            args=(
                httpd,
                shutdown_channel,
            ),
            daemon=True,
        )
        thread_maintain.start()
        self.port = port
        self.jwt_secret = jwt_secret
        self.tls_cert = tls_cert_der
        self.data_map = httpd.data
        self.shutdown_channel = shutdown_channel
        self.notification_channels = httpd.notification_channels


class VtP2pCtx:
    def __init__(
        self,
        public_addr: str = "",
        has_created_inbox: bool = False,
        inbox_server: VTInboxServer = None,
        has_configured_inbox: Set[str] = set(),
        remote_inboxs: Mapping[str, VTInbox] = {},
    ):
        self.public_addr = public_addr
        self.has_created_inbox = Mutex(has_created_inbox)
        self.inbox_server = inbox_server
        self.has_configured_inbox = has_configured_inbox
        self.remote_inboxes = remote_inboxs


def _set_variable_p2p(cl, key: str, payload: bytes, receiver: CL.Participant):
    if not cl.vt_p2p_ctx.remote_inboxes.get(receiver.user_id, ""):
        inbox = cl.get_variable_with_remote_storage("inbox", receiver)
        vt_inbox_dic = json.loads(inbox)
        if isinstance(vt_inbox_dic["tls_cert"], list):
            vt_inbox_dic["tls_cert"] = bytes(vt_inbox_dic["tls_cert"])
        inbox = VTInbox(
            vt_inbox_dic["addr"], vt_inbox_dic["vt_jwt"], vt_inbox_dic["tls_cert"]
        )
        if not inbox.addr:
            inbox = None
        cl.vt_p2p_ctx.remote_inboxes.update({receiver.user_id: inbox})
    remote_inbox = cl.vt_p2p_ctx.remote_inboxes.get(receiver.user_id, "")
    if remote_inbox:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        cert = x509.load_der_x509_certificate(remote_inbox.tls_cert)
        cert_file = NamedTemporaryFile()
        cert_file.write(cert.public_bytes(Encoding.PEM))  # conver DER format to PEM
        cert_file.seek(0)
        ctx.load_verify_locations(cert_file.name)
        cert_file.close()
        ctx.check_hostname = False
        stripped_addr = remote_inbox.addr.strip("https://")
        conn = HTTPSConnection(stripped_addr, context=ctx)
        headers = {
            "user_id": cl.get_user_id(),
            "key": key,
            "token": remote_inbox.vt_jwt,
        }
        conn.request("POST", "/post", payload, headers)
        try:
            response = conn.getresponse()
            if response.getcode() != Status_OK:
                raise Exception(f"Remote inbox: error {response.getcode()}")
        except Exception as e:
            raise e
    else:
        raise Exception("Remote inbox: not available")


def _get_variable_p2p(cl, key: str, sender: CL.Participant) -> bytes:
    # send inbox information to the sender by remote_storage
    if not sender.user_id in cl.vt_p2p_ctx.has_configured_inbox:
        # create inbox if it does not exist
        with cl.vt_p2p_ctx.has_created_inbox.lock():
            if (
                cl.vt_p2p_ctx.public_addr
                and cl.vt_p2p_ctx.has_created_inbox._value == False
            ):
                cl.vt_p2p_ctx.inbox_server = VTInboxServer()
                cl.vt_p2p_ctx.has_created_inbox._value = True
        # generate vt_inbox information for the sender
        if cl.vt_p2p_ctx.public_addr:
            jwt_secret = cl.vt_p2p_ctx.inbox_server.jwt_secret
            vt_jwt = jwt.encode(
                {"user_id": sender.user_id}, jwt_secret, algorithm="HS256"
            )
            vt_inbox = VTInbox(
                f"https://{cl.vt_p2p_ctx.public_addr}:{cl.vt_p2p_ctx.inbox_server.port}",
                vt_jwt,
                cl.vt_p2p_ctx.inbox_server.tls_cert,
            )
        else:
            vt_inbox = VTInbox("", "", b"")
        vt_inbox_vec = json.dumps(
            {
                "addr": vt_inbox.addr,
                "vt_jwt": vt_inbox.vt_jwt,
                "tls_cert": list(vt_inbox.tls_cert),
            }
        )
        cl.set_variable_with_remote_storage(
            "inbox", bytes(vt_inbox_vec, encoding="utf-8"), [sender]
        )
        cl.vt_p2p_ctx.has_configured_inbox.add(sender.user_id)
    if cl.vt_p2p_ctx.public_addr == "":
        raise Exception("Remote inbox: not available")
    tx = Queue()

    inbox_server = cl.vt_p2p_ctx.inbox_server
    with inbox_server.data_map.read():
        data = inbox_server.data_map.get((sender.user_id, key), "")
        if data:
            return data
    with inbox_server.notification_channels.write():
        inbox_server.notification_channels.update({(sender.user_id, key): tx})
    # try again after creating the channel
    with inbox_server.data_map.read():
        data = inbox_server.data_map.get((sender.user_id, key), "")
        if data:
            return data
    while tx.empty():
        continue
    
    inbox_server = cl.vt_p2p_ctx.inbox_server
    with inbox_server.data_map.read():
        data = inbox_server.data_map.get((sender.user_id, key), "")
        if data:
            return data
        else:
            raise Exception("Fail to retrieve data from the inbox")