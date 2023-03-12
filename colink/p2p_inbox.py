from typing import Mapping, Set
import colink as CL
import jwt
import json
import secrets
from http.server import HTTPServer, BaseHTTPRequestHandler
import ssl
import socket
import random
import threading
from threading import Condition
import ctypes
import atexit
import logging
import time
from cryptography import x509
import requests
from requests_toolbelt.adapters import host_header_ssl
from cryptography.hazmat.primitives.serialization import Encoding
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
    
    def do_GET(self):
        self._send_response(Status_OK)

    def do_POST(self):
        data = self.server.data
        notification_channels = self.server.notification_channels
        user_id = self.headers.get("user_id", None)
        key = self.headers.get("key", None)
        token = self.headers.get("token", None)
        if user_id is None or key is None or token is None:
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
        data[(user_id, key)] = body
        nc = notification_channels.get((user_id, key), None)
        if nc is not None:
            nc.acquire()
            nc.notify()
            nc.release()
        self._send_response(Status_OK)


# Kill thread code from https://github.com/fitoprincipe/ipygee/blob/ab622c0c8b4f66b7e131cf6b7aeb08e751ceb513/ipygee/threading.py#L12
def kill_thread(th):
    tid = th.ident
    """Raises an exception in the threads with id tid"""
    res = ctypes.pythonapi.PyThreadState_SetAsyncExc(
        ctypes.c_long(tid), ctypes.py_object(SystemExit)
    )
    if res == 0:
        raise ValueError("invalid thread id")
    elif res != 1:
        # """if it returns a number greater than one, you're in trouble,
        # and you should call it again with exc=NULL to revert the effect"""
        ctypes.pythonapi.PyThreadState_SetAsyncExc(tid, None)
        raise SystemError("PyThreadState_SetAsyncExc failed")


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
        port = random.randint(10000, 20000)
        while socket.socket().connect_ex(("0.0.0.0", port)) == 0:
            port = random.randint(10000, 20000)
        httpd = HTTPServer(("0.0.0.0", port), VTInBox_RequestHandler)
        httpd.data = dict()  # pass to http request handler
        httpd.notification_channels = dict()
        httpd.jwt_secret = jwt_secret
        httpd.socket = ssl.wrap_socket(
            httpd.socket,
            keyfile=priv_key_file.name,
            certfile=cert_file.name,
            server_side=True,
        )
        
        priv_key_file.close()
        self.server_thread = threading.Thread(
            target=httpd.serve_forever, args=(), daemon=True
        )
        httpd.thread = self.server_thread
        self.server_thread.start()
        self.port = port
        self.jwt_secret = jwt_secret
        self.tls_cert = tls_cert_der
        self.data_map = httpd.data
        self.notification_channels = httpd.notification_channels
        atexit.register(self.clean)
        while True:
            try:
                s = requests.Session()
                s.mount("https://", host_header_ssl.HostHeaderSSLAdapter())
                response = s.get(f"https://127.0.0.1:{port}",headers={"Host": "vt-p2p.colink",},verify=cert_file.name,cert=None)
            except Exception as error:
                logging.warning('Server failed once!')
                time.sleep(0.5)
                pass
            else:
                logging.warning('Server CDCG!')
                break
        cert_file.close()
    def clean(self):
        kill_thread(self.server_thread)


class VtP2pCtx:
    def __init__(
        self,
        public_addr: str = None,
        has_created_inbox: bool = False,
        inbox_server: VTInboxServer = None,
        has_configured_inbox: Set[str] = None,
        remote_inboxs: Mapping[str, VTInbox] = None,
    ):
        self.public_addr = public_addr
        self.has_created_inbox = has_created_inbox
        self.inbox_server = inbox_server
        self.has_configured_inbox = (
            has_configured_inbox if has_configured_inbox else set()
        )
        self.remote_inboxes = remote_inboxs if remote_inboxs else {}


def _send_variable_p2p(cl, key: str, payload: bytes, receiver: CL.Participant, idx):
    if not cl.vt_p2p_ctx.remote_inboxes.get(receiver.user_id, None):
        logging.warning(f"round {payload} send to user {idx} wait inbox")
        inbox = cl.recv_variable_with_remote_storage("inbox", receiver)
        vt_inbox_dic = json.loads(inbox)
        if isinstance(vt_inbox_dic["tls_cert"], list):
            vt_inbox_dic["tls_cert"] = bytes(vt_inbox_dic["tls_cert"])
        inbox = VTInbox(
            vt_inbox_dic["addr"], vt_inbox_dic["vt_jwt"], vt_inbox_dic["tls_cert"]
        )
        if not inbox.addr:
            inbox = None
        cl.vt_p2p_ctx.remote_inboxes[receiver.user_id] = inbox
        logging.warning(f"round {payload} send to user {idx} built inbox")
    remote_inbox = cl.vt_p2p_ctx.remote_inboxes.get(receiver.user_id, None)
    logging.warning(f"round {payload} send to user {idx} got inbox")
    if remote_inbox is not None:
        cert = x509.load_der_x509_certificate(remote_inbox.tls_cert)
        cert_file = NamedTemporaryFile()
        cert_file.write(cert.public_bytes(Encoding.PEM))  # conver DER format to PEM
        cert_file.seek(0)
        stripped_addr = remote_inbox.addr.strip("https://")
        logging.warning(f"round {payload} send to user {idx} before conn")
        headers = {
            "user_id": cl.get_user_id(),
            "key": key,
            "token": remote_inbox.vt_jwt,
            "Host": "vt-p2p.colink",
        }
        logging.warning(f"round {payload} send to user {idx} before post")
        # ssl_context = ssl.create_default_context()
        # ssl_context.check_hostname = False
        # ssl_context.load_verify_locations(cert_file.name)
        # req = urllib.request.Request(remote_inbox.addr, data=payload, headers=headers, method='POST')
        s = requests.Session()
        s.mount("https://", host_header_ssl.HostHeaderSSLAdapter())
        logging.warning(f"round {payload} send to user {idx} end post")
        try:
            logging.warning(
                f"round {payload} send to user {idx} end addr:{stripped_addr}"
            )
            resp = s.post(
                url=remote_inbox.addr,
                data=payload,
                headers=headers,
                verify=cert_file.name,
                cert=None,
            )
            logging.warning(f"round {payload} send to user {idx} URL OPENED!")
            if resp.status_code != Status_OK:
                raise Exception(f"Remote inbox: error {resp.status_code}")
        except Exception as e:
            raise e
        cert_file.close()
    else:
        raise Exception("Remote inbox: not available")


def _recv_variable_p2p(cl, key: str, sender: CL.Participant) -> bytes:
    # send inbox information to the sender by remote_storage
    if not sender.user_id in cl.vt_p2p_ctx.has_configured_inbox:
        # create inbox if it does not exist
        logging.warning(f"user {cl.ID}  round {cl.round} start recv")
        if cl.vt_p2p_ctx.public_addr and cl.vt_p2p_ctx.has_created_inbox == False:
            logging.warning(f"user {cl.ID}  round {cl.round} start server")
            cl.vt_p2p_ctx.inbox_server = VTInboxServer()
            cl.vt_p2p_ctx.has_created_inbox = True
            logging.warning(f"user {cl.ID}  round {cl.round} started server")
        else:
            logging.warning(f"user {cl.ID}  round {cl.round} server already started")
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
            vt_inbox = VTInbox(None, None, None)
        vt_inbox_vec = json.dumps(
            {
                "addr": vt_inbox.addr,
                "vt_jwt": vt_inbox.vt_jwt,
                "tls_cert": list(vt_inbox.tls_cert),
            }
        )
        cl.send_variable_with_remote_storage(
            "inbox", bytes(vt_inbox_vec, encoding="utf-8"), [sender]
        )
        cl.vt_p2p_ctx.has_configured_inbox.add(sender.user_id)
    if cl.vt_p2p_ctx.public_addr is None:
        raise Exception("Remote inbox: not available")
    logging.warning(f"receiver user {cl.ID}  round {cl.round} start condition")
    tx = Condition()
    inbox_server = cl.vt_p2p_ctx.inbox_server
    logging.warning(f"receiver user {cl.ID}  round {cl.round} try data")
    data = inbox_server.data_map.get((sender.user_id, key), None)
    if data is not None:
        return data
    logging.warning(f"receiver user {cl.ID}  round {cl.round} no data")
    tx.acquire()
    inbox_server.notification_channels[(sender.user_id, key)] = tx
    tx.wait()
    logging.warning(f"receiver user {cl.ID}  round {cl.round} got again data")
    data = inbox_server.data_map.get((sender.user_id, key), None)
    tx.release()
    logging.warning(f"receiver user {cl.ID}  round {cl.round} lock released")
    if data is not None:
        return data
    else:
        raise Exception("Fail to retrieve data from the inbox")
