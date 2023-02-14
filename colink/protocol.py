import os
import argparse
import pika
import logging
import queue
import time
import random
import threading
from threading import Thread
from .application import *
from .p2p_inbox import VtP2pCtx
from .colink import CoLink


def thread_func(q, protocol_and_role, cl, vt_public_addr, user_func):
    try:
        cl_app = CoLinkProtocol(protocol_and_role, cl, vt_public_addr, user_func)
        cl_app.start()
    except Exception as e:
        q.put(e)


class ProtocolOperator:
    def __init__(self, name: str):
        self.name = name
        self.mapping = {}

    def handle(self, cmd: str):
        def decorator(func):
            self.mapping[cmd] = func

        return decorator

    def run(
        self,
        cl: CoLink = None,
        keep_alive_when_disconnect: bool = False,
        vt_public_addr: str = "",
    ):
        if cl is None:
            cl, keep_alive_when_disconnect, vt_public_addr = _cl_parse_args()
        operator_funcs = {}
        protocols = set()
        failed_protocols = set()
        for protocol_and_role, user_func in self.mapping.items():
            if protocol_and_role.endswith(":@init"):
                protocol_name = protocol_and_role[: len(protocol_and_role) - 6]
                is_initialized_key = "_internal:protocols:{}:_is_initialized".format(
                    protocol_name
                )
                lock = cl.lock(is_initialized_key)
                res = cl.read_entry(is_initialized_key)
                if res is None or res[0] == 0:
                    try:
                        user_func(cl, None, [])
                    except Exception as e:
                        logging.error("{}: {}.".format(protocol_and_role, e))
                        failed_protocols.add(protocol_name)
                    else:
                        cl.update_entry(is_initialized_key, bytes([1]))
                cl.unlock(lock)
            else:
                protocols.add(protocol_and_role[: protocol_and_role.rfind(":")])
                operator_funcs[protocol_and_role] = user_func
        for protocol_name in failed_protocols:
            if protocol_name in protocols:
                protocols.remove(protocol_name)
        for protocol_name in protocols:
            is_initialized_key = "_internal:protocols:{}:_is_initialized".format(
                protocol_name
            )
            cl.update_entry(is_initialized_key, bytes([1]))

        threads = []
        q = queue.Queue()
        for protocol_and_role in self.mapping.keys():  # insert user func to map
            user_func = self.mapping[protocol_and_role]
            t = threading.Thread(
                target=thread_func,
                args=(q, protocol_and_role, cl, vt_public_addr, user_func),
                daemon=True,
            )
            threads.append(t)
        for t in threads:
            t.start()
        if keep_alive_when_disconnect:
            while True:
                if q.empty():
                    if threading.active_count() == 1:
                        break
                else:
                    err = q.get()
                    raise err
                time.sleep(0.01)
        else:
            counter = 0
            timer = time.time() + random.randint(32, 64)
            while True:
                if q.empty():
                    if threading.active_count() == 1:
                        break
                else:
                    err = q.get()
                    raise err
                # both catch thread error & detect server connection
                if time.time() > timer:
                    timer = time.time() + random.randint(32, 64)  # update timer
                    try:
                        cl.request_info()
                    except Exception as e:
                        counter += 1
                        if counter >= 3:
                            break
                    else:
                        counter = 0
                # here we don't directly sleep 32~64s like rust because we have to detect sub-thread errors
                time.sleep(0.01)

    def run_attach(self, cl: CoLink):
        thread = Thread(target=self.run, args=(cl, False, "127.0.0.1"), daemon=True)
        thread.start()


class CoLinkProtocol:
    def __init__(
        self,
        protocol_and_role: str,
        cl: CoLink,
        vt_public_addr: str,
        user_func,
    ):
        self.protocol_and_role = protocol_and_role
        self.cl = cl
        self.vt_public_addr = vt_public_addr
        self.user_func = user_func

    def start(self):
        operator_mq_key = "_internal:protocols:{}:operator_mq".format(
            self.protocol_and_role
        )
        res = self.cl.read_entries(
            [
                StorageEntry(
                    key_name=operator_mq_key,
                )
            ]
        )
        queue_name = ""
        if res is not None:
            queue_name = byte_to_str(res[0].payload)
        else:
            list_key = "_internal:protocols:{}:started".format(self.protocol_and_role)
            latest_key = "_internal:protocols:{}:started:latest".format(
                self.protocol_and_role
            )
            res = self.cl.read_entries(
                [
                    StorageEntry(
                        key_name=list_key,
                    )
                ]
            )
            start_timestamp = 0
            if res is not None:
                list_entry = res[0]
                lis = CoLinkInternalTaskIDList.FromString(list_entry.payload)
                if len(lis.task_ids_with_key_paths) == 0:
                    start_timestamp = get_path_timestamp(list_entry.key_path)
                else:
                    start_timestamp = 1e60
                    for p in lis.task_ids_with_key_paths:
                        start_timestamp = min(
                            start_timestamp, get_path_timestamp(p.key_path)
                        )
            queue_name = self.cl.subscribe(latest_key, start_timestamp)
            self.cl.create_entry(operator_mq_key, queue_name)
        mq_addr = self.cl.request_info().mq_uri
        param = pika.connection.URLParameters(url=mq_addr)
        mq = pika.BlockingConnection(param)  # establish rabbitmq connection
        channel = mq.channel()
        for method, _, body in channel.consume(queue_name):
            channel.basic_ack(method.delivery_tag)
            data = body
            message = SubscriptionMessage.FromString(data)
            if message.change_type != "delete":
                task_id = Task.FromString(message.payload)
                res = self.cl.read_entries(
                    [
                        StorageEntry(
                            key_name="_internal:tasks:{}".format(task_id.task_id),
                        )
                    ]
                )
                if res is not None:
                    task_entry = res[0]
                    task = Task.FromString(task_entry.payload)
                    if task.status == "started":
                        # begin user func
                        cl = self.cl
                        cl.set_task_id(task.task_id)
                        cl.vt_p2p_ctx = VtP2pCtx(self.vt_public_addr)
                        try:
                            self.user_func(cl, task.protocol_param, task.participants)
                        except Exception as e:
                            logging.info(
                                "ProtocolEntry start error: Task {}: {}.".format(
                                    task.task_id, e
                                )
                            )
                            raise e
                        if cl.vt_p2p_ctx.inbox_server is not None:
                            cl.vt_p2p_ctx.inbox_server = None
                        self.cl.finish_task(task.task_id)
                        print('task finished!',file=open("1.txt","a"))
                        logging.info("finnish task:%s", task.task_id)
                else:
                    logging.error("Pull Task Error.")
                    raise Exception("Pull Task Error.")


def _cl_parse_args() -> Tuple[CoLink, bool, str]:
    parser = argparse.ArgumentParser(description="protocol operator entry")
    parser.add_argument("--addr", type=str, default="", help="")
    parser.add_argument("--jwt", type=str, default="", help="")
    parser.add_argument("--ca", type=str, default="", help="")
    parser.add_argument("--cert", type=str, default="", help="")
    parser.add_argument("--key", type=str, default="", help="")
    parser.add_argument("--keep-alive-when-disconnect", action="store_true", help="")
    parser.add_argument("--vt-public-addr", type=str, default="", help="")
    args = parser.parse_args()
    addr = args.addr if args.addr else os.environ.get("COLINK_CORE_ADDR", "")
    jwt = args.jwt if args.jwt else os.environ.get("COLINK_JWT", "")
    ca = args.ca if args.ca else os.environ.get("COLINK_CA_CERT", "")
    cert = args.cert if args.cert else os.environ.get("COLINK_CLIENT_CERT", "")
    key = args.key if args.key else os.environ.get("COLINK_CLIENT_KEY", "")
    args.keep_alive_when_disconnect = args.keep_alive_when_disconnect or bool(
        os.environ.get("COLINK_KEEP_ALIVE_WHEN_DISCONNECT", "")
    )
    vt_public_addr = (
        args.vt_public_addr
        if args.vt_public_addr
        else os.environ.get("COLINK_VT_PUBLIC_ADDR", "")
    )
    cl = CoLink(addr, jwt)
    if ca != "":
        cl.ca_certificate(ca)
    if cert != "" and key != "":
        cl.identity(cert, key)
    return cl, args.keep_alive_when_disconnect, vt_public_addr
