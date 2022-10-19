import os
import argparse
import pika
import logging
from hashlib import sha256
import concurrent.futures
from concurrent.futures._base import TimeoutError
import colink as CL
from colink.sdk_a import byte_to_str, str_to_byte, CoLink, get_path_timestamp


def thread_func(protocol_and_role, cl, user_func):
    cl_app = CoLinkProtocol(protocol_and_role, cl, user_func)
    cl_app.start()


class ProtocolOperator:
    def __init__(self, name: str):
        self.name = name
        self.mapping = {}

    def handle(self, cmd: str):
        def decorator(func):
            self.mapping[cmd] = func

        return decorator

    def run(self):
        cl = _cl_parse_args()
        operator_funcs = {}
        protocols = []
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
                    cl.update_entry(is_initialized_key, bytes([1]))
                cl.unlock(lock)
            else:
                protocols.append(protocol_and_role[: protocol_and_role.rfind(":")])
                operator_funcs[protocol_and_role] = user_func

        for protocol_name in protocols:
            is_initialized_key = "_internal:protocols:{}:_is_initialized".format(
                protocol_name
            )
            cl.update_entry(is_initialized_key, bytes([1]))

        thread_pool = concurrent.futures.ThreadPoolExecutor(max_workers=64)
        threads = []
        for protocol_and_role in self.mapping.keys():  # insert user func to map
            user_func = self.mapping[protocol_and_role]
            threads.append(
                thread_pool.submit(thread_func, protocol_and_role, cl, user_func)
            )
        concurrent.futures.wait(
            threads, return_when=concurrent.futures.FIRST_EXCEPTION
        )  # wait until first exception occurs
        for t in threads:
            try:
                t.result(timeout=0.001)  # try if t has exception occur
            except concurrent.futures.TimeoutError:
                pass
            except Exception as e:  # found the thread where exception occurs
                thread_pool.shutdown(
                    wait=False, cancel_futures=True
                )  # kill all threads in thread pool
                raise e
        return


class CoLinkProtocol:
    def __init__(
        self,
        protocol_and_role: str,
        cl: CoLink,
        user_func,
    ):
        self.protocol_and_role = protocol_and_role
        self.cl = cl
        self.user_func = user_func

    def start(self):
        operator_mq_key = "_internal:protocols:{}:operator_mq".format(
            self.protocol_and_role
        )
        res = self.cl.read_entries(
            [
                CL.StorageEntry(
                    key_name=operator_mq_key,
                )
            ]
        )
        queue_name = ""
        if res is not None:
            operator_mq_entry = res[0]
            queue_name = byte_to_str(operator_mq_entry.payload)
        else:
            list_key = "_internal:protocols:{}:started".format(self.protocol_and_role)
            latest_key = "_internal:protocols:{}:started:latest".format(
                self.protocol_and_role
            )
            res = self.cl.read_entries(
                [
                    CL.StorageEntry(
                        key_name=list_key,
                    )
                ]
            )
            start_timestamp = 0
            if res is not None:
                list_entry = res[0]
                lis = CL.CoLinkInternalTaskIDList.FromString(list_entry.payload)
                if len(lis.task_ids_with_key_paths) == 0:
                    start_timestamp = get_path_timestamp(list_entry.key_path)
                else:
                    start_timestamp = 1e60
                    for p in lis.task_ids_with_key_paths:
                        start_timestamp = min(
                            start_timestamp, get_path_timestamp(p.key_path)
                        )
            queue_name = self.cl.subscribe(latest_key, start_timestamp)
            self.cl.create_entry(operator_mq_key, str_to_byte(queue_name))
        mq_addr, _ = self.cl.request_core_info()
        param = pika.connection.URLParameters(url=mq_addr)
        mq = pika.BlockingConnection(param)  # establish rabbitmq connection
        channel = mq.channel()
        for method, properties, body in channel.consume(queue_name):
            channel.basic_ack(method.delivery_tag)
            data = body
            message = CL.SubscriptionMessage.FromString(data)
            if message.change_type != "delete":
                task_id = CL.Task.FromString(message.payload)
                res = self.cl.read_entries(
                    [
                        CL.StorageEntry(
                            key_name="_internal:tasks:{}".format(task_id.task_id),
                        )
                    ]
                )
                if res is not None:
                    task_entry = res[0]
                    task = CL.Task.FromString(task_entry.payload)
                    if task.status == "started":
                        # begin user func
                        cl = self.cl
                        cl.set_task_id(task.task_id)
                        try:
                            self.user_func(cl, task.protocol_param, task.participants)
                        except Exception as e:
                            logging.info(
                                "ProtocolEntry start error: Task {}: {}.".format(
                                    task.task_id, e
                                )
                            )
                            raise e
                        self.cl.finish_task(task.task_id)

                        logging.info("finnish task:%s", task.task_id)
                else:

                    logging.error("Pull Task Error.")


def _cl_parse_args() -> CoLink:
    parser = argparse.ArgumentParser(description="protocol greeting")
    parser.add_argument("--addr", type=str, default="", help="")
    parser.add_argument("--jwt", type=str, default="", help="")
    parser.add_argument("--ca", type=str, default="", help="")
    parser.add_argument("--cert", type=str, default="", help="")
    parser.add_argument("--key", type=str, default="", help="")
    args = parser.parse_args()
    addr, jwt, ca, cert, key = args.addr, args.jwt, args.ca, args.cert, args.key
    if addr == "":
        if os.environ.get("COLINK_CORE_ADDR") is not None:
            addr = os.environ["COLINK_CORE_ADDR"]
    if jwt == "":
        if os.environ.get("COLINK_JWT"):
            jwt = os.environ["COLINK_JWT"]
    if ca == "":
        if os.environ.get("COLINK_CA_CERT") is not None:
            ca = os.environ["COLINK_CA_CERT"]
    if cert == "":
        if os.environ.get("COLINK_CLIENT_CERT") is not None:
            cert = os.environ["COLINK_CLIENT_CERT"]
    if key == "":
        if os.environ.get("COLINK_CLIENT_KEY") is not None:
            key = os.environ["COLINK_CLIENT_KEY"]
    cl = CoLink(addr, jwt)
    if ca != "":
        cl.ca_certificate(ca)
    if cert != "" and key != "":
        cl.identity(cert, key)
    return cl


def _sha256(s):
    return sha256(s.encode("utf-8")).hexdigest()
