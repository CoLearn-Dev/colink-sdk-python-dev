import functools
import queue
from typing import Tuple, List, Dict
import argparse
import pika
import copy
import logging
from hashlib import sha256
import concurrent.futures
import colink.colink_pb2 as colink_pb2
from colink.sdk_a import byte_to_str, str_to_byte, Dds, get_timestamp


def thread_func(protocol_and_role, dds, user_func):
    dds_app = DdsProtocol(protocol_and_role, dds, user_func)
    dds_app.start()


class ProtocolOperator:
    def __init__(self, name: str):
        self.name = name
        self.mapping = {}

    def handle(self, cmd: str):
        def decorator(func):
            self.mapping[cmd] = func

        return decorator

    def run(self):
        dds = _dds_parse_args()
        thread_pool = concurrent.futures.ThreadPoolExecutor(max_workers=64)
        threads = []
        for x in self.mapping.keys():  # insert user func to map
            dds = copy.deepcopy(dds)
            protocol_and_role = x
            user_func = self.mapping[x]
            threads.append(
                thread_pool.submit(thread_func, protocol_and_role, dds, user_func)
            )
        return


class DdsProtocol:
    def __init__(
        self,
        protocol_and_role: str,
        dds: Dds,
        user_func,
    ):
        self.protocol_and_role = protocol_and_role
        self.dds = dds
        self.user_func = user_func

    def start(self):

        # TODO blocker https://github.com/camelop/dds-dev/issues/25#issuecomment-1079913866
        operator_mq_key = "_internal:protocols:{}:operator_mq".format(
            self.protocol_and_role
        )
        res = self.dds.read_entries(
            [
                colink_pb2.StorageEntry(
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
            res = self.dds.read_entries(
                [
                    colink_pb2.StorageEntry(
                        key_name=list_key,
                    )
                ]
            )
            start_timestamp = 0
            if res is not None:
                list_entry = res[0]
                lis = colink_pb2.CoLinkInternalTaskIDList.FromString(list_entry.payload)
                if len(lis.task_ids_with_key_paths) == 0:
                    start_timestamp = get_timestamp(list_entry.key_path)
                else:
                    start_timestamp = 1e60
                    for p in lis.task_ids_with_key_paths:
                        start_timestamp = min(
                            start_timestamp, get_timestamp(p.key_path)
                        )
            queue_name = self.dds.subscribe(latest_key, start_timestamp)
            self.dds.create_entry(operator_mq_key, str_to_byte(queue_name))
        mq_addr, _ = self.dds.request_core_info()
        param = pika.connection.URLParameters(url=mq_addr)
        mq = pika.BlockingConnection(param)  # establish rabbitmq connection
        channel = mq.channel()
        for method, properties, body in channel.consume(queue_name):
            data = body
            message = colink_pb2.SubscriptionMessage.FromString(data)
            if message.change_type != "delete":
                task_id = colink_pb2.Task.FromString(message.payload)
                res = self.dds.read_entries(
                    [
                        colink_pb2.StorageEntry(
                            key_name="_internal:tasks:{}".format(task_id.task_id),
                        )
                    ]
                )
                if res is not None:
                    task_entry = res[0]
                    task = colink_pb2.Task.FromString(task_entry.payload)
                    if task.status == "started":
                        # begin user func
                        dds = self.dds
                        dds.set_task_id(task.task_id)
                        try:
                            self.user_func(dds, task.protocol_param, task.participants)
                        except Exception as e:
                            logging.info(
                                "ProtocolEntry start error: Task {}: {}.".format(
                                    task.task_id, e
                                )
                            )
                            raise e
                        self.dds.finish_task(task.task_id)
                        
                        logging.info("finnish task:%s", task.task_id)
                else:
                    
                    logging.error("Pull Task Error.")
            channel.basic_ack(method.delivery_tag)


def _dds_parse_args() -> Tuple[str, Dds]:
    parser = argparse.ArgumentParser(description="protocol greeting")
    parser.add_argument("--addr", type=str, default="", help="")
    parser.add_argument("--jwt", type=str, default="", help="")
    parser.add_argument("--ca", type=str, default="", help="")
    parser.add_argument("--cert", type=str, default="", help="")
    parser.add_argument("--key", type=str, default="", help="")
    args = parser.parse_args()
    addr, jwt, ca, cert, key = args.addr, args.jwt, args.ca, args.cert, args.key
    dds = Dds(addr, jwt)
    """
    if let Some(ca) = ca {
        dds = dds.ca_certificate(&ca);
    }
    if let (Some(cert), Some(key)) = (cert, key) {
        dds = dds.identity(&cert, &key);
    }
    """
    return dds

def _sha256(s):
    return sha256(s.encode('utf-8')).hexdigest()