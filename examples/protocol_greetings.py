import sys
import logging
from typing import List
import colink.colink_pb2 as colink_pb2
from colink.sdk_a import CoLink, byte_to_str
from colink.sdk_p import ProtocolOperator


pop = ProtocolOperator(__name__)


@pop.handle("greetings:initiator")
def run_initiator(cl: CoLink, param: bytes, participants: List[colink_pb2.Participant]):
    logging.info("initiator receive:%s", byte_to_str(param))


@pop.handle("greetings:receiver")
def run_receiver(cl: CoLink, param: bytes, participants: List[colink_pb2.Participant]):
    logging.info("Receiver receive: {}", byte_to_str(param))
    cl.create_entry(("tasks:{}:output").format(cl.get_task_id()), param)


if __name__ == "__main__":
    logging.basicConfig(filename="protocol_greeting.log", filemode="a")
    pop.run()
