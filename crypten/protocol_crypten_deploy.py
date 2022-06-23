import sys
import logging
from typing import List
import colink.colink_pb2 as colink_pb2
from colink.sdk_a import Dds, byte_to_str
from colink.sdk_p import ProtocolOperator


pop = ProtocolOperator(__name__)


@pop.handle("crypten_deploy:initiator")
def run_initiator(dds: Dds, param: bytes, participants: List[colink_pb2.Participant]):
    logging.info("initiator receive:%s", byte_to_str(param))
    


@pop.handle("crypten_deploy:receiver")
def run_receiver(dds: Dds, param: bytes, participants: List[colink_pb2.Participant]):

    #here we should wait for the initiator to write

    logging.info("Receiver receive: {}", byte_to_str(param))
    crypten_app_id=param[:]
    dds.create_entry(("crypten:{}:crypten_app_id").format(dds.get_task_id()), crypten_app_id)
    
    #dds.create_entry(("tasks:{}:output").format(dds.get_task_id()), param)


if __name__ == "__main__":
    logging.basicConfig(filename="protocol_crypten_deploy.log", filemode="a")
    pop.run()
