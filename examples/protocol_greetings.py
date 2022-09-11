import sys
import logging
from typing import List
import colink as CL
from colink.sdk_a import CoLink, byte_to_str
from colink.sdk_p import ProtocolOperator


pop = ProtocolOperator(__name__)


@pop.handle("greetings:initiator")
def run_initiator(cl: CoLink, param: bytes, participants: List[CL.Participant]):
    logging.info('greetings:initiator protocol operator!')
    

@pop.handle("greetings:receiver")
def run_receiver(cl: CoLink, param: bytes, participants: List[CL.Participant]):
    logging.info('greetings:receiver protocol operator!')
    cl.create_entry("tasks:{}:output".format(cl.get_task_id()), param)
    

if __name__ == "__main__":
    logging.basicConfig(
        filename="protocol_greeting.log", filemode="a", level=logging.INFO
    )
    pop.run()
