import logging
from typing import List
import colink as CL
from colink.sdk_a import CoLink
from colink.sdk_p import ProtocolOperator

pop = ProtocolOperator(__name__)


@pop.handle("test_variable_transfer:initiator")
def run_initiator(cl: CoLink, param: bytes, participants: List[CL.Participant]):
    logging.info("test_variable_transfer:initiator protocol operator!")
    cl.set_variable("output", param, participants[1:])


@pop.handle("test_variable_transfer:receiver")
def run_receiver(cl: CoLink, param: bytes, participants: List[CL.Participant]):
    logging.info("test_variable_transfer:receiver protocol operator!")
    receive_data = cl.get_variable("output", participants[0])
    cl.create_entry("tasks:{}:output".format(cl.get_task_id()), receive_data)


if __name__ == "__main__":
    logging.basicConfig(
        filename="protocol_test_variable_transfer.log", filemode="a", level=logging.INFO
    )
    pop.run()
