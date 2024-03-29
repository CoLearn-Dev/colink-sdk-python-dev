import logging
from typing import List
import colink as CL
from colink import CoLink, ProtocolOperator

pop = ProtocolOperator(__name__)


@pop.handle("greetings:@init")
def run_init(cl: CoLink, _param: bytes, _participants: List[CL.Participant]):
    logging.info("greetings:@init protocol operator!")


@pop.handle("greetings:initiator")
def run_initiator(cl: CoLink, param: bytes, participants: List[CL.Participant]):
    logging.info("greetings:initiator protocol operator!")
    cl.send_variable("test:greeting:output", param, participants[1:])


@pop.handle("greetings:receiver")
def run_receiver(cl: CoLink, param: bytes, participants: List[CL.Participant]):
    logging.info("greetings:receiver protocol operator!")
    receive_data = cl.recv_variable("test:greeting:output", participants[0])
    cl.create_entry("tasks:{}:output".format(cl.get_task_id()), receive_data)


if __name__ == "__main__":
    logging.basicConfig(
        filename="protocol_greeting.log", filemode="a", level=logging.INFO
    )
    pop.run()
