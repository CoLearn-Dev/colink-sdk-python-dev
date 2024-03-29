import logging
from typing import List
import colink as CL
from colink import CoLink, ProtocolOperator

pop = ProtocolOperator(__name__)


@pop.handle("greetings:initiator")
def run_initiator(cl: CoLink, param: bytes, participants: List[CL.Participant]):
    logging.info(f"greetings:initiator protocol operator! {cl.jwt}")


@pop.handle("greetings:receiver")
def run_receiver(cl: CoLink, param: bytes, participants: List[CL.Participant]):
    logging.info(f"greetings:receiver protocol operator! {cl.jwt}")
    cl.create_entry("tasks:{}:output".format(cl.get_task_id()), param)


if __name__ == "__main__":
    logging.basicConfig(
        filename="protocol_greeting.log", filemode="a", level=logging.INFO
    )
    pop.run()
