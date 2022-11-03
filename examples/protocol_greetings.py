import sys
import logging
from typing import List
import colink as CL
from colink.sdk_a import CoLink, byte_to_str
from colink.sdk_p import ProtocolOperator

pop = ProtocolOperator(__name__)


@pop.handle("greetings:initiator")
def run_initiator(cl: CoLink, param: bytes, participants: List[CL.Participant]):
    logging.info(f"greetings:initiator protocol operator! {cl.jwt}")


@pop.handle("greetings:receiver")
def run_receiver(cl: CoLink, param: bytes, participants: List[CL.Participant]):
    logging.info(f"greetings:receiver protocol operator! {cl.jwt}")
    # removed using variable transfer in this example, to avoid installing remote storage block for new CoLink server
    cl.create_entry("tasks:{}:output".format(cl.get_task_id()), param)


if __name__ == "__main__":
    logging.basicConfig(
        filename="protocol_greeting.log", filemode="a", level=logging.INFO
    )
    pop.run()
