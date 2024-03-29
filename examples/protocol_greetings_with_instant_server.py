import logging
from typing import List
import colink as CL
from colink import (
    CoLink,
    byte_to_str,
    ProtocolOperator,
    InstantServer,
    InstantRegistry,
)

pop = ProtocolOperator(__name__)


@pop.handle("greetings:initiator")
def run_initiator(cl: CoLink, param: bytes, participants: List[CL.Participant]):
    logging.info(f"greetings:initiator protocol operator! {cl.jwt}")


@pop.handle("greetings:receiver")
def run_receiver(cl: CoLink, param: bytes, participants: List[CL.Participant]):
    logging.info(f"greetings:receiver protocol operator! {cl.jwt}")
    cl.create_entry("tasks:{}:output".format(cl.get_task_id()), param)


if __name__ == "__main__":
    ir = InstantRegistry()
    is0 = InstantServer()
    is1 = InstantServer()
    cl0 = is0.get_colink().switch_to_generated_user()
    cl1 = is1.get_colink().switch_to_generated_user()
    pop.run_attach(cl0)
    pop.run_attach(cl1)
    participants = [
        CL.Participant(user_id=cl0.get_user_id(), role="initiator"),
        CL.Participant(user_id=cl1.get_user_id(), role="receiver"),
    ]
    task_id = cl0.run_task("greetings", "test", participants, True)
    res = cl1.read_or_wait(f"tasks:{task_id}:output")
    print(f"result: {byte_to_str(res)}")
