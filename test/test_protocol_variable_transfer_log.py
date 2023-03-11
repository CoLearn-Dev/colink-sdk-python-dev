import logging
from typing import List
import colink as CL
import logging
from colink import CoLink, byte_to_str, ProtocolOperator, InstantServer, InstantRegistry

NUM = 8


def getid(cl: CoLink, participants: List[CL.Participant]):
    for i in range(0, len(participants)):
        if cl.get_user_id() == participants[i].user_id:
            return i


pop = ProtocolOperator(__name__)


@pop.handle("variable_transfer_test:initiator")
def run_initiator(cl: CoLink, param: bytes, participants: List[CL.Participant]):
    for i in range(NUM):
        key = f"output{i}"
        key2 = f"output_remote_storage{i}"
        logging.warning(f"start send {i}")
        cl.send_variable(key, bytes(str(i),encoding='utf-8'), participants[1 : len(participants)])
        logging.warning(f"end send {i}")
        cl.send_variable_with_remote_storage(
            key2, bytes(str(i),encoding='utf-8'), participants[1 : len(participants)]
        )
        logging.warning(f"end send storage{i}")


@pop.handle("variable_transfer_test:receiver")
def run_receiver(cl: CoLink, param: bytes, participants: List[CL.Participant]):
    ID = getid(cl, participants)
    cl.ID = ID
    for i in range(NUM):
        cl.round = i
        key = f"output{i}"
        key2 = f"output_remote_storage{i}"
        logging.warning(f"{ID} start recv round {i}")
        msg = cl.recv_variable(key, participants[0])
        cl.create_entry(f"tasks:{cl.get_task_id()}:output{i}", msg)
        logging.warning(f"{ID } end recv round {i}")
        logging.warning(f"{ID} start recv storage round {i}")
        msg = cl.recv_variable_with_remote_storage(key2, participants[0])
        cl.create_entry(f"tasks:{cl.get_task_id()}:output_remote_storage{i}", msg)
        logging.warning(f"{ID} end recv storage round {i}")


def test_protocol_vt():
    ir = InstantRegistry()
    iss = []
    cls = []
    for i in range(NUM):
        _is = InstantServer()
        cl = _is.get_colink().switch_to_generated_user()
        pop.run_attach(cl)
        iss.append(_is)
        cls.append(cl)

    participants = [CL.Participant(user_id=cls[0].get_user_id(), role="initiator")]
    for i in range(1, NUM):
        participants.append(
            CL.Participant(user_id=cls[i].get_user_id(), role="receiver")
        )
    data = "test"
    task_id = cls[0].run_task("variable_transfer_test", data, participants, True)

    for idx in range(1, NUM):
        for idx2 in range(0, NUM):
            logging.warning(f"start read or wait user {idx} round{idx2}")
            res = cls[idx].read_or_wait(f"tasks:{task_id}:output{idx2}")
            logging.warning(f"end read or wait user {idx} round{idx2}")
            #assert byte_to_str(res) == data
            res = cls[idx].read_or_wait(f"tasks:{task_id}:output_remote_storage{idx2}")
            logging.warning(f"end read or wait storage user {idx} round{idx2}")
            #assert byte_to_str(res) == data


if __name__ == "__main__":
    logging.basicConfig(
        format="%(asctime)s,%(msecs)d %(name)s %(levelname)s %(message)s",
        datefmt="%H:%M:%S",
        level=logging.WARNING,
    )
    test_protocol_vt()
