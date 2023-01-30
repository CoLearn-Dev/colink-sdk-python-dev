import logging
from typing import List
import colink as CL
from colink import CoLink, byte_to_str, ProtocolOperator, InstantServer, InstantRegistry

pop = ProtocolOperator(__name__)


@pop.handle("variable_transfer_test:initiator")
def run_initiator(cl: CoLink, param: bytes, participants: List[CL.Participant]):
    for i in range(8):
        key = f"output{i}"
        key2 = f"output_remote_storage{i}"
        cl.set_variable(key, param, participants[1 : len(participants)])
        cl.set_variable_with_remote_storage(
            key2, param, participants[1 : len(participants)]
        )


@pop.handle("variable_transfer_test:receiver")
def run_receiver(cl: CoLink, param: bytes, participants: List[CL.Participant]):
    for i in range(8):
        key = f"output{i}"
        key2 = f"output_remote_storage{i}"
        msg = cl.get_variable(key, participants[0])
        cl.create_entry(f"tasks:{cl.get_task_id()}:output{i}", msg)
        msg = cl.get_variable_with_remote_storage(key2, participants[0])
        cl.create_entry(f"tasks:{cl.get_task_id()}:output_remote_storage{i}", msg)


def test_protocol_vt():
    ir = InstantRegistry()
    iss = []
    cls = []
    for i in range(8):
        _is = InstantServer()
        cl = _is.get_colink().switch_to_generated_user()
        pop.run_attach(cl)
        iss.append(_is)
        cls.append(cl)

    participants = [CL.Participant(user_id=cls[0].get_user_id(), role="initiator")]
    for i in range(1, 8):
        participants.append(
            CL.Participant(user_id=cls[i].get_user_id(), role="receiver")
        )
    data = "test"
    task_id = cls[0].run_task("variable_transfer_test", data, participants, True)

    for idx in range(1, 8):
        for idx2 in range(0, 8):
            res = cls[idx].read_or_wait(f"tasks:{task_id}:output{idx2}")
            assert byte_to_str(res) == data
            res = cls[idx].read_or_wait(f"tasks:{task_id}:output_remote_storage{idx2}")
            assert byte_to_str(res) == data


if __name__ == "__main__":
    test_protocol_vt()
