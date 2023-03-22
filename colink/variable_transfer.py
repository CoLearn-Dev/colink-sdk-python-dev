import logging
from typing import List, Any
import colink as CL
from threading import Thread
import logging
import copy
from .p2p_inbox import _recv_variable_p2p, _send_variable_p2p
from .application import try_convert_to_bytes


def send_variable_with_remote_storage(
    self, key: str, payload: bytes, receivers: List[CL.Participant]
):
    if self.task_id is None:
        logging.error("send_variable task_id not found")
        raise Exception("send_variable task_id not found")
    new_participants = [CL.Participant(user_id=self.get_user_id(), role="requester")]
    for p in receivers:
        if p.user_id == self.get_user_id():
            self.create_entry(
                "_remote_storage:private:{}:_variable_transfer:{}:{}".format(
                    p.user_id, self.get_task_id(), key
                ),
                payload,
            )
        else:
            new_participants.append(
                CL.Participant(
                    user_id=p.user_id,
                    role="provider",
                )
            )
    params = CL.CreateParams(
        remote_key_name="_variable_transfer:{}:{}".format(self.get_task_id(), key),
        payload=payload,
    )
    payload = params.SerializeToString()
    self.run_task("remote_storage.create", payload, new_participants, False)


def recv_variable_with_remote_storage(self, key: str, sender: CL.Participant) -> bytes:
    if self.task_id is None:
        logging.error("recv_variable task_id not found")
        raise Exception("recv_variable task_id not found")
    key = "_remote_storage:private:{}:_variable_transfer:{}:{}".format(
        sender.user_id, self.get_task_id(), key
    )
    res = self.read_or_wait(key)
    return res


def send_variable(self, key: str, payload: Any, receivers: List[CL.Participant]):
    def thd_send_var(cl, key: str, payload: bytes, receiver: CL.Participant):
        try:
            _send_variable_p2p(cl, key, payload, receiver)
        except Exception as e:
            cl.send_variable_with_remote_storage(key, payload, [receiver])

    payload = try_convert_to_bytes(payload)
    threads = []
    for receiver in receivers:
        threads.append(Thread(target=thd_send_var, args=(self, key, payload, receiver), daemon=True))
    for th in threads:
        th.start()


def recv_variable(self, key: str, sender: CL.Participant) -> bytes:
    if self.task_id is None:
        raise Exception("task_id not found")
    try:
        res = _recv_variable_p2p(self, key, sender)
    except Exception as e:
        res = self.recv_variable_with_remote_storage(key, sender)
    return res
