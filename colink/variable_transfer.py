import logging
from typing import List, Any
import colink as CL
import threading
from .p2p_inbox import _get_variable_p2p, _set_variable_p2p
from .application import try_convert_to_bytes


def set_variable_with_remote_storage(
    self, key: str, payload: bytes, receivers: List[CL.Participant]
):
    if self.task_id is None:
        logging.error("set_variable task_id not found")
        raise Exception("set_variable task_id not found")
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


def get_variable_with_remote_storage(self, key: str, sender: CL.Participant) -> bytes:
    if self.task_id is None:
        logging.error("get_variable task_id not found")
        raise Exception("get_variable task_id not found")
    key = "_remote_storage:private:{}:_variable_transfer:{}:{}".format(
        sender.user_id, self.get_task_id(), key
    )
    res = self.read_or_wait(key)
    return res


def set_variable(self, key: str, payload: Any, receivers: List[CL.Participant]):
    def thread_set_var(cl, key: str, payload: bytes, receiver: CL.Participant):
        try:
            _set_variable_p2p(cl, key, payload, receiver)
        except Exception as e:
            cl.set_variable_with_remote_storage(key, payload, [receiver])

    payload = try_convert_to_bytes(payload)
    threads = []
    for receiver in receivers:
        threads.append(
            threading.Thread(target=thread_set_var, args=(self, key, payload, receiver))
        )
    for th in threads:
        th.start()
    for th in threads:
        th.join()


def get_variable(self, key: str, sender: CL.Participant) -> bytes:
    if self.task_id is None:
        raise Exception("task_id not found")
    try:
        res = _get_variable_p2p(self, key, sender)
    except Exception as e:
        res = self.get_variable_with_remote_storage(key, sender)
    return res
