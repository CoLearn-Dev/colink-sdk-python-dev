import logging
from typing import List
import colink as CL


def set_variable(self, key: str, payload: bytes, receivers: List[CL.Participant]):
    if self.task_id is None:
        logging.error("set_variable task_id not found")
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


def get_variable(self, key: str, sender: CL.Participant) -> bytes:
    if self.task_id is None:
        logging.error("get_variable task_id not found")
    key = "_remote_storage:private:{}:_variable_transfer:{}:{}".format(
        sender.user_id, self.get_task_id(), key
    )
    res = self.read_or_wait(key)
    return res
