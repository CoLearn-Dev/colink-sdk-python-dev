import logging
from typing import List, Any
from .application import try_convert_to_bytes
import colink as CL


def remote_storage_create(
    self,
    providers: List[str],
    key: str,
    payload: Any,
    is_public: bool,
):
    payload = try_convert_to_bytes(payload)
    participants = [
        CL.Participant(
            user_id=self.get_user_id(),
            role="requester",
        )
    ]
    for provider in providers:
        participants.append(
            CL.Participant(
                user_id=provider,
                role="provider",
            )
        )
    params = CL.CreateParams(remote_key_name=key, payload=payload, is_public=is_public)
    payload = params.SerializeToString()
    self.run_task("remote_storage.create", payload, participants, False)


def remote_storage_read(
    self,
    provider: str,
    key: str,
    is_public: bool,
    holder_id: str,
) -> bytes:
    participants = [
        CL.Participant(
            user_id=self.get_user_id(),
            role="requester",
        ),
        CL.Participant(user_id=provider, role="provider"),
    ]
    params = CL.ReadParams(
        remote_key_name=key, is_public=is_public, holder_id=holder_id
    )
    payload = params.SerializeToString()
    task_id = self.run_task("remote_storage.read", payload, participants, False)
    status = self.read_or_wait("tasks:{}:status".format(task_id))
    if status[0] == 0:
        data = self.read_or_wait("tasks:{}:output".format(task_id))
        return data
    else:
        logging.error(f"remote_storage.read: status_code: {status[0]}")
        raise Exception(f"remote_storage.read: status_code: {status[0]}")


def remote_storage_update(
    self,
    providers: List[str],
    key: str,
    payload: Any,
    is_public: bool,
):
    payload = try_convert_to_bytes(payload)
    participants = [
        CL.Participant(
            user_id=self.get_user_id(),
            role="requester",
        )
    ]
    for provider in providers:
        participants.append(CL.Participant(user_id=provider, role="provider"))
    params = CL.UpdateParams(remote_key_name=key, payload=payload, is_public=is_public)
    payload = params.SerializeToString()
    self.run_task("remote_storage.update", payload, participants, False)


def remote_storage_delete(
    self,
    providers: List[str],
    key: str,
    is_public: bool,
):
    participants = [
        CL.Participant(
            user_id=self.get_user_id(),
            role="requester",
        )
    ]
    for provider in providers:
        participants.append(
            CL.Participant(
                user_id=provider,
                role="provider",
            )
        )
    params = CL.DeleteParams(
        remote_key_name=key,
        is_public=is_public,
    )
    payload = params.SerializeToString()
    self.run_task("remote_storage.delete", payload, participants, False)
