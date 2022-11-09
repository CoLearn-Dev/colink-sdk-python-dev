from colink.colink_pb2 import *
from colink.colink_pb2_grpc import *
from colink.colink_remote_storage_pb2 import *
from colink.colink_remote_storage_pb2_grpc import *
from colink.colink_policy_module_pb2 import *
from colink.colink_policy_module_pb2_grpc import *
from colink.colink_registry_pb2 import *
from colink.colink_registry_pb2_grpc import *
from typing import Tuple
from .sdk_a import *


class CoLink:
    def __init__(
        self,
        coreaddr: str,
        jwt: str,
        ca_certificate: str = None,
        identity: Tuple[str, str] = None,
    ):
        self.core_addr = str(coreaddr)
        self.jwt = str(jwt)
        self.task_id = ""
        self.ca_cert = ca_certificate
        self._identity = identity

    from .sdk_a import (
        request_info,
        import_guest_jwt,
        import_core_addr,
        set_task_id,
        get_task_id,
        import_user,
        generate_token,
        generate_token_with_expiration_time,
        create_entry,
        read_entries,
        read_entry,
        update_entry,
        delete_entry,
        run_task,
        run_task_with_expiration_time,
        confirm_task,
        finish_task,
        subscribe,
        unsubscribe,
        new_subscriber,
        ca_certificate,
        identity,
        _grpc_connect,
        read_keys,
        get_user_id,
        start_protocol_operator,
        stop_protocol_operator,
        update_jwt,
    )
    from .policy_module import (
        policy_module_start,
        policy_module_stop,
        policy_module_add_rule,
        policy_module_get_rules,
        policy_module_remove_rule,
    )
    from .remote_storage import (
        remote_storage_create,
        remote_storage_read,
        remote_storage_update,
        remote_storage_delete,
    )
    from .variable_transfer import set_variable, get_variable
    from .participant_id import get_participant_id
    from .registry import update_registries
    from .lock_key import lock, lock_with_retry_time, unlock
    from .wait_task_end import wait_task
    from .read_wait import read_or_wait
    from .switch_to_generated_user import (
        generate_user_and_import,
        switch_to_generated_user,
    )
