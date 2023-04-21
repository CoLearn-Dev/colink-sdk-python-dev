from typing import Tuple
from .p2p_inbox import VtP2pCtx


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

    def ca_certificate(self, ca_certificate: str):
        f_ca = open(ca_certificate, "rb")
        self.ca_cert = f_ca.read()
        f_ca.close()

    def identity(self, client_cert: str, client_key: str):
        f_cert = open(client_cert, "rb")
        client_cert = f_cert.read()
        f_cert.close()
        f_key = open(client_key, "rb")
        client_key = f_key.read()
        f_key.close()
        self._identity = (client_cert, client_key)

    def update_jwt(self, new_jwt: str):
        self.jwt = new_jwt

    from .application import (
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
        confirm_task,
        finish_task,
        subscribe,
        unsubscribe,
        new_subscriber,
        _grpc_connect,
        read_keys,
        get_user_id,
        start_protocol_operator,
        start_protocol_operator_full_config,
        stop_protocol_operator,
        generate_token_with_signature,
        get_core_addr,
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
    from .variable_transfer import (
        send_variable_with_remote_storage,
        recv_variable_with_remote_storage,
        send_variable,
        recv_variable,
    )

    set_variable_with_remote_storage = send_variable_with_remote_storage
    get_variable_with_remote_storage = recv_variable_with_remote_storage
    set_variable = send_variable
    get_variable = recv_variable
    from .participant_id import get_participant_index
    from .registry import update_registries
    from .lock_key import lock, lock_with_retry_time, unlock
    from .wait_task_end import wait_task
    from .read_wait import read_or_wait
    from .switch_to_generated_user import (
        generate_user_and_import,
        switch_to_generated_user,
    )
    from .wait_user_init_func import wait_user_init
