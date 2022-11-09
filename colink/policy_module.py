import uuid
from typing import List
import colink as CL
from colink.sdk_a import get_path_timestamp, byte_to_int
def policy_module_start(self):
    lock = self.lock("_policy_module:settings")
    res = self.read_entries([CL.StorageEntry(key_name="_policy_module:settings")])
    if res is not None:
        settings, timestamp = CL.Settings.FromString(
            res[0].payload
        ), get_path_timestamp(res[0].key_path)
    else:
        settings, timestamp = CL.Settings(), 0
    if settings.enable:
        self.unlock(lock)
        return self.wait_for_applying(
            timestamp
        )  # Wait for the current timestamp to be applied.
    settings.enable = True
    payload = settings.SerializeToString()

    timestamp = get_path_timestamp(
        self.update_entry("_policy_module:settings", payload)
    )
    self.unlock(lock)
    participants = [CL.Participant(user_id=self.get_user_id(), role="local")]
    self.run_task("policy_module", b"", participants, False)
    self.wait_for_applying(timestamp)

def policy_module_stop(self):
    lock = self.lock("_policy_module:settings")
    res = self.read_entry("_policy_module:settings")
    if res is not None:
        settings = CL.Settings.FromString(res)
    else:
        settings = CL.Settings()
    if not settings.enable:
        self.unlock(lock)
        return  # Return directly here because we only release the lock after the policy module truly stopped.
    settings.enable = False
    payload = settings.SerializeToString()
    timestamp = get_path_timestamp(
        self.update_entry("_policy_module:settings", payload)
    )
    res = self.wait_for_applying(timestamp)
    self.unlock(lock)  # Unlock after the policy module truly stopped.

def policy_module_get_rules(self) -> List[CL.Rule]:
    res = self.read_entry("_policy_module:settings")
    if res is not None:
        settings = CL.Settings.FromString(res)
    else:
        settings = CL.Settings()
    return settings.rules

def policy_module_add_rule(self, rule: CL.Rule) -> str:
    lock = self.lock("_policy_module:settings")
    res = self.read_entry("_policy_module:settings")
    if res:
        settings = CL.Settings.FromString(res)
    else:
        settings = CL.Settings()
    rule_id = str(uuid.uuid4())
    rule.rule_id = rule_id
    settings.rules.append(rule)
    payload = settings.SerializeToString()
    timestamp = get_path_timestamp(
        self.update_entry("_policy_module:settings", payload)
    )
    self.unlock(lock)
    if settings.enable:
        self.wait_for_applying(timestamp)
    return rule_id

def policy_module_remove_rule(self, rule_id: str):
    lock = self.lock("_policy_module:settings")
    res = self.read_entry("_policy_module:settings")
    if res:
        settings = CL.Settings.FromString(res)
    else:
        settings = CL.Settings()
    del settings.rules[:]
    settings.rules.extend([x for x in settings.rules if x.rule_id != rule_id])
    payload = settings.SerializeToString()
    timestamp = get_path_timestamp(
        self.update_entry("_policy_module:settings", payload)
    )
    self.unlock(lock)
    if settings.enable:
        self.wait_for_applying(timestamp)

def wait_for_applying(self, timestamp: int):
    key = "_policy_module:applied_settings_timestamp"
    res = self.read_entries([CL.StorageEntry(key_name=key)])
    if res is not None:
        applied_settings_timestamp = byte_to_int(res[0].payload)
        if applied_settings_timestamp >= timestamp:
            return
        start_timestamp = get_path_timestamp(res[0].key_path) + 1
    else:
        start_timestamp = 0
    queue_name = self.subscribe(key, start_timestamp)
    subscriber = self.new_subscriber(queue_name)
    while True:
        data = subscriber.get_next()
        message = CL.SubscriptionMessage.FromString(data)
        if message.change_type != "delete":
            applied_settings_timestamp = byte_to_int(message.payload)
            if applied_settings_timestamp >= timestamp:
                break
    self.unsubscribe(queue_name)