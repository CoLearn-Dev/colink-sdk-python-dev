import sys
import logging
import colink as CL
from colink import CoLink

if __name__ == "__main__":
    logging.basicConfig(
        filename="user_policy_module.log", filemode="a", level=logging.INFO
    )
    addr = sys.argv[1]
    jwt = sys.argv[2]
    cl = CoLink(addr, jwt)
    res = cl.policy_module_get_rules()
    print(f"{res}")

    rule_id = cl.policy_module_add_rule(
        CL.Rule(
            task_filter=CL.TaskFilter(protocol_name="greetings"),
            action=CL.Action(type="approve"),
            priority=1,
        )
    )
    print(f"rule_id: {rule_id}")
    res = cl.policy_module_get_rules()
    print(f"{res}")

    cl.policy_module_remove_rule(rule_id)
    res = cl.policy_module_get_rules()
    print(f"{res}")
