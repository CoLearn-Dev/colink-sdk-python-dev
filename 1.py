import colink as CL

if __name__ == "__main__":
    ir = CL.InstantRegistry()
    ist = CL.InstantServer()

    cl = ist.get_colink().switch_to_generated_user()

    cl.policy_module_add_rule(
        CL.Rule(
            task_filter = CL.TaskFilter(protocol_name="greetings"),
            action=CL.Action(
                type='forward',
                forward_target_keyname='web3_task:status:waiting'
            ),
            priority=1,
        )
    )