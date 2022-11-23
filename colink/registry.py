import colink as CL


def update_registries(self, registries: CL.Registries):
    participants = [
        CL.Participant(
            user_id=self.get_user_id(),
            role="update_registries",
        )
    ]
    payload = registries.SerializeToString()
    task_id = self.run_task("registry", payload, participants, False)
    self.wait_task(task_id)
