import colink as CL


def update_registries(self, registries: CL.Registries):
    participants = [
        CL.Participant(
            user_id=self.get_user_id(),
            role="update_registries",
        )
    ]
    payload = registries.SerializeToString()
    self.run_task("registry", payload, participants, False)
