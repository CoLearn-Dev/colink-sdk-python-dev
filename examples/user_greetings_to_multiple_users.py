import sys
import logging
import colink as CL
from colink import CoLink, decode_jwt_without_validation

if __name__ == "__main__":
    logging.basicConfig(
        filename="user_greeting_to_multi_users.log", filemode="a", level=logging.INFO
    )
    addr = sys.argv[1]
    users = sys.argv[2:]
    jwt_initiator = users[0]
    msg = "hello"
    user_id_initiator = decode_jwt_without_validation(jwt_initiator)
    participants = [
        CL.Participant(
            user_id=user_id_initiator.user_id,
            role="initiator",
        )
    ]
    for i in range(1, len(users)):
        participants.append(
            CL.Participant(
                user_id=decode_jwt_without_validation(users[i]).user_id,
                role="receiver",
            )
        )
    cl = CoLink(addr, jwt_initiator)
    task_id = cl.run_task("greetings", msg, participants, True)
    logging.info(
        "Task %s has been created, but it will remain in waiting status until the protocol starts.",
        task_id,
    )
