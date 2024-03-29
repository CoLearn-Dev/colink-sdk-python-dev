import sys
import logging
import colink as CL
from colink import CoLink, decode_jwt_without_validation

if __name__ == "__main__":
    logging.basicConfig(filename="user_run_task.log", filemode="a", level=logging.INFO)
    addr = sys.argv[1]
    jwt_a = sys.argv[2]
    jwt_b = sys.argv[3]
    msg = "hello"
    if len(sys.argv) > 4:
        msg = sys.argv[4]
    user_id_a = decode_jwt_without_validation(jwt_a).user_id
    user_id_b = decode_jwt_without_validation(jwt_b).user_id
    participants = [
        CL.Participant(
            user_id=user_id_a,
            role="initiator",
        ),
        CL.Participant(
            user_id=user_id_b,
            role="receiver",
        ),
    ]
    cl = CoLink(addr, jwt_a)
    core_pub_key = cl.request_info().core_public_key
    task_id = cl.run_task("greetings", msg, participants, True)
    logging.info(
        "Task %s has been created, but it will remain in waiting status until the protocol starts.",
        task_id,
    )
