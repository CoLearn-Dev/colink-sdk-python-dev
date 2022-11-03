import sys
import logging
import os
import colink as CL
from colink.sdk_a import decode_jwt_without_validation, CoLink, str_to_byte

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
    _, core_pub_key, _ = cl.request_info()
    task_id = cl.run_task("greetings", str_to_byte(msg), participants, True)
    logging.info(
        "Task %s has been created, but it will remain in waiting status until the protocol starts.",
        task_id,
    )
