import sys
import logging
import os
import colink.colink_pb2 as colink_pb2
from colink.sdk_a import decode_jwt_without_validation, Dds, str_to_byte

if __name__ == "__main__":
    logging.basicConfig(filename="user_run_task.log", filemode="a")
    addr = sys.argv[1]
    jwt_a = sys.argv[2]
    jwt_b = sys.argv[3]
    msg = "hello"
    if len(sys.argv) > 4:
        msg = sys.argv[4]
    user_id_a = decode_jwt_without_validation(jwt_a).user_id
    user_id_b = decode_jwt_without_validation(jwt_b).user_id
    participants = [
        colink_pb2.Participant(
            user_id=user_id_a,
            ptype="initiator",
        ),
        colink_pb2.Participant(
            user_id=user_id_b,
            ptype="receiver",
        ),
    ]
    dds = Dds(addr, jwt_a)
    _, core_pub_key = dds.request_core_info()
    task_id = dds.run_task("greetings", str_to_byte(msg), participants, True)
    logging.info(
        "Task %s has been created, but it will remain in waiting status until the protocol starts.",
        task_id,
    )
