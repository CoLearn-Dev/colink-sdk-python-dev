import sys
import logging
import colink as CL
from colink.sdk_a import decode_jwt_without_validation, CoLink, str_to_byte

if __name__ == "__main__":
    logging.basicConfig(filename="set_bot_credentials.log", filemode="a")
    addr = sys.argv[1]
    jwt_initiator = sys.argv[2]
    user_id_initiator = decode_jwt_without_validation(jwt_initiator)
    api_key = sys.argv[3]
    chat_id = sys.argv[4]

    participants = [
        CL.Participant(
            user_id=user_id_initiator.user_id,
            role="initiator",
        )
    ]
    
    cl = CoLink(addr, jwt_initiator)
    task_id = cl.run_task("telegram/set_credentials", str_to_byte(api_key + "|" + chat_id), participants, False)
    logging.info(
        "Task %s has been created, but it will remain in waiting status until the protocol starts.",
        task_id,
    )
