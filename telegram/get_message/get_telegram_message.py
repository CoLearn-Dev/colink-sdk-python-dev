import sys
import logging
import colink as CL
from colink.sdk_a import decode_jwt_without_validation, CoLink, str_to_byte

if __name__ == "__main__":
    logging.basicConfig(filename="send_telegram_message.log", filemode="a", level=logging.INFO)
    addr = sys.argv[1]
    jwt_initiator = sys.argv[2]
    user_id_initiator = decode_jwt_without_validation(jwt_initiator)
    participants = [
        CL.Participant(
            user_id=user_id_initiator.user_id,
            role="getter",
        )
    ]
    cl = CoLink(addr, jwt_initiator)
    task_id = cl.run_task("telegram/get_msg", b"", participants, False)
    logging.info(
        "Task %s has been created, but it will remain in waiting status until the protocol starts.",
        task_id,
    )
