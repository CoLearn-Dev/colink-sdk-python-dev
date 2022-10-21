import sys
import colink as CL
from colink.sdk_a import CoLink, decode_jwt_without_validation

if __name__ == "__main__":
    addr = sys.argv[1]
    jwt = sys.argv[2]
    protocol_name = "remote_storage.create"
    payload = b"hello"
    cl = CoLink(addr, jwt)
    new_participants = [
        CL.Participant(
            user_id=decode_jwt_without_validation(jwt).user_id, role="requester"
        )
    ]
    task_id = cl.run_task("remote_storage.create", payload, new_participants, False)
    print(f"create task: {task_id}")
    cl.wait_task(task_id)
    print("wait end")
