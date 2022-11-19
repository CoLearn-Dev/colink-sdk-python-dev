import sys
import colink as CL
from colink import CoLink, decode_jwt_without_validation

if __name__ == "__main__":
    addr = sys.argv[1]
    jwt = sys.argv[2]
    target_user = sys.argv[3]
    cl = CoLink(addr, jwt)
    user = CL.UserRecord(user_id=target_user)
    participants = [
        CL.Participant(
            user_id=decode_jwt_without_validation(jwt).user_id,
            role="query_from_registries",
        )
    ]
    payload = user.SerializeToString()
    task_id = cl.run_task("registry", payload, participants, False)
    print(f"create task: {task_id}")
    cl.wait_task(task_id)
    print(f"task finished: {task_id}")
