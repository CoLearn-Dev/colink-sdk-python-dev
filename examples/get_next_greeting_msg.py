import sys
import colink as CL
from colink import CoLink, byte_to_str

if __name__ == "__main__":
    addr = sys.argv[1]
    jwt = sys.argv[2]
    now = int(sys.argv[3])
    cl = CoLink(addr, jwt)
    latest_key = "_internal:protocols:greetings:finished:latest"
    message = cl.read_or_wait(latest_key)
    if message != None:
        task = CL.Task().FromString(message)
        res = cl.read_entries(
            [
                CL.StorageEntry(
                    key_name="tasks:{}:output".format(task.task_id),
                )
            ]
        )
        print(byte_to_str(res[0].payload), end="")  # send the greeting message to pipe
