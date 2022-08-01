import queue
import sys
import colink as CL
from colink.sdk_a import CoLink, byte_to_str

if __name__ == "__main__":
    addr = sys.argv[1]
    jwt = sys.argv[2]
    now = int(sys.argv[3])
    cl = CoLink(addr, jwt)
    latest_key = "_internal:protocols:greetings:finished:latest"
    queue_name = cl.subscribe(latest_key, now)
    subscriber = cl.new_subscriber(queue_name)
    data = subscriber.get_next()
    message = CL.SubscriptionMessage().FromString(data)
    if message.change_type != "delete":
        task_id = CL.Task().FromString(message.payload)
        res = cl.read_entries(
            [
                CL.StorageEntry(
                    key_name="tasks:{}:output".format(task_id.task_id),
                )
            ]
        )
        output_entry = res[0]
        print(
            byte_to_str(output_entry.payload), end=""
        )  # send the greeting message to pipe
