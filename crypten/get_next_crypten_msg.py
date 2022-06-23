import queue
import sys
import colink.colink_pb2 as colink_pb2
from colink.sdk_a import Dds, byte_to_str

if __name__ == "__main__":
    addr = sys.argv[1]
    jwt = sys.argv[2]
    now = int(sys.argv[3])
    dds = Dds(addr, jwt)
    latest_key = "_internal:protocols:crypten_deploy:finished:latest"
    queue_name = dds.subscribe(latest_key, now)
    subscriber = dds.new_subscriber(queue_name)
    data = subscriber.get_next()
    message = colink_pb2.SubscriptionMessage().FromString(data)
    if message.change_type != "delete":
        task_id = colink_pb2.Task().FromString(message.payload)
        res = dds.read_entries(
            [
                colink_pb2.StorageEntry(
                    key_name="crypten:{}:crypten_app_id".format(task_id.task_id),
                )
            ]
        )
        output_entry = res[0]
        print(
            byte_to_str(output_entry.payload), end=""
        )  # send the greeting message to pipe
