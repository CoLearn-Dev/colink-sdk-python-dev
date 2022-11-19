import logging
import colink as CL
from .application import get_path_timestamp, byte_to_str


def wait_user_init(self):
    is_initialized_key = "_internal:_is_initialized"
    res = self.read_entries([CL.StorageEntry(key_name=is_initialized_key)])
    if res is not None:
        if res[0].payload[0] == 1:
            return
        start_timestamp = get_path_timestamp(res[0].key_path) + 1
    else:
        start_timestamp = 0
    queue_name = self.subscribe(is_initialized_key, start_timestamp)

    subscriber = self.new_subscriber(queue_name)
    while True:
        data = subscriber.get_next()
        logging.info(f"Received [{byte_to_str(data)}]")
        message = CL.SubscriptionMessage.FromString(data)
        if message.change_type != "delete" and message.payload[0] == 1:
            break
    self.unsubscribe(queue_name)
