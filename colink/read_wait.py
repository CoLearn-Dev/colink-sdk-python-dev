import logging
import colink as CL


def read_or_wait(self, key: str) -> bytes:
    res = self.read_entry(key)
    if res is not None:
        return res
    else:
        queue_name = self.subscribe(key, 0)
        mut_subscriber = self.new_subscriber(queue_name)
        data = mut_subscriber.get_next()
        logging.info("Received [{}]".format(data))
        self.unsubscribe(queue_name)
        message = CL.SubscriptionMessage().FromString(data)
        if message.change_type != "delete":
            return message.payload
        else:
            logging.warning("Subscribe {} got delete event".format(key))
            return None
