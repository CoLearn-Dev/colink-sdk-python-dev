import colink as CL
from .application import get_path_timestamp


def wait_task(self, task_id: str):
    task_key = "_internal:tasks:{}".format(task_id)
    res = self.read_entries([CL.StorageEntry(key_name=task_key)])
    if res is not None:
        task = CL.Task.FromString(res[0].payload)
        if task.status == "finished":
            return
        start_timestamp = get_path_timestamp(res[0].key_path) + 1
    else:
        start_timestamp = 0
    queue_name = self.subscribe(task_key, start_timestamp)
    subscriber = self.new_subscriber(queue_name)
    while True:
        data = subscriber.get_next()
        message = CL.SubscriptionMessage.FromString(data)
        if message.change_type != "delete":
            task = CL.Task.FromString(message.payload)
            if task.status == "finished":
                break
    self.unsubscribe(queue_name)
