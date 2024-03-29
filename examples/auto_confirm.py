import sys
import logging
import colink as CL
from colink import CoLink, get_path_timestamp

if __name__ == "__main__":
    logging.basicConfig(filename="auto_confirm.log", filemode="a", level=logging.INFO)
    addr = sys.argv[1]
    jwt = sys.argv[2]
    protocol_name = sys.argv[3]
    cl = CoLink(addr, jwt)
    list_key = "_internal:protocols:{}:waiting".format(protocol_name)
    latest_key = "_internal:protocols:{}:waiting:latest".format(protocol_name)
    res = cl.read_entries(
        [
            CL.StorageEntry(
                key_name=list_key,
            )
        ]
    )
    start_timestamp = 0
    if res is not None:
        list_entry = res[0]
        list_ = CL.CoLinkInternalTaskIDList().FromString(
            list_entry.payload
        )  # parse colink proto struct from binary
        if len(list_.task_ids_with_key_paths) == 0:
            start_timestamp = get_path_timestamp(list_entry.key_path)
        else:
            start_timestamp = int(1e62)  # get min
            for i in range(len(list_.task_ids_with_key_paths)):
                start_timestamp = min(
                    start_timestamp,
                    get_path_timestamp(list_.task_ids_with_key_paths[i].key_path),
                )  # find earliest time stamp
    queue_name = cl.subscribe(latest_key, start_timestamp)
    subscriber = cl.new_subscriber(queue_name)
    while True:
        data = subscriber.get_next()
        message = CL.SubscriptionMessage().FromString(data)
        if message.change_type != "delete":
            task_id = CL.Task().FromString(message.payload)
            res = cl.read_entries(
                [
                    CL.StorageEntry(
                        key_name="_internal:tasks:{}".format(task_id.task_id),
                    )
                ]
            )
            task_entry = res[0]
            task = CL.Task().FromString(task_entry.payload)
            # IMPORTANT: you must check the status of the task received from the subscription.
            if task.status == "waiting":
                cl.confirm_task(task_id.task_id, True, False, "")
                logging.info("confirm task {}".format(task_id.task_id))
