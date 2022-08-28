import sys
import logging
import os
import colink as CL
from colink.sdk_a import decode_jwt_without_validation, CoLink, str_to_byte, byte_to_str

if __name__ == "__main__":
    logging.basicConfig(filename="user_run_task.log", filemode="a")
    addr = sys.argv[1]
    jwt_a = sys.argv[2]
    jwt_b = sys.argv[3]
    msg = "hello"
    if len(sys.argv) > 4:
        msg = sys.argv[4]

    user_id_a = decode_jwt_without_validation(jwt_a).user_id
    user_id_b = decode_jwt_without_validation(jwt_b).user_id

    cl = CoLink(addr, jwt_a)
    # create
    cl.remote_storage_create(
        [user_id_b],
        "remote_storage_demo",
        str_to_byte(msg),
        False,
    )
    clb = CoLink(addr, jwt_b)
    data = clb.read_or_wait(
        "_remote_storage:private:{}:remote_storage_demo".format(user_id_a)
    )
    print(byte_to_str(data))

    # read
    data = cl.remote_storage_read(user_id_b, "remote_storage_demo", False, "")
    print(byte_to_str(data))

    # update
    queue_name = clb.subscribe(
        "_remote_storage:private:{}:remote_storage_demo".format(user_id_a),
        None,
    )
    cl.remote_storage_update(
        [user_id_b],
        "remote_storage_demo",
        str_to_byte("update {}".format(msg)),
        False,
    )

    subscriber = clb.new_subscriber(queue_name)
    data = subscriber.get_next()
    message = CL.SubscriptionMessage().FromString(data)
    if message.change_type != "delete":
        print(byte_to_str(message.payload))
    else:
        logging.error("Receive delete change_type.")

    # delete
    cl.remote_storage_delete([user_id_b], "remote_storage_demo", False)

    data = subscriber.get_next()
    clb.unsubscribe(queue_name)
    message = CL.SubscriptionMessage().FromString(data)
    if message.change_type == "delete":
        print("Deleted")
    else:
        logging.error("Receive non-delete change_type.")