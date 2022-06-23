import sys
import logging
import time
import colink.colink_pb2 as colink_pb2
from colink.sdk_a import decode_jwt_without_validation, Dds, str_to_byte

if __name__ == "__main__":
    logging.basicConfig(filename="run_crypten_deploy.log", filemode="a")
    addr = sys.argv[1]
    users = sys.argv[2:]
    jwt_initiator = users[0]
    msg = "hello"  # here should generate the instance id and code, which the parameter would be given
    
    
    user_id_initiator = decode_jwt_without_validation(jwt_initiator)

    crypten_app_id='crypten-APP-ID_{}_{}'.format(user_id_initiator.user_id,int(time.time_ns()))  
    msg=crypten_app_id+''  #generate crypten_app_id

    participants = [
        colink_pb2.Participant(
            user_id=user_id_initiator.user_id,
            ptype="initiator",
        )
    ]
    for i in range(1, len(users)):
        participants.append(
            colink_pb2.Participant(
                user_id=decode_jwt_without_validation(users[i]).user_id,
                ptype="receiver",
            )
        )
    dds = Dds(addr, jwt_initiator)
    task_id = dds.run_task("crypten_deploy", str_to_byte(msg), participants, True)
    logging.info(
        "Task %s has been created, but it will remain in waiting status until the protocol starts.",
        task_id,
    )
