import random
import time
import logging
import grpc
from typing import Tuple
from .application import byte_to_int


def lock(self, key: str) -> Tuple[str, int]:
    return self.lock_with_retry_time(key, 100)


def lock_with_retry_time(
    self,
    key: str,
    retry_time_cap_in_ms: int,
) -> Tuple[str, int]:
    sleep_time_cap = 1
    rnd_num = random.getrandbits(32)-2**31
    while True:
        try:
            self.create_entry("_lock:{}".format(key), rnd_num)
        except grpc.RpcError as e:
            pass
        else:
            break
        st = random.randint(0, sleep_time_cap - 1)
        time.sleep(st / 1000)  # st is in milli-second
        sleep_time_cap *= 2
        if sleep_time_cap > retry_time_cap_in_ms:
            sleep_time_cap = retry_time_cap_in_ms
    return (key, rnd_num)


def unlock(self, lock_token: Tuple[str, int]):
    key, rnd_num = lock_token
    rnd_num_in_storage = byte_to_int(self.read_entry("_lock:{}".format(key)))
    if rnd_num_in_storage == rnd_num:
        self.delete_entry("_lock:{}".format(key))
    else:
        logging.error("Invalid token.")
        raise Exception("Invalid token.")
