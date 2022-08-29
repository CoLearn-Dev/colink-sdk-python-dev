import sys
import logging
import os
import copy
import threading
import colink as CL
from colink.sdk_a import decode_jwt_without_validation, CoLink, str_to_byte

def lock_and_unlock(cl):
    lock = cl.lock("example_lock_name")
    num = cl.read_entry("example_lock_counter")
    num = int().from_bytes(num, byteorder='little', signed=False)
    print(num)
    cl.update_entry("example_lock_counter",(num+1).to_bytes(length=32, byteorder='little', signed=False))
    cl.unlock(lock)

if __name__ == "__main__":
    logging.basicConfig(filename="user_lock.log", filemode="a")
    addr = sys.argv[1]
    jwt = sys.argv[2]

    cl = CoLink(addr, jwt)
    cl.update_entry("example_lock_counter", int(0).to_bytes(length=32, byteorder='little', signed=False))

    ths=[]
    child_processes=[]
    for _ in range(10):
        cl = copy.deepcopy(cl)
        ths.append(threading.Thread(target=lock_and_unlock, args=(cl,)))

    for th in ths:
        th.start()
    for th in ths:
        th.join()

    print('All threads ended!')
