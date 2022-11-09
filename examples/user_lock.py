import sys
import logging
import threading
from colink import CoLink
from colink.sdk_a import byte_to_int


def lock_and_unlock(cl):
    key, rnd_num = cl.lock("example_lock_name")
    num = byte_to_int(cl.read_entry("example_lock_counter"))
    print(num)
    cl.update_entry(
        "example_lock_counter",
        (num + 1).to_bytes(length=32, byteorder="little", signed=False),
    )
    cl.unlock((key, rnd_num))


if __name__ == "__main__":
    logging.basicConfig(filename="user_lock.log", filemode="a", level=logging.INFO)
    addr = sys.argv[1]
    jwt = sys.argv[2]

    cl = CoLink(addr, jwt)
    cl.update_entry(
        "example_lock_counter",
        int(0).to_bytes(length=32, byteorder="little", signed=False),
    )

    ths = []
    child_processes = []
    for _ in range(10):
        ths.append(threading.Thread(target=lock_and_unlock, args=(cl,)))

    for th in ths:
        th.start()
    for th in ths:
        th.join()

    print("All threads ended!")
