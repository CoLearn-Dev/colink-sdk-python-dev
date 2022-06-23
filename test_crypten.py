import os
import time
import random
import socket
import subprocess
from subprocess import DEVNULL
import concurrent.futures
from typing import List
import logging
import sys
from colink.sdk_p import _sha256
from colink.sdk_a import str_to_byte,byte_to_str

CORE_ADDR = "127.0.0.1"
CORE_DOMAIN_NAME = "localhost"
MQ_AMQP = "amqp://guest:guest@localhost:5672"
MQ_API = "http://guest:guest@localhost:15672/api"
MQ_PREFIX = "colink-test-python"
USER_NUM = [3, 3, 4, 4, 5, 5]


def run_crypten(port: int, user_num: int):
    try:
        addr = "http://{}:{}".format(CORE_ADDR, port)
        child_processes = []
        thread_pool = concurrent.futures.ThreadPoolExecutor(max_workers=64)
        threads = []
        if socket.socket().connect_ex((CORE_ADDR, port)) == 0:
            raise AssertionError(
                "listen {}:{}: address already in use.".format(CORE_ADDR, port)
            )
        if os.path.exists("./colink-server/admin_token.txt"):
            os.remove("./colink-server/admin_token.txt")
        child_processes.append(start_core(port, []))
        while True:
            if (
                os.path.exists("./colink-server/admin_token.txt")
                and socket.socket().connect_ex((CORE_ADDR, port)) == 0
            ):
                break
            time.sleep(0.1)
        with open("./colink-server/admin_token.txt", "r") as f:
            admin_token = f.read()
        users = admin_import_users_and_exchange_guest_jwts(addr, admin_token, user_num)
        assert len(users) == user_num
        start_time = time.time_ns()  # Note  here we use  nano seconds
        random_number = random.randint(0, 999)
        msg = str(random_number)
        threads = []  # thread pool

        threads.append(thread_pool.submit(run_crypten_deploy, addr, users))
        for i in range(1, user_num):
            threads.append(
                thread_pool.submit(run_auto_confirm, addr, users[i], "crypten_deploy")
            )
        for user in users:
            num = random.randrange(1, 2)
            for _ in range(num):
                threads.append(
                    thread_pool.submit(run_protocol_crypten_deploy, addr, user)
                )
        for th in threads:
            child_processes.append(th.result())
        logging.info("wait threads to be confirmed")
        rnd_receiver = random.randrange(1, user_num)
        msg = get_next_crypten_message(addr, users[rnd_receiver], int(start_time))
        for i,user in enumerate(users):
            print(i,_sha256(byte_to_str(user)))
        print(msg,len(msg))
        #assert msg == "hello".encode()
        #logging.info("verified received crypten msg: %s sent %s", msg, "hello")

    finally:
        for c in child_processes:
            c.kill()
        thread_pool.shutdown(wait=False, cancel_futures=True)


def start_core(port, param=[]):
    return subprocess.Popen(
        [
            "cargo",
            "run",
            "--",
            "--address",
            CORE_ADDR,
            "--port",
            str(port),
            "--mq-amqp",
            MQ_AMQP,
            "--mq-api",
            MQ_API,
            "--mq-prefix",
            MQ_PREFIX,
            *param,
        ],
        cwd="./colink-server",
        stdout=DEVNULL,
        stderr=DEVNULL,
    )


def admin_import_users_and_exchange_guest_jwts(
    addr: str, jwt: str, user_num: int
) -> List[str]:
    res = subprocess.run(
        [
            "python3",
            "-m",
            "examples.admin_import_user_exchange_jwt",
            addr,
            jwt,
            str(user_num),
        ],
        capture_output=True,
        check=True,
    )
    users = res.stdout.splitlines()
    return users


def run_crypten_deploy(addr: str, users: List[str]):
    time.sleep(random.randrange(0, 1000) / 1000)
    return subprocess.Popen(
        ["python3", "-m", "crypten.run_crypten_deploy", addr, *users],
        stdout=DEVNULL,
        stderr=sys.stdout,
    )


def run_auto_confirm(addr: str, jwt: str, protocol_name: str):
    time.sleep(random.randrange(0, 1000) / 1000)
    return subprocess.Popen(
        ["python3", "-m", "examples.auto_confirm", addr, jwt, protocol_name],
        stdout=DEVNULL,
        stderr=sys.stdout,
    )


def run_protocol_crypten_deploy(addr: str, jwt: str):
    time.sleep(random.randrange(0, 1000) / 1000)
    return subprocess.Popen(
        [
            "python3",
            "-m",
            "crypten.protocol_crypten_deploy",
            "--addr",
            addr,
            "--jwt",
            jwt,
        ],
        stdout=sys.stdout,
        stderr=sys.stdout,
    )


def get_next_crypten_message(addr: str, jwt: str, now: int):
    res = subprocess.run(
        ["python3", "-m", "crypten.get_next_crypten_msg", addr, jwt, str(now)],
        capture_output=True,
        check=True,
    )
    return res.stdout


def test_crypten():
    logging.basicConfig(filename="test_crypten.log", filemode="a", level=logging.INFO)
    for i in range(0, 6):
        run_crypten(8080 + i, USER_NUM[i])


if __name__ == "__main__":
    test_crypten()
