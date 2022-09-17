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

CORE_ADDR = "127.0.0.1"
CORE_DOMAIN_NAME = "localhost"
MQ_AMQP = "amqp://guest:guest@localhost:5672"
MQ_API = "http://guest:guest@localhost:15672/api"
MQ_PREFIX = "colink-test-python"
USER_NUM = [2, 2, 2, 2, 2, 3, 3, 4, 4, 5, 5]


def run_greetings(port: int, user_num: int):
    try:
        addr = "http://{}:{}".format(CORE_ADDR, port)
        child_processes = []
        thread_pool = concurrent.futures.ThreadPoolExecutor(max_workers=64)
        threads = []
        if socket.socket().connect_ex((CORE_ADDR, port)) == 0:
            raise AssertionError(
                "listen {}:{}: address already in use.".format(CORE_ADDR, port)
            )
        if os.path.exists("./colink-server-dev/host_token.txt"):
            os.remove("./colink-server-dev/host_token.txt")
        child_processes.append(start_core(port, []))
        while True:
            if (
                os.path.exists("./colink-server-dev/host_token.txt")
                and socket.socket().connect_ex((CORE_ADDR, port)) == 0
            ):
                break
            time.sleep(0.1)
        with open("./colink-server-dev/host_token.txt", "r") as f:
            host_token = f.read()
        users = host_import_users_and_exchange_guest_jwts(addr, host_token, user_num)
        assert len(users) == user_num
        start_time = time.time_ns()  # Note  here we use  nano seconds
        random_number = random.randint(0, 999)
        msg = str(random_number)
        threads = []  # thread pool
        if user_num == 2:
            threads.append(
                thread_pool.submit(user_run_task, addr, users[0], users[1], msg)
            )
        else:
            threads.append(
                thread_pool.submit(user_greetings_to_multiple_users, addr, users)
            )
        for i in range(1, user_num):
            threads.append(
                thread_pool.submit(run_auto_confirm, addr, users[i], "greetings")
            )
            threads.append(
                thread_pool.submit(
                    run_auto_confirm, addr, users[i], "remote_storage.create"
                )
            )
        for user in users:
            num = random.randrange(1, 2)
            for _ in range(num):
                threads.append(thread_pool.submit(remote_storage, addr, user))
                threads.append(thread_pool.submit(run_protocol_greeting, addr, user))
        for th in threads:
            child_processes.append(th.result())
        logging.info("wait threads to be confirmed")
        rnd_receiver = random.randrange(1, user_num)
        msg = get_next_greeting_message(addr, users[rnd_receiver], int(start_time))
        if user_num == 2:
            assert msg == str(random_number).encode()
            logging.info(
                "verified received greeting msg: %s sent %d", msg, random_number
            )
        else:
            assert msg == "hello".encode()
            logging.info("verified received greeting msg: %s sent %s", msg, "hello")

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
        cwd="./colink-server-dev",
        stdout=DEVNULL,
        stderr=DEVNULL,
    )


def remote_storage(addr, jwt):
    return subprocess.Popen(
        [
            "cargo",
            "run",
            "--",
            "--addr",
            addr,
            "--jwt",
            jwt,
        ],
        cwd="./colink-protocol-remote-storage-dev",
        stdout=sys.stdout,
        stderr=DEVNULL,
    )


def host_import_users_and_exchange_guest_jwts(
    addr: str, jwt: str, user_num: int
) -> List[str]:
    res = subprocess.run(
        [
            "python3",
            "examples/host_import_user_exchange_jwt.py",
            addr,
            jwt,
            str(user_num),
        ],
        capture_output=True,
        check=True,
    )
    users = res.stdout.splitlines()
    return users


def user_run_task(addr: str, jwt_a: str, jwt_b: str, msg: str):
    time.sleep(random.randrange(0, 1000) / 1000)
    return subprocess.Popen(
        [
            "python3",
            "examples/user_run_task.py",
            addr,
            jwt_a,
            jwt_b,
            msg,
        ],
        stdout=DEVNULL,
        stderr=sys.stdout,
    )


def user_greetings_to_multiple_users(addr: str, users: List[str]):
    time.sleep(random.randrange(0, 1000) / 1000)
    return subprocess.Popen(
        ["python3", "examples/user_greetings_to_multiple_users.py", addr, *users],
        stdout=DEVNULL,
        stderr=sys.stdout,
    )


def run_auto_confirm(addr: str, jwt: str, protocol_name: str):
    time.sleep(random.randrange(0, 1000) / 1000)
    return subprocess.Popen(
        ["python3", "examples/auto_confirm.py", addr, jwt, protocol_name],
        stdout=DEVNULL,
        stderr=sys.stdout,
    )


def run_protocol_greeting(addr: str, jwt: str):
    time.sleep(random.randrange(0, 1000) / 1000)
    return subprocess.Popen(
        [
            "python3",
            "examples/protocol_greetings.py",
            "--addr",
            addr,
            "--jwt",
            jwt,
        ],
        stdout=sys.stdout,
        stderr=sys.stdout,
    )


def get_next_greeting_message(addr: str, jwt: str, now: int):
    res = subprocess.run(
        ["python3", "examples/get_next_greeting_msg.py", addr, jwt, str(now)],
        capture_output=True,
        check=True,
    )
    return res.stdout


def test_example_protocol_greetings():
    logging.basicConfig(
        filename="test_example_protocol.log", filemode="a", level=logging.INFO
    )
    for i in range(0, 11):
        run_greetings(12300 + i, USER_NUM[i])


if __name__ == "__main__":
    test_example_protocol_greetings()
