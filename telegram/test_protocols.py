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

API_KEY = "<api_key>"
CHAT_ID = "<chat_id>"


def run_telegram_protocols(port: int, user_num: int):
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

        print(users[0])

        threads = []  # thread pool
        
        # Initialize telegram bot for user 0
        threads.append(
            thread_pool.submit(user_set_bot, addr, users[0], API_KEY, CHAT_ID)
        )

        threads.append(
            thread_pool.submit(run_protocol_set_credentials, addr, users[0])
        )
        
        # Have user 0 send message (via telegram)
        threads.append(
            thread_pool.submit(send_telegram_message, addr, users[0], "hello")
        )

        threads.append(
            thread_pool.submit(run_protocol_telegram_send_msg, addr, users[0])
        )

        for th in threads:
            child_processes.append(th.result())
        logging.info("wait threads to be confirmed")
        credentials = get_credentials(addr, users[0])
        # print(credentials)
        wait_for_msg_send(addr, users[0])

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


def remote_storage(addr,jwt):
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


def user_set_bot(addr: str, jwt: str, api_key: str, chat_id: str):
    time.sleep(random.randrange(0, 1000) / 1000)
    return subprocess.Popen(
        [
            "python3",
            "telegram/set_bot_credentials/set_bot_credentials.py",
            addr,
            jwt,
            api_key,
            chat_id
        ],
        stdout=DEVNULL,
        stderr=sys.stdout,
    )

def run_protocol_set_credentials(addr: str, jwt: str):
    time.sleep(random.randrange(0, 1000) / 1000)
    return subprocess.Popen(
        [
            "python3",
            "telegram/set_bot_credentials/protocol_set_bot_credentials.py",
            "--addr",
            addr,
            "--jwt",
            jwt,
        ],
        stdout=sys.stdout,
        stderr=sys.stdout,
    )

def get_credentials(addr: str, jwt: str):
    res = subprocess.run(
        ["python3", "telegram/set_bot_credentials/get_bot_credentials.py", addr, jwt],
        capture_output=True,
        check=True,
    )
    return res.stdout

def send_telegram_message(addr: str, jwt: str, msg: str):
    time.sleep(random.randrange(0, 1000) / 1000)
    return subprocess.Popen(
        [
            "python3",
            "telegram/send_message/send_telegram_message.py",
            addr,
            jwt,
            msg,
        ],
        stdout=DEVNULL,
        stderr=sys.stdout,
    )

def run_protocol_telegram_send_msg(addr: str, jwt: str):
    time.sleep(random.randrange(0, 1000) / 1000)
    return subprocess.Popen(
        [
            "python3",
            "telegram/send_message/protocol_telegram_send_msg.py",
            "--addr",
            addr,
            "--jwt",
            jwt,
        ],
        stdout=sys.stdout,
        stderr=sys.stdout,
    )

def wait_for_msg_send(addr: str, jwt: str):
    res = subprocess.run(
        ["python3", "telegram/send_message/wait_for_msg_send.py", addr, jwt],
        capture_output=True,
        check=True,
    )

def run_auto_confirm(addr: str, jwt: str, protocol_name: str):
    time.sleep(random.randrange(0, 1000) / 1000)
    return subprocess.Popen(
        ["python3", "examples/auto_confirm.py", addr, jwt, protocol_name],
        stdout=DEVNULL,
        stderr=sys.stdout,
    )

def test_example_telegram_protocol():
    logging.basicConfig(
        filename="test_example_protocol.log", filemode="a", level=logging.INFO
    )
    # for i in range(0, 11):
    #     run_greetings(12300 + i, USER_NUM[i])
    run_telegram_protocols(12300, 2)


if __name__ == "__main__":
    test_example_telegram_protocol()
