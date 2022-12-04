import subprocess
from subprocess import DEVNULL
import os
import shutil
import uuid
import random
import time
import socket
import atexit
from colink import CoLink


class InstantServer:
    def __init__(self):
        colink_home = get_colink_home()
        program = os.path.join(colink_home, "colink-server")
        if not os.path.exists(program):
            subprocess.Popen(
                [
                    "bash",
                    "-c",
                    'bash -c "$(curl -fsSL https://raw.githubusercontent.com/CoLearn-Dev/colinkctl/main/install_colink.sh)"',
                ],
                env={
                    "COLINK_INSTALL_SERVER_ONLY": "true",
                    "COLINK_INSTALL_SILENT": "true",
                },
            ).wait()
        self.id = str(uuid.uuid4())
        self.port = random.randint(10000, 20000)
        while socket.socket().connect_ex(("127.0.0.1", self.port)) == 0:
            self.port = random.randint(10000, 20000)

        working_dir = os.path.join(colink_home, "instant_servers", self.id)
        os.makedirs(working_dir, exist_ok=True)
        mq_amqp = os.environ.get(
            "COLINK_SERVER_MQ_AMQP", "amqp://guest:guest@localhost:5672"
        )
        mq_api = os.environ.get(
            "COLINK_SERVER_MQ_API", "http://guest:guest@localhost:15672/api"
        )
        self.process = subprocess.Popen(
            [
                program,
                "--address",
                "0.0.0.0",
                "--port",
                str(self.port),
                "--mq-amqp",
                mq_amqp,
                "--mq-api",
                mq_api,
                "--mq-prefix",
                f"colink-instant-server-{self.port}",
                "--core-uri",
                f"http://127.0.0.1:{self.port}",
                "--inter-core-reverse-mode",
            ],
            env={"COLINK_HOME": colink_home},
            cwd=working_dir,
            stdout=DEVNULL,
            stderr=DEVNULL,
        )
        while True:
            if (
                os.path.exists(os.path.join(working_dir, "host_token.txt"))
                and socket.socket().connect_ex(("127.0.0.1", self.port)) == 0
            ):
                break
            time.sleep(0.01)
        self.host_token = open(os.path.join(working_dir, "host_token.txt"), "r").read()
        atexit.register(self.clean)

    def clean(self):
        subprocess.Popen(
            ["pkill", "-9", "-P", str(self.process.pid)], stdout=DEVNULL, stderr=DEVNULL
        ).wait()
        self.process.kill()
        colink_home = get_colink_home()
        working_dir = os.path.join(colink_home, "instant_servers", self.id)
        shutil.rmtree(working_dir)

    def get_colink(self):
        return CoLink(coreaddr=f"http://127.0.0.1:{self.port}", jwt=self.host_token)


class InstantRegistry(InstantServer):
    def __init__(self):
        super().__init__()
        colink_home = get_colink_home()
        registry_file = os.path.join(colink_home, "reg_config")
        file = open(registry_file, "w")
        file.close()
        self.get_colink().switch_to_generated_user()

    def clean(self):
        super().clean()
        colink_home = get_colink_home()
        registry_file = os.path.join(colink_home, "reg_config")
        os.remove(registry_file)


def get_colink_home() -> str:
    if os.environ.get("COLINK_HOME", ""):
        colink_home = os.environ["COLINK_HOME"]
    elif os.environ.get("HOME", ""):
        colink_home = os.environ["HOME"] + "/.colink"
    else:
        raise Exception("colink home not found.")
    return colink_home
