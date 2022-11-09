import subprocess
from subprocess import DEVNULL
import os
import shutil
import uuid
import random
import time
import socket
from colink import CoLink

class InstantServer:
    def __init__(self,id:str,port:int,host_token:str,process:subprocess.Popen):
        self.id=id
        self.port=port
        self.host_token=host_token
        self.process=process

    def new(self)->InstantServer:
        colink_home = self.get_colink_home()
        program = os.path.join(colink_home,"colink-server")
        if not os.path.exists(program):
            subprocess.Popen(
            [
                "bash",
                "-c",
                "bash -c \"$(curl -fsSL https://raw.githubusercontent.com/CoLearn-Dev/colinkctl/main/install_colink.sh)\"",
                str(self.process.pid)
            ],
            )
        instant_server_id = str(uuid.uuid4())
        port = random.randint(10000,20000)
        while socket.socket().connect_ex(f"127.0.0.1:{port}")==0:
            port = random.randint(10000,20000)
        
        working_dir = os.path.join(colink_home,"instant_servers",instant_server_id)
        os.mkdir(working_dir)
        child=subprocess.Popen([ "--address",
                "0.0.0.0",
                "--port",
                str(port),
                "--mq-amqp",
                "amqp://guest:guest@localhost:5672",
                "--mq-api",
                "http://guest:guest@localhost:15672/api",
                "--mq-prefix",
                f"colink-instant-server-{port}",
                "--core-uri",
                f"http://127.0.0.1:{port}",
                "--inter-core-reverse-mode",],
                env={"COLINK_HOME": colink_home},
                cwd=working_dir,
                stdout=DEVNULL,
                stderr=DEVNULL,
                )
        while True:
            if os.path.exists(os.path.join(working_dir,"host_token.txt")) and socket.socket().connect_ex(f"127.0.0.1:{port}")==0:
                break
            time.sleep(0.01)
        
        host_token = open(os.path.join(working_dir,"host_token.txt"),'r').read()
        return InstantServer(
            id=instant_server_id,
            port=port,
            host_token=host_token,
            process=child,
        )
    

    
    def __del__(self):
        print('deconstruct!')
        subprocess.Popen(
        [
            "pkill",
            "-9",
            "-p",
            str(self.process.pid)
        ],
        stdout=DEVNULL,
        stderr=DEVNULL,
        )
        self.process.kill()
        
        colink_home = self.get_colink_home()
        working_dir = os.path.join(colink_home,"instant_servers",self.id)
        shutil.rmtree(working_dir)

    def get_colink(self) -> CoLink:
        return CoLink(f"http://127.0.0.1:{self.port}", self.host_token)


def get_colink_home() -> str:
    if os.environ.get("COLINK_HOME", ""):
        colink_home = os.environ["COLINK_HOME"]
    elif os.environ.get("HOME", ""):
        colink_home= os.environ["HOME"]+"/.colink"
    else:
        raise Exception("colink home not found.") 
    return colink_home
