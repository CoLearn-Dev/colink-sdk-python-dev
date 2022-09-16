# CoLink Python SDK
[![Python](https://img.shields.io/badge/python-3.9%20%7C%203.10-blue.svg)](https://badge.fury.io/py/colink)
[![PyPI version](https://badge.fury.io/py/colink.svg)](https://badge.fury.io/py/colink)

CoLink Python SDK  provides a Python3 language support toolkit for application developers which allows them to update storage, manage computation requests, and monitor CoLink server status.

## Requirements

- Python 3.9
- pytest


## Getting started
We can connect to CoLink server, run protocols, update storage, monitor server status by python SDK. For how to setup a CoLink server, please refer to [colinkctl](https://github.com/CoLearn-Dev/colinkctl).

Assuming that you have `colinkctl` installed, you can first setup up a CoLink server at port `15600` and create 2 users, also start the policy module to accept tasks:
```
colinkctl enable_dev_env
```
Two users exchange their jwt to each other:
```
python3 examples/user_exchange_jwt.py \
  http://127.0.0.1:15600 \
  $(cat ~/.colink/user_token.txt)
```
Two users run task `greetings`:
```
python3 examples/user_run_task.py \
  http://127.0.0.1:15600 \
  $(cat ~/.colink/user_token.txt)
```
Check the output of task creation:
```
cat user_run_task.log
```
In the current terminal, run the protocol operator of initiator:
```
python3 examples/protocol_greetings.py \
  --addr http://127.0.0.1:15600  \
  --jwt $(head -n 1 ~/.colink/user_token.txt)
```
Create a new terminal, run the protocol operator of receiver:
```
python3 examples/protocol_greetings.py \
  --addr http://127.0.0.1:15600 \
  --jwt $(tail -n 1 ~/.colink/user_token.txt)
```
Check the output of protocol operators:
```
cat protocol_greeting.log
```
## More examples, for details please refer to [here](https://github.com/CoLearn-Dev/colink-sdk-python-dev/tree/main/examples)

```
python3 examples/host_import_user.py
```
```
python3 examples/host_import_user_exchange_jwt.py <address> <host_jwt> <number> 
```
```
python3 examples/host_import_users_and_set_registry.py <address> <host_jwt> <number>
```
```
python3 examples/user_run_task.py <address> <user_jwt A> <user_jwt B> <message> # <message> is optional
```
```
python3 examples/user_greetings_to_multiple_users.py <address> <initiator_jwt> <receiver_jwt A> <receiver_jwt B> <receiver_jwt C> ...
```
```
python3 examples/auto_confirm.py <address> <user_jwt> <protocol_name>
```
```
python3 examples/get_next_greeting_message.py <address> <user_jwt> 
```
```
python3 examples/protocol_greetings.py --addr <address> --jwt <user_jwt> 
```
```
python3 examples/user_remote_storage.py <address> <user_jwt A> <user_jwt B> <message> # <message> is optional
```
```
python3 examples/user_lock.py <address> <user_jwt>
```
## Running Tests

```
pip3 install colink
pip3 install pytest
bash pull-and-build-server.sh
pytest test/test_python.py
```
