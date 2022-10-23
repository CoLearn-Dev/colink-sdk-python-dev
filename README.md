# CoLink Python SDK
[![Python](https://img.shields.io/badge/python-3.9%20%7C%203.10-blue.svg)](https://badge.fury.io/py/colink)
[![PyPI version](https://badge.fury.io/py/colink.svg)](https://badge.fury.io/py/colink)

CoLink Python SDK helps both application and protocol developers access the functionalities provided by [the CoLink server](https://github.com/CoLearn-Dev/colink-server-dev).

- For *application developers*, CoLink Python SDK allows them to update storage, manage computation requests, and monitor the CoLink server status.
- For *protocol developers*, CoLink Python SDK allows them to write CoLink Extensions that extend the functionality of CoLink to support new protocols.

## Requirements

- Python 3.9
- pytest


## Getting started
You can use this SDK to run protocols, update storage, developing protocol operators. Here is a tutorial for you about how to start a greetings task between two users.
- Set up CoLink server.
Please refer to [colinkctl](https://github.com/CoLearn-Dev/colinkctl), and run the command below. For the following steps, we assume you are using the default settings in colinkctl.
```
colinkctl enable_dev_env
```
- Create two new terminals and start protocol operator for two users separately.
```
python3 examples/protocol_greetings.py \
  --addr http://127.0.0.1:8080  \
  --jwt $(sed -n "1,1p" ~/.colink/user_token.txt)
```
```
python3 examples/protocol_greetings.py \
  --addr http://127.0.0.1:8080 \
  --jwt $(sed -n "2,2p" ~/.colink/user_token.txt)
```
- Run task
```
python3 examples/user_run_task.py \
  http://127.0.0.1:8080 \
  $(cat ~/.colink/user_token.txt)
```
- Check the output in protocol operators' terminals
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
python3 examples/user_start_protocol_operator.py <address> <user_jwt> <protocol_name>
```
```
python3 examples/user_stop_protocol_operator.py <address> <user_jwt> <instance_id>
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
