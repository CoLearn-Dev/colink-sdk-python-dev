# CoLink Python SDK for Application
CoLink Python SDK  provides a Python3 language support toolkit for application developers which allows them to update storage, manage computation requests, and monitor CoLink server status.



## Requirements

- Python 3.9
- pytest

## Examples

```
python3 examples/host_import_user.py
```
```
python3 examples/host_import_user_exchange_jwt.py <address> <host_jwt> <number> 
```
```
python3 examples/user_run_task.py <address> <user_jwt A> <user_jwt B> <message> # <message> is optional
```
```
python3 examples/user_greetings_to_multiple_users.py <address> <initiator_jwt> <receiver_jwt A> <receiver_jwt B> <receiver_jwt...
```
```
python3 examples/auto_confirm.py <address> <user_jwt> <protocol_name>
```
```
python3 examples/get_next_greeting_message.py <address> <user_jwt> 
```
```
python3 examples/protocol_greetings.py <address> <user_jwt> 
```

## Test

```
pip3 install colink
pip3 install pytest
bash pull-and-build-server.sh
pytest test/test_python.py
```
