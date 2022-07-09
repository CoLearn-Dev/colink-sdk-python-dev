# CoLink Python SDK for Application
CoLink Python SDK  provides a Python3 language support toolkit for application developers which allows them to update storage, manage computation requests, and monitor CoLink server status.



## Requirements

- Python 3.9
- pytest

## Examples

```
python3 -m examples.host_import_user
```
```
python3 -m examples.host_import_user_exchange_jwt <address> <host_jwt> <number> 
```
```
python3 -m examples.user_run_task <address> <user_jwt A> <user_jwt B> <message> # <message> is optional
```
```
python3 -m examples.user_greetings_to_multiple_users <address> <initiator_jwt> <receiver_jwt A> <receiver_jwt B> <receiver_jwt...
```
```
python3 -m examples.auto_confirm <address> <user_jwt> <protocol_name>
```
```
python3 -m examples.get_next_greeting_message <address> <user_jwt> 
```
```
python3 -m examples.protocol_greetings <address> <user_jwt> 
```

## Test

```
pip3 install -e .
pip3 install pytest
bash pull-and-build-server.sh
pytest test/test_python.py
```
