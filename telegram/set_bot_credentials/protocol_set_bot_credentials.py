import logging
from typing import List
import colink as CL
from colink.sdk_a import CoLink, byte_to_str, str_to_byte
from colink.sdk_p import ProtocolOperator

import telebot

pop = ProtocolOperator(__name__)

# @pop.handle("telegram/send_msg:initiator")
# def run_initiator(cl: CoLink, param: bytes, participants: List[CL.Participant]):
#     cl.set_variable("telegram:send_msg:output", param, participants[1:])
#     logging.info("Initiator sends: %s", byte_to_str(param))

@pop.handle("telegram/set_credentials:initiator")
def run_receiver(cl: CoLink, param: bytes, participants: List[CL.Participant]):
    message = byte_to_str(param)
    api_key, chat_id = message.split("|")

    cl.create_entry("telegram_api_key", str_to_byte(api_key))
    cl.create_entry("telegram_chat_id", str_to_byte(chat_id))

    logging.info("Credentials generated: %s, %s", api_key, chat_id)

if __name__ == "__main__":
    logging.basicConfig(filename="protocol_telegram_send_msg.log", filemode="a", level=logging.INFO)
    pop.run()
