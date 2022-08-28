import logging
from typing import List
import colink as CL
from colink.sdk_a import CoLink, byte_to_str
from colink.sdk_p import ProtocolOperator

import telebot

pop = ProtocolOperator(__name__)

@pop.handle("telegram/get_msg:getter")
def run_receiver(cl: CoLink, param: bytes, participants: List[CL.Participant]):
    pass

if __name__ == "__main__":
    logging.basicConfig(filename="protocol_telegram_send_msg.log", filemode="a", level=logging.INFO)
    pop.run()
