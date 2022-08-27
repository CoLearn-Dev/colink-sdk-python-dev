import logging
from typing import List
import colink as CL
from colink.sdk_a import CoLink, byte_to_str
from colink.sdk_p import ProtocolOperator

import telebot

pop = ProtocolOperator(__name__)

@pop.handle("telegram/send_photo:sender")
def run_receiver(cl: CoLink, param: bytes, participants: List[CL.Participant]):
    img_link = byte_to_str(param)
    
    keys = ["telegram_api_key", "telegram_chat_id"]
    api_key, chat_id = list(map(lambda key: byte_to_str(cl.read_or_wait(key)), keys))    

    # First attempt: using telegram/telegram.ext packages (issues with async)
    # async def send_tele_message(api_key, chat_id, msg):
    #     bot = ApplicationBuilder().token(credentials).build().bot
    #     await bot.send_message(chat_id, msg)
    
    # def wrapper(coro):
    #     return asyncio.run(coro)

    # with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
    #     coros = [send_tele_message(api_key, chat_id, byte_to_str(data))]
    #     executor.map(wrapper, coros)

    bot = telebot.TeleBot(api_key)
    bot.send_photo(chat_id, img_link)

    logging.info("Receiver receives: %s", img_link)

if __name__ == "__main__":
    logging.basicConfig(filename="protocol_telegram_send_photo.log", filemode="a", level=logging.INFO)
    pop.run()
