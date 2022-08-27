# Using python-telegram-bot package
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import ApplicationBuilder, CommandHandler, ContextTypes, filters, MessageHandler, PollAnswerHandler


import sys # for cli-parsing
import asyncio # for async logic
import threading # for threading logic

class CoLinkBot:

    # Mock user database, stores user information
    # Key: user_id
    # Value: User instance
    user_db = {}

    class User:
        def __init__(self, user_id, name):
            self.user_id = user_id
            self.name = name
            self.messages = []

    # Initialization #
    def __init__(self, api_key, chat_id):
        self.set_app_credentials(api_key, chat_id)

        async def initialize(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
            if (not self.verify_user(update)):
                return
            userInfo = update.effective_user
            self.user_db[userInfo.id] = self.User(userInfo.id, userInfo.first_name)
            await update.message.reply_text(f'Hello {userInfo.first_name}')

        async def message_listener(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
            user_id = update.effective_user.id
            self.user_db[user_id].messages.append(update.message.text)
        
        # Bind Telegram slash commands (i.e. /start) to backend method
        self.app.add_handler(CommandHandler("start", initialize))
        
        # Have bot listen for every message sent by Telegram user
        self.app.add_handler(MessageHandler(filters.TEXT & (~filters.COMMAND), message_listener))

        self.start_bot()

    def verify_user(self, update: Update):
        return update.message.chat.id == self.chat_id

    # Initializing Bot Information #
    def set_app_credentials(self, credentials, chat_id):
        self.app = ApplicationBuilder().token(credentials).build()
        self.bot = self.app.bot
        self.chat_id = chat_id

    def start_bot(self):
        self.app.run_polling()

    # Bot Utility #
    async def send_message(self, message) -> None:
        await self.bot.send_message(self.chat_id, message)

    async def send_image(self, img_path) -> None:
        photo = open(img_path, 'rb')
        await self.bot.send_photo(self.chat_id, photo)

    async def get_message(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        user_id = update.effective_user.id
        if self.user_db[user_id].messages:
            message = self.user_db[user_id].messages.pop(0)
            await update.message.reply_text(message)
            print(message)

async def test(bot):
    await bot.send_message("rawr")

if __name__ == '__main__':
    api_key = sys.argv[1]
    chat_id = sys.argv[2]
    bot = CoLinkBot(api_key, int(chat_id))
    # loop = asyncio.get_event_loop()
    # tasks = [
    #     loop.create_task(bot.send_message("rawr")),
    # ]
    # loop.run_until_complete(asyncio.wait(tasks))
    # loop.close()
