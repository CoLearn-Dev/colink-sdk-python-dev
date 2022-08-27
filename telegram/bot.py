import sys
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import ApplicationBuilder, CommandHandler, ContextTypes, filters, MessageHandler, PollAnswerHandler
import colink as CL
from colink.sdk_a import decode_jwt_without_validation, CoLink, str_to_byte

class CoLinkBot:

    # Initialization #
    def __init__(self, addr, jwt, api_key, chat_id):
        self.initialize_colink(addr, jwt)
        self.set_app_credentials(api_key, chat_id)

        async def initialize(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
            if (not self.verify_user(update)):
                await update.message.reply_text(f'Hello {update.effective_user.first_name}, please re-initialize this bot with your chat_id.')
                await update.message.reply_text(f'Your chat_id is: {update.message.chat.id}')
            else:
                await update.message.reply_text(f'Welcome {update.effective_user.first_name}!')

        async def message_listener(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
            print(update.message.text)
            self.cl.create_entry("telegram_message", str_to_byte(update.message.text))
        
        # Bind Telegram slash commands (i.e. /start) to backend method
        self.app.add_handler(CommandHandler("start", initialize))
        
        # Have bot listen for every message sent by Telegram user
        self.app.add_handler(MessageHandler(filters.TEXT & (~filters.COMMAND), message_listener))

    def verify_user(self, update: Update):
        return update.message.chat.id == int(self.chat_id)

    # Initializing Bot Information #
    def initialize_colink(self, addr, jwt):
        self.cl = CoLink(addr, jwt)

    def set_app_credentials(self, credentials, chat_id):
        self.app = ApplicationBuilder().token(credentials).build()
        self.bot = self.app.bot
        self.chat_id = chat_id

        if chat_id:
            # Initialize bot credentials in CoLink server
            res = self.cl.read_entries(
                [
                    CL.StorageEntry(
                        key_name="telegram_api_key"
                    ),
                    CL.StorageEntry(
                        key_name="telegram_chat_id"
                    )
                ]
            )
            if None in res:
                self.cl.create_entry("telegram_api_key", str_to_byte(api_key))
                self.cl.create_entry("telegram_chat_id", str_to_byte(chat_id))
            else:
                self.cl.update_entry("telegram_api_key", str_to_byte(api_key))
                self.cl.update_entry("telegram_chat_id", str_to_byte(chat_id))

    def start_bot(self):
        self.app.run_polling()

    # Bot Utility #
    async def send_message(self, message) -> None:
        await self.bot.send_message(self.chat_id, message)

    async def send_image_local(self, img_path) -> None:
        photo = open(img_path, 'rb')
        await self.bot.send_photo(self.chat_id, photo)

    async def send_image_url(self, url) -> None:
        await self.bot.send_photo(self.chat_id, url)

    async def get_message(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        user_id = update.effective_user.id
        if self.user_db[user_id].messages:
            message = self.user_db[user_id].messages.pop(0)
            await update.message.reply_text(message)
            print(message)


if __name__ == '__main__':
    addr = sys.argv[1]
    jwt = sys.argv[2]
    api_key = sys.argv[3]
    chat_id = sys.argv[4] if len(sys.argv) > 4 else None
    
    cl_bot = CoLinkBot(addr, jwt, api_key, chat_id)
    cl_bot.start_bot()
