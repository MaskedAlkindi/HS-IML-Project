import os
import logging
import requests
from telegram import Update
from telegram.ext import Updater, CommandHandler, CallbackContext
from threading import Thread
import time

# Setup logging
logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO)
logger = logging.getLogger(__name__)

API_URL = os.getenv('API_URL', 'https://walrus-app-s7ejr.ondigitalocean.app/bot')

def get_logs_from_api(passkey):
    headers = {'Authorization': f'Bearer {passkey}'}
    logger.info(f"Fetching logs with headers: {headers}")
    try:
        response = requests.get(f'{API_URL}/logs', headers=headers)
        logger.info(f"API Response: {response.status_code} - {response.text}")
        if response.status_code == 200:
            return response.json()
        else:
            return {'error': f'Failed to fetch logs: {response.status_code} - {response.text}'}
    except Exception as e:
        logger.error(f"Exception occurred: {e}")
        return {'error': f'Exception occurred: {str(e)}'}

def showlogs(update: Update, context: CallbackContext) -> None:
    passkey = context.args[0] if context.args else None
    if not passkey:
        update.message.reply_text('Passkey is required to view logs.')
        return

    logs = get_logs_from_api(passkey)
    if 'error' in logs:
        update.message.reply_text(logs['error'])
    else:
        log_messages = '\n'.join([f"{log['TimeStamp']} - {log['Action']} - {log['Details']}" for log in logs])
        update.message.reply_text(log_messages if log_messages else 'No logs found.')

def run_bot(bot_token):
    updater = Updater(bot_token)
    dispatcher = updater.dispatcher
    dispatcher.add_handler(CommandHandler("showlogs", showlogs))
    updater.start_polling()
    updater.idle()

def fetch_bot_tokens():
    try:
        response = requests.get(f'{API_URL}/getallbots')
        logger.info(f"API Response: {response.status_code} - {response.text}")
        if response.status_code == 200:
            return response.json()
        else:
            logger.error(f"Failed to fetch bot tokens: {response.status_code} - {response.text}")
            return []
    except Exception as e:
        logger.error(f"Exception occurred while fetching bot tokens: {e}")
        return []

def main():
    while True:
        bots = fetch_bot_tokens()
        for bot in bots:
            bot_token = bot['BotToken']
            thread = Thread(target=run_bot, args=(bot_token,))
            thread.start()
        time.sleep(3600)  # Refresh the bot tokens every hour

if __name__ == '__main__':
    main()
