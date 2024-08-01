import logging
import requests
from telegram import Update, ForceReply
from telegram.ext import Updater, CommandHandler, CallbackContext
from multiprocessing import Process

# Setup logging
logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO)
logger = logging.getLogger(__name__)

API_URL = 'https://walrus-app-s7ejr.ondigitalocean.app/bot'

def get_logs_from_api(passkey):
    headers = {'Authorization': f'Bearer {passkey}'}
    try:
        logger.info(f"Fetching logs with headers: {headers}")
        response = requests.get(f'{API_URL}/logs', headers=headers)
        logger.info(f"API Response: {response.status_code} - {response.text}")
        if response.status_code == 200:
            return response.json()
        else:
            return {'error': f'Failed to fetch logs: {response.status_code} - {response.text}'}
    except Exception as e:
        logger.error(f"Exception occurred: {e}")
        return {'error': f'Exception occurred: {str(e)}'}

def get_user_info_from_api(passkey):
    headers = {'Authorization': f'Bearer {passkey}'}
    try:
        logger.info(f"Fetching user info with headers: {headers}")
        response = requests.get(f'{API_URL}/getinfo', headers=headers)
        logger.info(f"API Response: {response.status_code} - {response.text}")
        if response.status_code == 200:
            return response.json()
        else:
            return {'error': f'Failed to fetch user info: {response.status_code} - {response.text}'}
    except Exception as e:
        logger.error(f"Exception occurred: {e}")
        return {'error': f'Exception occurred: {str(e)}'}

def start(update: Update, context: CallbackContext) -> None:
    user = update.effective_user
    update.message.reply_markdown_v2(
        fr'Hi {user.mention_markdown_v2()}\!',
        reply_markup=ForceReply(selective=True),
    )

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

def getinfo(update: Update, context: CallbackContext) -> None:
    passkey = context.args[0] if context.args else None
    if not passkey:
        update.message.reply_text('Passkey is required to view user info.')
        return

    info = get_user_info_from_api(passkey)
    if 'error' in info:
        update.message.reply_text(info['error'])
    else:
        info_message = f"Username: {info['Username']}\nFirst Name: {info['FirstName']}\nLast Name: {info['LastName']}\nType: {info['Type']}"
        update.message.reply_text(info_message)

def run_bot(bot_token):
    logger.info(f"Starting bot with token: {bot_token}")
    updater = Updater(bot_token, use_context=True)
    dispatcher = updater.dispatcher

    dispatcher.add_handler(CommandHandler("start", start))
    dispatcher.add_handler(CommandHandler("showlogs", showlogs))
    dispatcher.add_handler(CommandHandler("getinfo", getinfo))

    updater.start_polling()
    updater.idle()

def fetch_bot_tokens():
    headers = {'Authorization': f'Bearer 12345'}  # this passkey is hardcoded sorry :( demo purposes only)
    try:
        response = requests.get(f'{API_URL}/getallbots', headers=headers)
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
    bots = fetch_bot_tokens()
    processes = []
    for bot in bots:
        bot_token = bot['BotToken']
        process = Process(target=run_bot, args=(bot_token,))
        processes.append(process)
        process.start()
    
    for process in processes:
        process.join()

if __name__ == '__main__':
    main()
