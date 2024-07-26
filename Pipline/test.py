import requests
import logging

# Setup logging
logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO)
logger = logging.getLogger(__name__)

API_URL = 'https://walrus-app-s7ejr.ondigitalocean.app/bot'
PASSKEY = '12345'  # Replace with your actual passkey

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

logs = get_logs_from_api(PASSKEY)
print(logs)
