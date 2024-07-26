import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
import numpy as np

# Base URL for the API
BASE_URL = "https://walrus-app-s7ejr.ondigitalocean.app/api"

# Endpoints
SIGNUP_ENDPOINT = f"{BASE_URL}/signup"
LOGIN_ENDPOINT = f"{BASE_URL}/login"
CREATE_SCAN_ENDPOINT = f"{BASE_URL}/createscan"
GET_ALL_SCANS_ENDPOINT = f"{BASE_URL}/getallscans"
LOGS_ENDPOINT = f"{BASE_URL}/logs"
TEST_DB_ENDPOINT = f"{BASE_URL}/test-db"
CREATE_LOG_ENDPOINT = f"{BASE_URL}/createLog"

# New Endpoints
CREATE_BOT_ENDPOINT = f"{BASE_URL}/createbot"
GET_BOT_ENDPOINT = f"{BASE_URL}/getbot"
TOGGLE_BOT_ENDPOINT = f"{BASE_URL}/togglebot"

# Create a session with retry strategy
session = requests.Session()
retry = Retry(total=5, backoff_factor=1, status_forcelist=[502, 503, 504])
adapter = HTTPAdapter(max_retries=retry)
session.mount('https://', adapter)

# Global variable to store the token
token = None

# Function to sign up a new user
def signup(username, first_name, last_name, password, user_type):
    payload = {
        "username": username,
        "firstName": first_name,
        "lastName": last_name,
        "password": password,
        "type": user_type
    }
    try:
        response = session.post(SIGNUP_ENDPOINT, json=payload)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(response.json())
        print(f"Signup failed: {e}")
        return {"error": str(e)}

# Function to log in a user and retrieve a token
def login(username, password):
    global token
    payload = {
        "username": username,
        "password": password
    }
    try:
        response = session.post(LOGIN_ENDPOINT, json=payload)
        response.raise_for_status()
        result = response.json()
        token = result.get("token")  # Store the token in the global variable
        return result
    except requests.exceptions.RequestException as e:
        print(f"Login failed: {e}")
        return {"error": str(e)}

# Function to log out a user (clear token)
def logout():
    global token
    token = None  # Clear the token
    return {"message": "Logged out successfully"}





# Function to create a bot
def create_bot(bot_token, passkey, token):
    if not token:
        return {"error": "Authentication token not available."}
    headers = {
        "Authorization": f"Bearer {token}"
    }
    payload = {
        "bot_token": bot_token,
        "passkey": passkey
    }
    try:
        response = session.post(CREATE_BOT_ENDPOINT, headers=headers, json=payload)
        response.raise_for_status()
        return response.json()
    except RequestException as e:
        return {"error": str(e)}

# Function to get bot details
def get_bot(token):
    if not token:
        return {"error": "Authentication token not available."}
    headers = {
        "Authorization": f"Bearer {token}"
    }
    try:
        response = session.get(GET_BOT_ENDPOINT, headers=headers)
        response.raise_for_status()
        return response.json()
    except RequestException as e:
        return {"error": str(e)}

# Function to toggle bot status
def toggle_bot(is_active, token):
    if not token:
        return {"error": "Authentication token not available."}
    headers = {
        "Authorization": f"Bearer {token}"
    }
    payload = {
        "is_active": is_active
    }
    try:
        response = session.post(TOGGLE_BOT_ENDPOINT, headers=headers, json=payload)
        response.raise_for_status()
        return response.json()
    except RequestException as e:
        return {"error": str(e)}



# Function to get all bots
def get_all_bots(token):
    if not token:
        return {"error": "Authentication token not available."}
    headers = {
        "Authorization": f"Bearer {token}"
    }
    try:
        response = session.get(f"{BASE_URL}/getallbots", headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Get all bots failed: {e}")
        return {"error": str(e)}




# Function to create a scan
# Function to create a scan
def create_scan(file_info, is_malware, token):
    if not token:
        return {"error": "Authentication token not available."}
    headers = {
        "Authorization": f"Bearer {token}"
    }

    # Ensure all elements in file_info list are native Python types
    file_info = [
        int(x) if isinstance(x, (np.integer, np.int64)) else 
        float(x) if isinstance(x, (np.floating, np.float64)) else 
        x 
        for x in file_info
    ]

    payload = {
        "file_info": file_info,
        "ismalware": bool(is_malware)
    }
    try:
        response = session.post(CREATE_SCAN_ENDPOINT, headers=headers, json=payload)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Create scan failed: {e}")
        return {"error": str(e)}



# Function to get all scans
def get_all_scans(token):
    if not token:
        return {"error": "Authentication token not available."}
    headers = {
        "Authorization": f"Bearer {token}"
    }
    try:
        response = session.get(GET_ALL_SCANS_ENDPOINT, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Get all scans failed: {e}")
        return {"error": str(e)}

# Function to get logs
def get_logs(token):
    if not token:
        return {"error": "Authentication token not available."}
    headers = {
        "Authorization": f"Bearer {token}"
    }
    try:
        response = session.get(LOGS_ENDPOINT, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Get logs failed: {e}")
        return {"error": str(e)}

# Function to create a log
def create_log(action, details, token):
    if not token:
        return {"error": "Authentication token not available."}
    headers = {
        "Authorization": f"Bearer {token}"
    }
    payload = {
        "action": action,
        "details": details,
        "username": token
    }
    try:
        response = session.post(CREATE_LOG_ENDPOINT, headers=headers, json=payload)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Create log failed: {e}")
        return {"error": str(e)}

# Function to test DB connection
def test_db():
    try:
        response = session.get(TEST_DB_ENDPOINT)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Test DB connection failed: {e}")
        return {"error": str(e)}
