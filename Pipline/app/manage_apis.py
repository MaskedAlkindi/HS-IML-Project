import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

# Base URL for the API
BASE_URL = "https://walrus-app-s7ejr.ondigitalocean.app/api"

# Endpoints
SIGNUP_ENDPOINT = f"{BASE_URL}/signup"
LOGIN_ENDPOINT = f"{BASE_URL}/login"
CREATE_SCAN_ENDPOINT = f"{BASE_URL}/createscan"
GET_ALL_SCANS_ENDPOINT = f"{BASE_URL}/getallscans"
LOGS_ENDPOINT = f"{BASE_URL}/logs"
TEST_DB_ENDPOINT = f"{BASE_URL}/test-db"

# Create a session with retry strategy
session = requests.Session()
retry = Retry(total=5, backoff_factor=1, status_forcelist=[502, 503, 504])
adapter = HTTPAdapter(max_retries=retry)
session.mount('https://', adapter)

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
    payload = {
        "username": username,
        "password": password
    }
    try:
        response = session.post(LOGIN_ENDPOINT, json=payload)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Login failed: {e}")
        return {"error": str(e)}

# Function to log out a user (clear token)
def logout():
    return {"message": "Logged out successfully"}

# Function to create a scan
def create_scan(token, file_info, is_malware):
    headers = {
        "Authorization": f"Bearer {token}"
    }
    payload = {
        "file_info": file_info,
        "ismalware": is_malware
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

# Function to test DB connection
def test_db():
    try:
        response = session.get(TEST_DB_ENDPOINT)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Test DB connection failed: {e}")
        return {"error": str(e)}

# Example usage
if __name__ == "__main__":
    # Signup a new user
    signup_response = signup("newuser", "John", "Doe", "password123", "user")
    print("Signup response:", signup_response)

    # Login with the new user
    login_response = login("newuser", "password123")
    print("Login response:", login_response)

    # Extract token from login response
    token = login_response.get("token")

    if token:
        # Create a scan
        file_info = {"name": "file.exe", "size": 12345}
        create_scan_response = create_scan(token, file_info, True)
        print("Create scan response:", create_scan_response)

        # Get all scans
        all_scans_response = get_all_scans(token)
        print("Get all scans response:", all_scans_response)

        # Get logs
        logs_response = get_logs(token)
        print("Get logs response:", logs_response)

        # Test DB connection
        test_db_response = test_db()
        print("Test DB response:", test_db_response)

        # Logout
        logout_response = logout()
        print(logout_response)
    else:
        print("Failed to login and retrieve token.")
