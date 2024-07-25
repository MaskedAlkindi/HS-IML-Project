import requests

# Base URL for the API
BASE_URL = "http://localhost:9001/api"

# Endpoints
SIGNUP_ENDPOINT = f"{BASE_URL}/signup"
LOGIN_ENDPOINT = f"{BASE_URL}/login"
CREATE_SCAN_ENDPOINT = f"{BASE_URL}/createscan"
GET_ALL_SCANS_ENDPOINT = f"{BASE_URL}/getallscans"
LOGS_ENDPOINT = f"{BASE_URL}/logs"
TEST_DB_ENDPOINT = f"{BASE_URL}/test-db"

# Function to sign up a new user
def signup(username, first_name, last_name, password, user_type):
    payload = {
        "username": username,
        "firstName": first_name,
        "lastName": last_name,
        "password": password,
        "type": user_type
    }
    response = requests.post(SIGNUP_ENDPOINT, json=payload)
    return response.json()

# Function to log in a user and retrieve a token
def login(username, password):
    payload = {
        "username": username,
        "password": password
    }
    response = requests.post(LOGIN_ENDPOINT, json=payload)
    return response.json()

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
    response = requests.post(CREATE_SCAN_ENDPOINT, headers=headers, json=payload)
    return response.json()

# Function to get all scans
def get_all_scans(token):
    headers = {
        "Authorization": f"Bearer {token}"
    }
    response = requests.get(GET_ALL_SCANS_ENDPOINT, headers=headers)
    return response.json()

# Function to get logs
def get_logs(token):
    headers = {
        "Authorization": f"Bearer {token}"
    }
    response = requests.get(LOGS_ENDPOINT, headers=headers)
    return response.json()

# Function to test DB connection
def test_db():
    response = requests.get(TEST_DB_ENDPOINT)
    return response.json()

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
