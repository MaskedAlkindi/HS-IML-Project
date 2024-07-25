## API Documentation

### Base URL
```
http://localhost:3000
```

### Authentication
All endpoints, except the `/login` endpoint, require a Bearer Token for authentication.

### Endpoints

#### 1. Login
##### POST /login
Authenticates a user and returns a JWT token.

- **URL:** `/login`
- **Method:** POST
- **Request Body:**
  ```json
  {
    "username": "string",
    "password": "string"
  }
  ```
- **Response:**
  - **Success:**
    ```json
    {
      "token": "string"
    }
    ```
  - **Failure:**
    ```json
    {
      "message": "Invalid credentials"
    }
    ```
- **Status Codes:**
  - 200: Success
  - 401: Unauthorized

#### 2. Create Scan
##### POST /createscan
Creates a new scan entry in the database.

- **URL:** `/createscan`
- **Method:** POST
- **Headers:**
  ```json
  {
    "Authorization": "Bearer <token>"
  }
  ```
- **Request Body:**
  ```json
  {
    "file_info": { "key": "value" },
    "ismalware": 1
  }
  ```
- **Response:**
  - **Success:**
    ```json
    {
      "message": "Scan created successfully"
    }
    ```
  - **Failure:**
    ```json
    {
      "message": "Error message"
    }
    ```
- **Status Codes:**
  - 201: Created
  - 401: Unauthorized
  - 400: Bad Request

#### 3. Get All Scans
##### GET /getallscans
Retrieves all scans created by the authenticated user, organized by time periods.

- **URL:** `/getallscans`
- **Method:** GET
- **Headers:**
  ```json
  {
    "Authorization": "Bearer <token>"
  }
  ```
- **Response:**
  - **Success:**
    ```json
    {
      "allScans": [
        {
          "ScanID": 1,
          "TimeStamp": "YYYY-MM-DD HH:MM:SS",
          "File_info": { "key": "value" },
          "IsMalware": 1,
          "Username": "string"
        }
      ],
      "todayScans": [ /* ... */ ],
      "weekScans": [ /* ... */ ],
      "monthScans": [ /* ... */ ],
      "yearScans": [ /* ... */ ]
    }
    ```
  - **Failure:**
    ```json
    {
      "message": "Error message"
    }
    ```
- **Status Codes:**
  - 200: Success
  - 401: Unauthorized

#### 4. Create Log
##### POST /createlog
Creates a new log entry in the database. This endpoint is not directly accessible by users but is used internally to log actions.

- **URL:** `/createlog`
- **Method:** POST
- **Headers:**
  ```json
  {
    "Authorization": "Bearer <token>"
  }
  ```
- **Request Body:**
  ```json
  {
    "action": "string",
    "details": "string"
  }
  ```
- **Response:**
  - **Success:**
    ```json
    {
      "message": "Log created successfully"
    }
    ```
  - **Failure:**
    ```json
    {
      "message": "Error message"
    }
    ```
- **Status Codes:**
  - 201: Created
  - 401: Unauthorized
  - 400: Bad Request

#### 5. Get Logs
##### GET /logs
Retrieves all logs created by the authenticated user.

- **URL:** `/logs`
- **Method:** GET
- **Headers:**
  ```json
  {
    "Authorization": "Bearer <token>"
  }
  ```
- **Response:**
  - **Success:**
    ```json
    [
      {
        "LogID": 1,
        "TimeStamp": "YYYY-MM-DD HH:MM:SS",
        "Action": "string",
        "Details": "string",
        "Username": "string"
      }
    ]
    ```
  - **Failure:**
    ```json
    {
      "message": "Error message"
    }
    ```
- **Status Codes:**
  - 200: Success
  - 401: Unauthorized

### Error Messages
- **401 Unauthorized:** When the user is not authenticated or the token is invalid.
- **400 Bad Request:** When the request body is not properly formatted.
- **500 Internal Server Error:** When there is an error on the server side.

### Example JWT Payload
The JWT token contains the following payload:
```json
{
  "username": "string",
  "iat": 1627389130,
  "exp": 1627392730
}
```

### Notes
- Ensure to replace `<token>` with the actual JWT token in the Authorization header.
- The `file_info` field in the `/createscan` endpoint is a JSON object that can contain various information about the file being scanned.
- The time periods (today, this week, this month, this year) in the `/getallscans` endpoint are calculated based on the current date and time on the server.

---

This documentation provides a comprehensive overview of the API endpoints, their expected inputs and outputs, and the possible status codes. It should help you implement and test the backend services effectively.