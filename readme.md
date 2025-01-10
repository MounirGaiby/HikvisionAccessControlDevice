# Hikvision Device Mock Server

A Python server that simulates a Hikvision device for testing purposes. It implements digest authentication and various ISAPI endpoints.

## Features
- Digest Authentication
- HTTPS Support
- Device Info Endpoint
- User Count Endpoint
- Event Notification System

## Prerequisites
- Python 3.8+
- pip (Python package installer)

## Installation

1. Clone the repository
```bash
git clone [your-repo-url]
cd hikvision-mock
```

2. Install required dependencies
```bash
pip install requests
```

3. Generate SSL certificates (required for HTTPS)
```bash
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes
```

## Configuration
Default configuration is in the `CONFIG` object in main.py:
```python
CONFIG = {
    "username": "admin",
    "password": "admin",
    "realm": "DS-2CD2342WD-I",
    "port": 443,
    "cert_file": "cert.pem",
    "key_file": "key.pem",
    "hosts_file": "hosts.json"
}
```

## Running the Server
```bash
python main.py
```

## Testing Endpoints

Using curl (ignore SSL verification since we're using self-signed certificates):

1. Get Device Info
```bash
curl -k --digest -u admin:admin https://localhost/ISAPI/System/deviceInfo
```

2. Get User Count
```bash
curl -k --digest -u admin:admin "https://localhost/ISAPI/AccessControl/UserInfo/Count?format=json"
```

3. Get Notification Hosts
```bash
curl -k --digest -u admin:admin https://localhost/ISAPI/event/notification/httpHosts
```

4. Add New Host
```bash
curl -k --digest -u admin:admin \
  -X POST \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0" encoding="UTF-8"?>
<HttpHostNotification>
    <id>hik0</id>
    <url>/health</url>
    <protocolType>HTTP</protocolType>
    <parameterFormatType>JSON</parameterFormatType>
    <addressingFormatType>ipaddress</addressingFormatType>
    <ipAddress>127.0.0.1</ipAddress>
    <portNo>3001</portNo>
    <userName></userName>
    <httpAuthenticationMethod>none</httpAuthenticationMethod>
</HttpHostNotification>' \
  https://localhost/ISAPI/event/notification/httpHosts
```

5. Test Host
```bash
curl -k --digest -u admin:admin \
  -X POST \
  https://localhost/ISAPI/event/notification/httpHosts/hik0/test
```

6. Delete All Hosts
```bash
curl -k --digest -u admin:admin \
  -X DELETE \
  https://localhost/ISAPI/event/notification/httpHosts
```

## Project Structure
```
.
├── README.md
├── main.py
├── hosts.json       # Auto-generated file for storing hosts
├── cert.pem        # Generated SSL certificate
└── key.pem         # Generated SSL private key
```

## Security Note
This is a testing mock server. The included certificates (if any) and default credentials are for testing purposes only. Never use these in a production environment.

## License
MIT License