from http.server import HTTPServer, BaseHTTPRequestHandler
from hashlib import md5
import time
import ssl
import json
import xml.etree.ElementTree as ET
import requests
from datetime import datetime
import random
import os

CONFIG = {
    "username": "admin",
    "password": "admin",
    "realm": "DS-2CD2342WD-I",
    "port": 443,
    "cert_file": "cert.pem",
    "key_file": "key.pem",
    "hosts_file": "hosts.json"
}

DEVICE_INFO = '''<?xml version="1.0" encoding="UTF-8"?>
<DeviceInfo>
    <deviceName>Simulated Access Control Device</deviceName>
    <deviceID>66666</deviceID>
    <model>DS-2CD2342WD-I</model>
    <serialNumber>DS-2CD2342WD123456</serialNumber>
    <macAddress>11:22:33:44:55:66</macAddress>
    <firmwareVersion>V5.5.4</firmwareVersion>
    <deviceType>AccessControlDevice</deviceType>
</DeviceInfo>'''

# Initialize hosts file
if not os.path.exists(CONFIG["hosts_file"]):
    with open(CONFIG["hosts_file"], "w") as f:
        json.dump({"hosts": []}, f)

def load_hosts():
    with open(CONFIG["hosts_file"], "r") as f:
        return json.load(f)

def save_hosts(hosts_data):
    with open(CONFIG["hosts_file"], "w") as f:
        json.dump(hosts_data, f)

def generate_random_event():
    names = ["JOHN DOE", "JANE SMITH", "ALICE BROWN", "BOB WILSON"]
    card_numbers = ["1953862610", "1953862611", "1953862612", "1953862613"]
    
    return {
        "ipAddress": "192.168.171.112",
        "portNo": 443,
        "protocol": "HTTPS",
        "macAddress": ":".join([format(random.randint(0, 255), '02x') for _ in range(6)]),
        "channelID": 1,
        "dateTime": datetime.now().strftime("%Y-%m-%dT%H:%M:%S+01:00"),
        "activePostCount": random.randint(1, 10),
        "eventType": "AccessControllerEvent",
        "eventState": "active",
        "eventDescription": "Access Controller Event",
        "deviceID": "1",
        "AccessControllerEvent": {
            "deviceName": "Access Controller",
            "majorEventType": 5,
            "subEventType": 1,
            "cardNo": random.choice(card_numbers),
            "cardType": 1,
            "name": random.choice(names),
            "cardReaderKind": 1,
            "cardReaderNo": 1,
            "employeeNoString": str(random.randint(1, 100)),
            "serialNo": random.randint(1000, 2000),
            "userType": "normal",
            "currentVerifyMode": "cardOrFaceOrFp",
            "currentEvent": True,
            "frontSerialNo": random.randint(1000, 2000),
            "attendanceStatus": random.choice(["checkIn", "checkOut"]),
            "label": random.choice(["Check In", "Check Out"]),
            "statusValue": 0,
            "mask": "unknown",
            "purePwdVerifyEnable": True
        }
    }

class HikvisionHandler(BaseHTTPRequestHandler):
    def generate_nonce(self):
        return md5(str(time.time()).encode()).hexdigest()

    def generate_opaque(self):
        return md5(str(time.time()).encode()).hexdigest()

    def send_digest_auth_request(self):
        nonce = self.generate_nonce()
        opaque = self.generate_opaque()
        self.send_response(401)
        self.send_header('WWW-Authenticate', 
            f'Digest realm="{CONFIG["realm"]}", '
            f'qop="auth", '
            f'nonce="{nonce}", '
            f'opaque="{opaque}"')
        self.end_headers()
        return False

    def validate_auth(self, auth_header):
        if not auth_header:
            return False

        auth_params = {}
        for item in auth_header.split(','):
            if '=' in item:
                key, value = item.split('=', 1)
                auth_params[key.strip()] = value.strip(' "')

        print(f"DEBUG: Auth params received: {auth_params}")
        print(f"DEBUG: Request path: {self.path}")
        print(f"DEBUG: Request command: {self.command}")

        ha1 = md5(f"{CONFIG['username']}:{CONFIG['realm']}:{CONFIG['password']}".encode()).hexdigest()
        
        # Use auth_params['uri'] instead of self.path for ha2 calculation
        # This is because the client includes the query parameters in the uri
        ha2 = md5(f"{self.command}:{auth_params.get('uri', self.path)}".encode()).hexdigest()
        
        if 'qop' in auth_params:
            response = md5(f"{ha1}:{auth_params['nonce']}:{auth_params['nc']}:"
                         f"{auth_params['cnonce']}:auth:{ha2}".encode()).hexdigest()
        else:
            response = md5(f"{ha1}:{auth_params['nonce']}:{ha2}".encode()).hexdigest()

        print(f"DEBUG: Expected response: {response}")
        print(f"DEBUG: Received response: {auth_params.get('response', '')}")
        
        return response == auth_params.get('response', '')

    def do_GET(self):
        auth_header = self.headers.get('Authorization')
        
        if not auth_header:
            return self.send_digest_auth_request()

        if not auth_header.startswith('Digest '):
            return self.send_digest_auth_request()

        if not self.validate_auth(auth_header[7:]):
            return self.send_digest_auth_request()

        if self.path == '/ISAPI/event/notification/httpHosts':
            hosts_data = load_hosts()
            response = self.create_hosts_list_xml(hosts_data['hosts'])
            self.send_response(200)
            self.send_header('Content-Type', 'application/xml')
            self.end_headers()
            self.wfile.write(response.encode())
        elif self.path == '/ISAPI/System/deviceInfo':
            self.send_response(200)
            self.send_header('Content-Type', 'application/xml')
            self.send_header('Content-Length', str(len(DEVICE_INFO)))
            self.end_headers()
            self.wfile.write(DEVICE_INFO.encode())
        elif self.path.startswith('/ISAPI/AccessControl/UserInfo/Count'):
            try:
                user_count = {
                    "UserInfoCount": {
                        "userNumber": random.randint(1, 1000)
                    }
                }
                
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                response_data = json.dumps(user_count)
                self.send_header('Content-Length', str(len(response_data.encode())))
                self.end_headers()
                self.wfile.write(response_data.encode())
                
            except Exception as e:
                print(f"DEBUG: Error in UserInfo/Count: {str(e)}")
                self.send_response(500)
                self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

    def do_DELETE(self):
        auth_header = self.headers.get('Authorization')
        if not auth_header or not self.validate_auth(auth_header[7:]):
            return self.send_digest_auth_request()

        if self.path == '/ISAPI/event/notification/httpHosts':
            save_hosts({"hosts": []})
            self.send_response(200)
            self.end_headers()

    def do_POST(self):
        auth_header = self.headers.get('Authorization')
        if not auth_header or not self.validate_auth(auth_header[7:]):
            return self.send_digest_auth_request()

        if self.path == '/ISAPI/event/notification/httpHosts':
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length).decode('utf-8')
            
            hosts_data = load_hosts()
            new_host = self.parse_host_xml(post_data)
            # Keep any existing ID or use the one provided
            hosts_data['hosts'].append(new_host)
            save_hosts(hosts_data)
            
            self.send_response(200)
            self.end_headers()

        elif self.path.startswith('/ISAPI/event/notification/httpHosts/') and self.path.endswith('/test'):
            host_id = self.path.split('/')[-2]
            hosts_data = load_hosts()
            host = next((h for h in hosts_data['hosts'] if h['id'] == host_id), None)
            
            if host:
                try:
                    protocol = host['protocolType'].lower()
                    port = host['portNo']
                    ip = host['ipAddress']
                    url = f"{protocol}://{ip}:{port}{host['url']}"
                    
                    print(f"Testing URL: {url}")
                    
                    headers = {'Content-Type': 'application/json' if host['parameterFormatType'] == 'JSON' else 'application/xml'}
                    
                    response = requests.get(
                        url, 
                        headers=headers,
                        verify=False,
                        timeout=5
                    )
                    
                    print(f"Response status: {response.status_code}")
                    
                    if response.status_code == 200:
                        self.send_response(200)
                        self.end_headers()
                    else:
                        self.send_error_response()
                except Exception as e:
                    print(f"Error: {str(e)}")
                    self.send_error_response()
            else:
                self.send_error_response()

    def create_hosts_list_xml(self, hosts):
        root = ET.Element('HttpHostNotificationList')
        root.set('version', '2.0')
        root.set('xmlns', 'http://www.isapi.org/ver20/XMLSchema')
        
        for host in hosts:
            notification = ET.SubElement(root, 'HttpHostNotification')
            for key, value in host.items():
                elem = ET.SubElement(notification, key)
                elem.text = str(value)
                
        return ET.tostring(root, encoding='unicode')

    def parse_host_xml(self, xml_str):
        root = ET.fromstring(xml_str)
        host_data = {}
        for child in root:
            host_data[child.tag] = child.text
        return host_data

    def send_error_response(self):
        root = ET.Element('HttpHostTestResult')
        root.set('version', '2.0')
        root.set('xmlns', 'http://www.isapi.org/ver20/XMLSchema')
        error = ET.SubElement(root, 'errorDescription')
        error.text = "Failed to connect to host"
        
        self.send_response(200)
        self.send_header('Content-Type', 'application/xml')
        self.end_headers()
        self.wfile.write(ET.tostring(root))

def run_server():
    server = HTTPServer(('', CONFIG['port']), HikvisionHandler)
    
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(CONFIG['cert_file'], CONFIG['key_file'])
    server.socket = context.wrap_socket(server.socket, server_side=True)
    
    print(f'Starting HTTPS server on port {CONFIG["port"]}...')
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print('\nShutting down...')
        server.server_close()

if __name__ == '__main__':
    run_server()
