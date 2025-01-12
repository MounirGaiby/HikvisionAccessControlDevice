from http.server import HTTPServer, BaseHTTPRequestHandler
from hashlib import md5
import time
import ssl
import json
import xml.etree.ElementTree as ET
import requests
from datetime import datetime, timezone
import random
import os
import threading

CONFIG = {
    "username": "admin",
    "password": "admin",
    "realm": "DS-2CD2342WD-I",
    "port": 443,
    "cert_file": "cert.pem",
    "key_file": "key.pem",
    "hosts_file": "hosts.json",
    "users_file": "users.json"
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
</DeviceInfo>
'''

# Event minor types
ACS_EVENT_MINORS = [1, 2, 38, 40, 43, 46, 69, 72, 75, 77, 101, 153, 179, 181]
event_sender = None

# Initialize files
for file_name in [CONFIG["hosts_file"], CONFIG["users_file"]]:
    if not os.path.exists(file_name):
        with open(file_name, "w") as f:
            json.dump({"hosts": [] if file_name == CONFIG["hosts_file"] else [], 
                      "users": [] if file_name == CONFIG["users_file"] else []}, f)

class EventSender:
    def __init__(self):
        self.timer = None
        self.running = False
        
    def start(self):
        self.running = True
        self.schedule_next_event()
        
    def stop(self):
        self.running = False
        if self.timer:
            self.timer.cancel()
            
    def schedule_next_event(self):
        if not self.running:
            return
        
        send_event_to_hosts()
        self.timer = threading.Timer(30.0, self.schedule_next_event)
        self.timer.start()
        
    def trigger_manual_event(self):
        if self.timer:
            self.timer.cancel()
        send_event_to_hosts()
        self.schedule_next_event()

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

        ha1 = md5(f"{CONFIG['username']}:{CONFIG['realm']}:{CONFIG['password']}".encode()).hexdigest()
        ha2 = md5(f"{self.command}:{auth_params.get('uri', self.path)}".encode()).hexdigest()
        
        if 'qop' in auth_params:
            response = md5(f"{ha1}:{auth_params['nonce']}:{auth_params['nc']}:"
                         f"{auth_params['cnonce']}:auth:{ha2}".encode()).hexdigest()
        else:
            response = md5(f"{ha1}:{auth_params['nonce']}:{ha2}".encode()).hexdigest()
        
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
            self.end_headers()
            self.wfile.write(DEVICE_INFO.encode())
        elif self.path.startswith('/ISAPI/AccessControl/UserInfo/Count'):
            users_data = load_users()
            user_count = {
                "UserInfoCount": {
                    "userNumber": len(users_data.get('users', []))
                }
            }
            response_data = json.dumps(user_count)
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(response_data)))
            self.end_headers()
            self.wfile.write(response_data.encode())
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

        # Move auth check before any path handling
        if not auth_header and self.path != '/trigger-event':
            return self.send_digest_auth_request()
        
        if not auth_header or (auth_header and not auth_header.startswith('Digest ')) and self.path != '/trigger-event':
            return self.send_digest_auth_request()

        if auth_header and not self.validate_auth(auth_header[7:]) and self.path != '/trigger-event':
            return self.send_digest_auth_request()

        # Now handle paths
        if self.path == '/trigger-event':
            if event_sender:
                event_sender.trigger_manual_event()
            self.send_response(200)
            self.end_headers()
            return
        elif self.path.startswith('/ISAPI/event/notification/httpHosts/') and self.path.endswith('/test'):
            # Host testing endpoint
            host_id = self.path.split('/')[-2]
            hosts_data = load_hosts()
            host = next((h for h in hosts_data['hosts'] if h['id'] == host_id), None)
                
            if host:
                # Just return 200 for test
                self.send_response(200)
                self.end_headers()
            else:
                self.send_response(404)
                self.end_headers()
            return
        elif self.path == '/ISAPI/event/notification/httpHosts':
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length).decode('utf-8')
            
            hosts_data = load_hosts()
            new_host = self.parse_host_xml(post_data)
            hosts_data['hosts'].append(new_host)
            save_hosts(hosts_data)
            
            self.send_response(200)
            self.end_headers()

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

def load_users():
    try:
        with open(CONFIG["users_file"], "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return {"users": []}

def save_users(users_data):
    with open(CONFIG["users_file"], "w") as f:
        json.dump(users_data, f, indent=2)

def load_hosts():
    try:
        with open(CONFIG["hosts_file"], "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return {"hosts": []}

def save_hosts(hosts_data):
    with open(CONFIG["hosts_file"], "w") as f:
        json.dump(hosts_data, f, indent=2)

def get_next_event_type(last_event):
    event_flow = {
        None: "checkIn",
        "checkIn": "breakOut",
        "breakOut": "breakIn",
        "breakIn": "checkOut",
        "checkOut": "overtimeIn",
        "overtimeIn": "overtimeOut",
        "overtimeOut": "checkIn"
    }
    return event_flow.get(last_event, "checkIn")

def is_user_eligible_for_next_event(user):
    if not user['lastEventTime']:
        return True
        
    last_event_time = datetime.fromisoformat(user['lastEventTime'].replace('Z', '+00:00'))
    current_time = datetime.now(timezone.utc)
    
    return (current_time - last_event_time).total_seconds() > 60

def generate_event():
    users_data = load_users()
    eligible_user = None
    
    for user in users_data['users']:
        if is_user_eligible_for_next_event(user):
            eligible_user = user
            break
    
    if not eligible_user:
        for user in users_data['users']:
            user['lastEventType'] = None
            user['lastEventTime'] = None
        eligible_user = users_data['users'][0]
    
    next_event = get_next_event_type(eligible_user['lastEventType'])
    eligible_user['lastEventType'] = next_event
    eligible_user['lastEventTime'] = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
    save_users(users_data)
    
    return {
        "ipAddress": "192.168.171.112",
        "portNo": 443,
        "protocol": "HTTPS",
        "macAddress": ":".join([format(random.randint(0, 255), '02x') for _ in range(6)]),
        "channelID": 1,
        "dateTime": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
        "activePostCount": random.randint(1, 10),
        "eventType": "AccessControllerEvent",
        "eventState": "active",
        "eventDescription": "Access Controller Event",
        "deviceID": "66666",
        "AccessControllerEvent": {
            "deviceName": "Access Controller",
            "majorEventType": 5,
            "subEventType": random.choice(ACS_EVENT_MINORS),
            "cardNo": eligible_user['cardNo'],
            "cardType": 1,
            "name": eligible_user['name'],
            "cardReaderKind": 1,
            "cardReaderNo": 1,
            "employeeNoString": eligible_user['employeeNoString'],
            "serialNo": random.randint(1000, 2000),
            "userType": "normal",
            "currentVerifyMode": "cardOrFaceOrFp",
            "currentEvent": True,
            "frontSerialNo": random.randint(1000, 2000),
            "attendanceStatus": next_event,
            "statusValue": 0,
            "mask": "unknown",
            "purePwdVerifyEnable": True
        }
    }

def send_event_to_hosts():
    hosts_data = load_hosts()
    event = generate_event()
    
    for host in hosts_data.get('hosts', []):
        try:
            protocol = host['protocolType'].lower()
            port = host['portNo']
            ip = host['ipAddress']
            url = f"{protocol}://{ip}:{port}{host['url']}"
            
            headers = {'Content-Type': 'application/json' if host['parameterFormatType'] == 'JSON' else 'application/xml'}
            
            requests.post(
                url,
                json=event if host['parameterFormatType'] == 'JSON' else None,
                data=ET.tostring(dict_to_xml(event)) if host['parameterFormatType'] != 'JSON' else None,
                headers=headers,
                verify=False,
                timeout=5
            )
            print(f"Event sent to {url}")
            
        except Exception as e:
            print(f"Error sending event to host {host['id']}: {str(e)}")

def dict_to_xml(d):
    root = ET.Element('EventNotificationAlert')
    def _to_xml(d, parent):
        for key, value in d.items():
            child = ET.SubElement(parent, str(key))
            if isinstance(value, dict):
                _to_xml(value, child)
            else:
                child.text = str(value)
    _to_xml(d, root)
    return root

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
    event_sender = EventSender()
    event_sender.start()
    run_server()