import json
import random
from datetime import datetime

def generate_users():
    first_names = ["John", "Jane", "Alice", "Bob", "Charlie", "Diana", "Edward", "Fiona"]
    last_names = ["Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis"]
    
    users = []
    start_emp_no = 1001
    start_card_no = 1953862610
    
    for i in range(10):  # Generate 10 users
        name = f"{random.choice(first_names)} {random.choice(last_names)}".upper()
        users.append({
            "name": name,
            "cardNo": str(start_card_no + i),
            "employeeNoString": str(start_emp_no + i),
            "lastEventType": None,
            "lastEventTime": None
        })
    
    with open('users.json', 'w') as f:
        json.dump({"users": users}, f, indent=2)

if __name__ == '__main__':
    generate_users()