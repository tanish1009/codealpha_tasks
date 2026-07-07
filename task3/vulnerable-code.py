import os
from flask import Flask, request, jsonify

app = Flask(__name__)

def ping_host(ip_address):
    # ❌ VULNERABLE: Direct string interpolation with os.system invokes the system shell
    command = f"ping -c 1 {ip_address}"
    
    # Executes the string inside a shell environment
    exit_code = os.system(command)
    return exit_code

@app.route('/api/diagnose', methods=['GET'])
def diagnose_api():
    # User-controlled entry point via query parameters
    target_ip = request.args.get('ip')
    result_code = ping_host(target_ip)
    
    return jsonify({"status": "Executed", "exit_code": result_code})
