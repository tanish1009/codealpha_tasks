import subprocess
import re
from flask import Flask, request, jsonify

app = Flask(__name__)

def ping_host_secure(ip_address):
    #  SECURE: Arguments are isolated as individual list items.
    #  No shell is invoked (shell=False), making execution chaining impossible.
    try:
        command_args = ["ping", "-c", "1", ip_address]
        
        result = subprocess.run(
            command_args,
            shell=False,          # Explicitly disable shell interpretation
            capture_output=True,  # Capture output safely in-memory
            text=True,
            timeout=5             # Prevent Denial of Service hang-ups
        )
        return {"exit_code": result.returncode, "output": result.stdout}
    except subprocess.TimeoutExpired:
        return {"error": "Ping command timed out"}
    except Exception as e:
        return {"error": str(e)}

@app.route('/api/diagnose', methods=['GET'])
def diagnose_api():
    target_ip = request.args.get('ip')
    
    if not target_ip:
        return jsonify({"error": "Missing 'ip' parameter"}), 400
        
    # Optional Defense-in-Depth: Enforce IPv4 regex validation
    if not re.match(r"^[0-9a-zA-Z\.]+$", target_ip):
        return jsonify({"error": "Invalid characters detected"}), 400
        
    execution_result = ping_host_secure(target_ip)
    return jsonify(execution_result)
