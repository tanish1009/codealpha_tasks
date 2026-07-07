# 🛡️ Secure Ping Diagnostic API

## 📖 Overview

This project demonstrates the remediation of multiple security vulnerabilities in a Flask-based network diagnostic API.

The original implementation accepted user input and directly executed it using `os.system()`, making the application vulnerable to command injection, denial-of-service attacks, information leakage, and improper input validation.

The secure implementation follows secure coding best practices by replacing unsafe execution methods, validating user input, enforcing execution timeouts, and sanitizing error responses.

---

# 📂 Project Structure

```
.
├── vulnerable_app.py     # Original vulnerable implementation
├── secure_app.py         # Remediated secure implementation
└── README.md
```

---

# 🚨 Vulnerabilities Identified

## 🔴 1. OS Command Injection (CWE-78)

**Severity:** Critical

### Description

The vulnerable application constructs an operating system command using Python f-string interpolation:

```python
command = f"ping -c 1 {ip_address}"
os.system(command)
```

Since user input is directly embedded into the command string, an attacker can inject shell metacharacters and execute arbitrary commands.

---

## 🟠 2. Dangerous Subshell Execution (CWE-78)

**Severity:** High

### Description

The application uses:

```python
os.system()
```

This API launches a shell (`/bin/sh`) to execute commands, making exploitation significantly easier.

---

## 🟡 3. Uncontrolled Resource Consumption (CWE-400)

**Severity:** Medium

### Description

The vulnerable implementation has no timeout mechanism.

An attacker can provide a destination that causes the process to hang indefinitely, consuming server resources and potentially causing a denial of service.

---

## 🔵 4. Sensitive Information Leakage (CWE-117)

**Severity:** Low

### Description

Raw command failures and diagnostics may expose:

- Operating system information
- Directory paths
- Command execution details
- Network configuration

This information assists attackers during reconnaissance.

---

## 🟡 5. Missing Input Validation (CWE-20)

**Severity:** Medium

### Description

The vulnerable implementation accepts arbitrary input directly from:

```python
request.args.get("ip")
```

No validation is performed before the value reaches the command execution sink.

---

# ✅ Security Improvements

## 🔒 1. Replace `os.system()` with `subprocess.run()`

The secure implementation replaces:

```python
os.system(command)
```

with

```python
subprocess.run(
    command_args,
    shell=False,
    capture_output=True,
    text=True,
    timeout=5
)
```

### Benefits

- ✅ No shell is invoked
- ✅ Prevents command chaining
- ✅ Safer process execution
- ✅ Supports timeout handling
- ✅ Captures output safely

---

## 📦 2. Pass Arguments as a List

### Vulnerable

```python
command = f"ping -c 1 {ip}"
```

### Secure

```python
command_args = [
    "ping",
    "-c",
    "1",
    ip_address
]
```

Each argument is passed independently to the operating system, completely separating user input from executable instructions.

---

## 🧹 3. Input Validation

The secure implementation validates incoming parameters using Regular Expressions.

```python
if not re.match(r"^[0-9a-zA-Z\.]+$", target_ip):
    return jsonify({"error": "Invalid characters detected"}), 400
```

This allow-list permits only:

- Letters
- Digits
- Periods

and rejects shell metacharacters.

---

## ⏱️ 4. Timeout Protection

The application enforces a maximum execution time.

```python
timeout=5
```

If execution exceeds five seconds:

```python
except subprocess.TimeoutExpired:
    return {"error": "Ping command timed out"}
```

This prevents resource exhaustion attacks.

---

## 🛑 5. Sanitized Error Handling

Instead of exposing raw system messages, the secure implementation returns generic responses.

```python
except Exception:
    return {"error": "An internal execution error occurred"}
```

Verbose errors should be written to internal logging systems rather than returned to clients.

---

# 🔄 Secure Workflow

```
📥 Client Request
       │
       ▼
🌐 Receive IP Parameter
       │
       ▼
✅ Validate Input
       │
       ▼
📦 Create Argument List
       │
       ▼
⚙️ subprocess.run(shell=False)
       │
       ▼
⏱️ Execution Timeout
       │
       ▼
📤 Capture Output
       │
       ▼
📄 Return Sanitized JSON Response
```

---

# 💻 Example API Usage

## Request

```
GET /api/diagnose?ip=8.8.8.8
```

### ✅ Successful Response

```json
{
  "exit_code": 0,
  "output": "PING 8.8.8.8 ..."
}
```

### ❌ Invalid Input

```
GET /api/diagnose?ip=8.8.8.8;ls
```

```json
{
  "error": "Invalid characters detected"
}
```

### ⚠️ Missing Parameter

```
GET /api/diagnose
```

```json
{
  "error": "Missing 'ip' parameter"
}
```

### ⏳ Timeout Response

```json
{
  "error": "Ping command timed out"
}
```

---

# 🛠️ Security Best Practices Applied

- ✅ Removed `os.system()`
- ✅ Disabled shell execution using `shell=False`
- ✅ Used structured argument lists
- ✅ Validated user input with an allow-list regex
- ✅ Enforced command execution timeout
- ✅ Captured command output safely
- ✅ Returned sanitized error messages
- ✅ Reduced attack surface against command injection
- ✅ Improved resilience against denial-of-service attacks

---

# 📚 CWE References

| CWE ID | Vulnerability | Severity |
|---------|---------------|----------|
| CWE-78 | OS Command Injection | 🔴 Critical |
| CWE-78 | Dangerous Shell Execution | 🟠 High |
| CWE-400 | Uncontrolled Resource Consumption | 🟡 Medium |
| CWE-20 | Improper Input Validation | 🟡 Medium |
| CWE-117 | Information Exposure Through Error Messages | 🔵 Low |

---

# 🎯 Conclusion

The secure implementation significantly improves the application's security posture by eliminating shell-based command execution, validating user input, enforcing execution timeouts, and preventing sensitive information leakage.

By following secure coding best practices, the application is now far more resilient against command injection, denial-of-service attacks, and reconnaissance attempts.
