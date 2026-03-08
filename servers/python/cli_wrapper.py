
import sys
import os
import json
import asyncio
from ipaddress import IPv4Address, IPv6Address
from datetime import datetime

# Add the server directory to sys.path
sys.path.append(os.path.join(os.path.dirname(__file__), 'pow_captcha_server'))

# Need to make sure we can import from the parent directory structure
sys.path.append(os.path.join(os.path.dirname(__file__)))

from pow_captcha_server.core import POWCaptchaServer
from pow_captcha_server.interfaces import CaptchaValidatedPOW

async def main():
    server = POWCaptchaServer(default_difficulty=10, validity_seconds=300)

    for line in sys.stdin:
        if not line.strip():
            continue

        try:
            cmd = json.loads(line)
            action = cmd.get("action")
            params = cmd.get("params", {})

            if action == "get_challenge":
                ip_str = params.get("ip", "127.0.0.1")
                try:
                    ip = IPv4Address(ip_str)
                except:
                    try:
                        ip = IPv6Address(ip_str)
                    except:
                        ip = IPv4Address("127.0.0.1")

                fingerprint = params.get("fingerprint")

                try:
                    resp = await server.get_challenge(ip, fingerprint)
                    print(json.dumps({"result": {
                        "challenge": resp.challenge,
                        "difficulty": resp.difficulty,
                        "req_id": str(resp.req_id)
                    }}))
                except Exception as e:
                    print(json.dumps({"error": str(e)}))

            elif action == "validate_pow":
                request_data = params.get("request", {})
                ip_str = params.get("ip", "127.0.0.1")
                try:
                    ip = IPv4Address(ip_str)
                except:
                    try:
                        ip = IPv6Address(ip_str)
                    except:
                        ip = IPv4Address("127.0.0.1")

                fingerprint = params.get("fingerprint")

                try:
                    # Construct ValidatedPOW object
                    req = CaptchaValidatedPOW(**request_data)

                    valid = await server.validate_pow(req, ip, fingerprint)
                    print(json.dumps({"result": {"valid": valid}}))
                except Exception as e:
                    print(json.dumps({"error": str(e)}))

            elif action == "set_max_active":
                max_val = params.get("max")
                server.MAX_ACTIVE_CHALLENGES = max_val
                print(json.dumps({"result": {"ok": True}}))

            elif action == "generate_token":
                ip_str = params.get("ip", "127.0.0.1")
                try:
                    ip = IPv4Address(ip_str)
                except:
                    try:
                        ip = IPv6Address(ip_str)
                    except:
                        ip = IPv4Address("127.0.0.1")
                user_agent = params.get("user_agent", "")
                fingerprint = params.get("fingerprint", "")

                token = server.generate_clearance_token(ip, user_agent, fingerprint)
                print(json.dumps({"result": {"token": token}}))

            elif action == "validate_token":
                token = params.get("token", "")
                ip_str = params.get("ip", "127.0.0.1")
                try:
                    ip = IPv4Address(ip_str)
                except:
                    try:
                        ip = IPv6Address(ip_str)
                    except:
                        ip = IPv4Address("127.0.0.1")
                user_agent = params.get("user_agent", "")
                fingerprint = params.get("fingerprint", "")

                valid = server.validate_clearance_token(token, ip, user_agent, fingerprint)
                print(json.dumps({"result": {"valid": valid}}))

            else:
                print(json.dumps({"error": f"Unknown action: {action}"}))

        except json.JSONDecodeError:
            print(json.dumps({"error": "Invalid JSON"}))
        except Exception as e:
            print(json.dumps({"error": f"Unexpected error: {e}"}))

        sys.stdout.flush()

if __name__ == "__main__":
    asyncio.run(main())
