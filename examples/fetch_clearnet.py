"""Fetch a clearnet URL over Tor and confirm the exit is a Tor relay.

Run it with:  python examples/fetch_clearnet.py
"""

import torquests

response = torquests.get("https://check.torproject.org/api/ip", timeout=60)
data = response.json()

print(f"status   : {response.status_code}")
print(f"is tor   : {data['IsTor']}")
print(f"exit ip  : {data['IP']}")
