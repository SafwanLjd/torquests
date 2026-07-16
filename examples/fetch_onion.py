"""Fetch a v3 onion service over Tor.

The DuckDuckGo onion serves HTTPS; the Tor Project onion serves HTTP. torquests
handles both, so the only difference here is the scheme in the URL.

Run it with:  python examples/fetch_onion.py
"""

import torquests

ADDRESSES = [
    "https://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion",
    "http://2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion/",
]

for url in ADDRESSES:
    response = torquests.get(url, timeout=120)
    print(f"{response.status_code}  {len(response.content):>7} bytes  {url}")
