#!/usr/bin/python3



import asyncio, asyncssh, sys
from pathlib import Path

from twisted.words.im.locals import OFFLINE

#from collections import Counter

#HOSTS = ["10.0.109.33"]
HOSTS = ["10.0.109.34"]
#HOSTS = ["10.0.109.33", "10.0.109.34"]
USER = "oper"
COMMAND = "vbs_ls -l"            # shell command
SSH_KEY = "~/.ssh/id_ed25519" # or None to use agent/ssh-agent



async def run_one(host):
    try:
        async with asyncssh.connect(
            host,
            username=USER,
            connect_timeout=5,
        ) as conn:
            result = await conn.run(COMMAND, check=False)
            return {
                "host": host,
                "rc": result.exit_status,
                "err": result.stderr.strip(),
                "out": result.stdout.strip()
            }
    except (asyncssh.Error, OSError) as e:
        return {"host": host, "rc": 255, "out": "", "err": str(e)}



from collections import defaultdict
async def main():
    results = await asyncio.gather(*(run_one(h) for h in HOSTS))

    for r in results:
        print(r["out"])



if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(130)
