#!/usr/bin/python3



import asyncio, asyncssh, sys
from pathlib import Path

from twisted.words.im.locals import OFFLINE

#from collections import Counter

HOSTS = ["10.0.109.33"]
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
    """ Telling the user what's going on, and getting results from hosts """
    print(f"Getting results from hosts, please wait...")
    #results = await asyncio.gather(*(run_one(h) for h in HOSTS)) # this is working
    """----------------------------------------------------------------------"""

    # This section is for development face only. I need to add the proper host when reading from file
    offlinefile = True
    OFFLINE_FILE_NAME = "sessions.txt"  # raw stdout captured once
    if offlinefile:
        text = Path(OFFLINE_FILE_NAME).read_text()
        results = [{
            "host": "10.0.109.33",
            "rc": 0,
            "err": "",
            "out": text,
        }]
    elif not offlinefile:
        results = await asyncio.gather(*(run_one(h) for h in HOSTS))

    print(f"Parsing results...")

    counter = 0

    for r in results:
        for line in r["out"].splitlines():
            filedetails = line.split()
            if filedetails[0] == "Found":
                counter = counter + 1

            if(counter == 2):
                r["host"] = "10.0.109.34"
            #else:
            host = r["host"]

            #print(f"{host} {line}")
    # END OF: This section is for development face only. I need to add the proper host


    unique, seen = [], set()
    host = lasthost = ""

    for r in results:
        for line in r["out"].splitlines():
            host        = r["host"]
            filedetails = line.split()

            if(filedetails[0] != "Found"):
                session     = filedetails[7].split("_", 1)[0]
                #session     = filedetails[7].split("_", 1)[0]

            if((session and session not in seen) and ( filedetails[0] != "Found")):
                if(host == lasthost):
                    counter = counter + 1
                elif(host != lasthost):
                    counter = 0

                lasthost = host

                seen.add(session)
                unique.append(f"{host} {session} {counter}")
             #    unique.append(f"{host} {session}")

    print(f"Number of sessions on {host}: {counter}")
    print("\n".join(unique))

    #print("\n".join(filedetails))



if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(130)
