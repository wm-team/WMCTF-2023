import subprocess
import json
import re
import requests
import tempfile
import sys
import time

def get_package_id(command):
    try:
        output = subprocess.check_output(command, shell=True, text=True)
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"The command '{command}' failed with error: {e}") from e

    if match := re.search(r'"packageId": String\("([^"]*)"\)', output):
        return match[1]
    else:
        raise ValueError(f"No packageId found in the output of command '{command}'")

def get_bytecode(tmp_dir):
    path = f"{tmp_dir}/build/mollvme/bytecode_modules/mollvme.mv"
    with open(path, "rb") as f:
        bytecode = f.read()
    return bytecode

def new_module():
    print("Setting up environment... (if it takes > 10 seconds, please try again)")
    sys.stdout.flush()
    time.sleep(1)

    r = requests.post("http://sui:13339/gas", json={
        "FixedAmountRequest": {
            "recipient": "0xf791325f117d6a237b1b057692d6cfc3b6bb4db7aa4a69dd8a1f5aae5887b5cc"
        }
    })
    if r.status_code != 201:
        print("Failed to get gas")
        exit(1)

    # create a tmp directory using mkdtemp
    tmp_dir = tempfile.mkdtemp()
    package_id = get_package_id(f"timeout 20 python3 /app/mutator/run.py {tmp_dir}")
    bytecode = get_bytecode(tmp_dir)
    return (package_id, bytecode)
