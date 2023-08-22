import os
import time
import subprocess
import sys

from util import new_module

CAPTION = """
██╗    ██╗███╗   ███╗ ██████╗████████╗███████╗
██║    ██║████╗ ████║██╔════╝╚══██╔══╝██╔════╝
██║ █╗ ██║██╔████╔██║██║        ██║   █████╗  
██║███╗██║██║╚██╔╝██║██║        ██║   ██╔══╝  
╚███╔███╔╝██║ ╚═╝ ██║╚██████╗   ██║   ██║     
 ╚══╝╚══╝ ╚═╝     ╚═╝ ╚═════╝   ╚═╝   ╚═╝     
"""

class InvalidInput(Exception):
    pass

difficulty = int(os.environ.get("POW_DIFFICULTY", "0"))
r = os.system(f"python3 /app/server/pow.py ask {difficulty}")

if r != 0:
    print("Failed to solve proof of work")
    exit(1)

print("\n" * 100)
print(CAPTION)
print("You have 10 seconds to solve this challenge")

(module_address, bytecode) = new_module()
start = time.time()
print("Here is the bytecode:")
print(bytecode.hex())

print("Your input:")
try:
    user_input = input()
    # must be in hex format
    user_input = user_input.strip()
    if not user_input.startswith("0x"):
        user_input = f"0x{user_input}"

    # make sure the input is hex
    for c in user_input:
        if c not in "0123456789abcdefABCDEFxX":
            raise InvalidInput()
except InvalidInput:
    print("Invalid input")
    exit(1)
except Exception:
    print("Unknown error")
    exit(1)

end = time.time()
time_taken = end - start
if time_taken > 10:
    print("Too slow!")
    exit(1)

try:
    print("Running your input...")
    sys.stdout.flush()
    out = subprocess.check_output(["/app/misc/sui", "client", "call", "--function", "solve", "--module", "mollvme", "--package", module_address, "--gas-budget", "10000000", "--args", user_input], stderr=subprocess.STDOUT)
    # print(out.decode())
    # we want to find a line of "Status : Success" in the output
    if "Status : Success" in out.decode():
        print("Congrats! You solved the challenge!")
        print("Here is your flag:")
        print(os.environ.get("FLAG", "flag{this_is_a_fake_flag}"))
except subprocess.CalledProcessError as e:
    print("Incorrect input!")
    # print(e.output.decode())
    exit(1)
