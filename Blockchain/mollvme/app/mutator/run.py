from dummy_condition import *
from arith_condition import *
from mutator import *
from time import sleep
import tempfile
import shutil
import os
import sys

if __name__ == "__main__":
    # get tmp directory from cmd line
    tmp_dir = sys.argv[1]

    mutator = Mutator()
    code = mutator.generate_source_code()
    solution = mutator.get_solution()

    # print solution to stderr
    # print(solution, file=sys.stderr)

    # copy /app/mutator/Move.toml to the tmp directory
    shutil.copy("/app/mutator/Move.toml", tmp_dir)

    # mkdir source in the tmp directory
    os.mkdir(os.path.join(tmp_dir, "sources"))

    # write code to tmp/sources/modules.move
    with open(os.path.join(tmp_dir, "sources", "modules.move"), "w") as f:
        f.write(code)

    # change cwd to tmp directory
    os.chdir(tmp_dir)

    # run the compiler; stderr is redirected to stdout
    os.system("/app/misc/sui move build 2>&1")

    # publish the module
    os.system("/app/misc/sui client publish --gas-budget 10000000000 2>&1")
