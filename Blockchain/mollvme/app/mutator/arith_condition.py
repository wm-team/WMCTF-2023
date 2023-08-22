from dummy_condition import *

def rand_add(target):
    a = random.randint(0, target)
    b = target - a
    # return f"{a} + {b}"
    return (a, b)

def rand_sub(target):
    a = random.randint(0, target)
    b = target + a
    # return f"{b} - {a}"
    return (b, a)

def rand_mul(target):
    def get_factor(target):
        # return one factor of target
        factors = []
        for i in range(1, target + 1):
            if target % i == 0:
                factors.append(i)
        return random.choice(factors)
    if target == 0:
        # return f"0 * {random.randint(1, 1337)}"
        return (0, random.randint(1, 1337))
    a = get_factor(target)
    b = target // a
    # return f"{a} * {b}"
    return (a, b)

def rand_div(target):
    if target == 0:
        # return f"0 / {random.randint(1, 1337)}"
        return (0, random.randint(1, 1337))
    a = random.randint(1, target)
    b = target * a
    # return f"{b} / {a}"
    return (b, a)

def rand_mod(target):
    if target == 0:
        a = random.randint(1, 1337)
        # return f"{a} % {a}"
        return (a, a)
    a = random.randint(target + 1, target * 2)
    n = random.randint(1, target)
    b = a * n + target
    # return f"{b} % {a}"
    return (b, a)

def rand_or(target):
    if target == 0:
        return (0, 0)
    # for 0 bits in target, we need 0 in a and 0 in b
    # for 1 bits in target, one of a and b should be 1
    target = bin(target)[2:]
    a = ""
    b = ""
    for c in target:
        if c == "0":
            a += "0"
            b += "0"
        else:
            dice = random.randint(0, 2)
            if dice == 0:
                a += "1"
                b += "0"
            elif dice == 1:
                a += "0"
                b += "1"
            else:
                a += "1"
                b += "1"
    return (int(a, 2), int(b, 2))

def rand_and(target):
    target = bin(target)[2:]
    a = ""
    b = ""
    for c in target:
        if c == "1":
            a += "1"
            b += "1"
        else:
            dice = random.randint(0, 2)
            if dice == 0:
                a += "1"
                b += "0"
            elif dice == 1:
                a += "0"
                b += "1"
            else:
                a += "0"
                b += "0"
    return (int(a, 2), int(b, 2))

def rand_xor(target):
    a = random.randint(0, target)
    b = target ^ a
    return (a, b)


class ArithmeticNode(ValueNode):
    strategies = [
        rand_add,
        rand_sub,
        rand_mul,
        rand_div,
        rand_mod,
        rand_or,
        rand_and,
        rand_xor,
    ]
    OPS = [
        "+",
        "-",
        "*",
        "/",
        "%",
        "|",
        "&",
        "^",
    ]

    def __init__(self, value):
        assert isinstance(value, int)
        dice = random.randint(0, len(self.strategies) - 1)
        self.value = self.OPS[dice]
        (a, b) = self.strategies[dice](value)
        self.left = ValueNode(a)
        self.right = ValueNode(b)

    def eval_for_testing(self, expected: int):
        assert eval(self.generate()) == expected
    
    def generate(self, const_mapping=None):
        return f"({self.left.generate(const_mapping)} {self.value} {self.right.generate(const_mapping)})"

def sophisticate_dummy_node(node: ValueNode):
    if node.value == NOT:
        return node
    if node.left is None and node.right is None:
        return node if node.value in [TRUE, FALSE] else ArithmeticNode(node.value)
    if node.left is not None:
        node.left = sophisticate_dummy_node(node.left)
    if node.right is not None:
        node.right = sophisticate_dummy_node(node.right)
    return node

def generate_sophisticated_dummy_true(level):
    return sophisticate_dummy_node(generate_dummy_true(level))

def generate_sophisticated_dummy_false(level):
    return sophisticate_dummy_node(generate_dummy_false(level))