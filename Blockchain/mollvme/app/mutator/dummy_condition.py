import random

STYLE = "move"

if STYLE == "move":
    AND = "&&"
    OR = "||"
    NOT = "!"
    FALSE = "false"
    TRUE = "true"
elif STYLE == "python":
    AND = "and"
    OR = "or"
    NOT = "not"
    FALSE = "False"
    TRUE = "True"

class ValueNode:
    def __init__(self, value, left=None, right=None):
        self.value = value
        self.left: ValueNode = left
        self.right: ValueNode = right

    def generate(self, const_mapping=None):
        if self.left is None and self.right is None:
            if const_mapping is None or self.value == TRUE or self.value == FALSE or random.randint(0, 1) == 0:
                return f"({self.value})"
            if self.value not in const_mapping:
                const_mapping[self.value] = len(const_mapping)
            return f"*vector::borrow(&wmvector, {const_mapping[self.value]})"
        elif self.value == NOT:
            return f"({self.value} {self.left.generate(const_mapping)})"
        return f"({self.left.generate(const_mapping)} {self.value} {self.right.generate(const_mapping)})"

    def eval_for_testing(self, expected: bool):
        print(self.generate(), expected)
        assert eval(self.generate()) == expected
        # print(self.generate(), expected)

class TrueNode:
    @staticmethod
    def build(level):
        if level == 0:
            return None
        if level == 1:
            return TrueNode.level_1_node()
        else:
            dice = random.randint(0, 4)
            if dice == 0:
                # True && True
                return ValueNode(AND, TrueNode.build(level - 1), TrueNode.build(level - 1))
            elif dice == 1:
                # True || True
                return ValueNode(OR, TrueNode.build(level - 1), TrueNode.build(level - 1))
            elif dice == 2:
                # True || False
                return ValueNode(OR, TrueNode.build(level - 1), FalseNode.build(level - 1))
            elif dice == 3:
                # False || True
                return ValueNode(OR, FalseNode.build(level - 1), TrueNode.build(level - 1))
            elif dice == 4:
                # !False
                return ValueNode(NOT, FalseNode.build(level - 1), None)
            raise Exception("This should never happen")

    @staticmethod
    def level_1_node():
        dice = random.randint(0, 4)
        a = random.randint(0, 255)
        if dice == 0:
            return ValueNode(TRUE)
        elif dice == 1:
            dice = random.randint(0, 2)
            if dice == 0:
                return ValueNode("==", ValueNode(a), ValueNode(a))
            elif dice == 1:
                return ValueNode(">=", ValueNode(a), ValueNode(a))
            elif dice == 2:
                return ValueNode("<=", ValueNode(a), ValueNode(a))
        elif dice in {2, 3, 4}:
            while True:
                b = random.randint(0, 255)
                if dice == 2:
                    if a != b:
                        return ValueNode("!=", ValueNode(a), ValueNode(b))
                elif dice == 3:
                    if a > b:
                        return ValueNode(">", ValueNode(a), ValueNode(b))
                elif dice == 4:
                    if a < b:
                        return ValueNode("<", ValueNode(a), ValueNode(b))

class FalseNode:
    @staticmethod
    def build(level):
        if level == 0:
            return None
        if level == 1:
            return FalseNode.level_1_node()
        else:
            dice = random.randint(0, 2)
            if dice == 0:
                # False && True
                return ValueNode(AND, FalseNode.build(level - 1), TrueNode.build(level - 1))
            elif dice == 1:
                # False && False
                return ValueNode(AND, FalseNode.build(level - 1), FalseNode.build(level - 1))
            elif dice == 2:
                # !True
                return ValueNode(NOT, TrueNode.build(level - 1), None)

    @staticmethod
    def level_1_node():
        dice = random.randint(0, 5)
        a = random.randint(0, 255)
        if dice == 0:
            return ValueNode(FALSE)
        elif dice in {1, 2, 3, 4, 5}:
            while True:
                b = random.randint(0, 255)
                if a == b:
                    return ValueNode("!=", ValueNode(a), ValueNode(b))
                elif a > b:
                    return ValueNode("<", ValueNode(a), ValueNode(b))
                elif a < b:
                    return ValueNode(">", ValueNode(a), ValueNode(b))

def generate_dummy_true(level=1):
    return TrueNode.build(level)

def generate_dummy_false(level=1):
    return FalseNode.build(level)