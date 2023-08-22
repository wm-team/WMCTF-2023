from templates import *
from dummy_condition import *
from arith_condition import *

import random

class Mutator:
    def __init__(self, solution_len=32):
        self.const_mapping = {}  # value -> vector index
        self.code = INIT_TEMPLATE
        self.real_solution_code = []
        self.fake_solution_code = []
        self.dummy_assignment = []
        
        self.solution_len = solution_len
        self.solution_dict = {}
        self.init_mapping()
        self.init_solution()
    
    def init_mapping(self):
        first_256 = list(range(256))
        random.shuffle(first_256)
        for i in range(256):
            self.const_mapping[first_256[i]] = i

    def init_solution(self):
        self.solution = ""
        for i in range(self.solution_len):
            s = random.randint(0, 255)
            self.solution += "{:02x}".format(s)
            self.solution_dict[i] = s

    def generate_source_code(self) -> str:
        self.generate_real_solutions()
        self.generate_fake_solutions()
        self.generate_dummy_assignment()

        # print(f"Solution: 0x{self.solution}")

        self.replace_vector_init()
        self.replace_insert1()

        return self.code

    def generate_real_solutions(self):
        for i in range(self.solution_len):
            s = "{:02x}".format(self.solution_dict[i])
            dummy_true = generate_sophisticated_dummy_true(
                random.randint(1, 2),
            )
            dummy_false = generate_sophisticated_dummy_false(
                random.randint(1, 2),
            )
            dice = random.randint(0, len(REAL_SOLUTION_TEMPLATE) - 1)
            self.real_solution_code.append(
                    REAL_SOLUTION_TEMPLATE[dice].replace("INDEX", str(i))
                                        .replace("VALUE", f"*vector::borrow(&wmvector, {self.const_mapping[int(s, 16)]})")
                                        .replace("DUMMY_TRUE", dummy_true.generate(self.const_mapping))
                                        .replace("DUMMY_FALSE", dummy_false.generate(self.const_mapping))
                )

    def generate_fake_solutions(self):
        # generate 64 fake solutions
        for i in range(64):
            dummy_true = generate_sophisticated_dummy_true(
                random.randint(1, 2),
            )
            dummy_false = generate_sophisticated_dummy_false(
                random.randint(1, 2),
            )
            dice = random.randint(0, len(FAKE_SOLUTION_TEMPLATE) - 1)
            idx = random.randint(0, 31)
            real_solution = self.solution_dict[idx]
            # generate fake solution that is not equal to real solution
            fake_solution = real_solution
            while fake_solution == real_solution:
                fake_solution = random.randint(0, 255)
            self.fake_solution_code.append(
                    FAKE_SOLUTION_TEMPLATE[dice].replace("INDEX", str(idx))
                                        .replace("VALUE", f"*vector::borrow(&wmvector, {self.const_mapping[fake_solution]})")
                                        .replace("DUMMY_TRUE", dummy_true.generate(self.const_mapping))
                                        .replace("DUMMY_FALSE", dummy_false.generate(self.const_mapping))
                )

    def generate_dummy_assignment(self):
        rand_num = random.randint(0, 5)
        for i in range(16):
            self.dummy_assignment.append(
                f"        let dummy1{i} = {rand_num}; let dummy2{i} = {rand_num + 1}u8; let _dummy3{i} = dummy1{i} << dummy2{i};"
            )

        for i in range(16):
            self.dummy_assignment.append(
                f"        let bummy1{i} = {rand_num}; let bummy2{i} = {rand_num + 1}u8; let _bummy3{i} = bummy1{i} >> bummy2{i};"
            )

    def replace_vector_init(self):
        init_code = """let wmvector = vector::empty<u64>();"""
        '''
        for k, v in self.const_mapping.items():
            init_code += f"""
        vector::push_back(&mut wmvector, {k});"""
        '''
        # sort the const_mapping by value
        for k, v in sorted(self.const_mapping.items(), key=lambda item: item[1]):
            init_code += f"""
        vector::push_back(&mut wmvector, {k});"""
        
        self.code = self.code.replace("VECTOR_INIT", init_code)

    def replace_insert1(self):
        # random.shuffle(self.real_solution_code)
        # random.shuffle(self.fake_solution_code)
        insert1 = self.real_solution_code + self.fake_solution_code + self.dummy_assignment
        random.shuffle(insert1)

        self.code = self.code.replace("INSERT1", "\n".join(insert1))
    
    def get_solution(self):
        return self.solution