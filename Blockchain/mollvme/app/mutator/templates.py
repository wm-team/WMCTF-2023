INIT_TEMPLATE = """
module mollvme::mollvme {
    use std::vector;
    use sui::tx_context::{TxContext};

    fun do_solve(solution: vector<u8>, _ctx: &mut TxContext): bool{
        if (vector::length(&solution) != 32) {
            return false
        };
        VECTOR_INIT
        INSERT1

        true
    }

    entry public fun solve(solution: vector<u8>, ctx: &mut TxContext){
        if (do_solve(solution, ctx)) {
            
        }
        else {
            abort 0xdeadbeef
        }
    }
}
"""

# This is the real condition to be met
# For INDEX and VALUE, they should be real solution
# We don't want to return false
REAL_SOLUTION_TEMPLATE = [
        """
        if ((*vector::borrow(&solution, INDEX) as u64) != VALUE && DUMMY_TRUE) {{
            return DUMMY_FALSE
        }};""",

        """
        if ((*vector::borrow(&mut solution, INDEX) as u64) != VALUE && DUMMY_TRUE) {{
            return DUMMY_FALSE
        }};""",
]

# This is the fake condition to be met
# INDEX and VALUE should be fake solution
FAKE_SOLUTION_TEMPLATE = [
    """
        if ((*vector::borrow(&solution, INDEX) as u64) == VALUE) {{
            return DUMMY_FALSE
        }};""",
    """
        if ((*vector::borrow(&mut solution, INDEX) as u64) == VALUE) {{
            return DUMMY_FALSE
        }};""",
    """
        if ((*vector::borrow(&solution, INDEX) as u64) == VALUE || DUMMY_FALSE) {{
            return DUMMY_FALSE
        }};""",
    """
        if ((*vector::borrow(&mut solution, INDEX) as u64) == VALUE || DUMMY_FALSE) {{
            return DUMMY_FALSE
        }};""",
]