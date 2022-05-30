import sys
import os

flag_len = 59

class Hook:
    def __getitem__(self, idx):
        if isinstance(idx, slice):
            return self
        elif idx >= len(self):
            raise IndexError("xxx")

        print(f"Access of index: {idx}")
        return self

    def __and__(self, operand):
        print(f"Bitwise and with: {operand}")
        return self

    def __eq__(self, other):
        print(f"Equality comparison with: {other}")
        return True

    def __len__(self):
        return flag_len

import chall
chall.check_flag(Hook())
