class Hook:
    def __init__(self, len_):
        self.len_ = len_

    def __getitem__(self, idx):
        1/0

    def __len__(self):
        return self.len_

import chall

for i in range(0x100):
    try:
        chall.check_flag(Hook(len_=i))
    except ZeroDivisionError:
        print("Flag len:", i)
        break
