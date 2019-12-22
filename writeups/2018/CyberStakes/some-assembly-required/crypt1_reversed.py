#!/usr/bin/env python3

import requests
import sys

from typing import List


C2_URL = 'http://challenge.acictf.com:7518/c2'
KEY = [ord(c) for c in '75182d613b486cbb9a01c37498676f325759']
KS_KEY = [55, 109, 160, 196, 17, 60, 129, 238, 40, 106, 150, 105, 188, 225,
          250, 111, 172, 86, 126, 35, 141, 145, 120, 8, 136, 100, 27, 81, 53,
          187, 232, 227, 101, 58, 231, 226, 158, 164, 85, 25, 3, 34, 96, 189,
          47, 45, 70, 246, 54, 186, 132, 90, 181, 93, 130, 193, 116, 176, 144,
          33, 122, 24, 7, 80, 167, 118, 251, 4, 104, 243, 209, 113, 62, 57, 63,
          39, 36, 78, 97, 82, 140, 201, 184, 155, 26, 247, 220, 177, 254, 159,
          52, 152, 165, 190, 75, 143, 13, 151, 229, 127, 30, 166, 125, 38, 162,
          169, 207, 239, 154, 19, 123, 244, 114, 223, 22, 11, 68, 168, 185,
          107, 103, 50, 1, 23, 67, 234, 18, 211, 179, 195, 92, 131, 230, 42,
          203, 171, 15, 44, 10, 46, 222, 83, 192, 20, 199, 76, 206, 153, 135,
          205, 161, 221, 191, 64, 216, 142, 138, 156, 14, 252, 212, 66, 119,
          146, 84, 175, 69, 198, 48, 21, 148, 71, 149, 12, 180, 37, 170, 224,
          2, 117, 255, 233, 56, 128, 43, 73, 240, 65, 87, 9, 147, 91, 215, 72,
          124, 182, 32, 110, 210, 31, 77, 213, 245, 174, 99, 241, 51, 29, 183,
          95, 89, 202, 214, 49, 236, 139, 248, 121, 112, 41, 157, 79, 237, 249,
          218, 59, 194, 163, 6, 98, 242, 253, 133, 134, 235, 16, 74, 61, 94,
          219, 217, 178, 108, 228, 208, 173, 204, 200, 5, 102, 0, 88, 115, 197,
          137, 28]


def _crypt1(mem, p0, p1, p2, p3):
  l4 = 0; l5 = 0; l6 = 0; l7 = 0; l8 = 0; l9 = 0; l10 = 0; l11 = 0;
  l12 = 0; l13 = 0; l14 = 0; l15 = 0; l16 = 0; l17 = 0; l18 = 0; l19 = 0;
  l20 = 0; l21 = 0; l22 = 0; l23 = 0; l24 = 0; l25 = 0; l26 = 0; l27 = 0;
  l28 = 0; l29 = 0; l30 = 0; l31 = 0; l32 = 0; l33 = 0; l34 = 0; l35 = 0;
  l36 = 0; l37 = 0; l38 = 0; l39 = 0; l40 = 0; l41 = 0; l42 = 0; l43 = 0;
  l44 = 0; l45 = 0; l46 = 0; l47 = 0; l48 = 0; l49 = 0; l50 = 0; l51 = 0;
  l52 = 0; l53 = 0; l54 = 0; l55 = 0; l56 = 0; l57 = 0; l58 = 0; l59 = 0;
  l60 = 0; l61 = 0; l62 = 0; l63 = 0; l64 = 0; l65 = 0; l66 = 0; l67 = 0;
  l68 = 0; l69 = 0; l70 = 0; l71 = 0; l72 = 0; l73 = 0; l74 = 0; l75 = 0;
  l76 = 0; l77 = 0; l78 = 0; l79 = 0; l80 = 0; l81 = 0; l82 = 0; l83 = 0;
  l84 = 0; l85 = 0; l86 = 0; l87 = 0; l88 = 0; l89 = 0; l90 = 0; l91 = 0;
  l92 = 0; l93 = 0; l94 = 0; l95 = 0

  i0 = p0;
  l34 = i0;
  i0 = p1;
  l45 = i0;
  i0 = p2;
  l56 = i0;
  i0 = p3;
  l67 = i0;
  i0 = 1;
  l89 = i0;
  i0 = l34;
  l9 = i0;
  i0 = l9;
  l5 = i0;
  i0 = 0;
  l7 = i0;
  i0 = l45;
  l10 = i0;
  i0 = l89;
  l11 = i0;
  i0 = 0;
  i1 = l11;
  i0 -= i1;
  l12 = i0;
  i0 = l10;
  i1 = l12;
  i0 += i1;
  l13 = i0;
  i0 = l13;
  l4 = i0;
  i0 = l56;
  l14 = i0;
  i0 = l89;
  l15 = i0;
  i0 = 0;
  i1 = l15;
  i0 -= i1;
  l16 = i0;
  i0 = l14;
  i1 = l16;
  i0 += i1;
  l17 = i0;
  i0 = l17;
  l6 = i0;
  i0 = l89;
  l18 = i0;
  i0 = l18;
  l78 = i0;
  while True:
    i0 = l78;
    l19 = i0;
    i0 = l67;
    l20 = i0;
    i0 = l89;
    l21 = i0;
    i0 = l20;
    i1 = l21;
    i0 += i1;
    l22 = i0;
    i0 = l19;
    i1 = l22;
    i0 = i0 < i1;
    l23 = i0;
    i0 = l23;
    i0 = not i0;
    if i0:
      break
    i0 = l5;
    l24 = i0;
    i0 = l78;
    l25 = i0;
    i0 = l25;
    i1 = 255;
    i0 &= i1;
    l26 = i0;
    i0 = l26;
    i1 = 255;
    i0 &= i1;
    l27 = i0;
    i0 = l24;
    i1 = l27;
    i0 += i1;
    l28 = i0;
    i0 = l28;
    i0 = mem[i0];
    # i0 = i32_load8_s(Z_envZ_memory, (u64)(i0));
    l29 = i0;
    i0 = l29;
    i1 = 255;
    i0 &= i1;
    l30 = i0;
    i0 = l7;
    l31 = i0;
    i0 = l31;
    i1 = 255;
    i0 &= i1;
    l32 = i0;
    i0 = l32;
    i1 = l30;
    i0 += i1;
    l33 = i0;
    i0 = l33;
    i1 = 255;
    i0 &= i1;
    l35 = i0;
    i0 = l35;
    l7 = i0;
    i0 = l5;
    l36 = i0;
    i0 = l78;
    l37 = i0;
    i0 = l37;
    i1 = 255;
    i0 &= i1;
    l38 = i0;
    i0 = l38;
    i1 = 255;
    i0 &= i1;
    l39 = i0;
    i0 = l36;
    i1 = l39;
    i0 += i1;
    l40 = i0;
    i0 = l40;
    i0 = mem[i0];
    # i0 = i32_load8_s(Z_envZ_memory, (u64)(i0));
    l41 = i0;
    i0 = l41;
    l8 = i0;
    i0 = l5;
    l42 = i0;
    i0 = l7;
    l43 = i0;
    i0 = l43;
    i1 = 255;
    i0 &= i1;
    l44 = i0;
    i0 = l42;
    i1 = l44;
    i0 += i1;
    l46 = i0;
    i0 = l46;
    i0 = mem[i0];
    # i0 = i32_load8_s(Z_envZ_memory, (u64)(i0));
    l47 = i0;
    i0 = l5;
    l48 = i0;
    i0 = l78;
    l49 = i0;
    i0 = l49;
    i1 = 255;
    i0 &= i1;
    l50 = i0;
    i0 = l50;
    i1 = 255;
    i0 &= i1;
    l51 = i0;
    i0 = l48;
    i1 = l51;
    i0 += i1;
    l52 = i0;
    i0 = l52;
    i1 = l47;
    mem[i0] = i1;
    # i32_store8(Z_envZ_memory, (u64)(i0), i1);
    i0 = l8;
    l53 = i0;
    i0 = l5;
    l54 = i0;
    i0 = l7;
    l55 = i0;
    i0 = l55;
    i1 = 255;
    i0 &= i1;
    l57 = i0;
    i0 = l54;
    i1 = l57;
    i0 += i1;
    l58 = i0;
    i0 = l58;
    i1 = l53;
    mem[i0] = i1;
    # i32_store8(Z_envZ_memory, (u64)(i0), i1);
    i0 = l4;
    l59 = i0;
    i0 = l78;
    l60 = i0;
    i0 = l59;
    i1 = l60;
    i0 += i1;
    l61 = i0;
    i0 = l61;
    i0 = mem[i0];
    # i0 = i32_load8_s(Z_envZ_memory, (u64)(i0));
    l62 = i0;
    i0 = l62;
    i1 = 255;
    i0 &= i1;
    l63 = i0;
    i0 = l5;
    l64 = i0;
    i0 = l5;
    l65 = i0;
    i0 = l78;
    l66 = i0;
    i0 = l66;
    i1 = 255;
    i0 &= i1;
    l68 = i0;
    i0 = l68;
    i1 = 255;
    i0 &= i1;
    l69 = i0;
    i0 = l65;
    i1 = l69;
    i0 += i1;
    l70 = i0;
    i0 = l70;
    i0 = mem[i0];
    # i0 = i32_load8_s(Z_envZ_memory, (u64)(i0));
    l71 = i0;
    i0 = l71;
    i1 = 255;
    i0 &= i1;
    l72 = i0;
    i0 = l5;
    l73 = i0;
    i0 = l7;
    l74 = i0;
    i0 = l74;
    i1 = 255;
    i0 &= i1;
    l75 = i0;
    i0 = l73;
    i1 = l75;
    i0 += i1;
    l76 = i0;
    i0 = l76;
    i0 = mem[i0];
    # i0 = i32_load8_s(Z_envZ_memory, (u64)(i0));
    l77 = i0;
    i0 = l77;
    i1 = 255;
    i0 &= i1;
    l79 = i0;
    i0 = l72;
    i1 = l79;
    i0 += i1;
    l80 = i0;
    i0 = l80;
    i1 = 255;
    i0 &= i1;
    l81 = i0;
    i0 = l81;
    i1 = 255;
    i0 &= i1;
    l82 = i0;
    i0 = l64;
    i1 = l82;
    i0 += i1;
    l83 = i0;
    i0 = l83;
    i0 = mem[i0];
    # i0 = i32_load8_s(Z_envZ_memory, (u64)(i0));
    l84 = i0;
    i0 = l84;
    i1 = 255;
    i0 &= i1;
    l85 = i0;
    i0 = l63;
    i1 = l85;
    i0 ^= i1;
    l86 = i0;
    i0 = l86;
    i1 = 255;
    i0 &= i1;
    l87 = i0;
    i0 = l6;
    l88 = i0;
    i0 = l78;
    l90 = i0;
    i0 = l88;
    i1 = l90;
    i0 += i1;
    l91 = i0;
    i0 = l91;
    i1 = l87;
    mem[i0] = i1;
    # i32_store8(Z_envZ_memory, (u64)(i0), i1);
    i0 = l78;
    l92 = i0;
    i0 = l92;
    i1 = 1;
    i0 += i1;
    l93 = i0;
    i0 = l93;
    l78 = i0;


def crypt1(pt: List[int]) -> List[int]:
    # "malloc"
    mem = [0 for _ in range(10000)]

    # we store the obfuscated key at the beginng of memory
    mem = KS_KEY + mem[len(KS_KEY):]

    # insert our plaintext immediately after the key
    mem = mem[:256] + pt + mem[256+len(pt):]

    _crypt1(
        mem,     # our shimmed memory
        0,       # starting address of obfuscated key
        256,     # starting address of plaintext
        2048,    # where our result will be written to
        len(pt)  # length of what we are encrypting/decrypting
    )

    res = mem[2048:2048+len(pt)]
    return res


def send_to_c2(msg: str) -> str:
    """Send a string message to the C2 server and get the decrypted  result."""
    msg_as_ord = [ord(c) for c in msg]
    msg_encrypted = crypt1(msg_as_ord)
    resp = requests.post(C2_URL, data=str(msg_encrypted))
    if resp.status_code != 200:
        print('Got status code', resp.status_code)
        return None

    raw_resp = resp._content.decode('utf-8')
    encrypted_list = eval(raw_resp)
    decrypted_list = crypt1(encrypted_list)
    return ''.join([chr(i) for i in decrypted_list])

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print('Must specify what to send to C2', file=sys.stderr)
        sys.exit(1)

    pt = sys.argv[1]
    resp = send_to_c2(pt)
    if resp is None:
       sys.exit(1)

    print('Received response from C2:')
    print(resp)
