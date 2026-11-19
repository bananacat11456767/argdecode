# -*- coding: utf-8 -*-
"""argdecode 基础单元测试。

运行：python -m unittest discover -s tests -v
"""
import contextlib
import io
import itertools
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import argdecode as c  # noqa: E402


def columnar_encrypt(t, perm):
    """测试用列置换加密：是 columnar_decrypt 的逆过程。"""
    n = len(t)
    k = len(perm)
    if k <= 1 or k >= n:
        return t
    rows = -(-n // k)
    extra = n % k or k
    cols = [[""] * (rows if i < extra else rows - 1) for i in range(k)]
    row = col = 0
    for ch in t:
        cols[col][row] = ch
        col += 1
        if col == k:
            col = 0
            row += 1
    return "".join("".join(cols[p]) for p in perm)


class CodecTests(unittest.TestCase):
    def test_base64(self):
        self.assertEqual(c.b64_decode("aGVsbG8="), "hello")
        self.assertEqual(c.b64_decode("aGVsbG8"), "hello")  # 缺省 padding 也能解

    def test_base32(self):
        self.assertEqual(c.b32_decode("NBSWY3DP"), "hello")

    def test_hex(self):
        self.assertEqual(c.b16_decode("68656c6c6f"), "hello")

    def test_base58(self):
        self.assertEqual(c.b58_decode("Cn8eVZg"), "hello")

    def test_base85(self):
        self.assertEqual(c.b85_decode("Xk~0{Zy;h}b7eR+"), "hello base85")

    def test_morse(self):
        self.assertEqual(c.morse_decode(".... . .-.. .-.. --- / .-- --- .-. .-.. -.."), "hello world")

    def test_bacon(self):
        self.assertEqual(c.bacon_decode("aabbbaabaaababbababbabbba"), "hello")

    def test_a1z26(self):
        self.assertEqual(c.a1z26_decode("8-5-12-12-15"), "hello")


class CipherTests(unittest.TestCase):
    def test_caesar_roundtrip(self):
        s = "flag{this_is_a_test}"
        for k in range(26):
            self.assertEqual(c.caesar(c.caesar(s, k), -k), s)

    def test_atbash(self):
        self.assertEqual(c.atbash(c.atbash("hello")), "hello")

    def test_rail_roundtrip(self):
        s = "flag{rail_fence_works}"
        for r in range(2, 10):
            self.assertEqual(c.rail_decrypt(c.rail_encrypt(s, r), r), s)

    def test_fence_roundtrip(self):
        s = "flag{fence_groups_ok}"
        for k in range(2, 8):
            self.assertEqual(c.fence_col_dec(c.fence_col_enc(s, k), k), s)

    def test_vigenere(self):
        self.assertEqual(c.vigenere_dec("ifmmp", "b"), "hello")
        self.assertEqual(c.vigenere_dec("IFMMP", "B"), "HELLO")

    def test_columnar_key_perm(self):
        self.assertEqual(c.columnar_key_perm("key"), [1, 0, 2])

    def test_columnar_roundtrip(self):
        s = "flag{columnar_transposition}"
        for perm in itertools.permutations(range(3)):
            self.assertEqual(c.columnar_decrypt(columnar_encrypt(s, list(perm)), list(perm)), s)


class ScorerTests(unittest.TestCase):
    def test_flag_scores_high(self):
        self.assertGreater(c.Scorer([], None).score("flag{hello_world}"), 10000)

    def test_junk_scores_low(self):
        self.assertLess(c.Scorer([], None).score("qwertyuiop"), 0)

    @unittest.skipUnless(c.HAS_WORDFREQ, "需要 wordfreq")
    def test_word_like_beats_junk(self):
        sc = c.Scorer([], None)
        self.assertGreater(sc.score("ilovearg"), sc.score("kethisxq"))


class CliTests(unittest.TestCase):
    def test_list_ops(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = c.main(["--list-ops"])
        self.assertEqual(rc, 0)
        self.assertIn("caesar", buf.getvalue())

    def test_single_mode(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = c.main(["-m", "base64", "aGVsbG8="])
        self.assertEqual(rc, 0)
        self.assertIn("hello", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
