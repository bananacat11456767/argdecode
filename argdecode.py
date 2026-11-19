#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
argdecode.py —— 多层编码 / 古典密码 自动破解工具  v1.1.0

功能:
  1) 编码类: base64/base64url, base32, base16(hex), base58, base85/ascii85,
             URL 编码, HTML 实体, \uXXXX/\xNN 转义, 二进制, 十进制 ASCII,
             八进制, A1Z26, 摩斯电码, 培根密码, 倒序
  2) 古典密码: 凯撒, 仿射, Atbash, ROT13/ROT47, 栅栏(rail fence 两种方向),
             栅栏分组(fence), 列置换(columnar, 关键词/深度穷举),
             维吉尼亚(内置字典 + IC/卡方自动求密钥)
  3) 自动模式: 编码链 BFS + 古典密码单层穷举 + 多层波束搜索(beam search),
             用英文词频/三字母组/关键词/flag 格式综合打分排序

用法示例:
    python argdecode.py "lfxyyjua"
    python argdecode.py -f cipher.txt
    python argdecode.py "bGZ4eXlqdWE=" -m base64
    python argdecode.py "xxx" --layers 3 --beam 40 --top 40
    python argdecode.py "xxx" --keys mykey1,mykey2 --dict keys.txt
    python argdecode.py "xxx" --flag 'flag{'
    python argdecode.py "xxx" --json out.json
    python argdecode.py --list-ops
"""

import argparse
import base64
import binascii
import itertools
import json
import math
import re
import string
import sys
import time
from typing import Callable, Dict, List, Optional, Tuple

VERSION = "1.1.0"
LOWER = string.ascii_lowercase
UPPER = string.ascii_uppercase
CJK_RE = re.compile(r"[\u4e00-\u9fff]")
FLAG_RE = re.compile(r"[A-Za-z0-9_]{2,20}\{[^{}\n]{1,80}\}")
FLAG_FULL_RE = re.compile(r"([A-Za-z0-9_]{2,20})\{([^{}\n]{1,80})\}")

# ----------------------------------------------------------------------------
# 词频 / 评分数据 (自包含，无需第三方库；若装了 wordfreq 会自动增强)
# ----------------------------------------------------------------------------
try:
    from wordfreq import zipf_frequency as _zipf  # type: ignore
    HAS_WORDFREQ = True
except Exception:
    _zipf = None
    HAS_WORDFREQ = False

EN_COMMON = """
the be to of and a in that have it for not on with he as you do at this but his
by from they we say her she or an will my one all would there their what so up
out if about who get which go me when make can like time no just him know take
people into year your good some could them see other than then now look only
come its over think also back after use two how our work first well way even new
want because any these give day most us is are was were been has had did does
flag ctf key pass password secret admin welcome hello world love lucky success
answer question cipher caesar rail fence base vigenere affine atbash reverse
hack hacker group chat join invite member friend happy study school class team
code open enter hint mima jiami jiemi daan nihao woaini jiayou wechat telegram
discord congrats challenge easy hard simple decode encode crypt crypto text
message note read write file data user root login sign token auth secure safe
""".split()

TRIGRAMS = set("""
the and ing ion tio ent ati for her ter hat tha ere ate his con res ver all ons
nce men ith ted ers pro thi wit are ess not ive was ect rea com eve per int est
sta cti ica ist ear ain one our iti wor oul igh und use ues low ery rce lly
""".split())

BIGRAMS = set("""
th he in er an re on at en nd ti es or te of ed is it al ar st to nt ng se ha
as ou io le ve co me de hi ri ro ic ne ea ra ce li ch ll be ma si om ur ca el
ta la ns il wa ly no us si
""".split())

VOWELS = set("aeiou")

BAD_PATTERNS = [
    "qq", "qk", "kq", "vx", "xv", "qx", "xq", "qv", "vq", "jx", "xj", "zx",
    "xz", "vz", "zv", "kv", "vk", "kb", "bk", "bq", "qb", "dq", "qd", "dx", "xd",
    "jj", "kk", "vv", "ww", "yy", "xx", "zz",
]

KNOWN_FLAG_PREFIXES = {
    "flag", "ctf", "pctf", "hack", "key", "answer", "secret", "pass",
    "admin", "nssctf", "ctfshow", "buuctf", "moectf", "dasec", "qwb", "hgame",
}

ZH_COMMON = set("的一是不了人我在有他这中大来上国个到说们为子和你地出道也时"
                "年得就那要下以生会自着去之过家学对可她里后小么心多天而能好都"
                "然没日于起还发成事只作当想看文无开手十用主行方又如前所本见经"
                "头面公同三已老从动两长知民样现分将外但身些与高意进把法此实回"
                "二理美点月明其种声全工己话儿者向情部正名定女问力机给等几很业"
                "最间新什打便位因重被走电四第门相次东政海口使教西再平真听世气"
                "信北少关并内加化由却代军产入先山五太水万市眼体别处总才场师书")

PUNCT_OK = set(string.printable) - set("\x0b\x0c")
ALLOWED_PUNCT = set("{}_-.,!?@#:;'\"()[]/ \n\r\t")
CHAIN_PENALTY = 45.0  # 每多一层解码操作的扣分

# ----------------------------------------------------------------------------
# 基础工具
# ----------------------------------------------------------------------------
if HAS_WORDFREQ:
    from functools import lru_cache

    @lru_cache(maxsize=50000)
    def _zipf_cached(word: str) -> float:
        try:
            return float(_zipf(word, "en"))
        except Exception:
            return 0.0
else:
    def _zipf_cached(word: str) -> float:
        return 0.0


def _letters(t: str) -> str:
    return "".join(c for c in t if c.isalpha())


def _is_letters(t: str) -> bool:
    return bool(t) and all(c.isalpha() for c in t)


_WORDSET: Optional[set] = None


def _word_set() -> set:
    """常用英文词集合：内置词表 + wordfreq 高频词（zipf >= 2.5）。"""
    global _WORDSET
    if _WORDSET is not None:
        return _WORDSET
    ws = {w for w in EN_COMMON if len(w) >= 2}
    if HAS_WORDFREQ:
        try:
            from wordfreq import top_n_list  # type: ignore
            for w in top_n_list("en", 50000):
                if w.isalpha() and len(w) >= 2 and _zipf_cached(w) >= 2.5:
                    ws.add(w)
        except Exception:
            pass
    _WORDSET = ws
    return ws


_SEG_CACHE: Dict[str, Tuple[int, Tuple[str, ...], int]] = {}
_WORD2: Optional[set] = None


def _word2_set() -> set:
    """允许参与切分的两字母词：只收 is/to/of 这类高频词，避免 'ke','th','sx' 拼凑。"""
    global _WORD2
    if _WORD2 is None:
        _WORD2 = {w for w in _word_set() if len(w) == 2 and _zipf_cached(w) >= 4.5}
    return _WORD2


def _segment(token: str) -> Tuple[int, Tuple[str, ...]]:
    """把字母串切成常见单词，返回 (被覆盖的字符数, 词块元组)（最长匹配 DP）。"""
    if token in _SEG_CACHE:
        return _SEG_CACHE[token]
    n = len(token)
    if n == 0 or n > 60:
        return (0, ())
    ws = _word_set()
    cov = [0] * (n + 1)
    strong = [0] * (n + 1)
    cut = [0] * (n + 1)
    for i in range(1, n + 1):
        cov[i] = cov[i - 1]
        strong[i] = strong[i - 1]
        cut[i] = 0
        for L in range(1, min(i, 18) + 1):
            if L == 1:
                if token[i - 1] not in ("a", "i"):
                    continue
                piece = token[i - 1]
            elif L == 2:
                piece = token[i - 2:i]
                if piece not in _word2_set():
                    continue
            else:
                piece = token[i - L:i]
                if piece not in ws:
                    continue
            nc = cov[i - L] + L
            ns = strong[i - L] + (L if _zipf_cached(piece) >= 4.0 else 0)
            if nc > cov[i] or (nc == cov[i] and ns > strong[i]):
                cov[i] = nc
                strong[i] = ns
                cut[i] = L
    pieces: List[str] = []
    i = n
    while i > 0:
        L = cut[i]
        if L == 0:
            i -= 1
        else:
            pieces.append(token[i - L:i])
            i -= L
    pieces.reverse()
    res = (cov[n], tuple(pieces), strong[n])
    if len(_SEG_CACHE) > 200000:
        _SEG_CACHE.clear()
    _SEG_CACHE[token] = res
    return res


def _segment_len(token: str) -> int:
    return _segment(token)[0]


GOOD_SHORT = {"a", "i", "is", "to", "of", "it", "in", "on", "at", "as", "be", "my",
              "me", "we", "he", "no", "so", "up", "us", "do", "go", "if", "by", "or", "an", "am"}


def _good_piece(p: str) -> bool:
    if p in GOOD_SHORT:
        return True
    return len(p) >= 3 and _zipf_cached(p) >= 2.9


def _cjk_count(t: str) -> int:
    return len(CJK_RE.findall(t))


def _print_ratio(t: str) -> float:
    if not t:
        return 0.0
    bad = sum(1 for c in t if c not in PUNCT_OK)
    return 1.0 - bad / len(t)


# ----------------------------------------------------------------------------
# 编码 / 转码操作 (返回 None 表示不适用)
# ----------------------------------------------------------------------------
def b64_decode(t: str, urlsafe: bool = False) -> Optional[str]:
    s = re.sub(r"\s+", "", t)
    if not s or not re.fullmatch(r"[A-Za-z0-9+/=_-]+", s):
        return None
    if urlsafe or ("-" in s or "_" in s):
        s = s.replace("-", "+").replace("_", "/")
    s = s.rstrip("=")
    if len(s) % 4 == 1:
        return None
    s += "=" * (-len(s) % 4)
    try:
        raw = base64.b64decode(s, validate=True)
    except Exception:
        return None
    return _bytes_to_text(raw)


def b32_decode(t: str) -> Optional[str]:
    s = re.sub(r"\s+", "", t).upper()
    if not s or not re.fullmatch(r"[A-Z2-7]+=*", s):
        return None
    s = s.rstrip("=")
    s += "=" * (-len(s) % 8)
    try:
        return _bytes_to_text(base64.b32decode(s))
    except Exception:
        return None


def b16_decode(t: str) -> Optional[str]:
    s = re.sub(r"[\s:]", "", t)
    if len(s) < 4 or len(s) % 2 or not re.fullmatch(r"[0-9a-fA-F]+", s):
        return None
    try:
        return _bytes_to_text(bytes.fromhex(s))
    except Exception:
        return None


B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58_decode(t: str) -> Optional[str]:
    s = t.strip()
    if not s or not all(c in B58_ALPHABET for c in s):
        return None
    num = 0
    for c in s:
        num = num * 58 + B58_ALPHABET.index(c)
    raw = num.to_bytes((num.bit_length() + 7) // 8, "big") if num else b""
    pad = len(s) - len(s.lstrip("1"))
    return _bytes_to_text(b"\x00" * pad + raw)


def b85_decode(t: str) -> Optional[str]:
    """Python b85 (RFC 1924 字母表)"""
    s = t.strip()
    if len(s) < 8 or not re.fullmatch(r"[0-9A-Za-z!#$%&()*+\-;<=>?@^_`{|}~]+", s):
        return None
    try:
        return _bytes_to_text(base64.b85decode(s))
    except Exception:
        return None


def a85_decode(t: str) -> Optional[str]:
    """Adobe ascii85 / base85"""
    s = t.strip()
    if len(s) < 8 or not all(33 <= ord(c) <= 117 for c in s.replace("\n", "")):
        return None
    for adobe in (True, False):
        try:
            out = _bytes_to_text(base64.a85decode(s, adobe=adobe))
            if out:
                return out
        except Exception:
            pass
    return None


def url_decode(t: str) -> Optional[str]:
    if "%" not in t and "+" not in t:
        return None
    from urllib.parse import unquote_plus
    try:
        out = unquote_plus(t)
    except Exception:
        return None
    return out if out != t else None


def html_decode(t: str) -> Optional[str]:
    if "&" not in t or ";" not in t:
        return None
    import html
    try:
        out = html.unescape(t)
    except Exception:
        return None
    return out if out != t else None


def unicode_escape_decode(t: str) -> Optional[str]:
    if "\\u" not in t and "\\x" not in t and "\\U" not in t:
        return None
    try:
        out = t.encode("latin-1", "backslashreplace").decode("unicode_escape")
    except Exception:
        return None
    return out if out != t else None


def bin_decode(t: str) -> Optional[str]:
    s = re.sub(r"\s+", "", t)
    if len(s) < 8 or len(s) % 8 or not re.fullmatch(r"[01]+", s):
        return None
    try:
        raw = bytes(int(s[i:i + 8], 2) for i in range(0, len(s), 8))
    except Exception:
        return None
    out = _bytes_to_text(raw)
    return out if out and _print_ratio(out) > 0.85 else None


def dec_decode(t: str) -> Optional[str]:
    s = t.strip()
    if not re.fullmatch(r"[\d\s,.\-]+", s):
        return None
    nums = re.findall(r"\d+", s)
    if len(nums) < 3 or not all(32 <= int(x) <= 126 for x in nums):
        return None
    try:
        return "".join(chr(int(x)) for x in nums)
    except Exception:
        return None


def oct_decode(t: str) -> Optional[str]:
    s = t.strip()
    nums = re.findall(r"[0-7]{2,3}", s)
    if len(nums) < 3 or not re.fullmatch(r"[0-7\s]+", s):
        return None
    try:
        raw = bytes(int(x, 8) for x in nums)
    except Exception:
        return None
    return _bytes_to_text(raw)


def a1z26_decode(t: str) -> Optional[str]:
    s = t.strip()
    if not re.fullmatch(r"[\d\s,.\-/]+", s):
        return None
    nums = re.findall(r"\d+", s)
    if len(nums) < 2 or not all(1 <= int(x) <= 26 for x in nums):
        return None
    sep = "/" if "/" in s else ("-" if "-" in s else ("." if "." in s else None))
    if sep:
        out = s
        for part in re.split(r"\s+", out):
            toks = [int(x) for x in re.split(r"[,.\-/]", part) if x]
            if not toks:
                continue
            out = out.replace(part, "".join(chr(96 + x) for x in toks))
        return out
    return "".join(chr(96 + int(x)) for x in nums)


MORSE = {
    ".-": "a", "-...": "b", "-.-.": "c", "-..": "d", ".": "e", "..-.": "f",
    "--.": "g", "....": "h", "..": "i", ".---": "j", "-.-": "k", ".-..": "l",
    "--": "m", "-.": "n", "---": "o", ".--.": "p", "--.-": "q", ".-.": "r",
    "...": "s", "-": "t", "..-": "u", "...-": "v", ".--": "w", "-..-": "x",
    "-.--": "y", "--..": "z", ".----": "1", "..---": "2", "...--": "3",
    "....-": "4", ".....": "5", "-....": "6", "--...": "7", "---..": "8",
    "----.": "9", "-----": "0", ".-.-.-": ".", "--..--": ",", "..--..": "?",
    "-..-.": "/", "-....-": "-", ".--.-.": "@", "-...-": "=", ".-.-.": "+",
}


def morse_decode(t: str) -> Optional[str]:
    s = t.strip()
    if not s or not re.fullmatch(r"[.\-/| _]+", s):
        return None
    if not any(c in ".-" for c in s):
        return None
    words = re.split(r"\s*[/|]\s*", s) if ("/" in s or "|" in s) else [s]
    out_words = []
    for w in words:
        if "/" not in s and "|" not in s:
            toks = w.split()
            if len(toks) == 1 and len(toks[0]) > 6:
                return None
            letters = [MORSE.get(x) for x in toks]
        else:
            toks = w.split()
            letters = [MORSE.get(x) for x in toks]
        if letters and all(letters):
            out_words.append("".join(letters))
        else:
            return None
    out = " ".join(out_words)
    return out if out else None


def bacon_decode(t: str) -> Optional[str]:
    s = re.sub(r"[^A-Za-z]", "", t).lower()
    if len(s) < 15 or not re.fullmatch(r"[ab]+", s) or len(s) % 5:
        return None
    out = []
    for i in range(0, len(s), 5):
        out.append(chr(97 + int(s[i:i + 5].replace("a", "0").replace("b", "1"), 2)))
    return "".join(out)


def _bytes_to_text(raw: bytes) -> Optional[str]:
    for enc in ("utf-8", "gbk", "latin-1"):
        try:
            out = raw.decode(enc)
        except Exception:
            continue
        if out and _print_ratio(out) >= 0.85:
            return out
    return None


# ----------------------------------------------------------------------------
# 古典密码
# ----------------------------------------------------------------------------
def caesar(t: str, k: int) -> str:
    out = []
    for ch in t:
        if "a" <= ch <= "z":
            out.append(chr((ord(ch) - 97 + k) % 26 + 97))
        elif "A" <= ch <= "Z":
            out.append(chr((ord(ch) - 65 + k) % 26 + 65))
        else:
            out.append(ch)
    return "".join(out)


def atbash(t: str) -> str:
    out = []
    for ch in t:
        if "a" <= ch <= "z":
            out.append(chr(219 - ord(ch)))
        elif "A" <= ch <= "Z":
            out.append(chr(155 - ord(ch)))
        else:
            out.append(ch)
    return "".join(out)


def affine_dec(t: str, a: int, b: int) -> Optional[str]:
    try:
        a_inv = pow(a, -1, 26)
    except ValueError:
        return None
    out = []
    for ch in t:
        if "a" <= ch <= "z":
            out.append(chr((a_inv * (ord(ch) - 97 - b)) % 26 + 97))
        elif "A" <= ch <= "Z":
            out.append(chr((a_inv * (ord(ch) - 65 - b)) % 26 + 65))
        else:
            out.append(ch)
    return "".join(out)


def rot47(t: str) -> str:
    out = []
    for ch in t:
        o = ord(ch)
        if 33 <= o <= 126:
            out.append(chr(33 + (o - 33 + 47) % 94))
        else:
            out.append(ch)
    return "".join(out)


def rail_encrypt(t: str, r: int) -> str:
    if r <= 1 or r >= len(t):
        return t
    rails = [[] for _ in range(r)]
    row, step = 0, 1
    for ch in t:
        rails[row].append(ch)
        if row == 0:
            step = 1
        elif row == r - 1:
            step = -1
        row += step
    return "".join("".join(x) for x in rails)


def rail_decrypt(t: str, r: int) -> str:
    if r <= 1 or r >= len(t):
        return t
    n = len(t)
    pattern = []
    row, step = 0, 1
    for _ in range(n):
        pattern.append(row)
        if row == 0:
            step = 1
        elif row == r - 1:
            step = -1
        row += step
    cnt = [pattern.count(i) for i in range(r)]
    rails = []
    idx = 0
    for c in cnt:
        rails.append(list(t[idx:idx + c]))
        idx += c
    ptr = [0] * r
    out = []
    for row in pattern:
        out.append(rails[row][ptr[row]])
        ptr[row] += 1
    return "".join(out)


def fence_col_dec(t: str, k: int) -> str:
    """按 k 列分组写出、逐列读出的栅栏变体(解密)"""
    n = len(t)
    if k <= 1 or k >= n:
        return t
    rows = (n + k - 1) // k
    extra = n % k
    cols = []
    idx = 0
    for i in range(k):
        ln = rows if (extra == 0 or i < extra) else rows - 1
        cols.append(t[idx:idx + ln])
        idx += ln
    out = []
    for r in range(rows):
        for i in range(k):
            if r < len(cols[i]):
                out.append(cols[i][r])
    return "".join(out)


def fence_col_enc(t: str, k: int) -> str:
    n = len(t)
    if k <= 1 or k >= n:
        return t
    rows = [t[i:i + k] for i in range(0, n, k)]
    return "".join("".join(r[i] for r in rows if i < len(r)) for i in range(k))


def columnar_decrypt(t: str, perm: List[int]) -> str:
    n = len(t)
    ncols = len(perm)
    rows = (n + ncols - 1) // ncols
    extra = n % ncols or ncols
    cols: List[str] = [""] * ncols
    idx = 0
    for c in perm:
        ln = rows if c < extra else rows - 1
        cols[c] = t[idx:idx + ln]
        idx += ln
    out = []
    for r in range(rows):
        for c in range(ncols):
            if r < len(cols[c]):
                out.append(cols[c][r])
    return "".join(out)


def columnar_key_perm(key: str) -> List[int]:
    return [i for i, _ in sorted(enumerate(key), key=lambda x: (x[1].lower(), x[0]))]


def vigenere_dec(t: str, key: str) -> str:
    k = [ord(c.lower()) - 97 for c in key if c.isalpha()]
    if not k:
        return t
    out = []
    ki = 0
    for ch in t:
        if "a" <= ch <= "z":
            out.append(chr((ord(ch) - 97 - k[ki % len(k)]) % 26 + 97))
            ki += 1
        elif "A" <= ch <= "Z":
            out.append(chr((ord(ch) - 65 - k[ki % len(k)]) % 26 + 65))
            ki += 1
        else:
            out.append(ch)
    return "".join(out)


EN_FREQ = {
    "a": 8.167, "b": 1.492, "c": 2.782, "d": 4.253, "e": 12.702, "f": 2.228,
    "g": 2.015, "h": 6.094, "i": 6.966, "j": 0.153, "k": 0.772, "l": 4.025,
    "m": 2.406, "n": 6.749, "o": 7.507, "p": 1.929, "q": 0.095, "r": 5.987,
    "s": 6.327, "t": 9.056, "u": 2.758, "v": 0.978, "w": 2.360, "x": 0.150,
    "y": 1.974, "z": 0.074,
}


def _ic(seq: str) -> float:
    n = len(seq)
    if n < 2:
        return 0.0
    freq = {}
    for c in seq:
        freq[c] = freq.get(c, 0) + 1
    return sum(v * (v - 1) for v in freq.values()) / (n * (n - 1))


def _best_shift(seq: str) -> int:
    n = len(seq)
    if not n:
        return 0
    best, best_chi = 0, float("inf")
    for shift in range(26):
        chi = 0.0
        counts = [0] * 26
        for ch in seq:
            counts[(ord(ch) - 97 - shift) % 26] += 1
        for i in range(26):
            expected = EN_FREQ[chr(97 + i)] / 100.0 * n
            diff = counts[i] - expected
            chi += diff * diff / (expected + 1e-9)
        if chi < best_chi:
            best_chi, best = chi, shift
    return best


def vigenere_auto(t: str, max_keylen: int = 16) -> List[Tuple[str, str]]:
    """IC 估密钥长度 + 卡方求每个位置的位移"""
    letters = [c.lower() for c in t if c.isalpha()]
    n = len(letters)
    if n < 6:
        return []
    max_keylen = max(1, min(max_keylen, n // 3))
    scored = []
    for L in range(1, max_keylen + 1):
        cols = ["".join(letters[i] for i in range(j, n, L)) for j in range(L)]
        avg_ic = sum(_ic(c) for c in cols) / L if L else 0.0
        scored.append((avg_ic, L))
    scored.sort(reverse=True)
    lengths = [L for ic, L in scored[:4] if ic > 0.052] or [scored[0][1]]
    out = []
    seen = set()
    for L in lengths:
        key = []
        for j in range(L):
            col = "".join(letters[i] for i in range(j, n, L))
            key.append(chr(97 + _best_shift(col)))
        k = "".join(key)
        if k in seen:
            continue
        seen.add(k)
        out.append((k, vigenere_dec(t, k)))
    return out


# ----------------------------------------------------------------------------
# 评分
# ----------------------------------------------------------------------------
class Scorer:
    def __init__(self, keywords: List[str], flag_pat: Optional[str] = None):
        self.keywords = {}
        base = list(EN_COMMON)
        for w in base:
            if len(w) >= 3:
                self.keywords[w] = 120.0 + 45.0 * len(w)
        for w in keywords:
            w = w.strip().lower()
            if w:
                self.keywords[w] = 900.0 + 80.0 * len(w)
        self.flag_pat = flag_pat
        if flag_pat:
            self.flag_re = re.compile(r"(%s)[^{}\n]{0,80}\}" % re.escape(flag_pat))
        else:
            self.flag_re = FLAG_RE

    def score(self, t: str) -> float:
        if not t:
            return -1e9
        n = len(t)
        s = 0.0
        bad = sum(1 for c in t if c not in PUNCT_OK)
        s -= bad * 60.0
        if bad > n * 0.25:
            return -1e9 + n
        weird = sum(1 for c in t if (not c.isalnum()) and c not in ALLOWED_PUNCT)
        s -= weird * 300.0
        if weird > n * 0.25:
            return -1e9 + n

        if m := FLAG_FULL_RE.search(t):
            prefix, inner = m.group(1), m.group(2)
            pl = prefix.lower()
            pz = _zipf_cached(pl)
            if pl in KNOWN_FLAG_PREFIXES or pz >= 3.0:
                s += 30000.0
            elif "ctf" in pl or "flag" in pl:
                s += 20000.0
            else:
                s += 1500.0
            toks = [x for x in re.findall(r"[a-z]+", inner.lower()) if len(x) >= 3]
            if toks:
                s += 3000.0 * sum(_zipf_cached(x) for x in toks) + 10.0 * len(inner)
        if self.flag_pat and self.flag_pat in t:
            s += 150000.0

        low = t.lower()
        cjk = _cjk_count(t)
        if cjk:
            common = sum(1 for c in t if c in ZH_COMMON)
            s += 90.0 * common - 12.0 * (cjk - common)
            for w, wt in self.keywords.items():
                if w in low:
                    s += wt
            return s

        letters = sum(1 for c in low if "a" <= c <= "z")
        if letters == 0:
            return s - 200.0

        for w, wt in self.keywords.items():
            if w in low:
                s += wt

        for i in range(n - 2):
            if low[i:i + 3] in TRIGRAMS:
                s += 55.0
        for i in range(n - 1):
            if low[i:i + 2] in BIGRAMS:
                s += 7.0
            if low[i] == low[i + 1] and low[i].isalpha():
                s -= 25.0

        vowels = sum(1 for c in low if c in VOWELS)
        ratio = vowels / letters
        s -= abs(ratio - 0.385) * 420.0

        for b in BAD_PATTERNS:
            if b in low:
                s -= 260.0

        s -= low.count("q") * 6.0 + low.count("x") * 5.0 + low.count("z") * 9.0

        # 单词切分：干净切分且词越常用加分越多；带乱码碎片的重罚
        if letters >= 3 and n <= 200:
            for tok in re.findall(r"[a-z]{3,}", low):
                matched, pieces, strong = _segment(tok)
                junk = len(tok) - matched
                if junk > 0:
                    s -= 260.0 * junk
                elif 1 <= len(pieces) <= 3 and all(_good_piece(p) for p in pieces):
                    # 整串由 1~3 个常见词拼成，才最像"人写的答案"
                    s += 500.0 + 55.0 * len(tok)

        # 长度 3~9 的字母串，若有常见单词整体命中给额外奖励
        for w, wt in self.keywords.items():
            if len(w) >= 4 and w in low and len(low) <= 40:
                s += wt * 0.4

        if HAS_WORDFREQ and n <= 60 and weird == 0 and re.fullmatch(r"[a-z ]+", low):
            f = _zipf_cached(low)
            if f > 0:
                s += f * 380.0

        if len(set(low)) <= 3:
            s -= 240.0
        return s


# ----------------------------------------------------------------------------
# 操作注册表
# ----------------------------------------------------------------------------
def _codec_ops() -> List[Tuple[str, Callable[[str], Optional[str]]]]:
    return [
        ("base64", b64_decode),
        ("base64url", lambda t: b64_decode(t, urlsafe=True)),
        ("base32", b32_decode),
        ("hex", b16_decode),
        ("base58", b58_decode),
        ("base85", b85_decode),
        ("ascii85", a85_decode),
        ("url", url_decode),
        ("html", html_decode),
        ("unicode_escape", unicode_escape_decode),
        ("binary", bin_decode),
        ("decimal", dec_decode),
        ("octal", oct_decode),
        ("a1z26", a1z26_decode),
        ("morse", morse_decode),
        ("bacon", bacon_decode),
        ("rot13", lambda t: _rot13(t)),
        ("reverse", lambda t: t[::-1]),
    ]


def _rot13(t: str) -> Optional[str]:
    out = caesar(t, 13)
    return out if out != t else None


def codec_chain(raw: str, depth: int, limit: int) -> Dict[str, str]:
    results: Dict[str, str] = {raw: "input"}
    frontier: List[Tuple[str, str]] = [(raw, "input")]
    ops = _codec_ops()
    for _ in range(max(0, depth - 1)):
        nxt: List[Tuple[str, str]] = []
        for text, chain in frontier:
            for name, fn in ops:
                try:
                    out = fn(text)
                except Exception:
                    continue
                if not out or out == text or out in results:
                    continue
                results[out] = chain + " -> " + name
                nxt.append((out, results[out]))
                if len(results) >= limit:
                    return results
        frontier = nxt[:200]
        if not frontier:
            break
    return results


def static_cipher_ops(cfg) -> List[Tuple[str, Callable[[str], Optional[str]]]]:
    ops: List[Tuple[str, Callable[[str], Optional[str]]]] = []
    for k in range(1, 26):
        ops.append((f"caesar{k:+d}", lambda t, k=k: caesar(t, k)))
    coprime = [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25]
    for a in coprime:
        for b in range(26):
            ops.append((f"affine(a={a},b={b})", lambda t, a=a, b=b: affine_dec(t, a, b)))
    ops.append(("atbash", atbash))
    ops.append(("reverse", lambda t: t[::-1]))
    ops.append(("rot13", lambda t: caesar(t, 13)))
    ops.append(("rot47", rot47))
    maxr = cfg.max_rails
    for r in range(2, maxr + 1):
        ops.append((f"rail_dec{r}", lambda t, r=r: rail_decrypt(t, r)))
    for r in range(2, maxr + 1):
        ops.append((f"rail_enc{r}", lambda t, r=r: rail_encrypt(t, r)))
    for k in range(2, maxr + 1):
        ops.append((f"fence_dec{k}", lambda t, k=k: fence_col_dec(t, k)))
    for k in range(2, maxr + 1):
        ops.append((f"fence_enc{k}", lambda t, k=k: fence_col_enc(t, k)))
    for key in cfg.vigenere_keys:
        ops.append((f"vigenere({key})", lambda t, key=key: vigenere_dec(t, key)))
    return ops


def beam_ops(cfg) -> List[Tuple[str, Callable[[str], Optional[str]]]]:
    ops: List[Tuple[str, Callable[[str], Optional[str]]]] = []
    for k in range(1, 26):
        ops.append((f"caesar{k:+d}", lambda t, k=k: caesar(t, k)))
    ops.append(("atbash", atbash))
    ops.append(("reverse", lambda t: t[::-1]))
    ops.append(("rot13", lambda t: caesar(t, 13)))
    ops.append(("rot47", rot47))
    maxr = min(cfg.max_rails, 8)
    for r in range(2, maxr + 1):
        ops.append((f"rail_dec{r}", lambda t, r=r: rail_decrypt(t, r)))
    for r in range(2, maxr + 1):
        ops.append((f"rail_enc{r}", lambda t, r=r: rail_encrypt(t, r)))
    for k in range(2, maxr + 1):
        ops.append((f"fence_dec{k}", lambda t, k=k: fence_col_dec(t, k)))
    for key in cfg.vigenere_keys:
        ops.append((f"vigenere({key})", lambda t, key=key: vigenere_dec(t, key)))
    return ops


DEFAULT_VIGENERE_KEYS = [
    "key", "flag", "arg", "love", "cipher", "caesar", "rail", "fence", "secret",
    "qun", "ruqun", "jiayou", "woaini", "mima", "jiami", "jiemi", "daan", "hint",
    "password", "admin", "welcome", "hello", "world", "group", "chat", "code",
    "open", "enter", "answer", "ctf", "crypto", "simple", "easy", "abc", "test",
]


# ----------------------------------------------------------------------------
# 主流程
# ----------------------------------------------------------------------------
class Config:
    def __init__(self, args):
        self.layers = args.layers
        self.beam = args.beam
        self.top = args.top
        self.codec_depth = args.codec_depth
        self.codec_limit = args.codec_limit
        self.max_rails = args.max_rails
        self.deep = args.deep
        self.vigenere_keys = list(DEFAULT_VIGENERE_KEYS)
        if args.keys:
            for k in re.split(r"[,;]", args.keys):
                k = k.strip()
                if k and k not in self.vigenere_keys:
                    self.vigenere_keys.append(k)
        if args.dict:
            try:
                with open(args.dict, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        k = line.strip()
                        if k and k.isalpha() and k not in self.vigenere_keys:
                            self.vigenere_keys.append(k)
            except OSError as e:
                print(f"[!] 读取字典失败: {e}", file=sys.stderr)


def _add(results: Dict[str, Tuple[float, str]], text: Optional[str], chain: str,
         scorer: Scorer) -> None:
    if not text:
        return
    sc = scorer.score(text)
    # 每多一层操作扣分：能一步解出来的永远优先于绕四步的偶然巧合
    sc -= CHAIN_PENALTY * chain.count(" -> ")
    old = results.get(text)
    if old is None or sc > old[0]:
        results[text] = (sc, chain)


def _as_bytes(t: str) -> Optional[bytes]:
    s = re.sub(r"\s+", "", t)
    if len(s) >= 8 and len(s) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", s):
        try:
            return bytes.fromhex(s)
        except Exception:
            return None
    st = t.strip()
    if len(st) >= 8 and re.fullmatch(r"[A-Za-z0-9+/=_-]+", st):
        try:
            st2 = st.replace("-", "+").replace("_", "/")
            st2 += "=" * (-len(st2) % 4)
            return base64.b64decode(st2)
        except Exception:
            return None
    return None


def single_byte_xor(text: str, chain: str, results: Dict[str, Tuple[float, str]],
                    scorer: Scorer) -> None:
    raw = _as_bytes(text)
    if not raw or not (4 <= len(raw) <= 400):
        return
    for k in range(1, 256):
        out = bytes(b ^ k for b in raw)
        txt = _bytes_to_text(out)
        if txt:
            _add(results, txt, f"{chain} -> xor(0x{k:02x})", scorer)


def single_crack(text: str, chain: str, results: Dict[str, Tuple[float, str]],
                 cfg: Config, scorer: Scorer) -> None:
    for name, fn in static_cipher_ops(cfg):
        try:
            out = fn(text)
        except Exception:
            continue
        if out and out != text:
            _add(results, out, chain + " -> " + name, scorer)

    # 单字节异或
    single_byte_xor(text, chain, results, scorer)

    # 维吉尼亚自动求密钥
    try:
        for key, out in vigenere_auto(text):
            _add(results, out, f"{chain} -> vigenere_auto({key})", scorer)
    except Exception:
        pass

    # 列置换穷举
    if cfg.deep and 4 <= len(text) <= 80:
        n = len(text)
        for ncols in range(2, min(6, n - 1) + 1):
            for perm in itertools.permutations(range(ncols)):
                out = columnar_decrypt(text, list(perm))
                _add(results, out, f"{chain} -> columnar{list(perm)}", scorer)


def beam_search(seeds: List[Tuple[str, str]], cfg: Config, scorer: Scorer,
                results: Dict[str, Tuple[float, str]]) -> None:
    ops = beam_ops(cfg)
    frontier: List[Tuple[float, str, str]] = []
    for text, chain in seeds:
        sc = scorer.score(text)
        frontier.append((sc, text, chain))
        _add(results, text, chain, scorer)
    frontier.sort(key=lambda x: x[0], reverse=True)
    frontier = frontier[: cfg.beam]
    for _ in range(max(1, cfg.layers)):
        cand: Dict[str, Tuple[float, str]] = {}
        for sc, text, chain in frontier:
            for name, fn in ops:
                try:
                    out = fn(text)
                except Exception:
                    continue
                if not out or out == text:
                    continue
                sc2 = scorer.score(out)
                prev = cand.get(out)
                if prev is None or sc2 > prev[0]:
                    cand[out] = (sc2, chain + " -> " + name)
        if not cand:
            break
        for text, (sc, ch) in cand.items():
            _add(results, text, ch, scorer)
        frontier = sorted(((sc, tx, ch) for tx, (sc, ch) in cand.items()),
                          key=lambda x: x[0], reverse=True)[: cfg.beam]


def post_codec(texts: List[str], results: Dict[str, Tuple[float, str]],
               scorer: Scorer, cfg: Config) -> None:
    """密文 -> 编码 的情况：对高分候选再尝试一层编码解码"""
    for text, chain in texts:
        for name, fn in _codec_ops():
            try:
                out = fn(text)
            except Exception:
                continue
            if out and out != text:
                _add(results, out, chain + " -> " + name, scorer)


def solve(raw: str, cfg: Config, scorer: Scorer) -> Dict[str, Tuple[float, str]]:
    results: Dict[str, Tuple[float, str]] = {}
    _add(results, raw, "input", scorer)

    # 1) 编码链
    codec_map = codec_chain(raw, cfg.codec_depth, cfg.codec_limit)
    for text, chain in codec_map.items():
        _add(results, text, chain, scorer)

    # 2) 选择种子: 高分 + 全部纯字母候选
    scored_seeds = sorted(((scorer.score(t), t, ch) for t, ch in codec_map.items()),
                          key=lambda x: x[0], reverse=True)
    seeds: List[Tuple[str, str]] = []
    seen = set()
    for sc, t, ch in scored_seeds:
        if t in seen:
            continue
        seen.add(t)
        seeds.append((t, ch))
        if len(seeds) >= cfg.seed_count:
            break
    for t, ch in codec_map.items():
        if t not in seen and _is_letters(t) and 4 <= len(t) <= 80:
            seen.add(t)
            seeds.append((t, ch))
            if len(seeds) >= cfg.seed_count + 6:
                break

    # 3) 单层穷举 + 多层波束
    for text, chain in seeds:
        single_crack(text, chain, results, cfg, scorer)
    if cfg.layers > 0:
        for text, chain in seeds[: cfg.beam_seeds]:
            beam_search([(text, chain)], cfg, scorer, results)

    # 4) 收尾: 对高分候选再套一层编码
    top_now = sorted(results.items(), key=lambda kv: kv[1][0], reverse=True)[:60]
    post_codec([(t, ch) for t, (sc, ch) in top_now], results, scorer, cfg)
    return results


def format_output(raw: str, results: Dict[str, Tuple[float, str]],
                  elapsed: float, top: int) -> List[str]:
    ranked = sorted(((sc, t, ch) for t, (sc, ch) in results.items()),
                    key=lambda x: x[0], reverse=True)
    lines = []
    lines.append("=" * 78)
    lines.append(f"输入      : {raw!r}")
    lines.append(f"候选总数  : {len(ranked)}    耗时: {elapsed:.2f}s    "
                 f"评分引擎: {'wordfreq' if HAS_WORDFREQ else '内置'}")
    lines.append("=" * 78)
    lines.append(f"{'#':>3}  {'分数':>10}  {'解码链':<44}  结果")
    lines.append("-" * 78)
    for i, (sc, text, chain) in enumerate(ranked[:top], 1):
        show = text if len(text) <= 60 else text[:57] + "..."
        mark = " ★" if FLAG_RE.search(text) else ""
        lines.append(f"{i:>3}  {sc:>10.1f}  {chain[:44]:<44}  {show}{mark}")
    lines.append("-" * 78)

    flags = [(sc, t, ch) for sc, t, ch in ranked if FLAG_RE.search(t)]
    if flags:
        lines.append("")
        lines.append("★ 命中 flag 格式的候选:")
        for sc, text, chain in flags[:10]:
            lines.append(f"   {text}")
            lines.append(f"      <- {chain}")

    lines.append("")
    lines.append("提示: 用 -m <操作> 单独验证，如 -m caesar:5 / -m rail:3 / -m base64")
    return lines


MODE_HELP = """
可用 -m 操作 (参数用冒号分隔):
  base64 | base64url | base32 | hex | base58 | base85 | url | html
  unicode_escape | binary | decimal | octal | a1z26 | morse | bacon | reverse
  caesar:<k> | rot13 | rot47 | atbash | affine:<a>,<b>
  rail:<r> | railenc:<r> | fence:<k> | fenceenc:<k>
  columnar:<关键字> | vigenere:<关键字> | xor:<0x42>
""".strip()


def apply_mode(text: str, mode: str) -> Optional[str]:
    mode = mode.strip()
    name, _, arg = mode.partition(":")
    name = name.lower()
    simple = {
        "base64": b64_decode, "base64url": lambda t: b64_decode(t, True),
        "base32": b32_decode, "hex": b16_decode, "base58": b58_decode,
        "base85": b85_decode, "url": url_decode, "html": html_decode,
        "unicode_escape": unicode_escape_decode, "binary": bin_decode,
        "decimal": dec_decode, "octal": oct_decode, "a1z26": a1z26_decode,
        "morse": morse_decode, "bacon": bacon_decode, "reverse": lambda t: t[::-1],
        "rot13": lambda t: caesar(t, 13), "rot47": rot47, "atbash": atbash,
    }
    if name in simple:
        return simple[name](text)
    try:
        if name == "caesar":
            return caesar(text, int(arg))
        if name == "affine":
            a, b = [int(x) for x in re.split(r"[,\s]+", arg) if x]
            return affine_dec(text, a, b)
        if name == "rail":
            return rail_decrypt(text, int(arg))
        if name == "railenc":
            return rail_encrypt(text, int(arg))
        if name == "fence":
            return fence_col_dec(text, int(arg))
        if name == "fenceenc":
            return fence_col_enc(text, int(arg))
        if name == "columnar":
            return columnar_decrypt(text, columnar_key_perm(arg))
        if name == "vigenere":
            return vigenere_dec(text, arg)
        if name == "xor":
            key = int(arg, 0)
            raw = _as_bytes(text) or text.encode("latin-1", "ignore")
            out = bytes(b ^ key for b in raw)
            return _bytes_to_text(out) or out.decode("latin-1", "replace")
    except Exception:
        return None
    return None


def build_config(args) -> Config:
    cfg = Config(args)
    cfg.seed_count = args.seed_count
    cfg.beam_seeds = args.beam_seeds
    level = getattr(args, "level", "multi")
    if level == "single":
        cfg.layers = 0
    elif level == "deep":
        cfg.layers = max(cfg.layers, 3)
        cfg.deep = True
    return cfg


def read_input(args) -> str:
    if args.file:
        with open(args.file, "rb") as f:
            raw = f.read()
        for enc in ("utf-8", "gbk", "latin-1"):
            try:
                return raw.decode(enc).rstrip("\r\n")
            except Exception:
                continue
        return raw.decode("latin-1", "replace").rstrip("\r\n")
    if args.text == "-":
        try:
            return sys.stdin.read().rstrip("\r\n")
        except Exception:
            return ""
    if args.text is not None:
        return args.text
    return ""


def main(argv=None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    ap = argparse.ArgumentParser(
        description="多层编码 / 古典密码自动破解工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=MODE_HELP + "\n\n示例:\n  python argdecode.py \"lfxyyjua\"\n"
               "  python argdecode.py \"bGZ4eXlqdWE=\" -m base64\n"
               "  python argdecode.py \"xxx\" --layers 3 --top 40",
    )
    ap.add_argument("text", nargs="?", help="待破解的密文")
    ap.add_argument("-f", "--file", help="从文件读取密文")
    ap.add_argument("-m", "--mode", help="只执行指定操作(见下方列表)")
    ap.add_argument("--chain", help="按顺序执行多个操作, 逗号分隔, 如 base64,caesar:5")
    ap.add_argument("--level", choices=["single", "multi", "deep"], default="multi",
                    help="single=只做单层穷举; multi=两层组合(默认); deep=三层+列置换")
    ap.add_argument("--layers", type=int, default=2, help="波束搜索层数(默认2)")
    ap.add_argument("--beam", type=int, default=30, help="波束宽度(默认30)")
    ap.add_argument("--top", type=int, default=20, help="输出候选条数(默认20)")
    ap.add_argument("--seed-count", type=int, default=8, help="参与古典破解的种子数")
    ap.add_argument("--beam-seeds", type=int, default=3, help="参与多层搜索的种子数")
    ap.add_argument("--codec-depth", type=int, default=3, help="编码链最大层数")
    ap.add_argument("--codec-limit", type=int, default=400, help="编码链候选上限")
    ap.add_argument("--max-rails", type=int, default=12, help="栅栏最大栏数")
    ap.add_argument("--keys", help="额外维吉尼亚密钥，逗号分隔")
    ap.add_argument("--dict", help="维吉尼亚密钥字典文件(每行一个)")
    ap.add_argument("--keywords", help="额外关键词，逗号分隔(命中大幅加分)")
    ap.add_argument("--flag", help="flag 前缀，如 flag{ ; 默认匹配任意 xxx{...}")
    ap.add_argument("--json", help="把完整结果写入 JSON 文件")
    ap.add_argument("--deep", action="store_true", help="额外穷举列置换(较慢)")
    ap.add_argument("--all", action="store_true", help="输出全部候选")
    ap.add_argument("--list-ops", action="store_true", help="列出所有可用操作")
    ap.add_argument("-v", "--version", action="version", version="argdecode " + VERSION)
    args = ap.parse_args(argv)

    if args.list_ops:
        print(MODE_HELP)
        print("\n自动搜索包含: 上述全部编码 + 凯撒/仿射/Atbash/ROT/栅栏/列置换/"
              "维吉尼亚(字典+自动) + 多层组合")
        return 0

    raw = read_input(args)
    if not raw:
        ap.print_help()
        return 1

    if args.chain:
        cur = raw
        used = []
        for op in re.split(r"[,;]", args.chain):
            op = op.strip()
            if not op:
                continue
            nxt = apply_mode(cur, op)
            if nxt is None:
                print(f"[!] 第 {len(used) + 1} 步失败: {op}")
                return 2
            used.append(op)
            cur = nxt
        print(cur)
        print(f"\n[链] {' -> '.join(used)}", file=sys.stderr)
        return 0

    if args.mode:
        out = apply_mode(raw, args.mode)
        if out is None:
            print(f"[!] 操作不适用或参数错误: {args.mode}")
            return 2
        print(out)
        return 0

    keywords = []
    if args.keywords:
        keywords = [w.strip() for w in re.split(r"[,;]", args.keywords) if w.strip()]
    scorer = Scorer(keywords, args.flag)
    cfg = build_config(args)

    t0 = time.time()
    results = solve(raw, cfg, scorer)
    elapsed = time.time() - t0

    top = len(results) if args.all else args.top
    for line in format_output(raw, results, elapsed, top):
        print(line)

    if args.json:
        ranked = sorted(((sc, t, ch) for t, (sc, ch) in results.items()),
                        key=lambda x: x[0], reverse=True)
        data = {
            "input": raw,
            "version": VERSION,
            "elapsed": round(elapsed, 3),
            "wordfreq": HAS_WORDFREQ,
            "results": [
                {"rank": i, "score": round(sc, 2), "chain": ch, "text": t,
                 "flag": bool(FLAG_RE.search(t))}
                for i, (sc, t, ch) in enumerate(ranked, 1)
            ],
        }
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        print(f"\n[+] 结果已写入: {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
