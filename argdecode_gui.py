#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""argdecode Web GUI —— 只依赖 Python 标准库。

用法:
    python argdecode_gui.py                 # 默认 127.0.0.1:8765，并自动打开浏览器
    python argdecode_gui.py --port 9000 --no-browser

页面能力:
    * 自动多层破解（single / multi / deep 三档强度）
    * 单操作穷举（凯撒、栅栏、仿射、维吉尼亚、XOR、列置换……全部结果都列出）
    * 手动链式解码（按顺序执行任意操作，逐步查看中间结果）
    * 结果筛选、复制、导出 JSON、只看 flag
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import argdecode as core  # noqa: E402

LEVELS = {
    "single": {"layers": 0, "deep": False},
    "multi": {"layers": 2, "deep": False},
    "deep": {"layers": 3, "deep": True},
}

HTML = r"""<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>argdecode · 解码工作台</title>
<style>
:root{--bg:#0f1117;--panel:#171a23;--panel2:#1d2130;--line:#2a3040;--tx:#e6e9f0;--dim:#8b93a7;--acc:#4f8cff;--ok:#3ddc97;--warn:#ffb454;}
*{box-sizing:border-box}
html,body{height:100%}
body{margin:0;background:radial-gradient(1200px 600px at 20% -10%,#1a2540 0%,var(--bg) 55%);
 color:var(--tx);font:14px/1.65 "Segoe UI","Microsoft YaHei",system-ui,sans-serif}
header{display:flex;align-items:baseline;gap:12px;padding:18px 26px 10px}
header h1{font-size:19px;margin:0;letter-spacing:.5px}
header h1 b{color:var(--acc)}
header .sub{color:var(--dim);font-size:12px}
main{max-width:1180px;margin:0 auto;padding:0 18px 60px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:14px 16px;margin-bottom:14px}
textarea{width:100%;min-height:110px;resize:vertical;background:#0c0f16;color:var(--tx);
 border:1px solid var(--line);border-radius:9px;padding:12px;font:14px/1.5 Consolas,"Microsoft YaHei",monospace;outline:none}
textarea:focus{border-color:var(--acc)}
.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
.row.mt{margin-top:10px}
button{background:var(--panel2);color:var(--tx);border:1px solid var(--line);border-radius:8px;
 padding:7px 14px;cursor:pointer;font-size:13px;transition:.15s}
button:hover{border-color:var(--acc);color:#fff}
button.primary{background:linear-gradient(180deg,#4f8cff,#3a6fe0);border-color:#5f97ff;font-weight:600}
button.primary:hover{filter:brightness(1.1)}
button.small{padding:3px 9px;font-size:12px}
label.file{background:var(--panel2);border:1px dashed var(--line);border-radius:8px;padding:6px 12px;cursor:pointer;font-size:13px;color:var(--dim)}
label.file:hover{color:var(--tx);border-color:var(--acc)}
select,input[type=text],input[type=number]{background:#0c0f16;color:var(--tx);border:1px solid var(--line);
 border-radius:7px;padding:6px 9px;font-size:13px;outline:none}
select:focus,input:focus{border-color:var(--acc)}
.dim{color:var(--dim);font-size:12px}
.tabs{display:flex;gap:6px;margin:16px 0 10px}
.tabs button{border-bottom-left-radius:0;border-bottom-right-radius:0;border-bottom-color:transparent;color:var(--dim)}
.tabs button.active{background:var(--panel);color:var(--tx);border-color:var(--line);border-bottom-color:var(--panel);position:relative;top:1px}
.panel{display:none}
.panel.active{display:block}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:10px 18px;align-items:center}
.field{display:flex;flex-direction:column;gap:4px;font-size:12px;color:var(--dim)}
.hint{background:#12203a;border:1px solid #23396b;color:#9fb6e6;border-radius:8px;padding:7px 11px;font-size:12px;margin-top:10px}
.toolbar{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:10px}
.toolbar .sp{flex:1}
table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:left;color:var(--dim);font-weight:500;font-size:12px;border-bottom:1px solid var(--line);padding:7px 8px;white-space:nowrap}
td{border-bottom:1px solid #202532;padding:7px 8px;vertical-align:top}
tr:hover td{background:#1a1f2b}
td.mono{font-family:Consolas,monospace;word-break:break-all;color:#dfe5f2}
td.score{color:var(--warn);white-space:nowrap;font-variant-numeric:tabular-nums}
td.chain{color:var(--dim);font-size:12px;word-break:break-all;max-width:360px}
.badge{display:inline-block;background:#12351f;color:var(--ok);border:1px solid #1d5c37;border-radius:5px;padding:0 6px;font-size:11px;margin-left:6px}
#msg{margin:10px 2px 0;font-size:13px;min-height:18px}
#msg.err{color:#ff7b7b}
.manual-row{display:flex;gap:8px;align-items:center;margin-bottom:8px}
.manual-row .idx{color:var(--dim);width:22px;text-align:right}
.manual-row select{flex:0 0 200px}
.manual-row input{flex:1}
.steps{margin-top:12px}
.step{display:flex;gap:10px;align-items:flex-start;padding:9px 0;border-bottom:1px dashed #232a3a}
.step .op{color:var(--acc);font-size:12px;min-width:120px;padding-top:2px}
.step .txt{font-family:Consolas,monospace;word-break:break-all}
footer{color:var(--dim);font-size:12px;text-align:center;padding:10px 0 30px}
</style>
</head>
<body>
<header>
  <h1><b>arg</b>decode · 解码工作台</h1>
  <span class="sub">多层编码 / 古典密码 / 手动链式 — 本地离线运行</span>
</header>
<main>
  <section class="card">
    <div class="row">
      <textarea id="text" placeholder="在这里粘贴密文……（Ctrl+Enter 直接开始）"></textarea>
    </div>
    <div class="row mt">
      <label class="file">选择文件…<input type="file" id="file"></label>
      <button id="clear">清空</button>
      <span class="dim" id="meta"></span>
    </div>
  </section>

  <nav class="tabs">
    <button data-tab="auto" class="active">自动多层</button>
    <button data-tab="sweep">单操作穷举</button>
    <button data-tab="manual">手动链式</button>
  </nav>
<div id="msg"></div>

  <section class="card panel active" id="panel-auto">
    <div class="grid">
      <div class="field">破解强度
        <select id="level">
          <option value="single">单层穷举（快，只做一层古典密码）</option>
          <option value="multi" selected>自动多层（默认，两层组合）</option>
          <option value="deep">深度多层（三层 + 列置换，较慢）</option>
        </select>
      </div>
      <div class="field">输出条数
        <select id="top"><option>20</option><option selected>40</option><option>100</option><option>300</option></select>
      </div>
      <div class="field">flag 前缀（可空）
        <input type="text" id="flag" placeholder="如 flag{ 或 ctf{">
      </div>
      <div class="field">提示关键词（可空）
        <input type="text" id="keywords" placeholder="如 mima,ctf,你的id">
      </div>
    </div>
    <div class="row mt"><button class="primary" id="run-auto">开始破解</button>
      <span class="dim">Ctrl+Enter 也可以</span></div>
    <div class="hint">如果原文本身就是一串“对作者有意义、但看起来像乱码”的字符串，自动评分可能不适用：
      请用「手动链式」按你自己的规则逐步解码，或用「单操作穷举」逐个查看全部结果（不依赖评分）。</div>
  </section>

  <section class="card panel" id="panel-sweep">
    <div class="grid">
      <div class="field">操作族
        <select id="family">
          <option value="caesar">凯撒 0~25</option>
          <option value="rail">栅栏（解密方向）2~N</option>
          <option value="railenc">栅栏（加密方向）2~N</option>
          <option value="fence">分组栅栏 2~N</option>
          <option value="affine">仿射（312 组）</option>
          <option value="vigenere">维吉尼亚（内置字典）</option>
          <option value="xor">单字节 XOR 1~255</option>
          <option value="columnar">列置换（2~4 列全排列）</option>
          <option value="atbash">Atbash</option>
          <option value="rot13">ROT13</option>
          <option value="rot47">ROT47</option>
          <option value="reverse">倒序</option>
          <option value="base64">Base64</option>
          <option value="hex">Hex</option>
        </select>
      </div>
      <div class="field">最大栏数
        <input type="number" id="max-rails" value="12" min="2" max="40">
      </div>
      <div class="field">额外维吉尼亚密钥（可空）
        <input type="text" id="sweep-keys" placeholder="逗号分隔">
      </div>
    </div>
    <div class="row mt"><button class="primary" id="run-sweep">全部试一遍</button></div>
  </section>

  <section class="card panel" id="panel-manual">
    <div class="row" style="justify-content:space-between">
      <span class="dim">按顺序执行下列操作；每步都能看到中间结果。</span>
      <button class="small" id="add-op">+ 添加一步</button>
    </div>
    <div id="ops" style="margin-top:12px"></div>
    <div class="row mt"><button class="primary" id="run-manual">执行</button>
      <button class="small" id="ops-example">示例：rot13 → rail:3 → caesar:8</button></div>
    <div class="steps" id="steps"></div>
  </section>

  <section class="card" id="results-card" style="display:none">
    <div class="toolbar">
      <b id="res-title">结果</b>
      <span class="dim" id="res-meta"></span>
      <span class="sp"></span>
      <input type="text" id="filter" placeholder="筛选文本 / 解码链">
      <label class="dim"><input type="checkbox" id="only-flag"> 只看 flag</label>
      <button class="small" id="copy-all">复制全部</button>
      <button class="small" id="export">导出 JSON</button>
    </div>
    <div style="overflow-x:auto">
      <table>
        <thead><tr><th style="width:44px">#</th><th style="width:90px">分数</th><th>解码链</th><th>结果</th><th style="width:60px"></th></tr></thead>
        <tbody id="tbody"></tbody>
      </table>
    </div>
  </section>
</main>
<footer>argdecode GUI v1.1.0 · 数据只在本机处理，不会上传</footer>
<script>
const $ = s => document.querySelector(s);
const $$ = s => document.querySelectorAll(s);
let lastRun = null;

function showTab(name){
  $$('.tabs button').forEach(b => b.classList.toggle('active', b.dataset.tab === name));
  $$('.panel').forEach(p => p.classList.toggle('active', p.id === 'panel-' + name));
}
$$('.tabs button').forEach(b => b.onclick = () => showTab(b.dataset.tab));

function msg(t, isErr){ const m = $('#msg'); m.textContent = t || ''; m.className = isErr ? 'err' : ''; }
function esc(s){ return String(s).replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }

async function api(payload){
  msg('计算中……');
  try {
    const r = await fetch('/api/run', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(payload)});
    return await r.json();
  } catch (e) {
    return {ok:false, error:'请求失败：' + (e && e.message || e)};
  }
}

function renderAuto(data){
  if(!data.ok){ msg(data.error || '失败', true); return; }
  lastRun = {kind:'auto', data};
  msg('');
  $('#results-card').style.display = '';
  $('#res-title').textContent = '破解结果';
  $('#res-meta').textContent = '等级 ' + data.level + ' · 共 ' + data.total + ' 个候选 · 用时 ' + data.elapsed + 's · 评分 ' + data.engine;
  const rows = data.results.map(r => ({score:r.score, chain:r.chain, text:r.text, flag:r.flag}));
  paint(rows);
}

function renderSweep(data){
  if(!data.ok){ msg(data.error || '失败', true); return; }
  lastRun = {kind:'sweep', data};
  msg('');
  $('#results-card').style.display = '';
  $('#res-title').textContent = '穷举结果 · ' + data.family;
  $('#res-meta').textContent = '共 ' + data.count + ' 个结果（按分数排序，可筛选）';
  const rows = data.results.map(r => ({score:r.score, chain:r.label, text:r.text, flag:r.flag}));
  paint(rows);
}

function renderManual(data){
  if(!data.ok){ msg(data.error || '失败', true); }
  lastRun = {kind:'manual', data};
  const box = $('#steps'); box.innerHTML = '';
  (data.steps || []).forEach((st, i) => {
    const div = document.createElement('div'); div.className = 'step';
    div.innerHTML = '<div class="op">' + (i === 0 ? '输入' : esc(st.op)) + '</div><div class="txt">' + esc(st.text) + '</div>';
    box.appendChild(div);
  });
  if(data.ok){ msg('完成，最终结果：' + data.result); } else { msg(data.error, true); }
}

function paint(rows){
  window.__rows = rows;
  const q = ($('#filter').value || '').trim().toLowerCase();
  const onlyFlag = $('#only-flag').checked;
  let shown = rows.filter(r => (!onlyFlag || r.flag) && (!q || r.text.toLowerCase().includes(q) || r.chain.toLowerCase().includes(q)));
  const tb = $('#tbody'); tb.innerHTML = '';
  shown.slice(0, 1000).forEach((r, i) => {
    const tr = document.createElement('tr');
    tr.innerHTML = '<td class="dim">' + (i+1) + '</td>' +
      '<td class="score">' + r.score + '</td>' +
      '<td class="chain">' + esc(r.chain) + '</td>' +
      '<td class="mono">' + esc(r.text) + (r.flag ? '<span class="badge">flag</span>' : '') + '</td>' +
      '<td><button class="small">复制</button></td>';
    tr.querySelector('button').onclick = () => { navigator.clipboard.writeText(r.text); msg('已复制'); };
    tb.appendChild(tr);
  });
}

$('#run-auto').onclick = async () => {
  const text = $('#text').value.replace(/^[\r\n]+|[\r\n]+$/g, '');
  if(!text){ msg('请输入密文', true); return; }
  const data = await api({mode:'auto', text, level:$('#level').value, top:+$('#top').value,
    flag:$('#flag').value.trim(), keywords:$('#keywords').value.trim()});
  renderAuto(data);
};

$('#run-sweep').onclick = async () => {
  const text = $('#text').value.replace(/^[\r\n]+|[\r\n]+$/g, '');
  if(!text){ msg('请输入密文', true); return; }
  const data = await api({mode:'sweep', text, family:$('#family').value,
    max_rails:+$('#max-rails').value, keys:$('#sweep-keys').value.trim()});
  renderSweep(data);
};

const OPS = [
  ['base64','Base64'],['base64url','Base64URL'],['base32','Base32'],['hex','Hex'],
  ['base58','Base58'],['base85','Base85'],['url','URL 编码'],['html','HTML 实体'],
  ['unicode_escape','\\u 转义'],['binary','二进制'],['decimal','十进制'],['octal','八进制'],
  ['a1z26','A1Z26'],['morse','摩斯'],['bacon','培根'],['reverse','倒序'],
  ['rot13','ROT13'],['rot47','ROT47'],['atbash','Atbash'],
  ['caesar','凯撒 caesar:K'],['affine','仿射 affine:A,B'],
  ['rail','栅栏解密 rail:R'],['railenc','栅栏加密 railenc:R'],
  ['fence','分组栅栏 fence:K'],['fenceenc','分组栅栏加密 fenceenc:K'],
  ['columnar','列置换 columnar:KEY'],['vigenere','维吉尼亚 vigenere:KEY'],['xor','XOR xor:0x42']
];

function addRow(op, param){
  const div = document.createElement('div'); div.className = 'manual-row';
  const idx = document.createElement('span'); idx.className = 'idx'; idx.textContent = $('#ops').children.length + 1;
  const sel = document.createElement('select');
  OPS.forEach(([v, label]) => { const o = document.createElement('option'); o.value = v; o.textContent = label; sel.appendChild(o); });
  if(op) sel.value = op;
  const inp = document.createElement('input'); inp.type = 'text'; inp.placeholder = '参数，如 5 / secret / 0x42（无参数留空）'; inp.value = param || '';
  const del = document.createElement('button'); del.className = 'small'; del.textContent = '删除';
  del.onclick = () => { div.remove(); renumber(); };
  div.append(idx, sel, inp, del);
  $('#ops').appendChild(div);
}
function renumber(){ [...$('#ops').children].forEach((d, i) => d.querySelector('.idx').textContent = i + 1); }

$('#add-op').onclick = () => addRow('caesar', '5');
$('#ops-example').onclick = () => {
  $('#ops').innerHTML = '';
  addRow('rot13',''); addRow('rail','3'); addRow('caesar','8');
  $('#text').value = 'k{x_jqlyn_xfyx}fmn_y';
  $('#meta').textContent = '示例密文 · 14 字符';
  msg('已填入示例：rot13 → rail:3 → caesar:8，点「执行」查看每步结果');
};

$('#run-manual').onclick = async () => {
  const text = $('#text').value.replace(/^[\r\n]+|[\r\n]+$/g, '');
  if(!text){ msg('请输入密文', true); return; }
  const ops = [...$('#ops').children].map(d => {
    const sel = d.querySelector('select').value;
    const p = d.querySelector('input').value.trim();
    return p ? sel + ':' + p : sel;
  });
  if(!ops.length){ msg('请先添加至少一步操作', true); return; }
  const data = await api({mode:'manual', text, ops});
  $('#steps').innerHTML = '';
  renderManual(data);
};

$('#filter').oninput = () => { if(window.__rows) paint(window.__rows); };
$('#only-flag').onchange = () => { if(window.__rows) paint(window.__rows); };

$('#copy-all').onclick = () => {
  if(!window.__rows) return;
  navigator.clipboard.writeText(window.__rows.map(r => r.text).join('\n'));
  msg('已复制 ' + window.__rows.length + ' 条结果');
};

$('#export').onclick = () => {
  if(!lastRun) return;
  const blob = new Blob([JSON.stringify(lastRun.data, null, 2)], {type:'application/json'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob); a.download = 'argdecode-result.json'; a.click();
  URL.revokeObjectURL(a.href);
};

$('#clear').onclick = () => { $('#text').value = ''; $('#meta').textContent = ''; };
$('#file').onchange = e => {
  const f = e.target.files[0]; if(!f) return;
  const r = new FileReader();
  r.onload = () => { $('#text').value = String(r.result).replace(/^[\r\n]+|[\r\n]+$/g, ''); $('#meta').textContent = f.name + ' · ' + r.result.length + ' 字符'; };
  r.readAsText(f);
};
document.addEventListener('keydown', e => {
  if((e.ctrlKey || e.metaKey) && e.key === 'Enter'){
    const tab = document.querySelector('.tabs button.active').dataset.tab;
    if(tab === 'auto') $('#run-auto').click();
    else if(tab === 'sweep') $('#run-sweep').click();
    else $('#run-manual').click();
  }
});
addRow('rot13', '');
</script>
</body>
</html>"""


def _cfg(level="multi", beam=30, max_rails=12, keys="", layers=None):
    preset = LEVELS.get(level, LEVELS["multi"])
    args = SimpleNamespace(
        layers=preset["layers"] if layers is None else layers,
        beam=max(1, int(beam)),
        top=1000,
        codec_depth=3,
        codec_limit=400,
        max_rails=max(2, int(max_rails)),
        deep=preset["deep"],
        keys=keys or None,
        dict=None,
        seed_count=8,
        beam_seeds=3,
        level=level,
    )
    return core.build_config(args)


def _scorer(keywords="", flag=""):
    kws = [w.strip() for w in core.re.split(r"[,;]", keywords or "") if w.strip()]
    return core.Scorer(kws, flag or None)


def do_solve(text, level="multi", top=40, beam=30, max_rails=12,
             keys="", keywords="", flag=""):
    scorer = _scorer(keywords, flag)
    cfg = _cfg(level=level, beam=beam, max_rails=max_rails, keys=keys)
    t0 = time.time()
    results = core.solve(text, cfg, scorer)
    elapsed = time.time() - t0
    ranked = sorted(((s, t, c) for t, (s, c) in results.items()),
                    key=lambda x: x[0], reverse=True)
    items = [
        {"rank": i, "score": round(s, 1), "chain": c, "text": t,
         "flag": bool(core.FLAG_RE.search(t))}
        for i, (s, t, c) in enumerate(ranked[: max(1, int(top))], 1)
    ]
    return {"ok": True, "mode": "auto", "level": level,
            "elapsed": round(elapsed, 2), "total": len(ranked),
            "engine": "wordfreq" if core.HAS_WORDFREQ else "builtin",
            "results": items}


def do_manual(text, ops):
    cur = text
    steps = [{"op": "输入", "text": cur}]
    for op in ops:
        op = str(op).strip()
        if not op:
            continue
        nxt = core.apply_mode(cur, op)
        if nxt is None:
            return {"ok": False, "error": "操作失败或参数错误: " + op, "steps": steps}
        steps.append({"op": op, "text": nxt})
        cur = nxt
    return {"ok": True, "mode": "manual", "steps": steps, "result": cur}


def do_sweep(text, family="caesar", max_rails=12, keys=""):
    scorer = _scorer()
    out = []

    def add(label, val):
        if not val or val == text:
            return
        out.append({"label": label, "text": val, "score": round(scorer.score(val), 1),
                    "flag": bool(core.FLAG_RE.search(val))})

    fam = (family or "caesar").lower()
    mr = max(2, int(max_rails))
    if fam == "caesar":
        for k in range(26):
            add("caesar+%d" % k, core.caesar(text, k))
    elif fam == "rail":
        for r in range(2, mr + 1):
            add("rail%d" % r, core.rail_decrypt(text, r))
    elif fam == "railenc":
        for r in range(2, mr + 1):
            add("rail_enc%d" % r, core.rail_encrypt(text, r))
    elif fam == "fence":
        for k in range(2, mr + 1):
            add("fence%d" % k, core.fence_col_dec(text, k))
    elif fam == "affine":
        for a in (1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25):
            for b in range(26):
                add("affine(%d,%d)" % (a, b), core.affine_dec(text, a, b))
    elif fam == "vigenere":
        ks = list(core.DEFAULT_VIGENERE_KEYS)
        for k in core.re.split(r"[,;]", keys or ""):
            k = k.strip()
            if k and k not in ks:
                ks.append(k)
        for k in ks:
            add("vigenere(%s)" % k, core.vigenere_dec(text, k))
    elif fam == "xor":
        hexish = core.re.fullmatch(r"(?:[0-9a-fA-F]{2})+", text or "")
        raw = bytes.fromhex(text) if hexish else (text or "").encode("latin-1", "ignore")
        for k in range(1, 256):
            b = bytes(x ^ k for x in raw)
            t = core._bytes_to_text(b)
            if t:
                add("xor(0x%02x)" % k, t)
    elif fam == "columnar":
        import itertools
        n = len(text)
        for ncols in range(2, min(5, n - 1) + 1):
            for perm in itertools.permutations(range(ncols)):
                add("columnar%s" % list(perm), core.columnar_decrypt(text, list(perm)))
    else:
        simple = {
            "atbash": core.atbash,
            "rot13": lambda t: core.caesar(t, 13),
            "rot47": core.rot47,
            "reverse": lambda t: t[::-1],
            "base64": core.b64_decode,
            "hex": core.b16_decode,
        }
        fn = simple.get(fam)
        if fn is None:
            return {"ok": False, "error": "未知操作族: " + fam}
        add(fam, fn(text))

    out.sort(key=lambda x: x["score"], reverse=True)
    return {"ok": True, "mode": "sweep", "family": fam,
            "count": len(out), "results": out}


def handle_run(data):
    text = str(data.get("text") or "").strip("\r\n")
    if not text:
        return {"ok": False, "error": "请输入密文"}
    mode = data.get("mode") or "auto"
    if mode == "auto":
        return do_solve(text, data.get("level", "multi"), data.get("top", 40),
                        data.get("beam", 30), data.get("max_rails", 12),
                        data.get("keys", ""), data.get("keywords", ""),
                        data.get("flag", ""))
    if mode == "manual":
        ops = data.get("ops") or []
        if not isinstance(ops, list):
            return {"ok": False, "error": "ops 必须是数组"}
        return do_manual(text, ops)
    if mode == "sweep":
        return do_sweep(text, data.get("family", "caesar"),
                        data.get("max_rails", 12), data.get("keys", ""))
    return {"ok": False, "error": "未知模式: " + str(mode)}


class Handler(BaseHTTPRequestHandler):
    server_version = "argdecode-gui"

    def log_message(self, fmt, *args):
        pass

    def _send(self, code, body, ctype="application/json; charset=utf-8"):
        raw = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        try:
            self.wfile.write(raw)
        except Exception:
            pass

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            self._send(200, HTML, "text/html; charset=utf-8")
        elif self.path == "/favicon.ico":
            self._send(204, b"", "image/x-icon")
        else:
            self._send(404, "not found", "text/plain")

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n) if n else b"{}"
        try:
            data = json.loads(raw.decode("utf-8", "replace") or "{}")
        except Exception as e:
            self._send(400, json.dumps({"ok": False, "error": "JSON 解析失败: %s" % e}))
            return
        try:
            if self.path == "/api/run":
                resp = handle_run(data)
            else:
                resp = {"ok": False, "error": "未知接口"}
        except Exception as e:
            resp = {"ok": False, "error": "%s: %s" % (type(e).__name__, e)}
        self._send(200, json.dumps(resp, ensure_ascii=False))


def serve(port=8765, open_browser=True):
    httpd = None
    for p in range(port, port + 20):
        try:
            httpd = ThreadingHTTPServer(("127.0.0.1", p), Handler)
            port = p
            break
        except OSError:
            continue
    if httpd is None:
        print("[!] 没有可用端口，请用 --port 指定", file=sys.stderr)
        return 1
    url = "http://127.0.0.1:%d/" % port
    print("argdecode GUI 已启动: %s" % url)
    print("按 Ctrl+C 停止")
    if open_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    return 0


def main(argv=None):
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    ap = argparse.ArgumentParser(description="argdecode Web GUI")
    ap.add_argument("--port", type=int, default=8765, help="监听端口(默认 8765)")
    ap.add_argument("--no-browser", action="store_true", help="不自动打开浏览器")
    args = ap.parse_args(argv)
    return serve(args.port, not args.no_browser)


if __name__ == "__main__":
    sys.exit(main())
