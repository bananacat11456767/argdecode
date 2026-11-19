# 更新日志

## v1.1.0 — 首个开源版本（2026-11）

- 编码类：base64/base64url、base32、hex、base58、base85、ascii85、URL、HTML 实体、
  Unicode 转义、二进制、十进制、八进制、A1Z26、摩斯、培根、倒序。
- 古典密码：凯撒、仿射、Atbash、ROT13/ROT47、栅栏（rail fence 两个方向）、
  栅栏分组、列置换、维吉尼亚（内置密钥 + IC/卡方自动求密钥）、单字节 XOR。
- 自动模式：编码链 BFS + 单层穷举 + 多层波束搜索 + 收尾编码，词频/三字母组/flag 打分。
- 本地 Web GUI（纯标准库）：自动多层、单操作穷举、手动链式三个工作区，
  支持筛选、只看 flag、复制、导出 JSON。
- 评分改进：每多一层操作扣 45 分；按词频做单词切分，1~3 个常见词拼成的整串加分，
  带字母碎片的乱码重罚。
- Windows 双击 / 拖拽包装脚本（argdecode.bat、argdecode-gui.bat）。
- 单元测试 + GitHub Actions CI。
