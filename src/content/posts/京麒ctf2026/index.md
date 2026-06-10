---
title: "京麒CTF2026"
published: 2026-06-06
description: "京麒CTF2026 WriteUp"
image: "../../../assets/covers/default-cover.jpg"
tags: [writeup, re]
category: "WriteUp"
draft: false
---

# Hardware Flaws?!

**关键函数定位**

结合字符串交叉引用和附近调用关系，可以先给几个核心函数起名字：

- `sub_4E9410`：`main_logic`

作用：整体输入流程，读取 Key 和 Flag，调用校验函数，最后输出结果。

- `sub_4E9340`：`check_key`

作用：检查 Key 长度是否为 16，然后调用内部 Key 变换函数，和目标常量比较。

- `sub_18BA60`：`key_transform_wrapper`

作用：把 16 字节输入 Key 拷到栈上，依次调用 12 轮 `sub_18B530`，输出最终 16 字节结果。

- `sub_18B530`：`key_round_core`

作用：单轮 Key 变换核心，内部带有 cache/timing 风格逻辑。

- `sub_4E8C80`：`check_flag`

作用：检查 Flag 长度是否为 96，复制输入，进行 12 轮 Flag 变换，最后和目标密文比较。

- `sub_18BB20`

- `sub_1ED8B0`

- `sub_210430`

- `sub_249940`

- `sub_2A78A0`

- `sub_34B5B0`

- `sub_3A8F00`

- `sub_402FF0`

- `sub_4276A0`

- `sub_483860`

- `sub_4C1030`

- `sub_4C6BC0`

作用：`check_flag` 里的 12 个轮函数，每轮都对 96 字节状态做一次变换。

- `sub_18B460`

作用：环境检测函数。若检测失败，会输出 `Hmm...Seems your computer can't run this program properly...`

- `sub_18ACD0`

作用：环境检测里的核心计算例程，明显是一个类似 MD5 的摘要计算函数。

**主流程\`sub\_4E9410\`**

`sub_4E9410` 的逻辑很直接，可以还原成下面这样：

```c
int main_logic() {
    char key[0x80] = {0};
    char flag[0xA0] = {0};

    if (!environment_check()) {
        puts("Hmm...Seems your computer can't run this program properly. Maybe find another one?");
        return 0;
    }

    printf("Key: ");
    fgets(key, 0x80, stdin);
    key[strcspn(key, "\r\n")] = 0;

    if (!check_key(key, strlen(key_trimmed))) {
        puts("Wrong key!");
        return 0;
    }

    printf("Flag: ");
    fgets(flag, 0xA0, stdin);
    flag[strcspn(flag, "\r\n")] = 0;

    if (check_flag(flag, strlen(flag_trimmed), key))
        puts("Right flag!");
    else
        puts("Wrong flag!");

    return 0;
}
```

这个函数本身没有花活，关键在它调用的两个校验函数。

**环境检测\`sub\_18B460\`**

`main_logic` 一开始先调用 `sub_18B460`。

从汇编上看：

- 它会准备一个固定的 0x1c 字节数据块，地址在 `.rodata:0x4ef0b0`

- 调用 `sub_18ACD0` 做摘要计算

- 最终把结果和 `.rodata:0x4ef010` 开始的 16 字节常量比较

所以可以把它理解成：

```c
bool environment_check() {
    digest = hash_like_function(rodata_4ef0b0, 0x1c);
    return digest == rodata_4ef010;
}
```

这一步只影响能否进入正常交互，不参与 Key/Flag 本身的计算。

**Key 校验\`sub\_4E9340\`**

**函数作用**

`sub_4E9340` 的作用非常明确：

1. 检查输入长度是否为 `0x10`

2. 调用 `sub_18BA60` 对输入 Key 做 12 轮变换

3. 将结果与 `.rodata:0x4ef020` 的 16 字节目标值比较

关键汇编：

```asm
4e934f: cmp esi, 0x10
...
4e938e: call 18ba60
...
4e939b: movaps xmm1, [rip+0x5c7e]  ; 4ef020
4e93a2: movups xmm0, [rsp+0x20]
4e93a7: pcmpeqb xmm0, xmm1
```

**目标常量**

`.rodata:0x4ef020`：

```text
26 ba ff ba 31 af bb ee 4e 12 d9 05 67 16 a5 59
```

**内部变换函数**

`sub_18BA60` 可以命名为 `key_transform_wrapper`。

它的行为是：

1. 把 16 字节 Key 拷到栈上

2. 从 round 0 开始调用 `sub_18B530`

3. 最多执行 12 轮

4. 把最后的 16 字节状态写回输出缓冲区

关键汇编：

```asm
18ba7a: xor edi, edi
18ba7c: lea rsi, [rsp+0x20]
18ba81: call 18b530
...
18baa8: cmp eax, 0xc
...
18bae7: call 18b530
...
18bac9: mov [rcx], rdx
18bad1: mov [rcx+8], rdx
```

`sub_18B530` 是单轮核心。它会根据传入的 round 编号和当前 16 字节状态，生成新状态。这个函数内部有大量：

- `clflush`

- `mfence`

- `rdtscp`

- 对 `0x11c0` 小辅助块的调用

明显是把“缓存命中/未命中”当作比特信号来参与计算。

**Key 结果**

把 `.rodata:0x4ef020` 这个目标值逆回去，得到最终 Key：

```text
w31Rdm4cH1n3_k3Y
```

**Flag 校验\`sub\_4E8C80\`**

**函数作用**

`sub_4E8C80` 的参数是：

- `rdi`：flag 指针

- `esi`：flag 长度

- `rdx`：key 指针

它的逻辑可以概括为：

1. 长度必须为 `0x60`

2. 把输入 Flag 复制到工作缓冲区

3. 执行 12 轮状态变换

4. 做一次 0x300 次的小循环，把中间状态压缩/规整成 96 字节结果

5. 如果轮次未完成，还会继续外层循环

6. 最终与 `.rodata:0x4ef0e0` 的 96 字节目标密文比较

关键汇编：

```asm
4e8c99: cmp esi, 0x60
...
4e8d00: call memcpy
...
4e8e7b: call 18bb20
4e8ea5: call 1ed8b0
4e8ecf: call 210430
4e8ef9: call 249940
4e8f23: call 2a78a0
4e8f4d: call 34b5b0
4e8f77: call 3a8f00
4e8fa1: call 402ff0
4e8fcb: call 4276a0
4e8ff5: call 483860
4e901f: call 4c1030
4e9049: call 4c6bc0
...
4e92b8: lea rsi, [rip+0x5e21]        # 4ef0e0
4e92cc: call bcmp
```

**12 个轮函数**

`check_flag` 的核心就是下面这 12 个函数：

1. `sub_18BB20`

2. `sub_1ED8B0`

3. `sub_210430`

4. `sub_249940`

5. `sub_2A78A0`

6. `sub_34B5B0`

7. `sub_3A8F00`

8. `sub_402FF0`

9. `sub_4276A0`

10. `sub_483860`

11. `sub_4C1030`

12. `sub_4C6BC0`

它们的共同特征是：

- 参数形式都类似：输入状态、辅助缓存区、辅助位图区

- 内部都先初始化一个索引表

- 再结合 `rand`、缓存命中状态、位图缓冲区对 96 字节状态进行处理

也就是说，这 12 个函数就是整道题真正的 Flag 变换网络。

**规整阶段**

在 12 个轮函数调用之后，`sub_4E8C80` 还有一个比较关键的阶段：

- `rsp+0x130`：0x300 字节工作区

- `rsp+0x490`：96 字节位图区

- `rsp+0x430`：96 字节辅助标记区

- `rsp+0xd0`：最终 96 字节结果区

`0x4e906a` 到 `0x4e926a` 这一大段代码，本质上是在把前面轮函数留下的中间状态转成稳定的 96 字节输出。

其中最关键的两个操作是：

1. 根据 `rsp+0x430` 和 `rsp+0x490` 的位，调整 `rsp+0x130` 中对应字节

2. 再把 `rsp+0x130` 的符号信息收敛回 `rsp+0x490`

最后 `memcpy(rsp+0xd0, rsp+0x490, 0x60)`，把结果拿去比较。

**目标密文**

`.rodata:0x4ef0e0` 的 96 字节内容为：

```text
44 1d 8c f5 80 8b eb 28 1b e9 a4 82 3d 4f 06 20
76 46 04 5e 70 28 11 ca a8 a8 9e 93 ac 76 85 1f
71 25 66 99 a0 36 78 65 dd 21 b2 35 2e c8 8d 8f
67 3f 41 11 f3 6d 68 33 d6 e7 64 94 91 b9 75 30
4a 46 a6 23 d6 f1 12 39 01 45 13 ea 95 78 35 b9
67 76 8b d3 aa da 43 7b 9c 3e 14 79 ea a2 1e 14
```

```python
import time

from z3 import And as Z3And
from z3 import Bool, BoolVal, Not as Z3Not, Or as Z3Or, Solver, Xor as Z3Xor, sat

from emu_hw import HEAP_BASE, HWEmu, run_18b530, run_18ba60
from symbolic_hw import Expr, FALSE, KEY_ROUNDS, TRUE, extract_function, make_bit_vars

KEY_TARGET = bytes.fromhex("26baffba31afbbee4e12d9056716a559")
FLAG_TARGET = bytes.fromhex(
    "441d8cf5808beb281be9a4823d4f0620"
    "7646045e702811caa8a89e93ac76851f"
    "71256699a0367865dd21b2352ec88d8f"
    "673f4111f36d6833d6e7649491b97530"
    "4a46a623d6f11239014513ea957835b9"
    "67768bd3aada437b9c3e1479eaa21e14"
)

FLAG_ROUNDS = [
    0x18BB20,
    0x1ED8B0,
    0x210430,
    0x249940,
    0x2A78A0,
    0x34B5B0,
    0x3A8F00,
    0x402FF0,
    0x4276A0,
    0x483860,
    0x4C1030,
    0x4C6BC0,
]

# 0/3/6/9 are the four special key rounds. The others are direct Feistel-style rounds.
SPECIAL_KEY_ROUNDS = {0, 3, 6, 9}
ROUND11_XOR = bytes.fromhex(
    "399a7cf953b004a8e8a778da4c24f538"
    "938caff3b83fa66e1c55756625d75866"
    "36c96a86090ae57b65770da9a189175f"
    "9fd1a24155da1c4de3a12687325fd209"
    "1cc18677eea9704c61fe52b34db691bf"
    "a528526f364db10b252488abd951d9e0"
)
ROUND9_ROT = [1, 3, 5] * 32
ROUND1_XOR = bytes.fromhex(
    "9cbc37683b971b7ee8a7ac1ff36d9391"
    "4fee2a1908f544305ed9731b5be34714"
    "eb30c1c600379e0880e7c42e79e4826f"
    "e729c96f2d912a675fa2e5c2f82110cc"
    "0fde574a66a3e45ee397668254d3d3a8"
    "8e7676abac1d5bcb3ac9178c01e9cd7e"
)
ROUND1_PERM = [
    45, 34, 20, 25, 1, 47, 8, 36, 46, 19, 11, 44, 23, 17, 14, 9,
    39, 37, 27, 26, 15, 42, 40, 0, 4, 12, 5, 22, 18, 38, 32, 24,
    41, 7, 13, 6, 31, 30, 43, 2, 10, 29, 21, 3, 35, 33, 16, 28,
    93, 82, 68, 73, 49, 95, 56, 84, 94, 67, 59, 92, 71, 65, 62, 57,
    87, 85, 75, 74, 63, 90, 88, 48, 52, 60, 53, 70, 66, 86, 80, 72,
    89, 55, 61, 54, 79, 78, 91, 50, 58, 77, 69, 51, 83, 81, 64, 76,
]
ROUND7_XOR = bytes.fromhex(
    "b4ffc37025a3b4ffc37025a3b4ffc370"
    "25a3b4ffc37025a3b4ffc37025a3b4ff"
    "c37025a3b4ffc37025a3b4ffc37025a3"
    "b4ffc37025a3b4ffc37025a3b4ffc370"
    "25a3b4ffc37025a3b4ffc37025a3b4ff"
    "c37025a3b4ffc37025a3b4ffc37025a3"
)
ROUND7_PERM = [
    4, 2, 3, 5, 0, 1, 10, 8, 9, 11, 6, 7, 16, 14, 15, 17,
    12, 13, 22, 20, 21, 23, 18, 19, 28, 26, 27, 29, 24, 25, 34, 32,
    33, 35, 30, 31, 40, 38, 39, 41, 36, 37, 46, 44, 45, 47, 42, 43,
    52, 50, 51, 53, 48, 49, 58, 56, 57, 59, 54, 55, 64, 62, 63, 65,
    60, 61, 70, 68, 69, 71, 66, 67, 76, 74, 75, 77, 72, 73, 82, 80,
    81, 83, 78, 79, 88, 86, 87, 89, 84, 85, 94, 92, 93, 95, 90, 91,
]
ROUND7_INV_PERM = [0] * 96
for _i, _dst in enumerate(ROUND7_PERM):
    ROUND7_INV_PERM[_dst] = _i

def expr_to_z3(expr, memo):
    if expr.id in memo:
        return memo[expr.id]
    if expr is TRUE:
        out = BoolVal(True)
    elif expr is FALSE:
        out = BoolVal(False)
    elif expr.op == "var":
        out = Bool(expr.name)
    elif expr.op == "not":
        out = Z3Not(expr_to_z3(expr.args[0], memo))
    elif expr.op == "and":
        out = Z3And(*[expr_to_z3(a, memo) for a in expr.args])
    elif expr.op == "or":
        out = Z3Or(*[expr_to_z3(a, memo) for a in expr.args])
    elif expr.op == "xor":
        out = Z3Xor(expr_to_z3(expr.args[0], memo), expr_to_z3(expr.args[1], memo))
    else:
        raise ValueError(expr.op)
    memo[expr.id] = out
    return out

def bits_equal_bytes(solver, bits, target, memo):
    for i, byte in enumerate(target):
        for j in range(8):
            solver.add(expr_to_z3(bits[i * 8 + j], memo) == bool((byte >> j) & 1))

def model_to_bytes(model, prefix, nbytes):
    out = bytearray()
    for i in range(nbytes):
        v = 0
        for j in range(8):
            if model.eval(Bool(f"{prefix}_{i * 8 + j}"), model_completion=True):
                v |= 1 << j
        out.append(v)
    return bytes(out)

def solve_single_key_round(round_idx, target_state):
    addr = KEY_ROUNDS[round_idx]
    prefix = f"k{round_idx}"
    bits = make_bit_vars(prefix, 16)
    t0 = time.time()
    out_bits, bad_bits, ret, _emu = extract_function(addr, [(HEAP_BASE, bits)], 128)
    solver = Solver()
    memo = {}
    bits_equal_bytes(solver, out_bits, target_state, memo)
    for b in bad_bits:
        solver.add(expr_to_z3(b, memo) == False)
    if solver.check() != sat:
        raise RuntimeError(f"key round {round_idx} constraints are unsat")
    state = model_to_bytes(solver.model(), prefix, 16)
    _ret, real_out, _ = run_18b530(round_idx, state)
    print(
        f"key round {round_idx:02d} symbolic-invert {addr:#x} dt={time.time() - t0:.2f}s "
        f"in={state.hex()} out={real_out.hex()}",
        flush=True,
    )
    if real_out != target_state:
        raise RuntimeError(f"key round {round_idx} symbolic inverse failed recheck")
    return state

def feistel_inverse_round(round_idx, target_state):
    right_prev = target_state[:8]
    zero_state = b"\0" * 8 + right_prev
    _ret, zero_out, _ = run_18b530(round_idx, zero_state)
    left_prev = bytes(a ^ b for a, b in zip(target_state[8:], zero_out[8:]))
    state = left_prev + right_prev
    _ret, real_out, _ = run_18b530(round_idx, state)
    print(
        f"key round {round_idx:02d} feistel-invert {KEY_ROUNDS[round_idx]:#x} "
        f"in={state.hex()} out={real_out.hex()}",
        flush=True,
    )
    if real_out != target_state:
        raise RuntimeError(f"key round {round_idx} Feistel inverse failed recheck")
    return state

def solve_key():
    state = KEY_TARGET
    print("key target", state.hex(), flush=True)
    for round_idx in range(11, -1, -1):
        if round_idx in SPECIAL_KEY_ROUNDS:
            state = solve_single_key_round(round_idx, state)
        else:
            state = feistel_inverse_round(round_idx, state)
    _ret, final = run_18ba60(state)
    print("key recheck", final.hex(), flush=True)
    if final != KEY_TARGET:
        raise RuntimeError("final key recheck failed")
    return state

def forward_flag_round(round_idx, state, key_bytes):
    emu = HWEmu()
    state_addr = HEAP_BASE
    key_addr = HEAP_BASE + 0x1000
    pos_addr = HEAP_BASE + 0x2000
    neg_addr = HEAP_BASE + 0x3000
    emu.mu.mem_write(state_addr, state)
    emu.mu.mem_write(key_addr, key_bytes)
    emu.mu.mem_write(pos_addr, b"\0" * 0x60)
    emu.mu.mem_write(neg_addr, b"\0" * 0x60)
    if round_idx == 0:
        emu.call(FLAG_ROUNDS[round_idx], (state_addr, key_addr, pos_addr, neg_addr))
    else:
        emu.call(FLAG_ROUNDS[round_idx], (state_addr, 0, pos_addr, neg_addr))
    pos = bytes(emu.mu.mem_read(pos_addr, 0x60))
    neg = bytes(emu.mu.mem_read(neg_addr, 0x60))
    return bytes(a & (~b & 0xFF) for a, b in zip(pos, neg))

def forward_flag_all_rounds(flag_bytes, key_bytes):
    state = flag_bytes
    for round_idx in range(12):
        state = forward_flag_round(round_idx, state, key_bytes)
    return state

def inv_round11(state):
    return bytes(a ^ b for a, b in zip(state, ROUND11_XOR))

def inv_round10(state):
    out = bytearray(state)
    for i in range(0, len(out), 2):
        out[i], out[i + 1] = out[i + 1], out[i]
    return bytes(out)

def rol8(v, r):
    r &= 7
    return ((v << r) | (v >> (8 - r))) & 0xFF

def ror8(v, r):
    r &= 7
    return ((v >> r) | ((v << (8 - r)) & 0xFF)) & 0xFF

def inv_round9(state):
    out = bytearray(len(state))
    for i, b in enumerate(state):
        out[i] = ror8((~b) & 0xFF, ROUND9_ROT[i])
    return bytes(out)

def inv_round8(state):
    """
    Round 8 is block-local on each 4-byte chunk:
      y0 = 0xe6 ^ x2 ^ x3
      y1 = 0x3c ^ x1 ^ x2
      y2 = 0x28 ^ x0 ^ x1 ^ x3
      y3 = 0x83 ^ x0 ^ x1
    Invert each 4-byte chunk independently.
    """
    out = bytearray(len(state))
    for off in range(0, len(state), 4):
        y0, y1, y2, y3 = state[off : off + 4]
        x3 = y2 ^ y3 ^ 0xAB
        x2 = y0 ^ y2 ^ y3 ^ 0x4D
        x1 = y0 ^ y1 ^ y2 ^ y3 ^ 0x71
        x0 = y0 ^ y1 ^ y2 ^ 0xF2
        out[off : off + 4] = bytes((x0, x1, x2, x3))
    return bytes(out)

def inv_round7(state):
    tmp = bytes(a ^ b for a, b in zip(state, ROUND7_XOR))
    out = bytearray(len(tmp))
    for dst, src in enumerate(ROUND7_INV_PERM):
        out[src] = tmp[dst]
    return bytes(out)

def inv_round6(state):
    out = bytearray(len(state))
    for off in range(0, len(state), 8):
        y = list(state[off : off + 8])
        x = [0] * 8
        x[7] = y[0] ^ y[7]
        x[6] = 0x40 ^ y[6] ^ x[7]
        x[5] = 0x40 ^ y[5] ^ x[6]
        x[4] = 0x40 ^ y[4] ^ x[5]
        x[3] = 0x40 ^ y[3] ^ x[4]
        x[2] = 0x40 ^ y[2] ^ x[3]
        x[1] = 0x40 ^ y[1] ^ x[2]
        x[0] = 0x40 ^ y[0] ^ x[1]
        out[off : off + 8] = bytes(x)
    return bytes(out)

def inv_round5(state):
    base = bytes.fromhex("4106c3018b34aa48881302a2")
    out = bytearray(len(state))
    for off in range(0, len(state), 12):
        y0 = bytes(a ^ b for a, b in zip(state[off : off + 4], base[0:4]))
        y1 = bytes(a ^ b for a, b in zip(state[off + 4 : off + 8], base[4:8]))
        y2 = bytes(a ^ b for a, b in zip(state[off + 8 : off + 12], base[8:12]))
        c = bytes(a ^ b for a, b in zip(y0, y2))
        b = bytes(a ^ b for a, b in zip(y1, c))
        a = bytes(a ^ b for a, b in zip(y0, b))
        out[off : off + 4] = a
        out[off + 4 : off + 8] = b
        out[off + 8 : off + 12] = c
    return bytes(out)

def inv_round4(state, key_bytes):
    probe = bytearray(96)
    for off in range(0, 96, 32):
        probe[off + 8 : off + 16] = state[off : off + 8]
        probe[off + 24 : off + 32] = state[off + 16 : off + 24]
    ref = forward_flag_round(4, bytes(probe), key_bytes)
    out = bytearray(96)
    for off in range(0, 96, 32):
        out[off : off + 8] = bytes(
            a ^ b for a, b in zip(state[off + 8 : off + 16], ref[off + 8 : off + 16])
        )
        out[off + 8 : off + 16] = state[off : off + 8]
        out[off + 16 : off + 24] = bytes(
            a ^ b for a, b in zip(state[off + 24 : off + 32], ref[off + 24 : off + 32])
        )
        out[off + 24 : off + 32] = state[off + 16 : off + 24]
    return bytes(out)

def inv_round3(state):
    base = bytes.fromhex("f77e09ea2b4f24611c52990ab15c66c507aa165e780ecef3")
    out = bytearray(len(state))
    for off in range(0, len(state), 24):
        y0 = bytes(a ^ b for a, b in zip(state[off : off + 8], base[0:8]))
        y1 = bytes(a ^ b for a, b in zip(state[off + 8 : off + 16], base[8:16]))
        y2 = bytes(a ^ b for a, b in zip(state[off + 16 : off + 24], base[16:24]))
        c = bytes(a ^ b for a, b in zip(y0, y2))
        b = bytes(a ^ b for a, b in zip(y1, c))
        a = bytes(a ^ b for a, b in zip(y0, b))
        out[off : off + 8] = a
        out[off + 8 : off + 16] = b
        out[off + 16 : off + 24] = c
    return bytes(out)

def inv_round2(state):
    base = bytes.fromhex(
        "1cdb4f5c17885dd6c343a7668a67858b"
        "30cd5c17ac8c59513b85ed22e2b9dfe2"
    )
    out = bytearray(len(state))
    for off in range(0, len(state), 32):
        b = bytes(a ^ bb for a, bb in zip(state[off : off + 16], base[0:16]))
        a = bytes(
            aa ^ bb ^ cc
            for aa, bb, cc in zip(state[off + 16 : off + 32], base[16:32], b)
        )
        out[off : off + 16] = a
        out[off + 16 : off + 32] = b
    return bytes(out)

def inv_round1(state):
    out = bytearray(96)
    for i, pos in enumerate(ROUND1_PERM):
        out[i] = state[pos] ^ ROUND1_XOR[pos]
    return bytes(out)

def inv_round0(state):
    return bytes(ror8(b ^ 0xD8, 3) for b in state)

def solve_flag(key_bytes):
    state = FLAG_TARGET
    print("flag target", state.hex(), flush=True)
    for round_idx, fn in (
        (11, inv_round11),
        (10, inv_round10),
        (9, inv_round9),
        (8, inv_round8),
        (7, inv_round7),
        (6, inv_round6),
        (5, inv_round5),
    ):
        state = fn(state)
        print(f"flag round {round_idx:02d} inverse {state.hex()}", flush=True)
    state = inv_round4(state, key_bytes)
    print(f"flag round 04 inverse {state.hex()}", flush=True)
    for round_idx, fn in (
        (3, inv_round3),
        (2, inv_round2),
        (1, inv_round1),
        (0, inv_round0),
    ):
        state = fn(state)
        print(f"flag round {round_idx:02d} inverse {state.hex()}", flush=True)
    return state

if __name__ == "__main__":
    key = solve_key()
    print("KEY_HEX", key.hex())
    print("KEY_ASCII", key.decode())
    flag = solve_flag(key)
    print("FLAG_HEX", flag.hex())
    print("FLAG_ASCII", flag.decode())
    print("FLAG_FORWARD_OK", forward_flag_all_rounds(flag, key) == FLAG_TARGET)

```

```sql
key target 26baffba31afbbee4e12d9056716a559
key round 11 feistel-invert 0xcd450 in=12899d5643bb74f726baffba31afbbee out=26baffba31afbbee4e12d9056716a559
key round 10 feistel-invert 0xb4890 in=1825e1e41aa8f99a12899d5643bb74f7 out=12899d5643bb74f726baffba31afbbee
key round 09 symbolic-invert 0xae4d0 dt=9.12s in=1bd9fd562f5dae68002bc2b2d8d457cc out=1825e1e41aa8f99a12899d5643bb74f7
key round 08 feistel-invert 0x93060 in=4857336e68c447b71bd9fd562f5dae68 out=1bd9fd562f5dae68002bc2b2d8d457cc
key round 07 feistel-invert 0x7a630 in=672b743e7ec2ee4c4857336e68c447b7 out=4857336e68c447b71bd9fd562f5dae68
key round 06 symbolic-invert 0x742c0 dt=10.75s in=593edee81325e3a97ca663c73c8d0fbc out=672b743e7ec2ee4c4857336e68c447b7
key round 05 feistel-invert 0x58f00 in=20221bbc13ce3ba8593edee81325e3a9 out=593edee81325e3a97ca663c73c8d0fbc
key round 04 feistel-invert 0x403f0 in=3582e13934845e0a20221bbc13ce3ba8 out=20221bbc13ce3ba8593edee81325e3a9
key round 03 symbolic-invert 0x3acf0 dt=8.52s in=b6d1827fb37e2a0f4457863bab6814b3 out=3582e13934845e0a20221bbc13ce3ba8
key round 02 feistel-invert 0x1f880 in=2086949b80386523b6d1827fb37e2a0f out=b6d1827fb37e2a0f4457863bab6814b3
key round 01 feistel-invert 0x6d70 in=96aad78e228f732f2086949b80386523 out=2086949b80386523b6d1827fb37e2a0f
key round 00 symbolic-invert 0x1210 dt=10.27s in=77333152646d346348316e335f6b3359 out=96aad78e228f732f2086949b80386523
calls {'0x1050': 49, '0x1060': 36, '0x11c0': 11472, '0x18ba86': 1, '0x18baec': 11, '0x4e95e0': 6352}
timing 3173 3179
rip 0x41414000
key recheck 26baffba31afbbee4e12d9056716a559
KEY_HEX 77333152646d346348316e335f6b3359
KEY_ASCII w31Rdm4cH1n3_k3Y
flag target 441d8cf5808beb281be9a4823d4f06207646045e702811caa8a89e93ac76851f71256699a0367865dd21b2352ec88d8f673f4111f36d6833d6e7649491b975304a46a623d6f11239014513ea957835b967768bd3aada437b9c3e1479eaa21e14
flag round 11 inverse 7d87f00cd33bef80f34edc58716bf318e5caabadc817b7a4b4fdebf589a1dd7947ec0c1fa93c9d1eb856bf9c8f419ad0f8eee350a6b7747e35464213a3e6a739568720543858627560bb4159d8cea406c25ed9bc9c97f270b91a9cd233f3c7f4
flag round 10 inverse 877d0cf03bd380ef4ef358dc6b7118f3cae5adab17c8a4b7fdb4f5eba18979ddec471f0c3ca91e9d56b89cbf418fd09aeef850e3b7a67e7446351342e6a339a78756542058387562bb605941ced806a45ec2bcd9979c70f21ab9d29cf333f4c7
flag round 09 inverse 3c509f879861bf028d06f4194ad13f06a6d0298a479b6b420169500acbb34344985c1c9fe1ca0f31353ab108f538e52b88e07d0e09cac071cd659ded8c8b362c0f4dd5fb3de351ec22f3355f2639fc6b0d9e6831346c7c86bc32966c606661c1
flag round 08 inverse 010569b3b43568168d172d4656d33e92ada4480845842382ca4316f1c90e81ac2a365628d66492954cc7c112da727665e76ab6d8f103f51ac7a9f0dbc36cdbb1651d6c857d12cd1616ca05c111f9fc3c09bb19f2d6d38351ea050b5195d78d0b
flag round 07 inverse 91aac396b5fa084e67e5dce988fde207e22c0686f421fcf7ecd581ad7ebc73e9468b35536951e564629b531902c675edd475a8a05395d504d97841e54018c1be7793e8be62b5d87a34c6b15aa2353ccacb5148c3cf4021a6622ca856a7a8bfae
flag round 06 inverse b6678d0ed82d97df0027821eb77fc2603290fcba7cc8a915e14dd819f4ca36051412d9acbf968722cdef34277e3cba8f2abe8b63839045d0bb221a1bbebee667f0c714bc4260950d0c78fe0f15f782fe92190800830c0c6d8caec22a3cdb33cc
flag round 05 inverse db2dbd2b2c4cf3247f55ceb34d7ffd45bb06fc2402a2aad6e3ff474343b45c5b3c4ac016b0f426424e64626108bffc0e3b95f721502dbf43588950dbb180295b4e380c3d35cbb2c984c92214c9b71f1a577437acb352590c7158966076c2fe02
flag round 04 inverse a2a85013576fffbadb2dbd2b2c4cf324e27aad1829c96037bb06fc2402a2aad6dbf34de60b910c503c4ac016b0f4264215c26bdb99391e4d3b95f721502dbf43bc39e6d328cfd0384e380c3d35cbb2c9cc672a60a0f7f28e577437acb352590c
flag round 03 inverse 22af9f67ccd73b257779c69eb0f7e0feb006e2bf2de7751ffc4102a472378224b039f76a5bda0c9377982386e11766069c549ea6b1b0c74d7ee8fc9703c6fd61592f92bce2b724e780eb9298daf703b439ad974fc473951ce9982425d5d80157
flag round 02 inverse bebf6e935a344abd73fe8e7eaa1e38b33e74d03bdb5f66f3b43a61f83a906575007b7a87516ecf59f1b695558a0fc10eace2b8364c525145b4db84e06b70e38d4c9416b89dc0b57c91b5fcf967f1588a45f4dde0f53f793143a835fe5090863f
flag round 01 inverse ebbbd3e303619b51432261f3c39aab595159e312225171226159a322fa51ebea51c3735161227b592273aafb414b716179abfb22cb41eb594bf22251224af379fa227b9a4122794b6193c3514122cb726122517b228b7271612263594b824333
flag round 00 inverse 666c61677b376831735f376563486e30313067595f31355f37306f5f4431664631637531375f74305f754e6433723537346e645f6233663072455f315f526534445f7448335f347237696331335f6255375f31745f6a5535375f7730724b737d
FLAG_HEX 666c61677b376831735f376563486e30313067595f31355f37306f5f4431664631637531375f74305f754e6433723537346e645f6233663072455f315f526534445f7448335f347237696331335f6255375f31745f6a5535375f7730724b737d
FLAG_ASCII flag{7h1s_7ecHn010gY_15_70o_D1fF1cu17_t0_uNd3r574nd_b3f0rE_1_Re4D_tH3_4r7ic13_bU7_1t_jU57_w0rKs}
FLAG_FORWARD_OK True
```



# FoldNote

Java层中的mainactivity读取输入框文本，flag校验在so层

![Image](https://internal-api-drive-stream.feishu.cn/space/api/box/stream/download/authcode/?code=ZTZiMjJlZTcyMGUyMWU2ZDBjZGQ3NTQ0YzhlNjA3ZDVfZGRkNjhiMjM4MjdiY2U5MjBhMTU1YjhhNDdmNGY2MmVfSUQ6NzY0OTAyMjA2MDExOTE5ODY1MF8xNzgxMDg2MDM1OjE3ODExNzI0MzVfVjM)

对应的JNI函数名是

```c++
Java_com_example_foldnote_NativeBridge_check
```

![Image](https://internal-api-drive-stream.feishu.cn/space/api/box/stream/download/authcode/?code=MjAwYmJiOTg1MmQ5NTUwNTQ0NzAxYjBkODBlM2M5MzhfMzQ1YzYyZTU2NmI3NjQwNDdhMDJiMWU2ZjZjOTZjYzhfSUQ6NzY0OTAyMjIwOTM0MTIzMDA1MV8xNzgxMDg2MDM1OjE3ODExNzI0MzVfVjM)

JNI 入口的大致流程是：

1. 取 Java 字符串；

2. 初始化一个内嵌解释器/线程状态；

3. 从 `.rodata` 的 `qword_1640` 位置解析一段 `0x47e2` 字节的 blob；

4. 调用 VM，每次把输入的一个字符喂进去；

5. 取最终结果，与 `1` 比较。

关键调用形态：

自定义的校验被藏在python-like的VM逻辑里

```c
sub_5495C(tstate, qword_1640, 0x47E2, 1);
sub_54664(...);

for (i = 0; i < strlen(input); i++) {
    sub_4D718(..., i, input[i], 0);
}

result = sub_4EFFC(...);
return result == 1;
```

**Blob 格式**

把 `qword_1640` 的 `0x47e2` 字节 dump 成 `blob.bin` 后，发现它不是普通 `pyc` / `marshal`：

- 首字节是 `0x01`，不是合法 marshal type；

- 前面有 21 个字符串；

- 字符串表后面从 `0x124` 开始进入 code object。

前0x124的是按sub_60180接出来的，规则如下：

```c++
hdr = read_uleb()
wide = hdr & 1
len  = hdr >> 1
byte_count = len << wide
read(byte_count)
```

这题头部这些名字全都是普通单字节字符串，所以 wide=0，实际就是：

长度头 = 2 * 字符串长度

后面紧跟字符串原文

字符串表内容包括：

```text
frame
localsplus
frame_obj
stack_pointer
names
co_consts
eval_breaker
throwflag
next_instr
oparg
opcode
prev_instr
```

继续看 `sub_54B4C` 可以确认它是对象读取 dispatcher，`tag == 0x0e` 是 code object。读取整数时使用 ULEB128 / zigzag 变长编码，字节码扫描则依赖 `word_9C7E` 的 opcode 元数据表。

这里最重要的结论是：blob 是一个自定义 marshal-like code object 流，不是普通 Python 字节码文件。

整数、引用和 code operand 都会经过 reader 处理：

- `sub_6014C` / `sub_5E958` 读取 ULEB128；

- `sub_5E9A4` 读取 zigzag signed LEB128；

- `sub_6030C` 读取带低位标记的整数/引用；

- `sub_54B4C case 0x0e` 解析 code object；

- 字节码扫描时根据 `word_9C7E` 判断 opcode 长度和 operand 类型。

实际提取方式是先把 VM 字节码结构拆出来，再看 VM 运行时构造的常量对象。

按上面的 VM 对象提取过程，可以得到校验所需常量：

```python
delta = 0x8c927553
key = [
    0x56f75008,
    0x4dece3a2,
    0xa438ad1d,
    0x6ea0eac9,
]

target = [
    0x62a135fc,
    0x52f55e89,
    0x192a69b7,
    0x390d058c,
    0x6282d010,
    0x902a0225,
    0xfe59d65e,
    0x3045a6dd,
]

rounds = 12
```

判断它是 XXTEA 变种的依据有三点：

- 输入被按 little-endian 拆成 8 个 32-bit word，也就是 32 字节；

- 有 4 个 32-bit key word；

- 轮函数里出现典型的 `z >> 5`、`y << 2`、`y >> 3`、`z << 4`、`(p & 3) ^ e` 混合。

还原出的轮函数是：

```python
((((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4)))
 ^ ((sum ^ y) + (key[(p & 3) ^ e] ^ z)))
```

目标数组是加密后的 8 个 32-bit word。按 little-endian 解密后即可得到 flag。

```python
#!/usr/bin/env python3

from struct import pack, unpack

U32 = 0xFFFFFFFF
DELTA = 0x8C927553
ROUNDS = 12

K = (0x56F75008, 0x4DECE3A2, 0xA438AD1D, 0x6EA0EAC9)
CIPHER = (
    0x62A135FC,
    0x52F55E89,
    0x192A69B7,
    0x390D058C,
    0x6282D010,
    0x902A0225,
    0xFE59D65E,
    0x3045A6DD,
)

def step(z, y, total, p):
    e = (total >> 2) & 3
    a = (z >> 5) ^ ((y << 2) & U32)
    b = (y >> 3) ^ ((z << 4) & U32)
    c = (total ^ y) + (K[(p & 3) ^ e] ^ z)
    return ((a + b) ^ c) & U32

def unmix(block, total=DELTA * ROUNDS):
    if total == 0:
        return block

    v = list(block)
    y = v[0]
    for p in range(len(v) - 1, 0, -1):
        z = v[p - 1]
        v[p] = (v[p] - step(z, y, total & U32, p)) & U32
        y = v[p]

    z = v[-1]
    v[0] = (v[0] - step(z, y, total & U32, 0)) & U32
    return unmix(tuple(v), total - DELTA)

def remix(block):
    v = list(block)
    total = 0
    for _ in range(ROUNDS):
        total = (total + DELTA) & U32
        z = v[-1]
        for p in range(len(v) - 1):
            y = v[p + 1]
            v[p] = (v[p] + step(z, y, total, p)) & U32
            z = v[p]
        v[-1] = (v[-1] + step(z, v[0], total, len(v) - 1)) & U32
    return tuple(v)

plain = unmix(CIPHER)
flag = pack("<%dI" % len(plain), *plain)

print(flag.decode())
assert remix(plain) == CIPHER

```

flag{S1ay_Th3_5piRe2_2V2M55L3V5}



# L4byryη7h

附件里最显眼的是一个大约 `2.7 GB` 的文件 `l4byryη7h`。先判断它的格式，可以发现它不是压缩包，也不是镜像，而是一个 `64-bit ELF`。

进一步看节表，可以发现几个非常不正常的自定义 section：

- `limg`

- `loff`

- `lmsk`

- `ldata`

这几个 section 的命名已经很明显了：

- `limg`：像是迷宫整体信息。

- `loff`：每个节点对应数据块的偏移表。

- `lmsk`：额外的位图或掩码。

- `ldata`：真正的大块迷宫数据。

也就是说，这个 ELF 不是拿来正常运行逻辑的普通程序，而是一个“程序壳 + 超大数据容器”。

**先读 limg 头部**

```c++
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <wchar.h>
#endif

#define OFF_HDR 0x94a0ULL
#define OFF_LOFF 0x94d0ULL
#define OFF_LMSK 0x10094d0ULL
#define OFF_LDATA 0x10894d0ULL
#define TEXT_OFF 0x1000ULL
#define TEXT_SIZE 0x5855ULL
#define MASK 0xffffffffu

static uint8_t sbox[256], inv_sbox[256], rcon[10];
static uint8_t token[16];
static uint32_t seed, n_nodes, start_node, end_node, data_size;
static uint32_t *loff;
static uint8_t *lmsk, *ldata;
static uint8_t *block_cache;
static uint8_t *block_state; /* 0 unknown, 1 invalid, 2 valid */

static uint32_t rol32(uint32_t x, unsigned n) {
    n &= 31;
    return (x << n) | (x >> (32 - n));
}

static uint32_t u32le(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void put32le(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static uint32_t md5_mix(uint32_t x) {
    x ^= rol32(x, 7);
    x *= 0x9e3779b1u;
    x ^= rol32(x, 13);
    x *= 0x85ebca77u;
    x ^= x >> 16;
    return x;
}

static void derive_key_iv(uint32_t node, uint8_t key[16], uint8_t iv[16]) {
    uint32_t a = u32le(token), b = u32le(token + 4), c = u32le(token + 8), d = u32le(token + 12);
    uint32_t w[8];
    uint32_t n = node;
    w[0] = md5_mix(a ^ n ^ 0x243f6a88u);
    w[1] = md5_mix(rol32(n, 7) + b - 0x7a5cf72du);
    w[2] = md5_mix(n * 0x9e3779b1u ^ c ^ 0x13198a2eu);
    w[3] = md5_mix((n ^ 0xdeadbeefu) + d + 0x03707344u);
    w[4] = md5_mix(rol32(n, 13) ^ c ^ 0xa4093822u);
    w[5] = md5_mix(rol32(n, 3) + d + 0x299f31d0u);
    w[6] = md5_mix(n * 0x7f4a7c15u ^ a ^ 0x082efa98u);
    w[7] = md5_mix((n ^ 0xbaadf00du) + b - 0x13b19377u);
    for (int i = 0; i < 4; i++) {
        put32le(key + 4 * i, w[i]);
        put32le(iv + 4 * i, w[i + 4]);
    }
}

/* Minimal MD5, public-domain style implementation for one-shot hashing. */
typedef struct {
    uint32_t h[4];
    uint64_t len;
    uint8_t buf[64];
    size_t used;
} MD5_CTX2;

static uint32_t md5_k[64] = {
    0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
    0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,
    0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
    0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
    0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
    0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
    0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
    0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391
};

static uint8_t md5_s[64] = {
    7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,
    5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,
    4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,
    6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21
};

static void md5_block(MD5_CTX2 *ctx, const uint8_t b[64]) {
    uint32_t m[16], a = ctx->h[0], c = ctx->h[2], d = ctx->h[3], bb = ctx->h[1];
    for (int i = 0; i < 16; i++) m[i] = u32le(b + 4 * i);
    for (int i = 0; i < 64; i++) {
        uint32_t f, g;
        if (i < 16) { f = (bb & c) | (~bb & d); g = i; }
        else if (i < 32) { f = (d & bb) | (~d & c); g = (5 * i + 1) & 15; }
        else if (i < 48) { f = bb ^ c ^ d; g = (3 * i + 5) & 15; }
        else { f = c ^ (bb | ~d); g = (7 * i) & 15; }
        uint32_t tmp = d;
        d = c;
        c = bb;
        bb += rol32(a + f + md5_k[i] + m[g], md5_s[i]);
        a = tmp;
    }
    ctx->h[0] += a; ctx->h[1] += bb; ctx->h[2] += c; ctx->h[3] += d;
}

static void md5_init(MD5_CTX2 *ctx) {
    ctx->h[0] = 0x67452301; ctx->h[1] = 0xefcdab89; ctx->h[2] = 0x98badcfe; ctx->h[3] = 0x10325476;
    ctx->len = 0; ctx->used = 0;
}

static void md5_update(MD5_CTX2 *ctx, const uint8_t *data, size_t len) {
    ctx->len += (uint64_t)len * 8;
    while (len) {
        size_t n = 64 - ctx->used;
        if (n > len) n = len;
        memcpy(ctx->buf + ctx->used, data, n);
        ctx->used += n; data += n; len -= n;
        if (ctx->used == 64) {
            md5_block(ctx, ctx->buf);
            ctx->used = 0;
        }
    }
}

static void md5_final(MD5_CTX2 *ctx, uint8_t out[16]) {
    uint8_t one = 0x80, zero[64] = {0}, lenb[8];
    uint64_t bits = ctx->len;
    md5_update(ctx, &one, 1);
    size_t pad = (ctx->used <= 56) ? (56 - ctx->used) : (120 - ctx->used);
    md5_update(ctx, zero, pad);
    for (int i = 0; i < 8; i++) lenb[i] = (uint8_t)(bits >> (8 * i));
    md5_update(ctx, lenb, 8);
    for (int i = 0; i < 4; i++) put32le(out + 4 * i, ctx->h[i]);
}

static uint8_t x2(uint8_t a) {
    return (uint8_t)(((a << 1) & 0xff) ^ ((a & 0x80) ? 0x1b : 0));
}

static uint8_t gm(uint8_t a, uint8_t b) {
    uint8_t r = 0;
    while (b) {
        if (b & 1) r ^= a;
        a = x2(a);
        b >>= 1;
    }
    return r;
}

static void expand_key(const uint8_t key[16], uint8_t rk[176]) {
    memcpy(rk, key, 16);
    int i = 16, rc = 0;
    while (i <= 175) {
        uint8_t t[4] = {rk[i - 4], rk[i - 3], rk[i - 2], rk[i - 1]};
        if ((i & 15) == 0) {
            uint8_t tmp = t[0];
            t[0] = t[1]; t[1] = t[2]; t[2] = t[3]; t[3] = tmp;
            for (int j = 0; j < 4; j++) t[j] = sbox[t[j]];
            t[0] ^= rcon[rc++];
        }
        for (int j = 0; j < 4; j++) {
            rk[i] = rk[i - 16] ^ t[j];
            i++;
        }
    }
}

static void inv_shift(uint8_t st[16]) {
    uint8_t t;
    t = st[1]; st[1] = st[13]; st[13] = st[9]; st[9] = st[5]; st[5] = t;
    t = st[2]; st[2] = st[10]; st[10] = t;
    t = st[6]; st[6] = st[14]; st[14] = t;
    t = st[3]; st[3] = st[7]; st[7] = st[11]; st[11] = st[15]; st[15] = t;
}

static void inv_mix(uint8_t st[16]) {
    for (int col = 0; col < 4; col++) {
        int i = col * 4;
        uint8_t a = st[i], b = st[i + 1], c = st[i + 2], d = st[i + 3];
        st[i] = gm(a, 14) ^ gm(b, 11) ^ gm(c, 13) ^ gm(d, 9);
        st[i + 1] = gm(a, 9) ^ gm(b, 14) ^ gm(c, 11) ^ gm(d, 13);
        st[i + 2] = gm(a, 13) ^ gm(b, 9) ^ gm(c, 14) ^ gm(d, 11);
        st[i + 3] = gm(a, 11) ^ gm(b, 13) ^ gm(c, 9) ^ gm(d, 14);
    }
}

static void block_dec(const uint8_t in[16], const uint8_t key[16], uint8_t out[16]) {
    uint8_t rk[176], st[16];
    expand_key(key, rk);
    memcpy(st, in, 16);
    for (int i = 0; i < 16; i++) st[i] ^= rk[160 + i];
    for (int round = 9; round > 0; round--) {
        inv_shift(st);
        for (int i = 0; i < 16; i++) st[i] = inv_sbox[st[i]];
        for (int i = 0; i < 16; i++) st[i] ^= rk[16 * round + i];
        inv_mix(st);
    }
    inv_shift(st);
    for (int i = 0; i < 16; i++) st[i] = inv_sbox[st[i]];
    for (int i = 0; i < 16; i++) out[i] = st[i] ^ rk[i];
}

static void cbc_dec96(const uint8_t in[96], const uint8_t key[16], const uint8_t iv[16], uint8_t out[96]) {
    uint8_t prev[16], dec[16];
    memcpy(prev, iv, 16);
    for (int off = 0; off < 96; off += 16) {
        block_dec(in + off, key, dec);
        for (int i = 0; i < 16; i++) out[off + i] = dec[i] ^ prev[i];
        memcpy(prev, in + off, 16);
    }
}

static int expected(uint8_t op) {
    if ((op >= 1 && op <= 7) || op == 16) return 2;
    if (op == 10) return 1;
    if (op == 8 || op == 9 || (op >= 11 && op <= 15) || op == 17) return 3;
    return -1;
}

static int valid_block(const uint8_t *b) {
    if (!b || b[0] != 0x0f || b[1] != 0x0b || b[3] != 0x5f || b[95] != 0xcc) return 0;
    for (int i = 0; i < 4; i++) {
        if (expected(b[0x10 + i * 16]) != b[0x11 + i * 16]) return 0;
    }
    return 1;
}

static uint8_t *get_block(uint32_t node) {
    if (node >= n_nodes) return NULL;
    if (block_state[node] == 2) return block_cache + (size_t)node * 96;
    if (block_state[node] == 1) return NULL;
    uint32_t off = loff[node] ^ seed;
    if ((uint64_t)off + 96 > data_size) {
        block_state[node] = 1;
        return NULL;
    }
    const uint8_t *raw = ldata + off;
    uint8_t *dst = block_cache + (size_t)node * 96;
    if (node == start_node && valid_block(raw)) {
        memcpy(dst, raw, 96);
    } else {
        uint8_t key[16], iv[16];
        derive_key_iv(node, key, iv);
        cbc_dec96(raw, key, iv, dst);
    }
    if (!valid_block(dst)) {
        block_state[node] = 1;
        return NULL;
    }
    block_state[node] = 2;
    return dst;
}

static uint32_t add_sub(uint32_t a, uint32_t b, int sub) {
    return sub ? a - b : a + b;
}

static int eval_record(uint32_t node, const uint8_t *rec, uint32_t *out) {
    uint8_t op = rec[0], argc = rec[1], flags = rec[2], flags2 = rec[3];
    if (expected(op) != argc) return 0;
    uint32_t a = u32le(rec + 4), b = u32le(rec + 8), c = u32le(rec + 12), n = node, v;
    switch (op) {
    case 1: v = add_sub(n, a, flags & 1) ^ b; break;
    case 2: v = add_sub(a ^ n, b, flags & 1); break;
    case 3: v = b ^ a ^ n; break;
    case 4: v = add_sub(add_sub(n, a, flags & 1), b, (flags >> 1) & 1); break;
    case 5: v = rol32(n, a & 31) ^ b; break;
    case 6: v = add_sub(rol32(n, a & 31), b, flags & 1); break;
    case 7: v = rol32(a ^ n, flags & 31) + b; break;
    case 8: v = c ^ (n * (a | 1) + b); break;
    case 9: v = (b ^ rol32(n + a, flags & 31)) - c; break;
    case 10: v = a; break;
    case 11: { uint32_t t = a ^ n; v = add_sub(b ^ t, c, flags & 1); break; }
    case 12: v = add_sub(add_sub(n, a, flags & 1) ^ b, c, (flags >> 1) & 1); break;
    case 13: v = add_sub(add_sub(n, a, flags & 1), b, (flags >> 1) & 1) ^ c; break;
    case 14: v = c ^ b ^ rol32(n, a & 31); break;
    case 15: v = add_sub(rol32(n, a & 31), b, flags & 1) ^ c; break;
    case 16: v = add_sub(rol32(a ^ n, flags & 31), b, flags2 & 1); break;
    case 17: v = add_sub(b + n * (a | 1), c, flags & 1); break;
    default: return 0;
    }
    *out = v;
    return 1;
}

static int lmsk_bit(uint32_t node) {
    return (lmsk[node >> 3] >> (node & 7)) & 1;
}

static int seek64(FILE *fp, uint64_t off) {
#ifdef _WIN32
    return _fseeki64(fp, (long long)off, SEEK_SET);
#else
    return fseeko(fp, (off_t)off, SEEK_SET);
#endif
}

static FILE *open_challenge(void) {
#ifdef _WIN32
    return _wfopen(L"l4byry\u03b77h", L"rb");
#else
    return fopen("l4byryη7h", "rb");
#endif
}

static void *read_part(FILE *fp, uint64_t off, size_t size) {
    void *p = malloc(size);
    if (!p) {
        fprintf(stderr, "malloc failed: %zu\n", size);
        exit(1);
    }
    if (seek64(fp, off) || fread(p, 1, size, fp) != size) {
        fprintf(stderr, "read failed at %llu size %zu\n", (unsigned long long)off, size);
        exit(1);
    }
    return p;
}

int main(void) {
    FILE *fp = open_challenge();
    if (!fp) {
        perror("open");
        return 1;
    }
    uint8_t hdr[40];
    seek64(fp, OFF_HDR);
    fread(hdr, 1, 40, fp);
    n_nodes = u32le(hdr + 12);
    start_node = u32le(hdr + 16);
    end_node = u32le(hdr + 20);
    seed = u32le(hdr + 28);
    data_size = u32le(hdr + 32);

    uint8_t *text = read_part(fp, TEXT_OFF, TEXT_SIZE);
    MD5_CTX2 md;
    md5_init(&md);
    md5_update(&md, text, TEXT_SIZE);
    md5_final(&md, token);
    free(text);

    seek64(fp, 0x73a0);
    fread(sbox, 1, 256, fp);
    seek64(fp, 0x74a0);
    fread(inv_sbox, 1, 256, fp);
    seek64(fp, 0x75a0);
    fread(rcon, 1, 10, fp);

    loff = read_part(fp, OFF_LOFF, (size_t)n_nodes * 4);
    lmsk = read_part(fp, OFF_LMSK, (n_nodes + 7) / 8);
    ldata = read_part(fp, OFF_LDATA, data_size);
    fclose(fp);

    block_cache = malloc((size_t)n_nodes * 96);
    block_state = calloc(n_nodes, 1);
    uint32_t *queue = malloc((size_t)n_nodes * 4);
    uint32_t *prev = malloc((size_t)n_nodes * 4);
    uint8_t *prev_ch = malloc(n_nodes);
    if (!block_cache || !block_state || !queue || !prev || !prev_ch) {
        fprintf(stderr, "large allocation failed\n");
        return 1;
    }
    memset(prev, 0xff, (size_t)n_nodes * 4);

    printf("start=%#x end=%#x nodes=%#x token=", start_node, end_node, n_nodes);
    for (int i = 0; i < 16; i++) printf("%02x", token[i]);
    printf("\n");

    uint32_t head = 0, tail = 0, seen = 0;
    queue[tail++] = start_node;
    prev[start_node] = start_node;
    const char map[4] = {'w', 's', 'a', 'd'};
    while (head < tail && prev[end_node] == UINT32_MAX) {
        uint32_t node = queue[head++];
        uint8_t *b = get_block(node);
        if (!b) continue;
        if (++seen % 500000 == 0) {
            printf("seen=%u queue=%u cache_valid_unknown=%u\n", seen, tail - head, tail);
            fflush(stdout);
        }
        for (int i = 0; i < 4; i++) {
            uint32_t nxt;
            if (!eval_record(node, b + 0x10 + 16 * i, &nxt) || nxt >= n_nodes) continue;
            if (prev[nxt] != UINT32_MAX) continue;
            uint8_t *nb = get_block(nxt);
            if (!nb) continue;
            if (((nb[2] & 1) ^ lmsk_bit(nxt)) != 0) continue;
            prev[nxt] = node;
            prev_ch[nxt] = (uint8_t)map[i];
            queue[tail++] = nxt;
        }
    }

    if (prev[end_node] == UINT32_MAX) {
        fprintf(stderr, "no path found, visited=%u queued=%u\n", seen, tail);
        return 2;
    }
    size_t len = 0;
    for (uint32_t cur = end_node; cur != start_node; cur = prev[cur]) len++;
    char *path = malloc(len + 1);
    path[len] = 0;
    uint32_t cur = end_node;
    for (size_t i = len; i-- > 0;) {
        path[i] = (char)prev_ch[cur];
        cur = prev[cur];
    }
    uint8_t digest[16];
    md5_init(&md);
    md5_update(&md, (const uint8_t *)path, len);
    md5_final(&md, digest);
    printf("path_len=%zu\npath_md5=", len);
    for (int i = 0; i < 16; i++) printf("%02x", digest[i]);
    printf("\nflag{");
    for (int i = 0; i < 16; i++) printf("%02x", digest[i]);
    printf("}\n");
    FILE *out = fopen("shortest_path.txt", "wb");
    if (out) {
        fwrite(path, 1, len, out);
        fclose(out);
    }
    free(path);
    return 0;
}

```

读出 `limg` 后可得到：

- 节点总数：`0x400000`

- 每块大小：`0x60`

- 起点：`0x33519d`

- 终点：`0x365aa6`

- seed：`0x6260d8d0`

其中 `0x400000 = 4194304`，也就是四百多万个节点。这个规模已经说明两件事：

1. 不可能人工点路径。

2. 题目核心在于恢复图并自动搜索。

如果把它联想到二维迷宫，`0x400000 = 2048 * 2048`，也很像一个 `2048 x 2048` 的超大网格，但实际上程序并不是按二维坐标直接存图，而是按节点编号加规则跳转。

**程序在校验什么**

**main **

这是整个题最该先看的函数。

它的主要调用链如下：

1. `0x401bcf`：安装 `SIGSEGV` 处理器

2. `0x401306`：读取并校验 `limg`

3. `0x401387`：获取 `loff`

4. `0x4013e6`：获取 `ldata`

5. `0x40142b`：获取 `lmsk`

6. `0x401470`：对 `ldata` 起始地址做 `mprotect`

7. `0x4017b7`：读取用户传入的路径文件

8. `0x401588`：把 `WSAD` 字符串打包成 2bit 序列

9. `0x402c50`：初始化运行时状态并启动工作线程

10. `0x405dee`：真正执行路径校验主循环

11. `0x406666`：安装另外两个信号处理器并等待结果

**`0x401306`**

这个函数非常短，但信息量很大。

它直接访问固定地址 `0x40a4a0`，也就是 `limg` 的映射位置，并校验三个字段：

- `DWORD[0] == 0x4d5a4931`

- `DWORD[1] == 0x10000`

- `DWORD[2] == 0x60`

如果通过，就返回 `limg` 指针。

**`0x401512`**

这个函数很关键，因为它直接给出字符到方向编号的映射。

输入是一个字符，输出写到一个字节里。

最终映射是：

- `w/W -> 0`

- `s/S -> 1`

- `a/A -> 2`

- `d/D -> 3`

如果不是这几个字符，就返回失败。

这一步对应题目提示里的 `wasd`。

**`0x402c50`**

这个函数会初始化全局状态，然后启动一个工作线程，线程入口是 `0x4027d0`。

从这里能读出很多全局变量的角色：

- `0x40a140`：当前迷宫运行时上下文

- `0x40a300`：迷宫元数据镜像

- `0x40a2f0` / `0x40a2f4`：线程同步 / 状态标志

这个函数还调用了：

- `0x402436`

- `0x4029fa`

- `0x402af5`

- `0x40248d`

这些是初始化链的一部分，负责检查环境和准备内部结构。

**\`0x4027d0\`：工作线程入口**

这个函数里有一个很关键的循环。

它反复调用：

- `0x40248d`

- `0x40223d`

再结合共享状态更新，很明显这是一个“持续推进迷宫状态”的工作线程。

这条线程和后面的 signal handler 配合，完成整个路径消费过程。

**\`0x406666\`**

这个函数会再安装两个信号处理器：

- 信号 `4` 对应处理函数 `0x406099`

- 信号 `5` 对应处理函数 `0x40634d`

然后把“已安装”标志写到 `0x40a498`。

这意味着真正的校验逻辑，已经不再是一个朴素的 `for path: step(path)`，而是混进了信号驱动。

但对解题来说，我们不需要完全照着信号机制复刻，只要把“每一步怎样从当前节点走到下一节点”还原出来就够了。

**`0x405918`**

这个函数是最重要的结构识别函数之一。

它检查一个 `96` 字节块是否满足：

- `b[0] == 0x0f`

- `b[1] == 0x0b`

- `b[3] == 0x5f`

- `b[0x5f] == 0xcc`

然后还会检查四条记录的 `opcode` 是否合法。

这一步直接告诉我们：

1. 一个节点块大小就是 `0x60`

2. 块里从 `0x10` 开始有 4 条方向记录

3. 只要能解出满足这个格式的块，就说明我们对数据结构理解对了

**`0x4053aa`**

这就是整题最关键的函数之一。

它的参数形式本质上是：

```text
eval_record(current_node, record_ptr, ok_ptr)
```

做的事是：

1. 取 `record[0]` 作为 `opcode`

2. 取 `record[1]` 作为 `argc`

3. 若 `argc != expected_argc(opcode)` 则失败

4. 解析：

    - `record[2]` -> `flags`

    - `record[3]` -> `flags2`

    - `record[4:8]` -> `a`

    - `record[8:12]` -> `b`

    - `record[12:16]` -> `c`

5. 用当前节点编号 `node` 和这些参数算出下一个节点编号

也就是说：

```text
每个方向并不是“存了一个邻居编号”
而是“存了一条由当前 node 推导 next node 的表达式”
```

**0x405a07` 的逻辑**

这个函数非常直接：

```text
byte = lmsk[node >> 3]
bit  = (byte >> (node & 7)) & 1
```

所以 `lmsk` 的角色在这里终于被彻底坐实：

```text
lmsk 就是按节点编号索引的位图。
```

把 `0x405dee` 和 `0x405a07` 放回一起看，可以还原出真实检查：

```text
((next_block[2] & 1) ^ lmsk_bit(nxt)) == 0
```

这里要注意，参与检查的是：

- `nxt` 对应块里的某一位；

- 以及 `lmsk` 里 `nxt` 对应的一位。

所以到这一步，单步转移规则已经完整了：



1. 当前块按方向选中一条 16 字节记录；

2. `eval_record(cur, rec)` 算出候选 `nxt`；

3. 取 `nxt` 对应块；

4. 再检查 `((next_block[2] & 1) ^ lmsk_bit(nxt)) == 0`；

5. 通过了，`nxt` 才是真正可走的邻居。

**`0x404027`**** **

它会先读一段 16 字节 token，然后把：

- token 的四个 `uint32_t`

- 当前节点编号 `node`

- 若干固定常量

混在一起，最后生成 8 个 `uint32_t`。

其中：

- 前 4 个写成 `key[16]`

- 后 4 个写成 `iv[16]`

所以这里的结论非常明确：

```text
每个节点都有自己独立的 key/iv；
块解密参数不是全局固定的。
```

这也就解释了为什么不能对整个 `ldata` 统一做一次解密。

看完 `0x404027` 后，问题马上缩成一句话：

```text
那 16 字节 token 是谁写进去的？
```

如果 token 来源不清楚，`derive_key_iv` 就还差最后一块拼图。

继续找 token 的写入位置，会看到一整套很典型的 MD5 代码，尤其是这些常量非常扎眼：

- `0xd76aa478`

- `0x242070db`

- `0x4787c62a`

- `0x698098d8`

这些常量一出现，基本可以直接判定是 MD5 实现。

**最后确认下来的 token**

继续往前后对，就能确认它是对可执行部分做了一次 MD5，得到：

```text
4d7b8b3068ba7f7263e9dc35fc1e76e2
```

这个 16 字节结果再被喂给 `0x404027`，参与每节点 `key/iv` 派生。

我在求解器里验证时，等价实现为：

- 对文件偏移 `0x1000`

- 长度 `0x5855`

这一段做 MD5，得到相同 token。

**一开始为什么会先怀疑 AES-CBC**

看到这里时，特征已经非常像标准做法了：

- 每个节点都有 `key`

- 每个节点都有 `iv`

- 每个节点块大小是 `0x60 = 6 * 16`

所以第一反应自然是：

```text
这像 AES-CBC 解 6 个 16 字节块。
```

**标准 AES 为什么很快被排除**

如果是标准 AES，那么：

1. `off` 正确；

2. `key/iv` 正确；

3. 解出来的明文块应该立刻满足 `0x405918`。

但实际测试下来不对，绝大多数块解出来仍然通不过：

- `b[0] == 0x0f`

- `b[1] == 0x0b`

- `b[3] == 0x5f`

- `b[95] == 0xcc`

这说明还有一层假设错了。

**最后是怎么锁定“自定义 S-box AES-like CBC”的**

继续跟解密轮函数，再去看相关查表，会发现程序里确实有：

- `sbox`

- `inv_sbox`

- `rcon`

这套结构和 AES 很像，但表内容不是标准 AES 的表。

所以最终结论是：

```text
它保留了 AES 的整体框架；
但 S-box / inverse S-box 是自定义的；
模式上仍然是 CBC；
本质上是一个 AES-like CBC。
```

另外还有一个细节要注意：

- 起点节点块本身就是明文；

- 其他大量节点块需要按节点号派生 `key/iv` 后解密。

这也是为什么如果只抽样看起点附近，容易误以为 `ldata` 里全是明文块。

把前面所有结论合在一起，当前节点 `node` 的四个邻居生成规则就是：

1. `off = loff[node] ^ seed`

2. `raw = ldata + off`

3. 如果不是起点块，则按 `node` 派生 `key/iv`

4. 用自定义 S-box 的 AES-like CBC 解出 `plain[0x60]`

5. `plain` 必须通过 `0x405918` 的合法块检查

6. 对于四个方向 `dir = 0..3`：

    - `record = plain + 0x10 + dir * 0x10`

    - `nxt = eval_record(node, record)`

    - 取 `nxt` 的节点块

    - 再检查 `((next_block[2] & 1) ^ lmsk_bit(nxt)) == 0`

7. 通过检查的 `nxt` 才是合法邻居

```c++
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <wchar.h>
#endif

#define OFF_HDR 0x94a0ULL
#define OFF_LOFF 0x94d0ULL
#define OFF_LMSK 0x10094d0ULL
#define OFF_LDATA 0x10894d0ULL
#define TEXT_OFF 0x1000ULL
#define TEXT_SIZE 0x5855ULL
#define MASK 0xffffffffu

static uint8_t sbox[256], inv_sbox[256], rcon[10];
static uint8_t token[16];
static uint32_t seed, n_nodes, start_node, end_node, data_size;
static uint32_t *loff;
static uint8_t *lmsk, *ldata;
static uint8_t *block_cache;
static uint8_t *block_state; /* 0 unknown, 1 invalid, 2 valid */

static uint32_t rol32(uint32_t x, unsigned n) {
    n &= 31;
    return (x << n) | (x >> (32 - n));
}

static uint32_t u32le(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void put32le(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static uint32_t md5_mix(uint32_t x) {
    x ^= rol32(x, 7);
    x *= 0x9e3779b1u;
    x ^= rol32(x, 13);
    x *= 0x85ebca77u;
    x ^= x >> 16;
    return x;
}

static void derive_key_iv(uint32_t node, uint8_t key[16], uint8_t iv[16]) {
    uint32_t a = u32le(token), b = u32le(token + 4), c = u32le(token + 8), d = u32le(token + 12);
    uint32_t w[8];
    uint32_t n = node;
    w[0] = md5_mix(a ^ n ^ 0x243f6a88u);
    w[1] = md5_mix(rol32(n, 7) + b - 0x7a5cf72du);
    w[2] = md5_mix(n * 0x9e3779b1u ^ c ^ 0x13198a2eu);
    w[3] = md5_mix((n ^ 0xdeadbeefu) + d + 0x03707344u);
    w[4] = md5_mix(rol32(n, 13) ^ c ^ 0xa4093822u);
    w[5] = md5_mix(rol32(n, 3) + d + 0x299f31d0u);
    w[6] = md5_mix(n * 0x7f4a7c15u ^ a ^ 0x082efa98u);
    w[7] = md5_mix((n ^ 0xbaadf00du) + b - 0x13b19377u);
    for (int i = 0; i < 4; i++) {
        put32le(key + 4 * i, w[i]);
        put32le(iv + 4 * i, w[i + 4]);
    }
}

/* Minimal MD5, public-domain style implementation for one-shot hashing. */
typedef struct {
    uint32_t h[4];
    uint64_t len;
    uint8_t buf[64];
    size_t used;
} MD5_CTX2;

static uint32_t md5_k[64] = {
    0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
    0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,
    0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
    0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
    0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
    0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
    0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
    0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391
};

static uint8_t md5_s[64] = {
    7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,
    5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,
    4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,
    6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21
};

static void md5_block(MD5_CTX2 *ctx, const uint8_t b[64]) {
    uint32_t m[16], a = ctx->h[0], c = ctx->h[2], d = ctx->h[3], bb = ctx->h[1];
    for (int i = 0; i < 16; i++) m[i] = u32le(b + 4 * i);
    for (int i = 0; i < 64; i++) {
        uint32_t f, g;
        if (i < 16) { f = (bb & c) | (~bb & d); g = i; }
        else if (i < 32) { f = (d & bb) | (~d & c); g = (5 * i + 1) & 15; }
        else if (i < 48) { f = bb ^ c ^ d; g = (3 * i + 5) & 15; }
        else { f = c ^ (bb | ~d); g = (7 * i) & 15; }
        uint32_t tmp = d;
        d = c;
        c = bb;
        bb += rol32(a + f + md5_k[i] + m[g], md5_s[i]);
        a = tmp;
    }
    ctx->h[0] += a; ctx->h[1] += bb; ctx->h[2] += c; ctx->h[3] += d;
}

static void md5_init(MD5_CTX2 *ctx) {
    ctx->h[0] = 0x67452301; ctx->h[1] = 0xefcdab89; ctx->h[2] = 0x98badcfe; ctx->h[3] = 0x10325476;
    ctx->len = 0; ctx->used = 0;
}

static void md5_update(MD5_CTX2 *ctx, const uint8_t *data, size_t len) {
    ctx->len += (uint64_t)len * 8;
    while (len) {
        size_t n = 64 - ctx->used;
        if (n > len) n = len;
        memcpy(ctx->buf + ctx->used, data, n);
        ctx->used += n; data += n; len -= n;
        if (ctx->used == 64) {
            md5_block(ctx, ctx->buf);
            ctx->used = 0;
        }
    }
}

static void md5_final(MD5_CTX2 *ctx, uint8_t out[16]) {
    uint8_t one = 0x80, zero[64] = {0}, lenb[8];
    uint64_t bits = ctx->len;
    md5_update(ctx, &one, 1);
    size_t pad = (ctx->used <= 56) ? (56 - ctx->used) : (120 - ctx->used);
    md5_update(ctx, zero, pad);
    for (int i = 0; i < 8; i++) lenb[i] = (uint8_t)(bits >> (8 * i));
    md5_update(ctx, lenb, 8);
    for (int i = 0; i < 4; i++) put32le(out + 4 * i, ctx->h[i]);
}

static uint8_t x2(uint8_t a) {
    return (uint8_t)(((a << 1) & 0xff) ^ ((a & 0x80) ? 0x1b : 0));
}

static uint8_t gm(uint8_t a, uint8_t b) {
    uint8_t r = 0;
    while (b) {
        if (b & 1) r ^= a;
        a = x2(a);
        b >>= 1;
    }
    return r;
}

static void expand_key(const uint8_t key[16], uint8_t rk[176]) {
    memcpy(rk, key, 16);
    int i = 16, rc = 0;
    while (i <= 175) {
        uint8_t t[4] = {rk[i - 4], rk[i - 3], rk[i - 2], rk[i - 1]};
        if ((i & 15) == 0) {
            uint8_t tmp = t[0];
            t[0] = t[1]; t[1] = t[2]; t[2] = t[3]; t[3] = tmp;
            for (int j = 0; j < 4; j++) t[j] = sbox[t[j]];
            t[0] ^= rcon[rc++];
        }
        for (int j = 0; j < 4; j++) {
            rk[i] = rk[i - 16] ^ t[j];
            i++;
        }
    }
}

static void inv_shift(uint8_t st[16]) {
    uint8_t t;
    t = st[1]; st[1] = st[13]; st[13] = st[9]; st[9] = st[5]; st[5] = t;
    t = st[2]; st[2] = st[10]; st[10] = t;
    t = st[6]; st[6] = st[14]; st[14] = t;
    t = st[3]; st[3] = st[7]; st[7] = st[11]; st[11] = st[15]; st[15] = t;
}

static void inv_mix(uint8_t st[16]) {
    for (int col = 0; col < 4; col++) {
        int i = col * 4;
        uint8_t a = st[i], b = st[i + 1], c = st[i + 2], d = st[i + 3];
        st[i] = gm(a, 14) ^ gm(b, 11) ^ gm(c, 13) ^ gm(d, 9);
        st[i + 1] = gm(a, 9) ^ gm(b, 14) ^ gm(c, 11) ^ gm(d, 13);
        st[i + 2] = gm(a, 13) ^ gm(b, 9) ^ gm(c, 14) ^ gm(d, 11);
        st[i + 3] = gm(a, 11) ^ gm(b, 13) ^ gm(c, 9) ^ gm(d, 14);
    }
}

static void block_dec(const uint8_t in[16], const uint8_t key[16], uint8_t out[16]) {
    uint8_t rk[176], st[16];
    expand_key(key, rk);
    memcpy(st, in, 16);
    for (int i = 0; i < 16; i++) st[i] ^= rk[160 + i];
    for (int round = 9; round > 0; round--) {
        inv_shift(st);
        for (int i = 0; i < 16; i++) st[i] = inv_sbox[st[i]];
        for (int i = 0; i < 16; i++) st[i] ^= rk[16 * round + i];
        inv_mix(st);
    }
    inv_shift(st);
    for (int i = 0; i < 16; i++) st[i] = inv_sbox[st[i]];
    for (int i = 0; i < 16; i++) out[i] = st[i] ^ rk[i];
}

static void cbc_dec96(const uint8_t in[96], const uint8_t key[16], const uint8_t iv[16], uint8_t out[96]) {
    uint8_t prev[16], dec[16];
    memcpy(prev, iv, 16);
    for (int off = 0; off < 96; off += 16) {
        block_dec(in + off, key, dec);
        for (int i = 0; i < 16; i++) out[off + i] = dec[i] ^ prev[i];
        memcpy(prev, in + off, 16);
    }
}

static int expected(uint8_t op) {
    if ((op >= 1 && op <= 7) || op == 16) return 2;
    if (op == 10) return 1;
    if (op == 8 || op == 9 || (op >= 11 && op <= 15) || op == 17) return 3;
    return -1;
}

static int valid_block(const uint8_t *b) {
    if (!b || b[0] != 0x0f || b[1] != 0x0b || b[3] != 0x5f || b[95] != 0xcc) return 0;
    for (int i = 0; i < 4; i++) {
        if (expected(b[0x10 + i * 16]) != b[0x11 + i * 16]) return 0;
    }
    return 1;
}

static uint8_t *get_block(uint32_t node) {
    if (node >= n_nodes) return NULL;
    if (block_state[node] == 2) return block_cache + (size_t)node * 96;
    if (block_state[node] == 1) return NULL;
    uint32_t off = loff[node] ^ seed;
    if ((uint64_t)off + 96 > data_size) {
        block_state[node] = 1;
        return NULL;
    }
    const uint8_t *raw = ldata + off;
    uint8_t *dst = block_cache + (size_t)node * 96;
    if (node == start_node && valid_block(raw)) {
        memcpy(dst, raw, 96);
    } else {
        uint8_t key[16], iv[16];
        derive_key_iv(node, key, iv);
        cbc_dec96(raw, key, iv, dst);
    }
    if (!valid_block(dst)) {
        block_state[node] = 1;
        return NULL;
    }
    block_state[node] = 2;
    return dst;
}

static uint32_t add_sub(uint32_t a, uint32_t b, int sub) {
    return sub ? a - b : a + b;
}

static int eval_record(uint32_t node, const uint8_t *rec, uint32_t *out) {
    uint8_t op = rec[0], argc = rec[1], flags = rec[2], flags2 = rec[3];
    if (expected(op) != argc) return 0;
    uint32_t a = u32le(rec + 4), b = u32le(rec + 8), c = u32le(rec + 12), n = node, v;
    switch (op) {
    case 1: v = add_sub(n, a, flags & 1) ^ b; break;
    case 2: v = add_sub(a ^ n, b, flags & 1); break;
    case 3: v = b ^ a ^ n; break;
    case 4: v = add_sub(add_sub(n, a, flags & 1), b, (flags >> 1) & 1); break;
    case 5: v = rol32(n, a & 31) ^ b; break;
    case 6: v = add_sub(rol32(n, a & 31), b, flags & 1); break;
    case 7: v = rol32(a ^ n, flags & 31) + b; break;
    case 8: v = c ^ (n * (a | 1) + b); break;
    case 9: v = (b ^ rol32(n + a, flags & 31)) - c; break;
    case 10: v = a; break;
    case 11: { uint32_t t = a ^ n; v = add_sub(b ^ t, c, flags & 1); break; }
    case 12: v = add_sub(add_sub(n, a, flags & 1) ^ b, c, (flags >> 1) & 1); break;
    case 13: v = add_sub(add_sub(n, a, flags & 1), b, (flags >> 1) & 1) ^ c; break;
    case 14: v = c ^ b ^ rol32(n, a & 31); break;
    case 15: v = add_sub(rol32(n, a & 31), b, flags & 1) ^ c; break;
    case 16: v = add_sub(rol32(a ^ n, flags & 31), b, flags2 & 1); break;
    case 17: v = add_sub(b + n * (a | 1), c, flags & 1); break;
    default: return 0;
    }
    *out = v;
    return 1;
}

static int lmsk_bit(uint32_t node) {
    return (lmsk[node >> 3] >> (node & 7)) & 1;
}

static int seek64(FILE *fp, uint64_t off) {
#ifdef _WIN32
    return _fseeki64(fp, (long long)off, SEEK_SET);
#else
    return fseeko(fp, (off_t)off, SEEK_SET);
#endif
}

static FILE *open_challenge(void) {
#ifdef _WIN32
    return _wfopen(L"l4byry\u03b77h", L"rb");
#else
    return fopen("l4byryη7h", "rb");
#endif
}

static void *read_part(FILE *fp, uint64_t off, size_t size) {
    void *p = malloc(size);
    if (!p) {
        fprintf(stderr, "malloc failed: %zu\n", size);
        exit(1);
    }
    if (seek64(fp, off) || fread(p, 1, size, fp) != size) {
        fprintf(stderr, "read failed at %llu size %zu\n", (unsigned long long)off, size);
        exit(1);
    }
    return p;
}

int main(void) {
    FILE *fp = open_challenge();
    if (!fp) {
        perror("open");
        return 1;
    }
    uint8_t hdr[40];
    seek64(fp, OFF_HDR);
    fread(hdr, 1, 40, fp);
    n_nodes = u32le(hdr + 12);
    start_node = u32le(hdr + 16);
    end_node = u32le(hdr + 20);
    seed = u32le(hdr + 28);
    data_size = u32le(hdr + 32);

    uint8_t *text = read_part(fp, TEXT_OFF, TEXT_SIZE);
    MD5_CTX2 md;
    md5_init(&md);
    md5_update(&md, text, TEXT_SIZE);
    md5_final(&md, token);
    free(text);

    seek64(fp, 0x73a0);
    fread(sbox, 1, 256, fp);
    seek64(fp, 0x74a0);
    fread(inv_sbox, 1, 256, fp);
    seek64(fp, 0x75a0);
    fread(rcon, 1, 10, fp);

    loff = read_part(fp, OFF_LOFF, (size_t)n_nodes * 4);
    lmsk = read_part(fp, OFF_LMSK, (n_nodes + 7) / 8);
    ldata = read_part(fp, OFF_LDATA, data_size);
    fclose(fp);

    block_cache = malloc((size_t)n_nodes * 96);
    block_state = calloc(n_nodes, 1);
    uint32_t *queue = malloc((size_t)n_nodes * 4);
    uint32_t *prev = malloc((size_t)n_nodes * 4);
    uint8_t *prev_ch = malloc(n_nodes);
    if (!block_cache || !block_state || !queue || !prev || !prev_ch) {
        fprintf(stderr, "large allocation failed\n");
        return 1;
    }
    memset(prev, 0xff, (size_t)n_nodes * 4);

    printf("start=%#x end=%#x nodes=%#x token=", start_node, end_node, n_nodes);
    for (int i = 0; i < 16; i++) printf("%02x", token[i]);
    printf("\n");

    uint32_t head = 0, tail = 0, seen = 0;
    queue[tail++] = start_node;
    prev[start_node] = start_node;
    const char map[4] = {'w', 's', 'a', 'd'};
    while (head < tail && prev[end_node] == UINT32_MAX) {
        uint32_t node = queue[head++];
        uint8_t *b = get_block(node);
        if (!b) continue;
        if (++seen % 500000 == 0) {
            printf("seen=%u queue=%u cache_valid_unknown=%u\n", seen, tail - head, tail);
            fflush(stdout);
        }
        for (int i = 0; i < 4; i++) {
            uint32_t nxt;
            if (!eval_record(node, b + 0x10 + 16 * i, &nxt) || nxt >= n_nodes) continue;
            if (prev[nxt] != UINT32_MAX) continue;
            uint8_t *nb = get_block(nxt);
            if (!nb) continue;
            if (((nb[2] & 1) ^ lmsk_bit(nxt)) != 0) continue;
            prev[nxt] = node;
            prev_ch[nxt] = (uint8_t)map[i];
            queue[tail++] = nxt;
        }
    }

    if (prev[end_node] == UINT32_MAX) {
        fprintf(stderr, "no path found, visited=%u queued=%u\n", seen, tail);
        return 2;
    }
    size_t len = 0;
    for (uint32_t cur = end_node; cur != start_node; cur = prev[cur]) len++;
    char *path = malloc(len + 1);
    path[len] = 0;
    uint32_t cur = end_node;
    for (size_t i = len; i-- > 0;) {
        path[i] = (char)prev_ch[cur];
        cur = prev[cur];
    }
    uint8_t digest[16];
    md5_init(&md);
    md5_update(&md, (const uint8_t *)path, len);
    md5_final(&md, digest);
    printf("path_len=%zu\npath_md5=", len);
    for (int i = 0; i < 16; i++) printf("%02x", digest[i]);
    printf("\nflag{");
    for (int i = 0; i < 16; i++) printf("%02x", digest[i]);
    printf("}\n");
    FILE *out = fopen("shortest_path.txt", "wb");
    if (out) {
        fwrite(path, 1, len, out);
        fclose(out);
    }
    free(path);
    return 0;
}

```

flag{4d718320e7f0610cf9fd766f5ca831cf}





# rev-ai-can-do

题目

![Image](https://internal-api-drive-stream.feishu.cn/space/api/box/stream/download/authcode/?code=MjkyNTVjMTRiMDQ4NjdkNzE3ZTY5MTNiNzJlOTk5NTZfMDdiMTI2MjUzN2I2YjM0Mzc2M2JjMTU1Yjg2Yzg1NmFfSUQ6NzY0ODIxOTg1MjY0NTM1NDcxMV8xNzgxMDg2MDM1OjE3ODExNzI0MzVfVjM)

这题表面是一个APK，实际是一个Tauri Android应用

Java层主要是壳和WebView桥接，前端是React页面，核心协议，签名，请求发送都在libmsg_lib.so里

AndroidManifest.xml 里包名是 com.ctf，主 Activity 是 com.ctf.MainActivity，只申请了 INTERNET，并且usesCleartextTraffic=false，说明正常通信走 HTTPS。

![Image](https://internal-api-drive-stream.feishu.cn/space/api/box/stream/download/authcode/?code=MTE0NmJhMzAwZDNmYzY4MDM5MTM1YzE1NWVlNWJiZjZfMjVjNDliZWI2YWRlYWQ5Y2I1NDgxMWY4ZGRkYWM3MjdfSUQ6NzY0ODk4MDIwODU3MzQ1MTQ0Ml8xNzgxMDg2MDM1OjE3ODExNzI0MzVfVjM)

MainActivity 本身没有业务逻辑，只是做窗口/主题初始化，然后调用 super.onCreate()。真正的 Tauri/Wry 初始化在父类里。

![Image](https://internal-api-drive-stream.feishu.cn/space/api/box/stream/download/authcode/?code=YWY3MDE3YzRmMmIzMmMwOTFmYjhkNDUwZTE1NDA4Y2ZfY2M4NzEwNDI2MWI0YjY2ZmJiMzdlY2YwMGZjNDczZGNfSUQ6NzY0ODk4MDc1NjU1MDgzMTMzN18xNzgxMDg2MDM1OjE3ODExNzI0MzVfVjM)

WryActivity 负责 WebView 生命周期，并把 Activity 生命周期同步给 native：

```c++
Rust.onActivityCreate(this);
  Rust.onActivityDestroy(this);
  Rust.onActivityLowMemory();
  Rust.onNewIntent(intent);
  Rust.onWindowFocusChanged(this, z2);
```

![Image](https://internal-api-drive-stream.feishu.cn/space/api/box/stream/download/authcode/?code=OWFhZjk5MzViYWZiNGQ5NmU2MDkzY2U1YjQ3MDdiMjBfM2M1YTEwZTdkZWE0NTk1MGM2NTI3NWFhOWEwYjZhZTJfSUQ6NzY0ODk4MTc5MDgwMzQ3OTUwNV8xNzgxMDg2MDM1OjE3ODExNzI0MzVfVjM)

WryLifecycleObserver 进一步把 Android 生命周期转成 Rust 层事件：

```c++
Rust.create();
  Rust.wryCreate();
  Rust.start();
  Rust.resume();
  Rust.pause();
  Rust.stop();
```

![Image](https://internal-api-drive-stream.feishu.cn/space/api/box/stream/download/authcode/?code=ZjM4Njc2MWY1NjJmNDg3MjIxNTg3M2Y5YTIxMjg4MzZfYzNhOGIyYTgwZGE0OWJiZDcxOWQxMTEzYjVhMzMxMjlfSUQ6NzY0ODk4MjE2NzMxMzUxNzc0N18xNzgxMDg2MDM1OjE3ODExNzI0MzVfVjM)

最关键的是 Rust.java：

```c++
static {
   System.loadLibrary("msg_lib");
}
```

这里加载 libmsg_lib.so。Java 只声明 native 方法，比如：

```c++
Rust.ipc(...)
Rust.handleRequest(...)
Rust.shouldOverride(...)
Rust.assetLoaderDomain(...)
```

![Image](https://internal-api-drive-stream.feishu.cn/space/api/box/stream/download/authcode/?code=ZjRjMTdhNmU4OTBhNTgxYmExZGZlMDNlNGZkNjNkNWNfN2E1MGZlMzdmZDYyZTY0NWYwZjcyMmNlNDdiZDdiZTVfSUQ6NzY0ODk4MjY3NjQxMDIyMzgxNl8xNzgxMDg2MDM1OjE3ODExNzI0MzVfVjM)

也就是说 Java 层不是签名算法所在位置，它只是把 WebView、资源请求、IPC 消息交给 native。

Ipc.java 是 JS 到 native 的桥：

```java
**package** com.ctf;
**import** android.webkit.JavascriptInterface;
*/* JADX INFO: loaded from: classes.dex */*
**public** **final** **class** Ipc {
    */* JADX INFO: renamed from: a, reason: collision with root package name */*
    **public** **final** RustWebView f2242a;
    */* JADX INFO: renamed from: b, reason: collision with root package name */*
    **public** **final** RustWebViewClient f2243b;
    **public** Ipc(RustWebView rustWebView, RustWebViewClient rustWebViewClient) {
        A1.e.e("webView", rustWebView);
        A1.e.e("webViewClient", rustWebViewClient);
        **this**.f2242a = rustWebView;
        **this**.f2243b = rustWebViewClient;
    }
    @JavascriptInterface
    **public** **final** **void** postMessage(String str) {
        **if** (str != **null**) {
            Rust.ipc(**this**.f2242a.getId(), **this**.f2243b.f2268b, str);
        }
    }
}
```

前端调用 window.**TAURI_INTERNALS**.invoke(...) 后，消息最终会通过这个 IPC 进入 Rust 层。

前端逻辑从 libmsg_lib.so 里提取出的前端资源是 Tauri + React。页面非常简单，默认服务地址是：

```c++
https://msg.ctf.local:8443
```

只有两个按钮：

```c++
await invoke("register", {
    baseUrl,
    username,
    password
  });
```

```c++
await invoke("get_flag", {
    baseUrl
  });
```

SO 层逻辑libmsg_lib.so 才是核心。IDA 里能看到两个主要 command：

```c++
- cmd_register_main
 - cmd_get_flag_main
```

register 流程大概是：

1. 解析前端传入的 baseUrl / username / password

2. 请求 /nonce

3. 用 nonce、用户名、密码、设备/环境信息生成签名材料

4. 构造 /register 请求

5. 带上 body 和 header 发 HTTPS 请求

请求结构大致是：

```c++
POST /register
 Content-Type: application/json
 x-di: <base64 json>
 x-vm: <base64 128 bytes>
```

body 类似：

```json
{
    "cs": "...",
    "ds": "...",
    "it": "...",
    "n": "...",
    "u": "username",
    "p": "password"
}
```

get_flag 类似，也是先走 /nonce，再请求 /secret：

```c++
POST /secret
 Content-Type: application/json
 x-di: <base64 json>
```

body 没有用户名密码：

```json
{
    "cs": "...",
    "ds": "...",
    "it": "...",
    "n": "..." 
}
```

SO层还有x-di、x-vm、sig_vm、TLS、证书校验、cert pin mismatch、/proc/self/maps等，说明so里不只是签名，还有环境检测和TLS校验逻辑

相关函数说明

```c++
sig_vm / sig_vm_tail 负责签名材料，
url_or_body_helper 负责把材料落成 X-DI/X-VM，
net_url_tls + net_build_send 负责 HTTPS 发送与证书校验，
/proc/self/maps + frida + 27042 负责环境检查，
```

最开始的时候尝试Frida hook、patch证书校验、TLS MITM抓包时，服务端返回:

```c++
{"e":"invalid cs"}
```

这不是请求格式错，而是签名材料被污染。so 会检测运行环境，比如 Frida、maps、调试状态、证书环境等。一旦环境变化，Rust 生成的 cs 就和服务端预期不一致。

所以最终思路不是逆完整签名算法，而是把原 App 当签名 oracle：

网络部分用透明 TCP relay：

```c++
python tcp_relay.py --bind 127.0.0.1 --port 39994 --remote-host 60.205.163.215 --remote-port 57743
```

```python
import argparse
import socket
import threading

def pipe(src: socket.socket, dst: socket.socket, tag: str) -> None:
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
    except OSError as exc:
        print(f"[pipe {tag}] {type(exc).__name__}: {exc}", flush=True)
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass

def handle(client: socket.socket, addr, remote_host: str, remote_port: int) -> None:
    print(f"[conn] {addr[0]}:{addr[1]} -> {remote_host}:{remote_port}", flush=True)
    try:
        remote = socket.create_connection((remote_host, remote_port), timeout=8)
    except OSError as exc:
        print(f"[connect.error] {type(exc).__name__}: {exc}", flush=True)
        client.close()
        return

    threading.Thread(target=pipe, args=(client, remote, "c2s"), daemon=True).start()
    threading.Thread(target=pipe, args=(remote, client, "s2c"), daemon=True).start()

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--bind", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=39994)
    ap.add_argument("--remote-host", default="60.205.163.215")
    ap.add_argument("--remote-port", type=int, default=10857)
    args = ap.parse_args()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((args.bind, args.port))
    srv.listen(64)
    print(
        f"[listen] {args.bind}:{args.port} -> {args.remote_host}:{args.remote_port}",
        flush=True,
    )
    while True:
        client, addr = srv.accept()
        threading.Thread(
            target=handle,
            args=(client, addr, args.remote_host, args.remote_port),
            daemon=True,
        ).start()

if __name__ == "__main__":
    raise SystemExit(main())

```

设备 hosts：

```c++
127.0.0.1 msg.ctf.local
```

ADB reverse：

```c++
adb reverse tcp:8443 tcp:39994
```

这样app访问的是：

```c++
https://msg.ctf.local:8443
```

但实际字节流被透明转发到远端 60.205.163.215:57743。relay 不解 TLS，所以不会破坏证书校验和签名环境。

这样做的关键前提，是先拿到 WebView页面的执行权。

这一步是通过 WebView DevTools 完成的。应用本身是一个 Tauri Android 包装壳，界面内容本质上就是一个 WebView 加载的前端页面。只要临时打开：

```c++
android.webkit.WebView.setWebContentsDebuggingEnabled(true)
```

系统就会暴露一个类似 webview_devtools_remote_<pid> 的本地调试端口。把它通过 adb forward 转发到宿主机之后，就可以像调试Chrome 页面一样，通过 CDP 连接到这一个 WebView 页面。连上之后，请求 http://127.0.0.1:9222/json可以看到当前页面信息，其中 URL 是：http://tauri.localhost/

拿到页面上下文之后，问题就简单很多了。因为前端 JS 中本来就暴露了：

```c++
window.**TAURI_INTERNALS**.invoke(...)
```

而且解包后的 index.js 里可以直接看到，React 页面中的两个按钮最终就是调用：

```c++
window.**TAURI_INTERNALS**.invoke("register", { baseUrl, username, password })
```

```c++
window.**TAURI_INTERNALS**.invoke("get_flag", { baseUrl })
```

也就是说，前端按钮本身并没有实现签名算法，它只是把参数交给 Tauri IPC，后面再进入 native command。

所以最后采用的办法是：先只用一次 Frida 打开WebView.setWebContentsDebuggingEnabled(true)，随后立即 detach 并关闭frida-server，把进程恢复到“无 Frida 痕迹”的状态，就可以通过 CDP 的 Runtime.evaluate 在页面上下文执行 JavaScript。由于页面里本来就有 window.**TAURI_INTERNALS**，所以我不需要自己伪造 IPC 包，也不需要重写 cs/ds/it/x-di/x-vm 的生成逻辑，只要批量执行：

```c++
await window.__TAURI_INTERNALS__.invoke("register", {
    baseUrl: "https://msg.ctf.local:8443",
    username: "bulk_unique_xxx",
    password: "p"
  });
```

但用户名不能唯一，通过注册10000次，拿到flag

![Image](https://internal-api-drive-stream.feishu.cn/space/api/box/stream/download/authcode/?code=ZDRhMDA4Y2Y4ZWUzNDkwYTEwZWQ1ODNkNDRhMzM0MjJfZTllMzExNjFhZWVmNGVjMjhjYzYxZmUxOTEyOWU4MTZfSUQ6NzY0ODI5NTI3NTY3Njk5NDc5Nl8xNzgxMDg2MDM1OjE3ODExNzI0MzVfVjM)

