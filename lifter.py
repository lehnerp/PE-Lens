"""
Approximate x86/x64 -> pseudo-C reconstruction.

This is a readability aid, not a full decompiler. What it does:
  * builds the function's control-flow graph from decoded instructions
  * turns instructions into C-like statements (stack slots become local_XX/arg_N,
    imports become API names, pointers to strings become string literals)
  * recovers call arguments (x86 pushes, x64 rcx/rdx/r8/r9 + stack slots)
  * folds cmp/test + jcc into conditions
  * structures if / if-else / loops where the shape is clean, and falls back to
    goto + labels where it isn't
What it does not do: type recovery, data-flow simplification across blocks,
calling-convention inference, switch tables. For that use angr/Ghidra.

The lifter works on a neutral instruction format so it can be tested without
capstone:
  {"a": addr, "n": size, "m": mnemonic, "text": op_str,
   "kind": "call" | "jmp" | "jcc" | "ret" | "halt" | None, "tgt": int | None,
   "ops": [ {"t": "reg", "reg": "eax", "size": 4}
          | {"t": "imm", "v": 0x10, "size": 4}
          | {"t": "mem", "base": "ebp", "index": None, "scale": 1, "disp": -8,
             "size": 4, "abs": None (absolute/rip-relative address if any)} ]}

The ctx object supplies: is64, label(va), import_name(va), string_at(va) ->
(text, enc) | None, is_func(va), comment(va).
"""
import re
from collections import defaultdict

SIZE_T = {1: "uint8_t", 2: "uint16_t", 4: "uint32_t", 8: "uint64_t", 16: "__m128i", 32: "__m256i"}

_FAM = {
    "a": "rax eax ax al ah", "b": "rbx ebx bx bl bh", "c": "rcx ecx cx cl ch",
    "d": "rdx edx dx dl dh", "si": "rsi esi si sil", "di": "rdi edi di dil",
    "bp": "rbp ebp bp bpl", "sp": "rsp esp sp spl",
}
FAM = {r: f for f, regs in _FAM.items() for r in regs.split()}
X64_ARG_SLOT = {"c": 0, "d": 1, "r8": 2, "r9": 3}
X64_ARG_NAME = ["rcx", "rdx", "r8", "r9"]
CALLEE_SAVED = {"b", "si", "di", "bp", "r12", "r13", "r14", "r15"}
PURE_WRITE = {"mov", "movzx", "movsx", "movsxd", "lea", "movabs", "pop", "movd", "movq"}

ALU = {"add": "+=", "sub": "-=", "and": "&=", "or": "|=", "xor": "^=", "shl": "<<=",
       "sal": "<<=", "shr": ">>=", "imul": "*="}
REL = {"je": "==", "jz": "==", "jne": "!=", "jnz": "!=", "jl": "<", "jnge": "<",
       "jle": "<=", "jng": "<=", "jg": ">", "jnle": ">", "jge": ">=", "jnl": ">=",
       "jb": "<u", "jc": "<u", "jnae": "<u", "jbe": "<=u", "jna": "<=u", "ja": ">u",
       "jnbe": ">u", "jae": ">=u", "jnb": ">=u", "jnc": ">=u", "js": "<0", "jns": ">=0"}
NEGJ = {"je": "jne", "jz": "jnz", "jl": "jge", "jle": "jg", "jb": "jae", "jbe": "ja",
        "js": "jns", "jc": "jnc", "jo": "jno", "jp": "jnp", "jnge": "jnl", "jng": "jnle",
        "jnae": "jnb", "jna": "jnbe"}
NEGJ.update({v: k for k, v in list(NEGJ.items())})


def fam(reg):
    reg = (reg or "").lower()
    m = re.fullmatch(r"r(\d+)[dwb]?", reg)
    if m:
        return "r" + m.group(1)
    return FAM.get(reg, reg)


def c_string(text, enc):
    t = text[:160]
    t = t.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
    return ('L"' if enc == "utf16" else '"') + t + ('…"' if len(text) > 160 else '"')


def hexs(v):
    return str(v) if -10 < v < 10 else (f"-0x{-v:X}" if v < 0 else f"0x{v:X}")


class Lifter:
    def __init__(self, ctx, insns, start):
        self.ctx, self.ins, self.start = ctx, insns, start
        self.is64 = ctx.is64
        self.ret = "rax" if self.is64 else "eax"
        self.locals = {}
        self.args_x86 = set()

    # ------------------------------------------------------------ operands

    def const(self, v, size=4):
        s = self.ctx.string_at(v)
        if s is not None:
            return c_string(*s)
        if self.ctx.is_func(v):
            return self.ctx.label(v)
        api = self.ctx.import_name(v)
        if api:
            return "&" + api
        bits = (size or 4) * 8
        if v >= 1 << (bits - 1) and v < 1 << bits:
            neg = v - (1 << bits)
            if neg > -0x10000:
                return hexs(neg)
        return hexs(v)

    def stackvar(self, base, disp, size):
        f = fam(base)
        if f == "bp" and not self.is64 and disp >= 8:
            n = (disp - 8) // 4
            self.args_x86.add(n)
            return f"arg_{n}"
        if f == "bp":
            name = f"local_{-disp:X}" if disp < 0 else f"var_{disp:X}"
        else:
            name = f"stack_{disp:X}" if disp >= 0 else f"stack_m{-disp:X}"
        self.locals.setdefault(name, size)
        return name

    def addr_expr(self, o):
        parts = []
        if o.get("base"):
            parts.append(o["base"])
        if o.get("index"):
            parts.append(o["index"] + (f" * {o['scale']}" if o.get("scale", 1) != 1 else ""))
        d = o.get("disp", 0)
        if d or not parts:
            parts.append(hexs(d))
        return " + ".join(parts).replace("+ -", "- ")

    def mem(self, o):
        if o.get("abs") is not None:
            a = o["abs"]
            api = self.ctx.import_name(a)
            if api:
                return api
            return f"g_{a:X}"
        if o.get("base") and fam(o["base"]) in ("bp", "sp") and not o.get("index"):
            return self.stackvar(o["base"], o.get("disp", 0), o.get("size", 4))
        t = SIZE_T.get(o.get("size"), "uint8_t")
        return f"*({t}*)({self.addr_expr(o)})"

    def op(self, o):
        if o["t"] == "reg":
            return o["reg"]
        if o["t"] == "imm":
            return self.const(o["v"], o.get("size", 4))
        return self.mem(o)

    def lea(self, o):
        if o.get("abs") is not None:
            s = self.ctx.string_at(o["abs"])
            if s is not None:
                return c_string(*s)
            if self.ctx.is_func(o["abs"]):
                return self.ctx.label(o["abs"])
            return f"&g_{o['abs']:X}"
        if o.get("base") and fam(o["base"]) in ("bp", "sp") and not o.get("index"):
            return "&" + self.stackvar(o["base"], o.get("disp", 0), 0)
        return self.addr_expr(o)

    def reads(self, i):
        out = set()
        for k, o in enumerate(i["ops"]):
            if o["t"] == "reg" and (k > 0 or i["m"] not in PURE_WRITE):
                out.add(fam(o["reg"]))
            elif o["t"] == "mem":
                out.update(fam(r) for r in (o.get("base"), o.get("index")) if r)
        return out

    # ------------------------------------------------------------ conditions

    def cond(self, flags, m, negate=False):
        if negate:
            if m in NEGJ:
                m = NEGJ[m]
            else:
                return f"!({self.cond(flags, m)})"
        if m in ("jecxz", "jrcxz", "jcxz"):
            return f"{m[1:-1]} == 0"
        if m.startswith("loop"):
            return f"--{'rcx' if self.is64 else 'ecx'} != 0"
        rel = REL.get(m)
        if rel is None or flags is None:
            return f"/* {m} */ flags"
        kind = flags[0]
        if kind == "cmp":
            a, b = flags[1], flags[2]
        else:
            a = f"({flags[1]} & {flags[2]})" if kind == "test" and flags[1] != flags[2] else flags[1]
            b = "0"
        if rel in ("<0", ">=0"):
            e = f"(int)({a} - {b})" if kind == "cmp" else f"(int){a}"
            return f"{e} {rel[:-1]} 0"
        if rel.endswith("u"):
            r = rel[:-1]
            if b == "0":
                return {">": f"{a} != 0", "<=": f"{a} == 0", "<": "0 /* never */", ">=": "1 /* always */"}[r]
            return f"(unsigned){a} {r} {b}"
        return f"{a} {rel} {b}"

    # ------------------------------------------------------------ CFG

    def build_blocks(self):
        addrs = sorted(self.ins)
        leaders = {self.start}
        for a in addrs:
            i = self.ins[a]
            nxt = a + i["n"]
            if i["kind"] in ("jcc", "jmp") and i["tgt"] in self.ins:
                leaders.add(i["tgt"])
            if i["kind"] in ("jcc", "jmp", "ret", "halt") and nxt in self.ins:
                leaders.add(nxt)
        blocks, cur, expected = {}, None, None
        for a in addrs:
            i = self.ins[a]
            if cur is None or a in leaders or a != expected:
                cur = a
                blocks[a] = []
            blocks[cur].append(i)
            expected = a + i["n"]
            if i["kind"] in ("jcc", "jmp", "ret", "halt"):
                cur = None
        self.blocks = blocks
        self.order = sorted(blocks)
        self.idx = {a: k for k, a in enumerate(self.order)}
        self.succ, self.preds = {}, defaultdict(set)
        for a, insns in blocks.items():
            last = insns[-1]
            end = last["a"] + last["n"]
            s = []
            if last["kind"] == "jcc":
                s = [x for x in (last["tgt"], end) if x in blocks]
            elif last["kind"] == "jmp":
                s = [last["tgt"]] if last["tgt"] in blocks else []
            elif last["kind"] not in ("ret", "halt") and end in blocks:
                s = [end]
            self.succ[a] = s
            for x in s:
                self.preds[x].add(a)

    # ------------------------------------------------------------ statements

    def lift_block(self, addr):
        insns = self.blocks[addr]
        st, flags, slots, pushes, regapi = [], None, {}, [], {}
        prologue = addr == self.start
        term = ("fall",)

        def emit(a, text):
            st.append({"a": a, "t": text})
            return len(st) - 1

        def take_args():
            if self.is64:
                n = max(slots) + 1 if slots else 0
                args = []
                for s in range(n):
                    if s in slots:
                        k, e = slots[s]
                        st[k] = None
                        args.append(e)
                    else:
                        args.append(X64_ARG_NAME[s] if s < 4 else f"stack_{0x20 + (s - 4) * 8:X}")
                slots.clear()
                return args
            args = []
            for k, e in reversed(pushes):
                st[k] = None
                args.append(e)
            pushes.clear()
            return args

        def callee(i):
            if i["tgt"] is not None:
                return self.ctx.label(i["tgt"])
            o = i["ops"][0] if i["ops"] else None
            if o is None:
                return "(*unknown)"
            if o["t"] == "reg":
                return regapi.get(fam(o["reg"])) or f"(*{o['reg']})"
            api = self.ctx.import_name(o["abs"]) if o["t"] == "mem" and o.get("abs") is not None else None
            return api or f"(*{self.op(o)})"

        for i in insns:
            m, ops, a = i["m"], i["ops"], i["a"]
            o0 = ops[0] if ops else None
            o1 = ops[1] if len(ops) > 1 else None
            r0 = fam(o0["reg"]) if o0 and o0["t"] == "reg" else None

            # ---- prologue / epilogue noise
            if prologue:
                if m == "push" and r0 in CALLEE_SAVED:
                    continue
                if m == "mov" and r0 == "bp" and o1 and o1["t"] == "reg" and fam(o1["reg"]) == "sp":
                    continue
                if m in ("sub", "and") and r0 == "sp":
                    continue
                if (self.is64 and m == "mov" and o0 and o0["t"] == "mem" and o0.get("base")
                        and fam(o0["base"]) == "sp" and o1 and o1["t"] == "reg"):
                    continue
                prologue = False
            if m in ("nop", "endbr32", "endbr64", "fnop", "leave") or (m in ("add", "sub") and r0 == "sp"):
                continue
            if m == "pop" and r0 in CALLEE_SAVED:
                continue
            if m == "push" and self.is64:
                continue

            # ---- control flow
            if i["kind"] == "call":
                name = callee(i)
                args = take_args()
                emit(a, f"{self.ret} = {name}({', '.join(args)});")
                flags = None
                regapi.pop("a", None)
                continue
            if i["kind"] == "ret":
                term = ("stmt", a, f"return {self.ret};")
                break
            if i["kind"] == "halt":
                term = ("stmt", a, "__debugbreak();  // int3/ud2/hlt")
                break
            if i["kind"] == "jcc":
                term = ("cond", a, m, flags, i["tgt"], a + i["n"])
                break
            if i["kind"] == "jmp":
                t = i["tgt"]
                if t is not None and t in self.blocks:
                    term = ("jmp", a, t)
                elif t is not None:
                    term = ("stmt", a, f"return {self.ctx.label(t)}({', '.join(take_args())});  // tail call")
                elif o0 and o0["t"] == "mem" and o0.get("abs") is not None and self.ctx.import_name(o0["abs"]):
                    term = ("stmt", a, f"return {self.ctx.import_name(o0['abs'])}({', '.join(take_args())});  // tail call")
                else:
                    term = ("stmt", a, f"goto *({self.op(o0)});  // indirect jump, maybe a switch table")
                break

            # ---- x64: if an arg register is used as a *source* for local work
            # (not a call, not just being overwritten), it's no longer a pending arg.
            if self.is64 and i["kind"] is None:
                zeroing = (m == "xor" and o0 and o1 and o0.get("reg") == o1.get("reg"))
                src = set()
                if not zeroing:
                    for k, o in enumerate(ops):
                        if o["t"] == "reg" and (k > 0 or m not in PURE_WRITE):
                            src.add(fam(o["reg"]))
                        elif o["t"] == "mem":
                            src.update(fam(r) for r in (o.get("base"), o.get("index")) if r)
                for fm, slot in X64_ARG_SLOT.items():
                    if fm in src and slot in slots:
                        del slots[slot]

            text, lhs, rhs = self.translate(i, flags)
            new_flags = self._flags_after(i)
            if new_flags is not False:
                flags = new_flags
            if text is None:
                continue
            k = emit(a, text)

            if m == "mov" and o1 and o1["t"] == "mem" and o1.get("abs") is not None and r0:
                api = self.ctx.import_name(o1["abs"])
                if api:
                    regapi[r0] = api
            elif r0:
                regapi.pop(r0, None)

            if self.is64:
                pure = m in PURE_WRITE or (m == "xor" and o1 and o1["t"] == "reg" and o1["reg"] == o0["reg"])
                if r0 in X64_ARG_SLOT:
                    if pure and rhs is not None:
                        slots[X64_ARG_SLOT[r0]] = (k, rhs)
                    else:
                        slots.pop(X64_ARG_SLOT[r0], None)
                elif (m == "mov" and o0 and o0["t"] == "mem" and o0.get("base") and fam(o0["base"]) == "sp"
                      and not o0.get("index") and o0.get("disp", 0) >= 0x20 and o0["disp"] % 8 == 0):
                    slots[4 + (o0["disp"] - 0x20) // 8] = (k, rhs)
            elif m == "push":
                pushes.append((k, rhs))

        return [s for s in st if s], term

    def _flags_after(self, i):
        m, ops = i["m"], i["ops"]
        if m in ("cmp", "test") and len(ops) == 2:
            return (m, self.op(ops[0]), self.op(ops[1]))
        if m in ALU or m in ("inc", "dec", "neg", "sar", "adc", "sbb"):
            return ("res", self.op(ops[0])) if ops else None
        if m in ("bt", "bts", "btr", "btc", "comiss", "comisd", "ucomiss", "ucomisd"):
            return None
        return False  # flags unchanged

    def translate(self, i, flags):
        """Return (statement text or None, lhs, rhs)."""
        m, ops = i["m"], i["ops"]
        o0 = ops[0] if ops else None
        o1 = ops[1] if len(ops) > 1 else None
        n = len(ops)
        if m in ("cmp", "test"):
            return None, None, None
        if m in ("mov", "movabs", "movd", "movq", "movaps", "movups", "movdqa", "movdqu") and n == 2:
            l, r = self.op(o0), self.op(o1)
            return f"{l} = {r};", l, r
        if m in ("movzx",) and n == 2:
            l, r = self.op(o0), self.op(o1)
            return f"{l} = {r};", l, r
        if m in ("movsx", "movsxd") and n == 2:
            l, r = self.op(o0), f"(int{o1.get('size', 4) * 8}_t){self.op(o1)}"
            return f"{l} = {r};", l, r
        if m == "lea" and n == 2:
            l, r = self.op(o0), self.lea(o1)
            return f"{l} = {r};", l, r
        if m == "xor" and n == 2 and o0["t"] == "reg" and o1["t"] == "reg" and o0["reg"] == o1["reg"]:
            l = self.op(o0)
            return f"{l} = 0;", l, "0"
        if m in ALU and n == 2:
            l, r = self.op(o0), self.op(o1)
            return f"{l} {ALU[m]} {r};", l, None
        if m == "imul" and n == 3:
            l = self.op(o0)
            r = f"{self.op(o1)} * {self.op(ops[2])}"
            return f"{l} = {r};", l, r
        if m == "sar" and n == 2:
            l = self.op(o0)
            return f"{l} = (int{o0.get('size', 4) * 8}_t){l} >> {self.op(o1)};", l, None
        if m in ("rol", "ror") and n == 2:
            l = self.op(o0)
            return f"{l} = {m.upper()}{o0.get('size', 4) * 8}({l}, {self.op(o1)});", l, None
        if m in ("adc", "sbb") and n == 2:
            l = self.op(o0)
            return f"{l} {'+' if m == 'adc' else '-'}= {self.op(o1)} + CF;", l, None
        if m == "inc":
            l = self.op(o0)
            return f"{l}++;", l, None
        if m == "dec":
            l = self.op(o0)
            return f"{l}--;", l, None
        if m == "neg":
            l = self.op(o0)
            return f"{l} = -{l};", l, None
        if m == "not":
            l = self.op(o0)
            return f"{l} = ~{l};", l, None
        if m == "bswap":
            l = self.op(o0)
            return f"{l} = BSWAP({l});", l, None
        if m == "xchg" and n == 2:
            return f"SWAP({self.op(o0)}, {self.op(o1)});", None, None
        if m == "push":
            r = self.op(o0)
            return f"push({r});", None, r
        if m == "pop":
            l = self.op(o0)
            return f"{l} = pop();", l, None
        if m in ("cdq", "cqo", "cwd"):
            return ("rdx" if m == "cqo" else "edx") + " = sign_extend(" + ("rax" if m == "cqo" else "eax") + ");", None, None
        if m in ("div", "idiv") and n == 1:
            a, d = ("rax", "rdx") if o0.get("size") == 8 else ("eax", "edx")
            return f"{d} = ({d}:{a}) % {self.op(o0)}; {a} = ({d}:{a}) / {self.op(o0)};", None, None
        if m in ("mul", "imul") and n == 1:
            return f"edx:eax = eax * {self.op(o0)};", None, None
        if m.startswith("set") and n == 1:
            l = self.op(o0)
            return f"{l} = ({self.cond(flags, 'j' + m[3:])});", l, None
        if m.startswith("cmov") and n == 2:
            l = self.op(o0)
            return f"if ({self.cond(flags, 'j' + m[4:])}) {l} = {self.op(o1)};", l, None
        if m.startswith("rep") and ("stos" in m or "movs" in m):
            unit = {"b": 1, "w": 2, "d": 4, "q": 8}.get(m[-1], 1)
            cnt = "rcx" if self.is64 else "ecx"
            di, si = ("rdi", "rsi") if self.is64 else ("edi", "esi")
            mul = f" * {unit}" if unit > 1 else ""
            if "stos" in m:
                return f"memset({di}, {'al' if unit == 1 else 'eax'}, {cnt}{mul});", None, None
            return f"memcpy({di}, {si}, {cnt}{mul});", None, None
        if m in ("syscall", "sysenter"):
            return f"syscall({self.ret});  // direct system call", None, None
        if m == "int" and i["text"].strip() == "0x29":
            return "__fastfail(ecx);", None, None
        if m in ("cpuid", "rdtsc", "rdrand", "pause", "lfence", "mfence", "sfence"):
            return f"__{m}();", None, None
        return f"__asm {{ {m} {i['text']} }}", None, None

    # ------------------------------------------------------------ structuring

    def run(self):
        self.build_blocks()
        self.lifted = {a: self.lift_block(a) for a in self.order}
        self.lines, self.gotos, self.override = [], set(), {}
        self.loop_stack, self.loop_done = [], set()
        self.emit_range(0, len(self.order), 1)
        return self.render()

    def single_entry(self, lo, hi, allowed, check_from=None):
        """Blocks order[check_from:hi] are only entered from order[lo:hi] or from `allowed`."""
        inside = set(self.order[lo:hi])
        for a in self.order[lo if check_from is None else check_from:hi]:
            for p in self.preds[a]:
                if p not in inside and p not in allowed:
                    return False
        return True

    def line(self, a, ind, text, kind="code"):
        cmt = self.ctx.comment(a) if a is not None and kind != "label" else None
        self.lines.append({"a": a, "i": ind, "t": text + (f"  // {cmt}" if cmt else ""), "k": kind})

    def goto(self, a, ind, tgt, prefix=""):
        for header, exit_ in reversed(self.loop_stack):
            if tgt == exit_:
                self.line(a, ind, prefix + "break;")
                return
            if tgt == header:
                self.line(a, ind, prefix + "continue;")
                return
            break
        self.gotos.add(tgt)
        self.line(a, ind, prefix + f"goto L_{tgt:X};")

    def emit_range(self, lo, hi, ind):
        i = lo
        while i < hi:
            addr = self.order[i]
            # ---- loops: find the furthest back edge to this block inside the range
            if addr not in self.loop_done:
                back = [k for k in range(i, hi) if addr in self.succ[self.order[k]]
                        and self.order[k] >= addr and self._term(self.order[k])[0] in ("cond", "jmp")]
                if back and self.single_entry(i, back[-1] + 1, set(), check_from=i + 1):
                    k = back[-1]
                    last = self.order[k]
                    t = self._term(last)
                    exit_ = self.order[k + 1] if k + 1 < len(self.order) else None
                    self.loop_done.add(addr)
                    self.loop_stack.append((addr, exit_))
                    if t[0] == "cond" and t[4] == addr:
                        self.line(addr, ind, "do {")
                        self.override[last] = ("none",)
                        self.emit_range(i, k + 1, ind + 1)
                        self.line(t[1], ind, f"}} while ({self.cond(t[3], t[2])});")
                        self.loop_stack.pop()
                        if t[5] in self.blocks and t[5] != exit_:
                            self.goto(t[1], ind, t[5])
                    else:
                        # header conditional whose taken edge leaves the loop body -> while (cond)
                        hdr = self._term(addr)
                        hdr_exits = (hdr[0] == "cond" and k > i
                                     and not (i < self.idx.get(hdr[4], -1) <= k)
                                     and self.idx.get(hdr[5]) == i + 1)
                        if hdr_exits:
                            self.line(addr, ind, f"while ({self.cond(hdr[3], hdr[2], negate=True)}) {{")
                            self.override[addr] = ("none",)      # drop the header jcc
                            self.override[last] = ("none",)      # drop the trailing back-jmp
                            self.emit_range(i, k + 1, ind + 1)
                            self.line(None, ind, "}")
                            if hdr[4] in self.blocks and hdr[4] != exit_:
                                self.goto(hdr[1], ind, hdr[4])
                        else:
                            self.line(addr, ind, "while (1) {")
                            self.override[last] = ("none",) if t[0] == "jmp" else ("cond_keep",)
                            self.emit_range(i, k + 1, ind + 1)
                            self.line(None, ind, "}")
                        self.loop_stack.pop()
                    i = k + 1
                    continue

            self.line(addr, 0, f"L_{addr:X}:", "label")
            stmts, _ = self.lifted[addr]
            for s in stmts:
                self.line(s["a"], ind, s["t"])
            t = self._term(addr)

            if t[0] == "cond":
                _, a, m, flags, tgt, fall = t
                ti = self.idx.get(tgt)
                # ---- if / if-else
                if ti is not None and i + 1 <= ti <= hi and fall == (self.order[i + 1] if i + 1 < len(self.order) else None) \
                        and ti > i + 1 and self.single_entry(i + 1, ti, {addr}):
                    then_last = self.order[ti - 1]
                    lt = self._term(then_last)
                    ei = self.idx.get(lt[2]) if lt[0] == "jmp" else None
                    if ei is not None and ti < ei <= hi and self.single_entry(ti, ei, {addr}):
                        self.line(a, ind, f"if ({self.cond(flags, m, negate=True)}) {{")
                        self.override[then_last] = ("none",)
                        self.emit_range(i + 1, ti, ind + 1)
                        self.line(None, ind, "} else {")
                        self.emit_range(ti, ei, ind + 1)
                        self.line(None, ind, "}")
                        i = ei
                        continue
                    self.line(a, ind, f"if ({self.cond(flags, m, negate=True)}) {{")
                    self.emit_range(i + 1, ti, ind + 1)
                    self.line(None, ind, "}")
                    i = ti
                    continue
                self.goto(a, ind, tgt, f"if ({self.cond(flags, m)}) ")
                if fall in self.blocks and self.idx[fall] != i + 1:
                    self.goto(a, ind, fall)
            elif t[0] == "cond_keep":
                _, a, m, flags, tgt, fall = t[1]
                self.goto(a, ind, tgt, f"if ({self.cond(flags, m)}) ")
                if fall in self.blocks and self.idx.get(fall) != i + 1:
                    self.goto(a, ind, fall)
            elif t[0] == "jmp":
                if not (i + 1 < len(self.order) and self.order[i + 1] == t[2]):
                    self.goto(t[1], ind, t[2])
            elif t[0] == "stmt":
                self.line(t[1], ind, t[2])
            elif t[0] == "fall":
                insns = self.blocks[addr]
                end = insns[-1]["a"] + insns[-1]["n"]
                if end in self.blocks and not (i + 1 < len(self.order) and self.order[i + 1] == end):
                    self.goto(insns[-1]["a"], ind, end)
            i += 1

    def _term(self, addr):
        ov = self.override.get(addr)
        t = self.lifted[addr][1]
        if ov is None:
            return t
        if ov[0] == "cond_keep" and t[0] == "cond":
            return ("cond_keep", t)
        return ("none",)

    def render(self):
        name = self.ctx.label(self.start)
        if self.is64:
            used, written = set(), set()
            for insn in self.blocks.get(self.start, []):
                if insn["kind"] is not None:
                    break
                m, ops = insn["m"], insn["ops"]
                zeroing = (m == "xor" and len(ops) == 2 and ops[0].get("reg") == ops[1].get("reg"))
                srcs = set()
                if not zeroing:
                    for k, o in enumerate(ops):
                        if o["t"] == "reg" and (k > 0 or m not in PURE_WRITE):
                            srcs.add(fam(o["reg"]))
                        elif o["t"] == "mem":
                            srcs.update(fam(r) for r in (o.get("base"), o.get("index")) if r)
                for fm, s in X64_ARG_SLOT.items():
                    if fm in srcs and fm not in written:
                        used.add(s)
                if ops and ops[0]["t"] == "reg" and m not in ("cmp", "test"):
                    written.add(fam(ops[0]["reg"]))
            params = ", ".join(X64_ARG_NAME[s] for s in sorted(used)) or "void"
        else:
            params = ", ".join(f"uint32_t arg_{n}" for n in range(max(self.args_x86) + 1)) if self.args_x86 else "void"
        out = [{"a": self.start, "i": 0, "t": f"{'uint64_t' if self.is64 else 'uint32_t'} {name}({params})", "k": "sig"},
               {"a": None, "i": 0, "t": "{", "k": "code"}]
        body_text = "\n".join(l["t"] for l in self.lines)
        for v, sz in sorted(self.locals.items()):
            if not re.search(r"\b" + re.escape(v) + r"\b", body_text):
                continue  # consumed as a call argument, never used as a local
            out.append({"a": None, "i": 1, "t": f"{SIZE_T.get(sz, 'uint8_t') if sz else 'uint8_t'} {v};", "k": "decl"})
        if any(l["k"] == "decl" for l in out):
            out.append({"a": None, "i": 0, "t": "", "k": "code"})
        for ln in self.lines:
            if ln["k"] == "label":
                if int(ln["t"][2:-1], 16) not in self.gotos:
                    continue
            out.append(ln)
        out.append({"a": None, "i": 0, "t": "}", "k": "code"})
        return out


def to_text(lines):
    return "\n".join(("" if ln["k"] == "label" else "    " * ln["i"]) + ln["t"] for ln in lines)
