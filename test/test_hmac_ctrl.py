'''
Tests for hmac07_ctrl.v (tt07): HMAC-SHA256 with precomputed key states on
sha07_block and the tt07 round core.  Run with:  make HMAC=yes
'''

import hashlib
import hmac
import os
import random

import cocotb
from cocotb.clock import Clock
from cocotb.triggers import ClockCycles, RisingEdge, Timer

GateLevelTest = os.environ.get('GATES') == 'yes'

# RFC 4231 cases whose key and data fit (keys zero-padded to 32 bytes)
RFC4231 = [
    (bytes([0x0b] * 20), b'Hi There',
     'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7'),
    (b'Jefe', b'what do ya want for nothing?',
     '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843'),
    (bytes([0xaa] * 20), bytes([0xdd] * 50),
     '773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe'),
    (bytes(range(1, 26)), bytes([0xcd] * 50),
     '82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b'),
]


def pack(data, width):
    return int.from_bytes(data.ljust(width, b'\0'), 'big')


def all_bits(dut):
    '''Every register of interest in ctrl, sha07_block and the core.'''
    regs = {f'ctrl.{n}': getattr(dut, n).value.binstr
            for n in ('istate', 'ostate', 'inner', 'mac')}
    blk = dut.blk
    for n in ('hreg', 'rd', 'h_out'):
        regs[f'blk.{n}'] = getattr(blk, n).value.binstr
    for i in range(16):
        regs[f'blk.w[{i}]'] = blk.w[i].value.binstr
    for i in range(10):
        regs[f'core.register_file[{i}]'] = blk.core.register_file[i].value.binstr
    regs['core.io_out'] = blk.core.io_out.value.binstr
    return regs


async def setup(dut):
    cocotb.start_soon(Clock(dut.clk, 20, units='ns').start())
    for n in ('load_key', 'start', 'abort', 'clear_key', 'key', 'msg', 'msg_len'):
        getattr(dut, n).value = 0
    dut.rst_n.value = 0
    await ClockCycles(dut.clk, 3)
    dut.rst_n.value = 1
    await ClockCycles(dut.clk, 3)


async def pulse_and_wait(dut, sig, limit=5000):
    sig.value = 1
    await RisingEdge(dut.clk)
    sig.value = 0
    for cycles in range(1, limit):
        await RisingEdge(dut.clk)
        await Timer(1, units='ns')
        assert dut.err.value == 0, 'unexpected err'
        if dut.done.value:
            return cycles
    raise AssertionError('no done')


async def load_key(dut, key):
    dut.key.value = pack(key, 32)
    cycles = await pulse_and_wait(dut, dut.load_key)
    assert dut.key_valid.value == 1
    return cycles


async def run(dut, msg):
    dut.msg.value = pack(msg, 55)
    dut.msg_len.value = len(msg)
    cycles = await pulse_and_wait(dut, dut.start)
    return int(dut.mac.value).to_bytes(32, 'big'), cycles


@cocotb.test(skip=GateLevelTest)
async def test_rfc4231(dut):
    await setup(dut)
    for n, (key, msg, expected) in enumerate(RFC4231, 1):
        kc = await load_key(dut, key)
        mac, mc = await run(dut, msg)
        dut._log.info(f'RFC 4231 case {n}: {mac.hex()} (load_key {kc} cycles, HMAC {mc} cycles)')
        assert mac.hex() == expected
        await RisingEdge(dut.clk)


@cocotb.test(skip=GateLevelTest)
async def test_key_reuse_all_lengths(dut):
    await setup(dut)
    rng = random.Random(4231)
    key = bytes(rng.randrange(256) for _ in range(32))
    await load_key(dut, key)
    dut.key.value = 0          # the key port is no longer needed
    counts = set()
    for length in range(56):
        msg = bytes(rng.randrange(256) for _ in range(length))
        mac, cycles = await run(dut, msg)
        assert mac == hmac.new(key, msg, hashlib.sha256).digest(), f'length {length}'
        counts.add(cycles)
        await RisingEdge(dut.clk)
    dut._log.info(f'56 lengths correct with one load_key; HMAC cycles {min(counts)}-{max(counts)}')


@cocotb.test(skip=GateLevelTest)
async def test_errors(dut):
    await setup(dut)
    dut.msg_len.value = 3
    dut.start.value = 1
    await RisingEdge(dut.clk)
    dut.start.value = 0
    await Timer(1, units='ns')
    assert dut.err.value == 1, 'start without key must fail'
    await load_key(dut, b'k')
    dut.msg_len.value = 56
    dut.start.value = 1
    await RisingEdge(dut.clk)
    dut.start.value = 0
    await Timer(1, units='ns')
    assert dut.err.value == 1, 'msg_len 56 must fail'


@cocotb.test(skip=GateLevelTest)
async def test_key_not_kept_after_load(dut):
    '''After load_key no register (ctrl, sha07_block, core) holds 4 consecutive
    bytes of K, K^ipad or K^opad; only the derived states remain.'''
    await setup(dut)
    key = bytes(range(0xa0, 0xc0))
    windows = {key[i:i + 4] for i in range(29)}
    windows |= {bytes(b ^ p for b in w) for w in windows for p in (0x36, 0x5c)}
    await load_key(dut, key)
    dut.key.value = 0
    await ClockCycles(dut.clk, 2)
    await Timer(1, units='ns')
    for name, bits in all_bits(dut).items():
        raw = int(bits, 2).to_bytes(len(bits) // 8, 'big')
        hits = [w.hex() for w in windows if w in raw or w[::-1] in raw]
        assert not hits, f'key material in {name}: {hits}'


@cocotb.test(skip=GateLevelTest)
async def test_scrubbed_after_operation(dut):
    await setup(dut)
    await load_key(dut, b'scrub' * 6)
    await run(dut, b'some message')
    await ClockCycles(dut.clk, 2)
    await Timer(1, units='ns')
    left = {k: v for k, v in all_bits(dut).items()
            if v.strip('0') and not k.startswith(('ctrl.istate', 'ctrl.ostate', 'ctrl.mac'))}
    assert not left, f'state left after operation: {sorted(left)}'


@cocotb.test(skip=GateLevelTest)
async def test_abort_keeps_key(dut):
    await setup(dut)
    key = b'abort keeps the key states...'
    await load_key(dut, key)
    dut.msg.value = pack(b'first', 55)
    dut.msg_len.value = 5
    dut.start.value = 1
    await RisingEdge(dut.clk)
    dut.start.value = 0
    await ClockCycles(dut.clk, 900)                # inside the outer compression
    assert dut.ready.value == 0
    dut.abort.value = 1
    await RisingEdge(dut.clk)
    dut.abort.value = 0
    await ClockCycles(dut.clk, 2)
    await Timer(1, units='ns')
    left = {k for k, v in all_bits(dut).items()
            if v.strip('0') and not k.startswith(('ctrl.istate', 'ctrl.ostate'))}
    assert not left, f'not cleared by abort: {sorted(left)}'
    assert dut.key_valid.value == 1
    mac, _ = await run(dut, b'second')
    assert mac == hmac.new(key, b'second', hashlib.sha256).digest()


@cocotb.test(skip=GateLevelTest)
async def test_clear_key(dut):
    await setup(dut)
    await load_key(dut, b'clear me')
    await run(dut, b'x')
    dut.clear_key.value = 1
    await RisingEdge(dut.clk)
    dut.clear_key.value = 0
    await ClockCycles(dut.clk, 2)
    await Timer(1, units='ns')
    left = {k for k, v in all_bits(dut).items() if v.strip('0')}
    assert not left, f'not cleared by clear_key: {sorted(left)}'
    assert dut.key_valid.value == 0
    dut.msg_len.value = 1
    dut.start.value = 1
    await RisingEdge(dut.clk)
    dut.start.value = 0
    await Timer(1, units='ns')
    assert dut.err.value == 1
