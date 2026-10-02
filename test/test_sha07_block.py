'''
Tests for sha07_block.v: SHA-256 compression on the tt07 round core.

NIST example vectors ("abc", one block; the 448-bit message, two blocks) and
random messages against hashlib.  Run with:  make BLOCK=yes
'''

import hashlib
import os
import random
import struct

import cocotb
from cocotb.clock import Clock
from cocotb.triggers import ClockCycles, RisingEdge, Timer

GateLevelTest = os.environ.get('GATES') == 'yes'

IV = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
      0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]

NIST = [
    (b'abc', 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'),
    (b'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq',
     '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1'),
]


def pad(msg):
    n = len(msg)
    msg = msg + b'\x80' + b'\0' * ((55 - n) % 64) + struct.pack('>Q', 8 * n)
    return [msg[i:i + 64] for i in range(0, len(msg), 64)]


def words_to_int(words):
    v = 0
    for w in words:
        v = (v << 32) | w
    return v


async def setup(dut):
    cocotb.start_soon(Clock(dut.clk, 20, units='ns').start())
    dut.start.value = 0
    dut.abort.value = 0
    dut.h_in.value = 0
    dut.block.value = 0
    dut.rst_n.value = 0
    await ClockCycles(dut.clk, 3)
    dut.rst_n.value = 1
    await ClockCycles(dut.clk, 3)


async def compress(dut, h, block):
    '''Run one compression; return (h_out int, cycles).'''
    dut.h_in.value = h
    dut.block.value = int.from_bytes(block, 'big')
    dut.start.value = 1
    await RisingEdge(dut.clk)
    dut.start.value = 0
    for cycles in range(1, 2000):
        await RisingEdge(dut.clk)
        await Timer(1, units='ns')
        if dut.done.value:
            return int(dut.h_out.value), cycles
    raise AssertionError('no done')


async def sha256_on_core(dut, msg):
    h = words_to_int(IV)
    total = 0
    for block in pad(msg):
        h, cycles = await compress(dut, h, block)
        total += cycles
        await RisingEdge(dut.clk)
    return h.to_bytes(32, 'big'), total


@cocotb.test(skip=GateLevelTest)
async def test_nist_examples(dut):
    await setup(dut)
    for msg, expected in NIST:
        digest, cycles = await sha256_on_core(dut, msg)
        dut._log.info(f'{msg[:12]!r}...: {digest.hex()} ({len(pad(msg))} block(s), {cycles} cycles)')
        assert digest.hex() == expected


@cocotb.test(skip=GateLevelTest)
async def test_random_vs_hashlib(dut):
    await setup(dut)
    rng = random.Random(180)
    for length in [0, 1, 55, 56, 63, 64, 65, 119, 120, 200] + [rng.randint(0, 300) for _ in range(10)]:
        msg = bytes(rng.randrange(256) for _ in range(length))
        digest, _ = await sha256_on_core(dut, msg)
        assert digest == hashlib.sha256(msg).digest(), f'length {length}'


@cocotb.test(skip=GateLevelTest)
async def test_scrubbed_after_block(dut):
    '''After done: schedule window, working registers, h_out and the core's
    register file are all zero.'''
    await setup(dut)
    await compress(dut, words_to_int(IV), bytes(range(64)))
    await RisingEdge(dut.clk)
    await Timer(1, units='ns')
    for i in range(16):
        assert not dut.w[i].value.binstr.strip('0'), f'w[{i}]'
    for name in ('hreg', 'rd', 'h_out'):
        assert not getattr(dut, name).value.binstr.strip('0'), name
    for i in range(10):
        assert int(dut.core.register_file[i].value) == 0, f'core register {i}'


@cocotb.test(skip=GateLevelTest)
async def test_abort(dut):
    await setup(dut)
    dut.h_in.value = words_to_int(IV)
    dut.block.value = int.from_bytes(bytes(range(64)), 'big')
    dut.start.value = 1
    await RisingEdge(dut.clk)
    dut.start.value = 0
    await ClockCycles(dut.clk, 300)
    dut.abort.value = 1
    await RisingEdge(dut.clk)
    dut.abort.value = 0
    await RisingEdge(dut.clk)
    await Timer(1, units='ns')
    assert dut.busy.value == 0
    for i in range(10):
        assert int(dut.core.register_file[i].value) == 0, f'core register {i}'
    digest, _ = await sha256_on_core(dut, b'abc')
    assert digest.hex() == NIST[0][1]
