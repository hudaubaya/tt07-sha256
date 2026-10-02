# SPDX-License-Identifier: Apache-2.0
#
# Zeroization-by-reset tests for tt_um_xeniarose_sha256.
#
# The register file (A..H working state, W, K) and io_out use an asynchronous
# active-low reset.  These tests check that, after reset, no state derived from
# previously processed (secret) data survives: neither inside the design
# (every signal compared with a clean reset) nor through the I/O interface.
#
# Run with:  make MODULE=test_zeroize

import os

import cocotb
from cocotb.clock import Clock
from cocotb.handle import (ConstantObject, HierarchyArrayObject,
                           HierarchyObject, ModifiableObject,
                           NonHierarchyIndexableObject, NonHierarchyObject)
from cocotb.triggers import ClockCycles, Timer

from test import K, H, TestMeta, io_read, io_trigger, io_write, test_one_sha_full

GateLevelTest = os.environ.get('GATES') == 'yes'

SECRET_WORDS = [0xDEADBEEF, 0xCAFEBABE, 0x8BADF00D, 0xFEEDFACE,
                0x0BADC0DE, 0xFACEFEED, 0xD15EA5E5, 0xB16B00B5,
                0x5EC12E7A, 0x13371337]

CLK_PERIOD_US = 10
NUM_REGS = 10


def snapshot(handle, prefix='', out=None):
    '''Recursively read every signal below handle: {name: bitstring}.'''
    if out is None:
        out = {}
    for child in handle:
        name = prefix + child._name
        if name.endswith('clk'):
            continue
        if isinstance(child, (ModifiableObject, ConstantObject)):
            out[name] = child.value.binstr
        elif isinstance(child, NonHierarchyIndexableObject):
            left, right = child._range  # iterate by declared index, not position
            step = 1 if right >= left else -1
            for i in range(left, right + step, step):
                out[f'{name}[{i}]'] = child[i].value.binstr
        elif isinstance(child, (HierarchyObject, HierarchyArrayObject)):
            snapshot(child, name + '.', out)
        elif isinstance(child, NonHierarchyObject):
            out[name] = str(child.value)
    return out


def assert_same(dut, clean, dirty, what):
    bad = sorted(k for k in clean if clean[k] != dirty.get(k))
    for k in bad[:20]:
        dut._log.error(f'{what}: residue in {k}: clean={clean[k]} after={dirty[k]}')
    assert not bad, f'{what}: {len(bad)} signal(s) differ from a clean reset'
    dut._log.info(f'{what}: {len(clean)} signals identical to clean reset')


def register_file(dut):
    return [int(dut.user_project.register_file[i].value) for i in range(NUM_REGS)]


def idle_inputs(dut):
    dut.ena.value = 1
    dut.ui_in.value = 0
    dut.uio_in.value = 0


async def reset_and_snapshot(dut):
    idle_inputs(dut)
    dut.rst_n.value = 0
    await ClockCycles(dut.clk, 10)
    await Timer(1, units='ns')
    during = snapshot(dut.user_project)
    dut.rst_n.value = 1
    await ClockCycles(dut.clk, 5)
    await Timer(1, units='ns')
    after = snapshot(dut.user_project)
    return during, after


async def start_clean(dut):
    clk_task = cocotb.start_soon(Clock(dut.clk, CLK_PERIOD_US, units='us').start())
    golden = await reset_and_snapshot(dut)
    return clk_task, golden


async def load_secrets(dut, meta):
    for i, w in enumerate(SECRET_WORDS):
        await io_write(dut, meta, i * 4, w)
    assert register_file(dut) == SECRET_WORDS


async def read_all_registers(dut):
    meta = TestMeta()
    return [await io_read(dut, meta, i * 4) for i in range(NUM_REGS)]


async def check_reset(dut, golden, what):
    during, after = await reset_and_snapshot(dut)
    assert_same(dut, golden[0], during, f'{what} (reset held)')
    assert_same(dut, golden[1], after, f'{what} (reset released)')
    regs = await read_all_registers(dut)
    assert regs == [0] * NUM_REGS, f'{what}: readable after reset: {[hex(r) for r in regs]}'


@cocotb.test(skip=GateLevelTest)
async def test_zeroize_loaded_registers(dut):
    '''Secret words written into all ten registers.'''
    _, golden = await start_clean(dut)
    await load_secrets(dut, TestMeta())
    await check_reset(dut, golden, 'loaded registers')


@cocotb.test(skip=GateLevelTest)
async def test_zeroize_after_full_hash(dut):
    '''A full multi-block hash leaves the last round state in A..H, W, K.'''
    _, golden = await start_clean(dut)
    meta = TestMeta()
    await test_one_sha_full(dut, meta, b'secret passphrase: correct horse battery staple' * 2)
    assert any(register_file(dut)), 'expected working state to be non-zero'
    await check_reset(dut, golden, 'after full hash')


@cocotb.test(skip=GateLevelTest)
async def test_zeroize_mid_round(dut):
    '''Reset right after a compression round was triggered.'''
    _, golden = await start_clean(dut)
    meta = TestMeta()
    for i in range(8):
        await io_write(dut, meta, i * 4, H[i])
    await io_write(dut, meta, 32, SECRET_WORDS[8])
    await io_write(dut, meta, 36, K[0])
    await io_trigger(dut, meta)
    await check_reset(dut, golden, 'mid round')


@cocotb.test(skip=GateLevelTest)
async def test_zeroize_output_latch(dut):
    '''io_out holds a secret byte after a read; reset must clear uio_out at once.'''
    clk_task, golden = await start_clean(dut)
    meta = TestMeta()
    await load_secrets(dut, meta)
    await io_read(dut, meta, 0)
    assert int(dut.uio_out.value) == SECRET_WORDS[0] >> 24
    dut.rst_n.value = 0
    await Timer(1, units='ns')  # asynchronous: no clock edge needed
    assert int(dut.uio_out.value) == 0
    await check_reset(dut, golden, 'output latch')


@cocotb.test(skip=GateLevelTest)
async def test_zeroize_without_clock(dut):
    '''Asynchronous reset clears everything even with the clock stopped.'''
    clk_task, golden = await start_clean(dut)
    await load_secrets(dut, TestMeta())
    clk_task.kill()
    dut.clk.value = 0
    idle_inputs(dut)
    dut.rst_n.value = 0
    await Timer(1, units='ns')
    assert register_file(dut) == [0] * NUM_REGS
    assert_same(dut, golden[0], snapshot(dut.user_project), 'clock stopped')
    cocotb.start_soon(Clock(dut.clk, CLK_PERIOD_US, units='us').start())
    await check_reset(dut, golden, 'clock restarted')


@cocotb.test(skip=GateLevelTest)
async def test_zeroize_short_pulse(dut):
    '''A 1 ns reset pulse between clock edges is enough.'''
    _, golden = await start_clean(dut)
    await load_secrets(dut, TestMeta())
    idle_inputs(dut)
    await Timer(CLK_PERIOD_US / 4, units='us')  # away from any clock edge
    dut.rst_n.value = 0
    await Timer(1, units='ns')
    dut.rst_n.value = 1
    await Timer(1, units='ns')
    assert register_file(dut) == [0] * NUM_REGS


@cocotb.test(skip=GateLevelTest)
async def test_reuse_after_reset(dut):
    '''The core still hashes correctly after a zeroizing reset.'''
    await start_clean(dut)
    await load_secrets(dut, TestMeta())
    await reset_and_snapshot(dut)
    await test_one_sha_full(dut, TestMeta(), b'message digest')
