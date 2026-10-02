'''
Tests for hmac_avmm.v (tt07): same register map as the tt05-shaman wrapper,
with key states precomputed on the first START.  Run with:  make AVMM=yes
'''

import hashlib
import hmac
import os
import random

import cocotb
from cocotb.clock import Clock
from cocotb.triggers import ClockCycles, RisingEdge, Timer

from test_hmac_ctrl import RFC4231, all_bits

GateLevelTest = os.environ.get('GATES') == 'yes'

CTRL, STATUS, MSG_LEN, ID = 0x00, 0x04, 0x08, 0x0C
KEY, MSG, MAC = 0x20, 0x40, 0x80
START, CLEAR_KEY, CLEAR_DATA = 1, 2, 4
READY, DONE, ERR, KEY_LOADED = 1, 2, 4, 8


class Bus:
    '''Minimal Avalon-MM master: one transfer per call, read latency 1.'''

    def __init__(self, dut):
        self.dut = dut
        self.transfers = 0

    async def write(self, offset, value):
        d = self.dut
        d.avs_address.value = offset >> 2
        d.avs_writedata.value = value
        d.avs_write.value = 1
        await RisingEdge(d.clk)
        d.avs_write.value = 0
        self.transfers += 1

    async def read(self, offset):
        d = self.dut
        d.avs_address.value = offset >> 2
        d.avs_read.value = 1
        await RisingEdge(d.clk)
        d.avs_read.value = 0
        await Timer(1, units='ns')
        self.transfers += 1
        return int(d.avs_readdata.value)

    async def write_bytes(self, offset, data, words):
        data = data.ljust(4 * words, b'\0')
        for i in range(words):
            await self.write(offset + 4 * i, int.from_bytes(data[4 * i:4 * i + 4], 'little'))

    async def read_bytes(self, offset, words):
        out = b''
        for i in range(words):
            out += (await self.read(offset + 4 * i)).to_bytes(4, 'little')
        return out


async def setup(dut):
    cocotb.start_soon(Clock(dut.clk, 20, units='ns').start())
    dut.avs_read.value = 0
    dut.avs_write.value = 0
    dut.avs_address.value = 0
    dut.avs_writedata.value = 0
    dut.reset.value = 1
    await ClockCycles(dut.clk, 5)
    dut.reset.value = 0
    await ClockCycles(dut.clk, 2)
    return Bus(dut)


async def wait_status(bus, mask, limit=20000):
    for _ in range(limit):
        st = await bus.read(STATUS)
        if st & mask == mask:
            return st
    raise AssertionError(f'status {mask:#x} not reached')


async def mac_of(bus, msg, key=None):
    if key is not None:
        await bus.write_bytes(KEY, key, 8)
    await bus.write_bytes(MSG, msg, 14)
    await bus.write(MSG_LEN, len(msg))
    await bus.write(CTRL, START)
    st = await wait_status(bus, DONE)
    assert not st & ERR
    return await bus.read_bytes(MAC, 8)


def residue(dut, keep=()):
    return sorted(k for k, v in all_bits(dut.ctrl).items()
                  if v.strip('0') and not k.startswith(keep))


@cocotb.test(skip=GateLevelTest)
async def test_id_and_rfc4231(dut):
    bus = await setup(dut)
    assert await bus.read(ID) == 0x484D4143
    assert await bus.read(STATUS) == READY
    for n, (key, msg, expected) in enumerate(RFC4231, 1):
        mac = await mac_of(bus, msg, key)
        dut._log.info(f'RFC 4231 case {n} over Avalon-MM: {mac.hex()}')
        assert mac.hex() == expected


@cocotb.test(skip=GateLevelTest)
async def test_key_reuse(dut):
    bus = await setup(dut)
    rng = random.Random(10)
    key = bytes(rng.randrange(256) for _ in range(32))
    await bus.write_bytes(KEY, key, 8)
    for _ in range(20):
        msg = bytes(rng.randrange(256) for _ in range(rng.randint(0, 55)))
        assert await mac_of(bus, msg) == hmac.new(key, msg, hashlib.sha256).digest()


@cocotb.test(skip=GateLevelTest)
async def test_key_registers_wiped_after_first_start(dut):
    bus = await setup(dut)
    key = bytes(range(1, 33))
    await bus.write_bytes(KEY, key, 8)
    for i in range(8):
        assert await bus.read(KEY + 4 * i) == 0, 'key readable over the bus'
    assert int(dut.key_w[0].value) != 0
    mac = await mac_of(bus, b'first')
    assert mac == hmac.new(key, b'first', hashlib.sha256).digest()
    for i in range(8):
        assert int(dut.key_w[i].value) == 0, f'KEY[{i}] not wiped after precompute'
    assert await bus.read(STATUS) & KEY_LOADED
    assert await mac_of(bus, b'second') == hmac.new(key, b'second', hashlib.sha256).digest()


@cocotb.test(skip=GateLevelTest)
async def test_rekey(dut):
    bus = await setup(dut)
    k1, k2 = b'first key' * 3, b'second key!' * 2
    assert await mac_of(bus, b'm', k1) == hmac.new(k1, b'm', hashlib.sha256).digest()
    assert await mac_of(bus, b'm', k2) == hmac.new(k2, b'm', hashlib.sha256).digest()
    assert await mac_of(bus, b'n') == hmac.new(k2, b'n', hashlib.sha256).digest()


@cocotb.test(skip=GateLevelTest)
async def test_errors(dut):
    bus = await setup(dut)
    await bus.write(CTRL, START)
    st = await bus.read(STATUS)
    assert st & ERR and st & READY and not st & KEY_LOADED
    await bus.write_bytes(KEY, b'k' * 32, 8)
    await bus.write(MSG_LEN, 56)
    await bus.write(CTRL, START)
    assert await bus.read(STATUS) & ERR
    await bus.write(MSG_LEN, 3)
    await bus.write_bytes(MSG, b'abc', 14)
    await bus.write(CTRL, START)
    assert not (await bus.read(STATUS)) & ERR
    await bus.write(CTRL, START)
    assert (await bus.read(STATUS)) & ERR
    await bus.write(MSG_LEN, 9)
    assert await bus.read(MSG_LEN) == 3
    await wait_status(bus, DONE)
    mac = await bus.read_bytes(MAC, 8)
    assert mac == hmac.new(b'k' * 32, b'abc', hashlib.sha256).digest()


@cocotb.test(skip=GateLevelTest)
async def test_scrubbed_after_each_operation(dut):
    '''After DONE only the key states and the MAC remain anywhere.'''
    bus = await setup(dut)
    await mac_of(bus, b'scrub test message', b'K' * 32)
    await ClockCycles(dut.clk, 3)
    await Timer(1, units='ns')
    left = residue(dut, keep=('ctrl.istate', 'ctrl.ostate', 'ctrl.mac'))
    assert not left, f'state left after operation: {left}'


@cocotb.test(skip=GateLevelTest)
async def test_clear_key_and_abort(dut):
    bus = await setup(dut)
    key = b'abort-me' * 4
    await mac_of(bus, b'first', key)
    await bus.write(CTRL, START)
    await ClockCycles(dut.clk, 900)
    assert not (await bus.read(STATUS)) & READY
    await bus.write(CTRL, CLEAR_KEY)
    await ClockCycles(dut.clk, 3)
    await Timer(1, units='ns')
    for i in range(8):
        assert int(dut.key_w[i].value) == 0
    left = residue(dut)
    assert not left, f'not cleared by CLEAR_KEY: {left}'
    assert await bus.read_bytes(MAC, 8) == bytes(32)
    st = await bus.read(STATUS)
    assert st & READY and not st & KEY_LOADED and not st & DONE
    await bus.write(CTRL, START)
    assert (await bus.read(STATUS)) & ERR
    assert await mac_of(bus, b'first', key) == hmac.new(key, b'first', hashlib.sha256).digest()


@cocotb.test(skip=GateLevelTest)
async def test_clear_data_keeps_key(dut):
    bus = await setup(dut)
    key = b'keep this key!!!' * 2
    await mac_of(bus, b'some data', key)
    await bus.write(CTRL, START)
    await ClockCycles(dut.clk, 300)                 # abort mid-operation too
    await bus.write(CTRL, CLEAR_DATA)
    await ClockCycles(dut.clk, 3)
    await Timer(1, units='ns')
    for i in range(14):
        assert int(dut.msg_w[i].value) == 0
    assert await bus.read(MSG_LEN) == 0
    assert await bus.read_bytes(MAC, 8) == bytes(32)
    left = residue(dut, keep=('ctrl.istate', 'ctrl.ostate'))
    assert not left, f'not cleared by CLEAR_DATA: {left}'
    assert (await bus.read(STATUS)) & KEY_LOADED
    assert await mac_of(bus, b'next') == hmac.new(key, b'next', hashlib.sha256).digest()


@cocotb.test(skip=GateLevelTest)
async def test_bus_level_latency(dut):
    '''Cycles for the first HMAC after a key write (includes precompute) and
    for a following one.'''
    bus = await setup(dut)
    key = bytes(32)
    count = {'n': 0}

    async def counter():
        while True:
            await RisingEdge(dut.clk)
            count['n'] += 1
    cocotb.start_soon(counter())
    msg = b'authenticate me: nonce=8f3a21c0'
    await bus.write_bytes(KEY, key, 8)
    t0 = count['n']
    assert await mac_of(bus, msg) == hmac.new(key, msg, hashlib.sha256).digest()
    first = count['n'] - t0
    t0 = count['n']
    assert await mac_of(bus, msg) == hmac.new(key, msg, hashlib.sha256).digest()
    second = count['n'] - t0
    dut._log.info(f'over the bus: first HMAC after key write {first} cycles '
                  f'(includes precompute), next HMAC {second} cycles')
