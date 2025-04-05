import pytest
import os
import struct

from multiprocessing import Queue, Process
from typing import List

from pymmapipc.mmapipc import MmapIPC, MAGIC_NUMBER, StructFormats, StructSizes, HeaderIndices, SignBits


@pytest.fixture
def temp_file(tmp_path):
    test_file = tmp_path / "test_ipc.mmap"
    yield str(test_file)


def test_initialize(temp_file):
    mmap = MmapIPC(temp_file)   # noqa: F841

    # Verify mmap file exists
    assert os.path.exists(temp_file)

    # Verfy mmap header correct
    with open(temp_file, 'rb') as f:
        raw_header = f.read(StructSizes.Header)
        magic, version, ptr_a, ptr_b, sign = struct.unpack(StructFormats.Header.value, raw_header)
        assert magic == MAGIC_NUMBER
        assert version == 1
        assert sign & (SignBits.OPA | SignBits.OPB) != 0
        assert sign & SignBits.OPA == SignBits.OPA


def test_OP_assign(temp_file):
    oa = MmapIPC(temp_file)         # noqa: F841
    with open(temp_file, 'rb') as f:
        raw_header = f.read(StructSizes.Header)
        sign = struct.unpack(StructFormats.Header.value, raw_header)[HeaderIndices.Sign]
        assert sign & (SignBits.OPA | SignBits.OPB) == SignBits.OPA

    ob = MmapIPC(temp_file)         # noqa: F841
    with open(temp_file, 'rb') as f:
        raw_header = f.read(StructSizes.Header)
        sign = struct.unpack(StructFormats.Header.value, raw_header)[HeaderIndices.Sign]
        assert sign & (SignBits.OPA | SignBits.OPB) == (SignBits.OPA | SignBits.OPB)

    with pytest.raises(BufferError) as e:
        oc = MmapIPC(temp_file)     # noqa: F841

    assert str(e.value) == "This mmap file in use."


def test_reset_behavior(temp_file):
    oa = MmapIPC(temp_file)
    with open(temp_file, 'rb') as f:
        raw_header = f.read(StructSizes.Header)
        sign = struct.unpack(StructFormats.Header.value, raw_header)[HeaderIndices.Sign]
        assert sign & (SignBits.OPA | SignBits.OPB) == SignBits.OPA

    del oa

    with open(temp_file, 'rb') as f:
        raw_header = f.read(StructSizes.Header)
        sign = struct.unpack(StructFormats.Header.value, raw_header)[HeaderIndices.Sign]
        assert sign & (SignBits.OPA | SignBits.OPB) == 0


def test_invalid_magic(temp_file):
    MmapIPC(temp_file)

    with open(temp_file, 'r+b') as f:
        f.seek(0)
        f.write(struct.pack('<I', 0xDEADBEEF))

    with pytest.raises(BufferError) as e:
        MmapIPC(temp_file)

    assert str(e.value) == f"Error magic number: {bytes.fromhex(hex(0xDEADBEEF)[2:])[::-1]}"


def test_send_recv_basic(temp_file):
    sender = MmapIPC(temp_file)
    receiver = MmapIPC(temp_file)

    test_data = b'Hello Worlda'
    sent_num = sender.send(test_data)
    assert sent_num == len(test_data)

    recv_data = receiver.recv()
    assert recv_data == test_data


def test_multi_data_transfer(temp_file):
    sender = MmapIPC(temp_file)
    receiver = MmapIPC(temp_file)

    test_data_1 = b'A' * 1024
    test_data_2 = b'B' * 1024

    sent_num_1 = sender.send(test_data_1)
    assert sent_num_1 == len(test_data_1)
    sent_num_2 = sender.send(test_data_2)
    assert sent_num_2 == len(test_data_2)

    recv_data_1 = receiver.recv()
    assert recv_data_1 == test_data_1
    recv_data_2 = receiver.recv()
    assert recv_data_2 == test_data_2


def test_buffer_full(temp_file):
    test_buff_size = 16
    sender = MmapIPC(temp_file, buff_size=test_buff_size)
    receiver = MmapIPC(temp_file, buff_size=test_buff_size)

    # Forward (in_offset >= out_offset)
    test_data = b'A' * (test_buff_size // 2 - 4)
    sent_num = sender.send(test_data)
    assert sent_num == len(test_data)

    test_data = b'B' * (test_buff_size // 2 - 4)
    sent_num = sender.send(test_data)
    assert sent_num == len(test_data)

    assert sender.send(b'C') == 0

    receiver.recv()
    receiver.recv()

    # Backward (out_offset >= in_offset)
    test_data = b'A' * (test_buff_size // 2 - 4)
    sent_num = sender.send(test_data)

    receiver.recv()

    test_data = b'B' * (test_buff_size - 4)
    sent_num = sender.send(test_data)

    assert sender.send(b'C') == 0


def test_ring_buffer_wrapping(temp_file):
    test_buff_size = 32
    sender = MmapIPC(temp_file, buff_size=test_buff_size)
    receiver = MmapIPC(temp_file, buff_size=test_buff_size)

    test_data = b'A' * ((test_buff_size // 2) - 4)
    sent_num = sender.send(test_data)
    assert sent_num == len(test_data)

    recv_data = receiver.recv()
    assert recv_data == test_data

    test_data = b'B' * (test_buff_size - 4)
    sent_num = sender.send(test_data)
    assert sent_num == len(test_data)

    recv_data = receiver.recv()
    assert recv_data == test_data


def test_data_size_wrapping(temp_file):
    test_buff_size = 32
    sender = MmapIPC(temp_file, buff_size=test_buff_size)
    receiver = MmapIPC(temp_file, buff_size=test_buff_size)

    test_data = b'A' * ((test_buff_size - 2) - 4)
    sent_num = sender.send(test_data)
    assert sent_num == len(test_data)

    recv_data = receiver.recv()
    assert recv_data == test_data

    test_data = b'B' * (test_buff_size - 4)
    sent_num = sender.send(test_data)
    assert sent_num == len(test_data)

    recv_data = receiver.recv()
    assert recv_data == test_data


def test_empty_read(temp_file):
    test_buff_size = 4
    receiver = MmapIPC(temp_file, buff_size=test_buff_size)

    assert receiver.recv() is None


def test_overtime_rw(temp_file):
    test_buff_size = 4
    sender = MmapIPC(temp_file, buff_size=test_buff_size)
    receiver = MmapIPC(temp_file, buff_size=test_buff_size)

    with pytest.raises(TimeoutError):
        sender.send(b'A' * 8, blocking=True, timeout=0.1)

    with pytest.raises(TimeoutError):
        receiver.recv(blocking=True, timeout=0.1)


def _task_send(temp_file: str, test_data: List[bytes], queue: Queue) -> None:
    sender = MmapIPC(temp_file)
    status = []
    for i in range(10):
        index = i % len(test_data)
        sent_num = sender.send(test_data[index], blocking=True, timeout=None)
        status.append(sent_num == len(test_data[index]))

    queue.put(("send", status))


def _task_read(temp_file: str, test_data: List[bytes], queue: Queue) -> None:
    reader = MmapIPC(temp_file)
    status = []
    for i in range(10):
        index = i % len(test_data)
        recv_data = reader.recv(blocking=True)
        status.append(recv_data == test_data[index])

    queue.put(("recv", status))


def test_multiprocess_rw_concurrent(temp_file):
    test_data = [
        b'1' * 512,
        b'2' * 512,
        b'3' * 512,
        b'4' * 512,
        b'5' * 512,
        b'6' * 512,
        b'7' * 512,
        b'8' * 512,
        b'9' * 512,
        b'A' * 512
    ]

    queue = Queue()
    p_send = Process(target=_task_send, args=(temp_file, test_data, queue))
    p_read = Process(target=_task_read, args=(temp_file, test_data, queue))

    p_read.start()
    p_send.start()

    p_read.join()
    p_send.join()

    status_1 = queue.get()
    status_2 = queue.get()

    print(status_1)
    print(status_2)

    assert status_1[1] == status_2[1]
