"""
        +--------------------------------+
        |          Magic Number          |
        +--------------------------------+
        |            Version             |
        +--------------------------------+
+-------+   Single Buffer Base Point A   |                A                                  B
|       +--------------------------------+           +----------+                   +-----------------+
| +-----+   Single Buffer Base Point B   |     Send  |   Data   +------------------>| Single Buffer B |
| |     +-+-+-+--------------------------+           +----------+                   +-----------------+
| |     |R|O|O|                          |                                          +----+------------+
| |     |S|P|P|                          |           +----------+                   |Size|  Data....  |
| |     |T|A|B|                          |     Read  |   Data   |<-----+            +----+------------+
| |     +-+-+-+--------------------------+           +----------+      |           31    0
| |     31    29                         0                             |
| |                                                                    |
| |     +--------------------------------+        +-----------------+  |
| +---->|      Ring Buffer In Offset     |        | Single Buffer A |  |
|       +--------------------------------+        +-----------------+  |
|       |      Ring Buffer Out Offset    |        +----+------------+  |
|       +--------------------------------+        |Size|  Data....  +--+
|       |        Ring Buffer Size        |        +----+------------+
|       +--------------------------------+       31    0
|       31                               0
|
|       +--------------------------------+
+------>|      Ring Buffer In Offset     |
        +--------------------------------+
        |      Ring Buffer Out Offset    |
        +--------------------------------+
        |        Ring Buffer Size        |
        +--------------------------------+
        31                               0
"""


import mmap
import struct
import os
import time

from enum import IntEnum, Enum
from typing import Optional, Tuple, Sequence


class StructFormats(Enum):
    Header = "<IIIII"
    Buffer = "<III"


class StructSizes(IntEnum):
    Header = struct.calcsize(StructFormats.Header)
    Buffer = struct.calcsize(StructFormats.Buffer)


class HeaderIndices(IntEnum):
    Magic = 0
    Version = 1
    Buffer_Base_Point_A = 2
    Buffer_Base_Point_B = 3
    Sign = 4


class BufferIndices(IntEnum):
    InOffset = 0
    OutOffset = 1
    Size = 2


class SignBits(IntEnum):
    OPB = 0x20000000
    OPA = 0x40000000
    RST = 0x80000000


__version__ = 1
MAGIC_NUMBER = 0x50414D4D


class MmapIPC():
    def __init__(self, mmap_file: str, buff_size: int = 4096):
        self.is_initialized = False

        # Initialize file
        if (not os.path.exists(mmap_file)):
            self.__init_mmap_file(mmap_file, buff_size)

        self.mmap = self.__mmap(mmap_file)

        header = self.__read_mmap_header()
        if (header[HeaderIndices.Magic] == 0x00000000):
            self.__init_mmap_struct(buff_size)

        elif (header[HeaderIndices.Magic] not in [MAGIC_NUMBER, 0x00000000]):
            raise BufferError(
                f"Error magic number: {str(bytes.fromhex(hex(header[HeaderIndices.Magic])[2:])[::-1])}"
            )

        self.assign_op = 0
        self.recv_buff_base_ptr = 0
        self.send_buff_base_ptr = 0

        self.assign_op, self.recv_buff_base_ptr, self.send_buff_base_ptr = self.__get_buff_base_ptr()

        self.is_initialized = True

    def __mmap(self, mmap_file: str) -> mmap.mmap:
        self.fd = open(mmap_file, 'r+b')
        return mmap.mmap(
            self.fd.fileno(),
            0,
            access=mmap.ACCESS_WRITE
        )

    def __init_mmap_file(self, mmap_file: str, buff_size: int) -> None:
        struct_size = StructSizes.Header + StructSizes.Buffer * 2

        with open(mmap_file, 'wb') as f:
            f.write(b'\x00' * (struct_size + (buff_size + 1) * 2))

    def __init_mmap_struct(self, buff_size: int) -> None:
        buff_base_ptr_A = StructSizes.Header
        buff_base_ptr_B = buff_base_ptr_A + StructSizes.Buffer + buff_size + 1

        # Initialize mmap header
        self.__write_mmap_header((
            MAGIC_NUMBER,
            __version__,
            buff_base_ptr_A,
            buff_base_ptr_B,
            0x00000000
        ))

        # Initialize buff A
        self.__write_buff_header(
            buff_base_ptr_A,
            (0x00000000, 0x00000000, buff_size + 1)
        )

        # Initialize buff B
        self.__write_buff_header(
            buff_base_ptr_B,
            (0x00000000, 0x00000000, buff_size + 1)
        )

    def __get_buff_base_ptr(self) -> Tuple:
        header = list(self.__read_mmap_header())
        sign = header[HeaderIndices.Sign]
        self.mmap.seek(0)
        if (not (sign & SignBits.OPA)):
            # OPA
            header[HeaderIndices.Sign] = sign | SignBits.OPA
            self.mmap.write(struct.pack(
                StructFormats.Header,
                *header
            ))

            return (SignBits.OPA, header[HeaderIndices.Buffer_Base_Point_A], header[HeaderIndices.Buffer_Base_Point_B])

        if (not (sign & SignBits.OPB)):
            # OPB
            header[HeaderIndices.Sign] = sign | SignBits.OPB
            self.mmap.write(struct.pack(
                StructFormats.Header,
                *header
            ))

            return (SignBits.OPB, header[HeaderIndices.Buffer_Base_Point_B], header[HeaderIndices.Buffer_Base_Point_A])

        raise BufferError("This mmap file in use.")

    def __read_buff_header(self, buff_ptr: int) -> Tuple:
        self.mmap.seek(buff_ptr)
        raw_buff_header = self.mmap.read(StructSizes.Buffer)
        return struct.unpack(StructFormats.Buffer, raw_buff_header)

    def __write_buff_header(self, buff_base_ptr: int, header: Sequence) -> None:
        self.mmap.seek(buff_base_ptr)
        self.mmap.write(struct.pack(
            StructFormats.Buffer,
            *header
        ))

    def __update_buff_offset(self, offset_ptr: int, offset: int) -> None:
        self.mmap.seek(offset_ptr)
        self.mmap.write(struct.pack(
            '<I',
            offset
        ))

    def __read_mmap_header(self) -> Tuple:
        self.mmap.seek(0)
        raw_mmap_header = self.mmap.read(StructSizes.Header)
        return struct.unpack(StructFormats.Header, raw_mmap_header)

    def __write_mmap_header(self, header: Sequence) -> None:
        self.mmap.seek(0)
        self.mmap.write(struct.pack(
            StructFormats.Header,
            *header
        ))

    def __calc_buff_available_size(self, in_offset: int, out_offset: int, buff_size: int) -> Tuple[int, int]:
        if in_offset >= out_offset:
            return (buff_size - in_offset, out_offset)

        else:
            return (out_offset - in_offset, 0)

    def send(self, data: bytes, blocking: bool = False, timeout: Optional[float] = 15.0) -> int:
        in_offset, out_offset, buff_size = self.__read_buff_header(self.send_buff_base_ptr)

        front_available, back_available = self.__calc_buff_available_size(in_offset, out_offset, buff_size)
        total_available = front_available + back_available

        data_size = len(data)
        require_size = data_size + 4

        if (total_available < require_size and not blocking):
            return 0

        sleep_time = 0.1
        while total_available < require_size:
            if (timeout is not None):
                if (timeout <= 0):
                    raise TimeoutError()

                sleep_time = min(sleep_time, timeout)
                timeout -= sleep_time

            time.sleep(sleep_time)
            in_offset, out_offset, buff_size = self.__read_buff_header(self.send_buff_base_ptr)
            front_available, back_available = self.__calc_buff_available_size(in_offset, out_offset, buff_size)
            total_available = front_available + back_available

        len_f = min(require_size, front_available)
        self.mmap.seek(self.send_buff_base_ptr + StructSizes.Buffer + in_offset)
        data = struct.pack('<I', data_size) + data
        self.mmap.write(data[:len_f])

        len_b = data_size - len_f
        if (len_b > 0):
            self.mmap.seek(self.send_buff_base_ptr + StructSizes.Buffer)
            self.mmap.write(data[len_f:])

        # Update in_offset
        in_offset = (in_offset + require_size) % buff_size
        self.__update_buff_offset(self.send_buff_base_ptr + (BufferIndices.InOffset * 4), in_offset)

        return data_size

    def recv(self, blocking: bool = False, timeout: Optional[float] = 15.0) -> Optional[bytes]:
        in_offset, out_offset, buff_size = self.__read_buff_header(self.recv_buff_base_ptr)

        if (in_offset == out_offset and not blocking):
            return None

        sleep_time = 0.1
        while in_offset == out_offset:
            if (timeout is not None):
                if (timeout <= 0):
                    raise TimeoutError()

                sleep_time = min(sleep_time, timeout)
                timeout -= sleep_time

            time.sleep(sleep_time)
            in_offset, out_offset, buff_size = self.__read_buff_header(self.recv_buff_base_ptr)

        self.mmap.seek(self.recv_buff_base_ptr + StructSizes.Buffer + out_offset)

        tail_read_len = buff_size - out_offset
        if (tail_read_len < 4):
            raw_data_size = self.mmap.read(tail_read_len)
            self.mmap.seek(self.recv_buff_base_ptr + StructSizes.Buffer)
            raw_data_size += self.mmap.read(4 - tail_read_len)

        else:
            raw_data_size = self.mmap.read(4)

        data_size: int
        data_size = struct.unpack('<I', raw_data_size)[0]

        len_f = min(data_size, buff_size - (out_offset + 4))

        if (len_f <= 0):
            len_f = data_size

        data = self.mmap.read(len_f)

        len_b = data_size - len(data)
        if (len_b > 0):
            self.mmap.seek(self.recv_buff_base_ptr + StructSizes.Buffer)
            data_b = self.mmap.read(len_b)
            data += data_b

        # Update out_offset
        out_offset = (out_offset + 4 + data_size) % buff_size
        self.__update_buff_offset(self.recv_buff_base_ptr + (BufferIndices.OutOffset * 4), out_offset)

        return data

    def __del__(self) -> None:
        if (self.is_initialized):
            # Clean OP Bit
            raw_mmap_header = list(self.__read_mmap_header())
            raw_mmap_header[HeaderIndices.Sign] &= ~self.assign_op
            self.__write_mmap_header(raw_mmap_header)

            # Clean recv buffer
            raw_recv_buff_header = list(self.__read_buff_header(self.recv_buff_base_ptr))
            raw_recv_buff_header[BufferIndices.InOffset] = 0
            raw_recv_buff_header[BufferIndices.OutOffset] = 0
            self.__write_buff_header(self.recv_buff_base_ptr, raw_recv_buff_header)

        # Close & Release
        self.mmap.close()
        self.fd.close()
