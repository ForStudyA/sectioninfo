package pe;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;

// 工具类，提供按小端序读取不同类型的方法
// 实例化后使用e.g.
// 1. 先打开文件获取 Channel
// try (RandomAccessFile raf = new RandomAccessFile("file.bin", "r");
//      FileChannel channel = raf.getChannel()) {
    
//     // 2. 实例化 LittleEndianReader
//     LittleEndianReader reader = new LittleEndianReader(channel);
    
//     // 3. 使用实例方法
//     int data = reader.readInt(0x3C);
//     short machine = reader.readShort(0x100);
//     byte b = reader.readByte(0x200);
// }
public class LittleEndianReader {
    private final FileChannel channel;
    private final ByteBuffer buffer;

    public LittleEndianReader(FileChannel channel) {
        this.channel = channel;
        this.buffer = ByteBuffer.allocate(32);
        this.buffer.order(ByteOrder.LITTLE_ENDIAN);
    }

    public byte readByte(long offset) throws IOException {
        buffer.clear();
        buffer.limit(1);
        readFully(offset, 1);
        return buffer.get(0);
    }

    public short readShort(long position) throws IOException {
        buffer.clear();
        buffer.limit(2);
        readFully(position, 2);
        return buffer.getShort(0);
    }

    public int readInt(long position) throws IOException {
        buffer.clear();
        buffer.limit(4);
        readFully(position, 4);
        return buffer.getInt(0);
    }

    public long readLong(long position) throws IOException {
        buffer.clear();
        buffer.limit(8);
        readFully(position, 8);
        return buffer.getLong(0);
    }

    public float readFloat(long position) throws IOException {
        buffer.clear();
        buffer.limit(4);
        readFully(position, 4);
        return buffer.getFloat(0);
    }

    public double readDouble(long position) throws IOException {
        buffer.clear();
        buffer.limit(8);
        readFully(position, 8);
        return buffer.getDouble(0);
    }

    public char readChar(long position) throws IOException {
        buffer.clear();
        buffer.limit(2);
        readFully(position, 2);
        return buffer.getChar(0);
    }

    public String readAsciiString(long position, int length) throws IOException {
        ByteBuffer nameBuffer = ByteBuffer.allocate(length);
        int read = 0;
        while (read < length) {
            int n = channel.read(nameBuffer, position + read);
            if (n < 0) {
                throw new IOException("EOF reading ASCII string at offset " + (position + read)
                    + ", expected " + length + " bytes but got " + read);
            }
            read += n;
        }
        byte[] bytes = nameBuffer.array();
        int end = 0;
        while (end < bytes.length && bytes[end] != 0) {
            end++;
        }
        // 过滤不可打印字符（0x00-0x1F, 0x7F-0x9F），替换为 '.' 避免方框乱码
        byte[] clean = new byte[end];
        int out = 0;
        for (int i = 0; i < end; i++) {
            int b = bytes[i] & 0xFF;
            if (b >= 0x20 && b < 0x7F || b >= 0xA0) {
                clean[out++] = bytes[i];
            } else {
                clean[out++] = (byte) '.';
            }
        }
        return new String(clean, 0, out, StandardCharsets.ISO_8859_1);
    }

    private void readFully(long position, int length) throws IOException {
        int read = 0;
        while (read < length) {
            int n = channel.read(buffer, position + read);
            if (n < 0) {
                throw new IOException("EOF at offset " + (position + read)
                    + ", expected " + length + " bytes but got " + read);
            }
            read += n;
        }
    }
}
