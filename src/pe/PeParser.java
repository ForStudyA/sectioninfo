package pe;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.channels.FileChannel;

import model.RawData;

/**
 * 原始数据提取器（低层接口）。
 * 适用场景：
 * - 需要拿到 RawData 做二次处理，而不是直接展示。
 *
 * 使用方式：
 * try {
 *     RawData raw = PeParser.parse(filePath);
 *     // 再交给转换层或自行处理
 * } catch (IOException ex) {
 *     // 文件读取异常：文件不存在、权限不足、读取失败等
 * }
 *
 * 异常处理说明：
 * - 文件读取相关问题通过 IOException 抛给调用方。
 * - PE 格式异常不抛异常，在返回的 RawData.TypeError 中标记。
 */
public final class PeParser {
    private PeParser() {
    }

    /**
     * 读取 PE 文件并提取原始字段到 RawData。
     * @param filename PE 文件路径
     * @return 原始数据对象；若格式异常，返回对象的 RawData.TypeError 为 true
     * @throws IOException 文件读取相关异常
     */
    public static RawData parse(String filename) throws IOException {
        RawData rawdata = new RawData();
        rawdata.sourceFilePath = filename;

        try (RandomAccessFile raf = new RandomAccessFile(filename, "r")) {
            FileChannel channel = raf.getChannel();
            LittleEndianReader lreader = new LittleEndianReader(channel);

            rawdata.dosHeader
                .magic(lreader.readShort(0))
                .lfanew(lreader.readInt(0x3c));

            final int ntHeaderPosition = rawdata.dosHeader.e_lfanew;
            rawdata.signature = lreader.readInt(ntHeaderPosition);

            final int fileHeaderPosition = ntHeaderPosition + 4;
            rawdata.fileHeader
                .machine(lreader.readShort(fileHeaderPosition))
                .numberOfSections(lreader.readShort(fileHeaderPosition + 2))
                .timeDateStamp(lreader.readInt(fileHeaderPosition + 4))
                .pointerToSymbolTable(lreader.readInt(fileHeaderPosition + 8))
                .numberOfSymbols(lreader.readInt(fileHeaderPosition + 12))
                .sizeOfOptionalHeader(lreader.readShort(fileHeaderPosition + 16))
                .characteristics(lreader.readShort(fileHeaderPosition + 18));

            final int optionalHeaderPosition = fileHeaderPosition + 20;
            rawdata.optionalHeader
                .magic(lreader.readShort(optionalHeaderPosition))
                .majorLinkerVersion(lreader.readByte(optionalHeaderPosition + 2))
                .minorLinkerVersion(lreader.readByte(optionalHeaderPosition + 3))
                .addressOfEntryPoint(lreader.readInt(optionalHeaderPosition + 16))
                .baseOfCode(lreader.readInt(optionalHeaderPosition + 20));

            int sectionAlignmentPosition;
            if (rawdata.optionalHeader.magic == 0x10B) {
                rawdata.optionalHeader.imageBase(Integer.toUnsignedLong(lreader.readInt(optionalHeaderPosition + 24)));
                sectionAlignmentPosition = optionalHeaderPosition + 28;
            } else if (rawdata.optionalHeader.magic == 0x20B) {
                rawdata.optionalHeader.imageBase(lreader.readLong(optionalHeaderPosition + 24));
                sectionAlignmentPosition = optionalHeaderPosition + 32;
            } else {
                rawdata.TypeError = true;
                return rawdata;
            }

            rawdata.optionalHeader
                .sectionAlignment(lreader.readInt(sectionAlignmentPosition))
                .fileAlignment(lreader.readInt(sectionAlignmentPosition + 4))
                .majorOperatingSystemVersion(lreader.readShort(sectionAlignmentPosition + 8))
                .minorOperatingSystemVersion(lreader.readShort(sectionAlignmentPosition + 10))
                .majorImageVersion(lreader.readShort(sectionAlignmentPosition + 12))
                .minorImageVersion(lreader.readShort(sectionAlignmentPosition + 14))
                .majorSubsystemVersion(lreader.readShort(sectionAlignmentPosition + 16))
                .minorSubsystemVersion(lreader.readShort(sectionAlignmentPosition + 18))
                .sizeOfImage(lreader.readInt(sectionAlignmentPosition + 24))
                .sizeOfHeaders(lreader.readInt(sectionAlignmentPosition + 28))
                .subsystem(lreader.readShort(sectionAlignmentPosition + 36));

            final int sectionTablePosition = optionalHeaderPosition + Short.toUnsignedInt(rawdata.fileHeader.sizeOfOptionalHeader);
            final int sectionCount = Short.toUnsignedInt(rawdata.fileHeader.numberOfSections);
            for (int i = 0; i < sectionCount; i++) {
                final int sectionPosition = sectionTablePosition + i * 40;
                RawData.RawSectionInfo section = new RawData.RawSectionInfo()
                    .name(lreader.readAsciiString(sectionPosition, 8))
                    .virtualSize(lreader.readInt(sectionPosition + 8))
                    .virtualAddress(lreader.readInt(sectionPosition + 12))
                    .sizeOfRawData(lreader.readInt(sectionPosition + 16))
                    .pointerToRawData(lreader.readInt(sectionPosition + 20))
                    .characteristics(lreader.readInt(sectionPosition + 36));
                rawdata.addSection(section);
            }
        }

        return rawdata;
    }
}
