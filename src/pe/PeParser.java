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
 * - PE 格式异常不抛异常，在返回的 RawData.typeError 中标记。
 */
public final class PeParser {
    // PE 规范常量
    private static final long DOS_MAGIC = 0x5A4D;           // "MZ"
    private static final int DOS_LFANEW_OFFSET = 0x3C;      // e_lfanew 在 DOS 头中的偏移
    private static final int PE_SIGNATURE = 0x00004550;      // "PE\0\0"
    private static final int COFF_HEADER_SIZE = 20;          // IMAGE_FILE_HEADER 大小
    private static final int SECTION_HEADER_SIZE = 40;       // IMAGE_SECTION_HEADER 大小
    private static final int MAX_SECTIONS = 96;              // 合理节数量上界

    private PeParser() {
    }

    /**
     * 读取 PE 文件并提取原始字段到 RawData。
     * @param filename PE 文件路径
     * @return 原始数据对象；若格式异常，返回对象的 RawData.typeError 为 true
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
                .lfanew(lreader.readInt(DOS_LFANEW_OFFSET));

            // 用 long 避免 e_lfanew + 4 溢出绕过边界检查
            final long ntHeaderPosition = Integer.toUnsignedLong(rawdata.dosHeader.e_lfanew);

            // 校验 e_lfanew 合理性
            if (ntHeaderPosition + 4 > channel.size()) {
                rawdata.typeError = true;
                return rawdata;
            }

            rawdata.signature = lreader.readInt(ntHeaderPosition);

            // 校验 PE 签名 "PE\0\0"
            if (rawdata.signature != PE_SIGNATURE) {
                rawdata.typeError = true;
                return rawdata;
            }

            final long fileHeaderPosition = ntHeaderPosition + 4;
            rawdata.fileHeader
                .machine(lreader.readShort(fileHeaderPosition))
                .numberOfSections(lreader.readShort(fileHeaderPosition + 2))
                .timeDateStamp(lreader.readInt(fileHeaderPosition + 4))
                .pointerToSymbolTable(lreader.readInt(fileHeaderPosition + 8))
                .numberOfSymbols(lreader.readInt(fileHeaderPosition + 12))
                .sizeOfOptionalHeader(lreader.readShort(fileHeaderPosition + 16))
                .characteristics(lreader.readShort(fileHeaderPosition + 18));

            final long optionalHeaderPosition = fileHeaderPosition + COFF_HEADER_SIZE;
            rawdata.optionalHeader
                .magic(lreader.readShort(optionalHeaderPosition))
                .majorLinkerVersion(lreader.readByte(optionalHeaderPosition + 2))
                .minorLinkerVersion(lreader.readByte(optionalHeaderPosition + 3))
                .addressOfEntryPoint(lreader.readInt(optionalHeaderPosition + 16))
                .baseOfCode(lreader.readInt(optionalHeaderPosition + 20));

            long sectionAlignmentPosition;
            if (rawdata.optionalHeader.magic == 0x10B) {
                rawdata.optionalHeader.imageBase(Integer.toUnsignedLong(lreader.readInt(optionalHeaderPosition + 24)));
                sectionAlignmentPosition = optionalHeaderPosition + 28;
            } else if (rawdata.optionalHeader.magic == 0x20B) {
                rawdata.optionalHeader.imageBase(lreader.readLong(optionalHeaderPosition + 24));
                sectionAlignmentPosition = optionalHeaderPosition + 32;
            } else {
                rawdata.typeError = true;
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

            final long sectionTablePosition = optionalHeaderPosition + Short.toUnsignedInt(rawdata.fileHeader.sizeOfOptionalHeader);
            final int sectionCount = Short.toUnsignedInt(rawdata.fileHeader.numberOfSections);

            // 校验节数量和节表位置合理性
            if (sectionCount > MAX_SECTIONS || sectionTablePosition + (long) sectionCount * SECTION_HEADER_SIZE > channel.size()) {
                rawdata.typeError = true;
                return rawdata;
            }

            // 校验对齐合理性：sectionAlignment 和 fileAlignment 应为 2 的幂且 > 0
            if (rawdata.optionalHeader.sectionAlignment <= 0
                || (rawdata.optionalHeader.sectionAlignment & (rawdata.optionalHeader.sectionAlignment - 1)) != 0
                || rawdata.optionalHeader.fileAlignment <= 0
                || (rawdata.optionalHeader.fileAlignment & (rawdata.optionalHeader.fileAlignment - 1)) != 0) {
                rawdata.typeError = true;
                return rawdata;
            }

            // 校验 sizeOfHeaders 合理性：应大于 0 且不超过文件大小
            if (rawdata.optionalHeader.sizeOfHeaders <= 0
                || rawdata.optionalHeader.sizeOfHeaders > channel.size()) {
                rawdata.typeError = true;
                return rawdata;
            }

            for (int i = 0; i < sectionCount; i++) {
                final long sectionPosition = sectionTablePosition + (long) i * SECTION_HEADER_SIZE;
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
