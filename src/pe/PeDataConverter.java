package pe;

import java.io.IOException;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Locale;

import model.RawData;
import model.ShowData;

final class PeDataConverter {
    private static final DateTimeFormatter DATE_TIME_FORMATTER =
        DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss", Locale.getDefault())
            .withZone(ZoneId.systemDefault());

    private PeDataConverter() {
    }

    public static ShowData convert(RawData raw) {
        ShowData show = ShowData.create();
        if (raw == null || raw.typeError) {
            show.dosHeader.magicStatus("格式异常");
            return show;
        }

        try {
            show.dosHeader
                .magicStatus(Short.toUnsignedInt(raw.dosHeader.e_magic) == 0x5A4D ? "有效 (MZ)" : "无效");

            show.fileHeader
                .machine(formatMachine(raw.fileHeader.machine))
                .numberOfSections(Integer.toString(Short.toUnsignedInt(raw.fileHeader.numberOfSections)))
                .timeDateStamp(formatTimeDateStamp(raw.fileHeader.timeDateStamp))
                .pointerToSymbolTable(formatHex(raw.fileHeader.pointerToSymbolTable, 8))
                .numberOfSymbols(Integer.toUnsignedString(raw.fileHeader.numberOfSymbols))
                .sizeOfOptionalHeader(formatHex(Short.toUnsignedInt(raw.fileHeader.sizeOfOptionalHeader), 4))
                .characteristics(formatFileCharacteristics(raw.fileHeader.characteristics));

            show.optionalHeader
                .magic(formatOptionalMagic(raw.optionalHeader.magic))
                .LinkerVersion(formatUnsignedByte(raw.optionalHeader.majorLinkerVersion) + "."
                    + formatUnsignedByte(raw.optionalHeader.minorLinkerVersion))
                .addressOfEntryPoint(formatHex(raw.optionalHeader.addressOfEntryPoint, 8))
                .baseOfCode(formatHex(raw.optionalHeader.baseOfCode, 8))
                .imageBase(formatImageBase(raw.optionalHeader.imageBase))
                .sectionAlignment(formatHex(raw.optionalHeader.sectionAlignment, 8))
                .fileAlignment(formatHex(raw.optionalHeader.fileAlignment, 8))
                .OperatingSystemVersion(formatUnsignedShort(raw.optionalHeader.majorOperatingSystemVersion) + "."
                    + formatUnsignedShort(raw.optionalHeader.minorOperatingSystemVersion))
                .ImageVersion(formatUnsignedShort(raw.optionalHeader.majorImageVersion) + "."
                    + formatUnsignedShort(raw.optionalHeader.minorImageVersion))
                .SubsystemVersion(formatUnsignedShort(raw.optionalHeader.majorSubsystemVersion) + "."
                    + formatUnsignedShort(raw.optionalHeader.minorSubsystemVersion))
                .sizeOfImage(formatBytes(raw.optionalHeader.sizeOfImage) + " 字节")
                .sizeOfHeaders(formatBytes(raw.optionalHeader.sizeOfHeaders) + " 字节")
                .subsystem(formatSubsystem(raw.optionalHeader.subsystem));

            for (RawData.RawSectionInfo rawSection : raw.sections) {
                show.addSection(new ShowData.SectionInfo()
                    .name(getRealSectionName(raw, rawSection.name))
                    .virtualSize(formatBytes(rawSection.virtualSize) + " 字节")
                    .virtualAddress(formatHex(rawSection.virtualAddress, 8))
                    .sizeOfRawData(formatBytes(rawSection.sizeOfRawData) + " 字节")
                    .pointerToRawData(formatHex(rawSection.pointerToRawData, 8))
                    .characteristics(formatSectionCharacteristics(rawSection.characteristics)));
            }
        } catch (RuntimeException ex) {
            // 异常时重置所有字段，避免部分填充的脏数据
            ShowData errorShow = ShowData.create();
            errorShow.dosHeader.magicStatus("读取异常");
            System.err.println("[PeDataConverter] convert failed: " + ex.getClass().getSimpleName() + ": " + ex.getMessage());
            return errorShow;
        }

        validateShowData(show);
        return show;
    }

    /**
     * 转换后验证：确保所有 ShowData 字段非空，防止 UI 层 NPE。
     * 如果有字段为 null，填充为安全的默认值。
     */
    private static void validateShowData(ShowData show) {
        if (show.dosHeader.magicStatus == null) show.dosHeader.magicStatus("未知");
        if (show.fileHeader.machine == null) show.fileHeader.machine("未知");
        if (show.fileHeader.numberOfSections == null) show.fileHeader.numberOfSections("0");
        if (show.fileHeader.timeDateStamp == null) show.fileHeader.timeDateStamp("未知");
        if (show.fileHeader.pointerToSymbolTable == null) show.fileHeader.pointerToSymbolTable("0x00000000");
        if (show.fileHeader.numberOfSymbols == null) show.fileHeader.numberOfSymbols("0");
        if (show.fileHeader.sizeOfOptionalHeader == null) show.fileHeader.sizeOfOptionalHeader("0x0000");
        if (show.fileHeader.characteristics == null) show.fileHeader.characteristics("未知");
        if (show.optionalHeader.magic == null) show.optionalHeader.magic("未知");
        if (show.optionalHeader.LinkerVersion == null) show.optionalHeader.LinkerVersion("0.0");
        if (show.optionalHeader.addressOfEntryPoint == null) show.optionalHeader.addressOfEntryPoint("0x00000000");
        if (show.optionalHeader.baseOfCode == null) show.optionalHeader.baseOfCode("0x00000000");
        if (show.optionalHeader.imageBase == null) show.optionalHeader.imageBase("0");
        if (show.optionalHeader.sectionAlignment == null) show.optionalHeader.sectionAlignment("0x00000000");
        if (show.optionalHeader.fileAlignment == null) show.optionalHeader.fileAlignment("0x00000000");
        if (show.optionalHeader.OperatingSystemVersion == null) show.optionalHeader.OperatingSystemVersion("0.0");
        if (show.optionalHeader.ImageVersion == null) show.optionalHeader.ImageVersion("0.0");
        if (show.optionalHeader.SubsystemVersion == null) show.optionalHeader.SubsystemVersion("0.0");
        if (show.optionalHeader.sizeOfImage == null) show.optionalHeader.sizeOfImage("0 字节");
        if (show.optionalHeader.sizeOfHeaders == null) show.optionalHeader.sizeOfHeaders("0 字节");
        if (show.optionalHeader.subsystem == null) show.optionalHeader.subsystem("未知");
        for (ShowData.SectionInfo sec : show.sections) {
            if (sec.name == null) sec.name("未知");
            if (sec.virtualSize == null) sec.virtualSize("0 字节");
            if (sec.virtualAddress == null) sec.virtualAddress("0x00000000");
            if (sec.sizeOfRawData == null) sec.sizeOfRawData("0 字节");
            if (sec.pointerToRawData == null) sec.pointerToRawData("0x00000000");
            if (sec.characteristics == null) sec.characteristics("未知");
        }
    }

    private static String formatMachine(short machine) {
        int value = Short.toUnsignedInt(machine);
        return switch (value) {
            case 0x014C -> "x86 (32位)";
            case 0x8664 -> "x64 (64位)";
            case 0x01C0 -> "ARM";
            case 0xAA64 -> "ARM64";
            default -> formatHex(value, 4);
        };
    }

    private static String formatTimeDateStamp(int timestamp) {
        if (timestamp == 0) {
            return "0";
        }
        long epochSecond = Integer.toUnsignedLong(timestamp);
        return DATE_TIME_FORMATTER.format(Instant.ofEpochSecond(epochSecond));
    }

    private static String formatFileCharacteristics(short characteristics) {
        int value = Short.toUnsignedInt(characteristics);
        StringBuilder sb = new StringBuilder();
        appendTextFlag(sb, value, 0x0002, "可执行文件");
        appendTextFlag(sb, value, 0x2000, "DLL文件");
        appendTextFlag(sb, value, 0x0001, "无重定位");
        if (sb.length() == 0) {
            return formatHex(value, 4);
        }
        return sb.toString();
    }

    private static String formatOptionalMagic(short magic) {
        int value = Short.toUnsignedInt(magic);
        return switch (value) {
            case 0x010B -> "PE32";
            case 0x020B -> "PE32+";
            default -> formatHex(value, 4);
        };
    }

    private static String formatImageBase(long imageBase) {
        if (imageBase == 0) {
            return "0";
        }
        return String.format(Locale.ROOT, "0x%X", imageBase);
    }

    private static String formatSubsystem(short subsystem) {
        int value = Short.toUnsignedInt(subsystem);
        return switch (value) {
            case 0x0001 -> "Native";
            case 0x0002 -> "Windows GUI";
            case 0x0003 -> "Windows CUI";
            default -> formatHex(value, 4);
        };
    }

    private static String formatSectionCharacteristics(int characteristics) {
        StringBuilder sb = new StringBuilder();

        // -------- 类型标志（低4位：节中包含什么）--------
        appendTextFlag(sb, characteristics, 0x00000020, "代码");
        appendTextFlag(sb, characteristics, 0x00000040, "已初始化数据");
        appendTextFlag(sb, characteristics, 0x00000080, "未初始化数据");
        appendTextFlag(sb, characteristics, 0x00000100, "扩展重定位数据");
        appendTextFlag(sb, characteristics, 0x00000200, "包含注释/其他");
        appendTextFlag(sb, characteristics, 0x00000800, "链接器私有");
        appendTextFlag(sb, characteristics, 0x00001000, "压缩数据");

        // -------- 权限标志（高4位：内存中如何访问）--------
        appendTextFlag(sb, characteristics, 0x10000000, "可共享");
        appendTextFlag(sb, characteristics, 0x20000000, "可执行");
        appendTextFlag(sb, characteristics, 0x40000000, "可读");
        appendTextFlag(sb, characteristics, 0x80000000, "可写");

        // -------- 其他标志 --------
        appendTextFlag(sb, characteristics, 0x02000000, "可丢弃");
        appendTextFlag(sb, characteristics, 0x04000000, "不可缓存");
        appendTextFlag(sb, characteristics, 0x08000000, "不可分页");

        if (sb.length() == 0) {
            return formatHex(characteristics, 8);
        }
        return sb.toString();
    }

    private static void appendTextFlag(StringBuilder sb, int value, int mask, String text) {
        if ((value & mask) == 0) {
            return;
        }
        if (sb.length() > 0) {
            sb.append(" | ");
        }
        sb.append(text);
    }

    private static String formatBytes(int value) {
        return Integer.toUnsignedString(value);
    }

    private static String formatUnsignedByte(byte value) {
        return Integer.toUnsignedString(Byte.toUnsignedInt(value));
    }

    private static String formatUnsignedShort(short value) {
        return Integer.toUnsignedString(Short.toUnsignedInt(value));
    }

    private static String formatHex(long value, int width) {
        if (width <= 0) {
            return String.format(Locale.ROOT, "0x%X", value);
        }
        return String.format(Locale.ROOT, "0x%0" + width + "X", value);
    }

    private static String getRealSectionName(RawData raw, String rawName) {
        if (rawName == null || rawName.isEmpty()) {
            return rawName;
        }
        if (rawName.charAt(0) != '/') {
            return rawName;
        }
        if (raw.sourceFilePath == null || raw.sourceFilePath.isEmpty()) {
            return rawName;
        }

        try (java.io.RandomAccessFile raf = new java.io.RandomAccessFile(raw.sourceFilePath, "r")) {
            java.nio.channels.FileChannel channel = raf.getChannel();
            LittleEndianReader lreader = new LittleEndianReader(channel);
            final long pointerToSymbolTable = Integer.toUnsignedLong(raw.fileHeader.pointerToSymbolTable);
            final long numberOfSymbols = Integer.toUnsignedLong(raw.fileHeader.numberOfSymbols);
            final long stringTablePosition = pointerToSymbolTable + 18 * numberOfSymbols;
            final long realNamePosition = stringtoLong(rawName.substring(1));
            if (realNamePosition < 0) {
                return rawName;
            }
            StringBuilder realName = new StringBuilder();
            for (long i = 0; i < 256; i++) { // 硬上限 256 字节防止无限循环
                byte nowch = lreader.readByte(stringTablePosition + realNamePosition + i);
                if (nowch == 0) {
                    break;
                }
                int c = nowch & 0xFF;
                if ((c >= 0x20 && c < 0x7F) || c >= 0xA0) {
                    realName.append((char) c);
                } else {
                    realName.append('.');
                }
            }
            String result = realName.toString();
            return result.isEmpty() ? rawName : result;
        } catch (IOException ex) {
            return rawName;
        }
    }

    private static long stringtoLong(String str) {
        if (str == null || str.isEmpty()) {
            return -1;
        }
        long ret = 0;
        for (int i = 0; i < str.length(); i++) {
            char ch = str.charAt(i);
            if (ch < '0' || ch > '9') {
                return -1; // 非数字字符，无效输入
            }
            ret = ret * 10 + (ch - '0');
            if (ret < 0) {
                return -1; // 溢出
            }
        }
        return ret;
    }
}
