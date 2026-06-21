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
        if (raw == null || raw.TypeError) {
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
        } catch (IOException ex) {
            show.dosHeader.magicStatus("读取异常");
        }

        return show;
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
        appendTextFlag(sb, characteristics, 0x40000000, "可读");
        appendTextFlag(sb, characteristics, 0x80000000, "可写");
        appendTextFlag(sb, characteristics, 0x20000000, "可执行");
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

    private static String getRealSectionName(RawData raw, String rawName) throws IOException {
        if (rawName == null || rawName.isEmpty()) {
            return "null";
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
            final int pointerToSymbolTable = raw.fileHeader.pointerToSymbolTable;
            final int numberOfSymbols = raw.fileHeader.numberOfSymbols;
            final int stringTablePosition = pointerToSymbolTable + 18 * numberOfSymbols;
            final int realNamePosition = stringtoInt(rawName.substring(1));
            StringBuilder realName = new StringBuilder();
            for (int i = 0;; i++) {
                byte nowch = lreader.readByte(stringTablePosition + realNamePosition + i);
                if (nowch == 0) {
                    break;
                }
                realName.append((char) nowch);
            }
            return realName.toString();
        }
    }

    private static int stringtoInt(String str) {
        int ret = 0;
        if (str != null && !str.isEmpty()) {
            for (int i = 0; i < str.length(); i++) {
                ret = ret * 10 + str.charAt(i) - '0';
            }
        }
        return ret;
    }
}
