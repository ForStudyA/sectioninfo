package model;

import java.util.ArrayList;
import java.util.List;

/**
 * PE 文件原始数据模型（二进制层）
 * 保留文件中的原始二进制值，不做格式化转换。
 * 数据流：PeParser.parse() → RawData → PeDataConverter → ShowData
 */
public class RawData {
    public boolean typeError;          // 格式校验标志：true 表示 PE 格式异常
    public String sourceFilePath;      // 原始文件路径，供回读文件用
    public byte[] coffStringTable;     // COFF 字符串表缓存（用于解析 "/N" 长节名）
    public RawDosHeader dosHeader;     // DOS 头
    public int signature;              // PE 签名 "PE\0\0" (0x00004550)
    public RawPeFileHeader fileHeader; // 标准 PE 文件头 (20字节)
    public RawPeOptionalHeader optionalHeader; // 可选头 (PE32=224字节, PE32+=240字节)
    public List<RawSectionInfo> sections;      // 节表列表，每节 40 字节

    public RawData() {
        this.dosHeader = new RawDosHeader();
        this.fileHeader = new RawPeFileHeader();
        this.optionalHeader = new RawPeOptionalHeader();
        this.sections = new ArrayList<>();
    }

    public static RawData create() { return new RawData(); }

    public RawData addSection(RawSectionInfo section) {
        this.sections.add(section);
        return this;
    }

    // ==================== 子数据类 ====================

    /** DOS 头 — 仅保留 2 个核心字段，其余为 MS-DOS 遗留物 */
    public static class RawDosHeader {
        public short e_magic;      // 魔数 0x5A4D ("MZ")，标识 PE 文件
        public int e_lfanew;       // PE 签名的文件偏移，用于定位 NT 头

        public RawDosHeader magic(short v)  { this.e_magic = v;  return this; }
        public RawDosHeader lfanew(int v)   { this.e_lfanew = v; return this; }
    }

    /** 标准 PE 文件头 (IMAGE_FILE_HEADER) — 20 字节 */
    public static class RawPeFileHeader {
        public short machine;              // CPU 架构：0x014C=x86, 0x8664=x64, 0xAA64=ARM64
        public short numberOfSections;     // 节的数量
        public int timeDateStamp;          // 编译时间戳 (自 1970-01-01 的秒数)
        public int pointerToSymbolTable;   // COFF 符号表偏移，通常为 0
        public int numberOfSymbols;        // COFF 符号数量，通常为 0
        public short sizeOfOptionalHeader; // 可选头大小：PE32=0xE0, PE32+=0xF0
        public short characteristics;      // 文件特性标志 (bit1=EXE, bit13=DLL)

        public RawPeFileHeader machine(short v)              { this.machine = v;              return this; }
        public RawPeFileHeader numberOfSections(short v)     { this.numberOfSections = v;     return this; }
        public RawPeFileHeader timeDateStamp(int v)          { this.timeDateStamp = v;        return this; }
        public RawPeFileHeader pointerToSymbolTable(int v)   { this.pointerToSymbolTable = v; return this; }
        public RawPeFileHeader numberOfSymbols(int v)        { this.numberOfSymbols = v;      return this; }
        public RawPeFileHeader sizeOfOptionalHeader(short v) { this.sizeOfOptionalHeader = v; return this; }
        public RawPeFileHeader characteristics(short v)      { this.characteristics = v;      return this; }
    }

    /** 可选头 (IMAGE_OPTIONAL_HEADER) — PE32/PE32+ 字段偏移不同 */
    public static class RawPeOptionalHeader {
        public short magic;                  // 0x010B=PE32, 0x020B=PE32+
        public byte majorLinkerVersion;      // 链接器主版本号
        public byte minorLinkerVersion;      // 链接器次版本号
        public int addressOfEntryPoint;      // 入口点 RVA，加载器从这里开始执行
        public int baseOfCode;               // 代码段起始 RVA
        public long imageBase;               // 映像基址，PE32 4字节 / PE32+ 8字节
        public int sectionAlignment;         // 内存对齐粒度，典型值 0x1000 (4KB)
        public int fileAlignment;            // 文件对齐粒度，典型值 0x200 (512B)
        public short majorOperatingSystemVersion; // 所需操作系统主版本
        public short minorOperatingSystemVersion; // 所需操作系统次版本
        public short majorImageVersion;      // 映像主版本号
        public short minorImageVersion;      // 映像次版本号
        public short majorSubsystemVersion;  // 子系统主版本号
        public short minorSubsystemVersion;  // 子系统次版本号
        public int sizeOfImage;              // 加载后总内存大小 (字节)
        public int sizeOfHeaders;            // 所有头部总大小 (字节)
        public short subsystem;              // 子系统：1=Native, 2=GUI, 3=CUI

        public RawPeOptionalHeader magic(short v)                     { this.magic = v;                     return this; }
        public RawPeOptionalHeader majorLinkerVersion(byte v)         { this.majorLinkerVersion = v;        return this; }
        public RawPeOptionalHeader minorLinkerVersion(byte v)         { this.minorLinkerVersion = v;        return this; }
        public RawPeOptionalHeader addressOfEntryPoint(int v)         { this.addressOfEntryPoint = v;       return this; }
        public RawPeOptionalHeader baseOfCode(int v)                  { this.baseOfCode = v;                return this; }
        public RawPeOptionalHeader imageBase(long v)                  { this.imageBase = v;                 return this; }
        public RawPeOptionalHeader sectionAlignment(int v)            { this.sectionAlignment = v;          return this; }
        public RawPeOptionalHeader fileAlignment(int v)               { this.fileAlignment = v;             return this; }
        public RawPeOptionalHeader majorOperatingSystemVersion(short v) { this.majorOperatingSystemVersion = v; return this; }
        public RawPeOptionalHeader minorOperatingSystemVersion(short v) { this.minorOperatingSystemVersion = v; return this; }
        public RawPeOptionalHeader majorImageVersion(short v)         { this.majorImageVersion = v;         return this; }
        public RawPeOptionalHeader minorImageVersion(short v)         { this.minorImageVersion = v;         return this; }
        public RawPeOptionalHeader majorSubsystemVersion(short v)     { this.majorSubsystemVersion = v;     return this; }
        public RawPeOptionalHeader minorSubsystemVersion(short v)     { this.minorSubsystemVersion = v;     return this; }
        public RawPeOptionalHeader sizeOfImage(int v)                 { this.sizeOfImage = v;               return this; }
        public RawPeOptionalHeader sizeOfHeaders(int v)               { this.sizeOfHeaders = v;             return this; }
        public RawPeOptionalHeader subsystem(short v)                 { this.subsystem = v;                 return this; }
    }

    /** 节表信息 (IMAGE_SECTION_HEADER) — 每节 40 字节 */
    public static class RawSectionInfo {
        public String name;                // 节名称，如 ".text"、".data"；超长名以 "/偏移" 引用 COFF 字符串表
        public int virtualSize;            // 内存中的实际大小
        public int virtualAddress;         // 内存中的起始偏移 (RVA)
        public int sizeOfRawData;          // 文件中的大小（对齐后）
        public int pointerToRawData;       // 文件中的起始偏移
        public int characteristics;        // 节属性标志 (bit5=代码, bit30=可执行, bit31=可读, bit32=可写)

        public RawSectionInfo name(String v)                   { this.name = v;                return this; }
        public RawSectionInfo virtualSize(int v)               { this.virtualSize = v;         return this; }
        public RawSectionInfo virtualAddress(int v)            { this.virtualAddress = v;      return this; }
        public RawSectionInfo sizeOfRawData(int v)             { this.sizeOfRawData = v;       return this; }
        public RawSectionInfo pointerToRawData(int v)          { this.pointerToRawData = v;    return this; }
        public RawSectionInfo characteristics(int v)           { this.characteristics = v;     return this; }
    }
}
