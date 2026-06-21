package model;

import java.util.ArrayList;
import java.util.List;

/**
 * 顶层交换类：解析器写入，UI只读出
 * 包含：DOS头 + 标准PE头 + 可选头 + 节表列表
 *
 * 用法：
 *   RawData raw = RawData.create();                           // 子对象自动就绪
 *   raw.dosHeader.e_magic = (short) 0x5A4D;
 *   raw.addSection(new RawSectionInfo().name(".text").virtualSize(0x2000)...);
 *
 * 或链式：
 *   RawData raw = RawData.create()
 *       .dos(d -> { d.e_magic = 0x5A4D; d.e_lfanew = 0x80; })
 *       .file(f -> { f.machine = 0x014C; f.numberOfSections = 4; })
 *       .opt(o -> { o.magic = 0x010B; o.imageBase = 0x400000; })
 *       .addSection(...);
 */
public class RawData {
    // 如果类型异常不需要转换信息，直接在showdata中public String characteristics返回"类型异常"
    public boolean TypeError;
    // 原始文件路径，供转换层处理长节名等需要回读文件的场景
    public String sourceFilePath;
    public RawDosHeader dosHeader;
    public int signature;              // *****PE签名 "PE\0\0"
    public RawPeFileHeader fileHeader;
    public RawPeOptionalHeader optionalHeader;
    public List<RawSectionInfo> sections;

    /** 构造时就创建所有子对象，无需手动 new */
    public RawData() {
        this.dosHeader = new RawDosHeader();
        this.fileHeader = new RawPeFileHeader();
        this.optionalHeader = new RawPeOptionalHeader();
        this.sections = new ArrayList<>();
    }

    public static RawData create() {
        return new RawData();
    }

    public RawData addSection(RawSectionInfo section) {
        this.sections.add(section);
        return this;
    }

    // ==================== 子数据类（嵌套） ====================

    /**
     * DOS头 - 只保留2个核心字段，其余为MS-DOS遗留物，不解析
     */
    public static class RawDosHeader {
        public short e_magic;      // 魔数，校验是否为"MZ"（0x5A4D）
        public int e_lfanew;       // *****关键偏移量，指向NT头起始位置（内部定位用，UI不展示）

        public RawDosHeader magic(short v)  { this.e_magic = v;  return this; }
        public RawDosHeader lfanew(int v)   { this.e_lfanew = v; return this; }
    }

    /**
     * 标准PE文件头（IMAGE_FILE_HEADER） 20字节
     */
    public static class RawPeFileHeader {
        public short machine;              // *****CPU架构，如 0x14C = x86，0x8664 = x64（需转换成 x86 32位 等）
        public short numberOfSections;     // 节数量（直接显示数字）
        public int timeDateStamp;          // *****时间戳（原始值，UI层再转换）
        public int pointerToSymbolTable;   // *****符号表偏移（调试信息，通常为0，显示原始值即可）
        public int numberOfSymbols;        // *****符号数量（调试信息，通常为0）
        public short sizeOfOptionalHeader; // *****可选头大小，PE32 为 0xE0，PE32+ 为 0xF0
        public short characteristics;      // *****文件特性原始值（需由 UI 层转换成“可执行文件 / DLL文件”等）

        public RawPeFileHeader machine(short v)              { this.machine = v;              return this; }
        public RawPeFileHeader numberOfSections(short v)     { this.numberOfSections = v;     return this; }
        public RawPeFileHeader timeDateStamp(int v)          { this.timeDateStamp = v;        return this; }
        public RawPeFileHeader pointerToSymbolTable(int v)   { this.pointerToSymbolTable = v; return this; }
        public RawPeFileHeader numberOfSymbols(int v)        { this.numberOfSymbols = v;      return this; }
        public RawPeFileHeader sizeOfOptionalHeader(short v) { this.sizeOfOptionalHeader = v; return this; }
        public RawPeFileHeader characteristics(short v)      { this.characteristics = v;      return this; }
    }

    /**
     * IMAGE_OPTIONAL_HEADER
     * 注意：PE32 和 PE32+ 的字段偏移不同，解析时需根据 Magic 判断
     */
    public static class RawPeOptionalHeader {
        // -------- 标准字段（PE32 和 PE32+ 共有）--------
        public short magic;                  // *****0x10B = PE32，0x20B = PE32+（需转换成 "PE32" 或 "PE32+"）
        public byte majorLinkerVersion;      // 链接器主版本（原始值）
        public byte minorLinkerVersion;      // 链接器次版本（原始值）
        public int addressOfEntryPoint;      // *****入口点 RVA（原始值，UI层再格式化）
        public int baseOfCode;               // *****代码段起始 RVA（原始值）

        // -------- 32/64 位相关的字段（注意偏移差异） --------
        public long imageBase;               // *****映像基址（原始值）
        public int sectionAlignment;         // *****映像对齐粒度（内存中）
        public int fileAlignment;            // *****文件对齐粒度（文件中）
        public short majorOperatingSystemVersion; // 操作系统主版本号
        public short minorOperatingSystemVersion; // 操作系统次版本号
        public short majorImageVersion;      // 映像主版本号
        public short minorImageVersion;      // 映像次版本号
        public short majorSubsystemVersion;  // 子系统主版本号
        public short minorSubsystemVersion;  // 子系统次版本号
        public int sizeOfImage;              // *****映像总大小（原始值）
        public int sizeOfHeaders;            // *****头部总大小（原始值）
        public short subsystem;              // *****子系统类型（原始值）

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

    /**
     * 节表信息（IMAGE_SECTION_HEADER） 每个节40字节
     */
    public static class RawSectionInfo {
        public String name;                // 节名称，如 ".text"、".data"、".rdata"
        public int virtualSize;            // *****虚拟大小（内存中实际大小）
        public int virtualAddress;         // *****虚拟地址（RVA）
        public int sizeOfRawData;          // *****原始数据大小（文件中对齐后大小）
        public int pointerToRawData;       // *****文件偏移（节在文件中的起始位置）
        public int characteristics;        // *****节特征原始值
        public String characteristicsDesc; // 节权限描述，由UI层转换显示
        public RawSectionInfo name(String v)                   { this.name = v;                return this; }
        public RawSectionInfo virtualSize(int v)               { this.virtualSize = v;         return this; }
        public RawSectionInfo virtualAddress(int v)            { this.virtualAddress = v;      return this; }
        public RawSectionInfo sizeOfRawData(int v)             { this.sizeOfRawData = v;       return this; }
        public RawSectionInfo pointerToRawData(int v)          { this.pointerToRawData = v;    return this; }
        public RawSectionInfo characteristics(int v)           { this.characteristics = v;     return this; }
        public RawSectionInfo characteristicsDesc(String v)    { this.characteristicsDesc = v; return this; }
    }
}
