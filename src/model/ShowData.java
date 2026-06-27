package model;

import java.util.ArrayList;
import java.util.List;

/**
 * PE 文件显示数据模型（UI 层）
 * 所有字段为 String，已格式化为人类可读形式，可直接用于 UI 展示。
 * 异常时通过 dosHeader.magicStatus 传递状态："读取异常" / "格式异常" / "无效" / "有效 (MZ)"
 */
public class ShowData {
    public DosHeaderInfo dosHeader;             // DOS 头显示信息
    public FileHeaderInfo fileHeader;           // 标准 PE 文件头显示信息
    public OptionalHeaderInfo optionalHeader;   // 可选头显示信息
    public List<SectionInfo> sections;          // 节表显示信息列表

    public ShowData() {
        this.dosHeader = new DosHeaderInfo();
        this.fileHeader = new FileHeaderInfo();
        this.optionalHeader = new OptionalHeaderInfo();
        this.sections = new ArrayList<>();
    }

    public static ShowData create() { return new ShowData(); }

    public ShowData addSection(SectionInfo section) {
        this.sections.add(section);
        return this;
    }

    // ==================== 子数据类 ====================

    /** DOS 头显示信息 */
    public static class DosHeaderInfo {
        public String magicStatus; // "有效 (MZ)" / "无效" / "格式异常" / "读取异常" / "未加载"

        public DosHeaderInfo magicStatus(String v) { this.magicStatus = v; return this; }
    }

    /** 标准 PE 文件头显示信息 */
    public static class FileHeaderInfo {
        public String machine;              // CPU 架构："x86 (32位)" / "x64 (64位)" / "ARM64" / 十六进制
        public String numberOfSections;     // 节数量，如 "5"
        public String timeDateStamp;        // 编译时间 "yyyy-MM-dd HH:mm:ss"，值为 0 显示 "0"
        public String pointerToSymbolTable; // 符号表偏移 "0x00000000"
        public String numberOfSymbols;      // 符号数量，如 "0"
        public String sizeOfOptionalHeader; // 可选头大小 "0x00E0" (PE32) / "0x00F0" (PE32+)
        public String characteristics;      // 文件特性 "可执行文件" / "DLL文件" / "无重定位"，多值用 " | " 分隔

        public FileHeaderInfo machine(String v)              { this.machine = v;              return this; }
        public FileHeaderInfo numberOfSections(String v)     { this.numberOfSections = v;     return this; }
        public FileHeaderInfo timeDateStamp(String v)        { this.timeDateStamp = v;        return this; }
        public FileHeaderInfo pointerToSymbolTable(String v) { this.pointerToSymbolTable = v; return this; }
        public FileHeaderInfo numberOfSymbols(String v)      { this.numberOfSymbols = v;      return this; }
        public FileHeaderInfo sizeOfOptionalHeader(String v) { this.sizeOfOptionalHeader = v; return this; }
        public FileHeaderInfo characteristics(String v)      { this.characteristics = v;      return this; }
    }

    /** 可选头显示信息 */
    public static class OptionalHeaderInfo {
        public String magic;                    // "PE32" / "PE32+"
        public String LinkerVersion;            // 链接器版本 "主版本.次版本"，如 "14.38"
        public String addressOfEntryPoint;      // 入口点 RVA "0x00001000"
        public String baseOfCode;               // 代码段起始 RVA "0x00001000"
        public String imageBase;                // 映像基址 "0x00400000"，值为 0 显示 "0"
        public String sectionAlignment;         // 内存对齐 "0x00001000" (4KB)
        public String fileAlignment;            // 文件对齐 "0x00000200" (512B)
        public String OperatingSystemVersion;   // 所需操作系统版本 "主版本.次版本"，如 "6.0"
        public String ImageVersion;             // 映像版本 "主版本.次版本"，通常 "0.0"
        public String SubsystemVersion;         // 子系统版本 "主版本.次版本"
        public String sizeOfImage;              // 加载后总大小 "数值 字节"
        public String sizeOfHeaders;            // 头部总大小 "数值 字节"
        public String subsystem;                // "Windows GUI" / "Windows CUI" / "Native"

        public OptionalHeaderInfo magic(String v)                  { this.magic = v;                  return this; }
        public OptionalHeaderInfo LinkerVersion(String v)          { this.LinkerVersion = v;          return this; }
        public OptionalHeaderInfo addressOfEntryPoint(String v)    { this.addressOfEntryPoint = v;    return this; }
        public OptionalHeaderInfo baseOfCode(String v)             { this.baseOfCode = v;             return this; }
        public OptionalHeaderInfo imageBase(String v)              { this.imageBase = v;              return this; }
        public OptionalHeaderInfo sectionAlignment(String v)       { this.sectionAlignment = v;       return this; }
        public OptionalHeaderInfo fileAlignment(String v)          { this.fileAlignment = v;          return this; }
        public OptionalHeaderInfo OperatingSystemVersion(String v) { this.OperatingSystemVersion = v; return this; }
        public OptionalHeaderInfo ImageVersion(String v)           { this.ImageVersion = v;           return this; }
        public OptionalHeaderInfo SubsystemVersion(String v)       { this.SubsystemVersion = v;       return this; }
        public OptionalHeaderInfo sizeOfImage(String v)            { this.sizeOfImage = v;            return this; }
        public OptionalHeaderInfo sizeOfHeaders(String v)          { this.sizeOfHeaders = v;          return this; }
        public OptionalHeaderInfo subsystem(String v)              { this.subsystem = v;              return this; }
    }

    /** 节信息显示 */
    public static class SectionInfo {
        public String name;              // 节名称 ".text" / ".data" / ".rsrc" 等
        public String virtualSize;       // 内存大小 "数值 字节"
        public String virtualAddress;    // 内存偏移 RVA "0x00001000"
        public String sizeOfRawData;     // 文件大小 "数值 字节"
        public String pointerToRawData;  // 文件偏移 "0x00000400"
        public String characteristics;   // "代码 | 可读 | 可执行"，多值用 " | " 分隔

        public SectionInfo name(String v)             { this.name = v;             return this; }
        public SectionInfo virtualSize(String v)      { this.virtualSize = v;      return this; }
        public SectionInfo virtualAddress(String v)   { this.virtualAddress = v;   return this; }
        public SectionInfo sizeOfRawData(String v)    { this.sizeOfRawData = v;    return this; }
        public SectionInfo pointerToRawData(String v) { this.pointerToRawData = v; return this; }
        public SectionInfo characteristics(String v)  { this.characteristics = v;  return this; }
    }
}
