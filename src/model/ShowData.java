package model;

import java.util.ArrayList;
import java.util.List;

/**
 * 显示数据
 * 只保存适合 UI 直接展示的字符串结果
 */
public class ShowData {
    // DOS 头显示信息
    public DosHeaderInfo dosHeader;
    // 标准 PE 文件头显示信息
    public FileHeaderInfo fileHeader;
    // 可选头显示信息
    public OptionalHeaderInfo optionalHeader;
    // 节表显示信息列表
    public List<SectionInfo> sections;

    /** 构造时就创建所有子对象，无需手动 new */
    public ShowData() {
        this.dosHeader = new DosHeaderInfo();
        this.fileHeader = new FileHeaderInfo();
        this.optionalHeader = new OptionalHeaderInfo();
        this.sections = new ArrayList<>();
    }

    public static ShowData create() {
        return new ShowData();
    }

    public ShowData addSection(SectionInfo section) {
        this.sections.add(section);
        return this;
    }

    // ==================== 子数据类（嵌套） ====================

    /**
     * DOS 头显示信息
     * 仅保存前端直接展示所需的状态字符串
     */
    public static class DosHeaderInfo {
        public String magicStatus; // "有效 (MZ)" / "无效" / "格式异常" / "读取异常"

        public DosHeaderInfo magicStatus(String v) {
            this.magicStatus = v;
            return this;
        }
    }

    /**
     * 标准 PE 文件头显示信息
     */
    public static class FileHeaderInfo {
        public String machine;              // 机器类型
        public String numberOfSections;     // 节数
        public String timeDateStamp;         // 时间戳
        public String pointerToSymbolTable;  // 符号表偏移
        public String numberOfSymbols;       // 符号数量
        public String sizeOfOptionalHeader;  // 可选头大小
        public String characteristics;       // 文件特征

        public FileHeaderInfo machine(String v)              { this.machine = v;              return this; }
        public FileHeaderInfo numberOfSections(String v)     { this.numberOfSections = v;     return this; }
        public FileHeaderInfo timeDateStamp(String v)        { this.timeDateStamp = v;        return this; }
        public FileHeaderInfo pointerToSymbolTable(String v) { this.pointerToSymbolTable = v; return this; }
        public FileHeaderInfo numberOfSymbols(String v)      { this.numberOfSymbols = v;      return this; }
        public FileHeaderInfo sizeOfOptionalHeader(String v) { this.sizeOfOptionalHeader = v; return this; }
        public FileHeaderInfo characteristics(String v)      { this.characteristics = v;      return this; }
    }

    /**
     * 可选头显示信息
     */
    public static class OptionalHeaderInfo {
        public String magic;                    // PE32 / PE32+
        public String LinkerVersion;            // 链接器版本
        public String addressOfEntryPoint;      // 入口点
        public String baseOfCode;               // 代码段起始
        public String imageBase;                // 映像基址
        public String sectionAlignment;         // 节对齐
        public String fileAlignment;            // 文件对齐
        public String OperatingSystemVersion;   // 操作系统版本
        public String ImageVersion;             // 映像版本
        public String SubsystemVersion;         // 子系统版本
        public String sizeOfImage;              // 映像大小
        public String sizeOfHeaders;            // 头部大小
        public String subsystem;                // 子系统类型

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

    /**
     * 节信息显示
     */
    public static class SectionInfo {
        public String name;              // 节名
        public String virtualSize;       // 虚拟大小
        public String virtualAddress;    // 虚拟地址
        public String sizeOfRawData;     // 原始数据大小
        public String pointerToRawData;  // 文件偏移
        public String characteristics;   // 节特征

        public SectionInfo name(String v)             { this.name = v;             return this; }
        public SectionInfo virtualSize(String v)      { this.virtualSize = v;      return this; }
        public SectionInfo virtualAddress(String v)   { this.virtualAddress = v;   return this; }
        public SectionInfo sizeOfRawData(String v)    { this.sizeOfRawData = v;    return this; }
        public SectionInfo pointerToRawData(String v) { this.pointerToRawData = v; return this; }
        public SectionInfo characteristics(String v)  { this.characteristics = v;  return this; }
    }
}
