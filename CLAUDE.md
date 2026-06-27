# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Test

```powershell
# 编译所有源文件
javac --release 21 -encoding UTF-8 -cp bin -d bin `
  src\model\RawData.java `
  src\model\ShowData.java `
  src\pe\LittleEndianReader.java `
  src\pe\PeDataConverter.java `
  src\pe\PeParser.java `
  src\pe\PeShowParser.java `
  src\test\PeFeatureTest.java

# 运行测试（接受命令行参数或标准输入传入 PE 文件路径）
java -cp bin test.PeFeatureTest "D:\path\to\some.exe"

# 或者交互式输入路径
java -cp bin test.PeFeatureTest
```

## Architecture

### 数据流

```
PE 文件 → PeParser.parse() → RawData → PeDataConverter.convert() → ShowData → UI
         ↑ 低层（抛 IOException）       ↑ 高层（不抛异常，吞掉所有异常）
```

统一入口：`PeShowParser.parse(String filename)` — 始终返回 `ShowData`，不抛异常。

### 两层数据模型

- **RawData**（`model.RawData`）— 与 PE 规范一一对应的原始二进制字段（short/int/long），供二次处理使用
- **ShowData**（`model.ShowData`）— 所有字段已格式化为字符串，直接供 UI 展示。发生异常时通过 `show.dosHeader.magicStatus` 传递状态（"读取异常" / "格式异常" / "有效 (MZ)"）

### 核心类

| 类 | 职责 | 关键约定 |
|---|---|---|
| `PeParser` | 原始二进制提取，按偏移量读取 PE 结构 | 文件异常抛 `IOException`；格式异常标记 `RawData.TypeError` |
| `PeDataConverter` | 将 RawData 原始值转换为可读字符串 | 内部捕获 `IOException` 置为"读取异常"；使用 `switch` 表达式匹配已知枚举值 |
| `PeShowParser` | 展示层统一入口 | `final class` + 私有构造；`parse()` 永不抛异常 |
| `LittleEndianReader` | 小端序二进制读取工具 | 基于 `FileChannel` + `ByteBuffer`；提供 `readByte/Short/Int/Long/Float/Double/Char/AsciiString` |
| `SectionInfoUI` | GUI 入口（TODO，尚未实现） | `main()` 方法已预留 |

### 数据类风格

所有数据嵌套类使用 **fluent builder 模式**：
- `public` 字段直接访问，无 getter/setter
- 链式 setter 返回 `this`
- 静态工厂 `create()` 工厂方法
- 构造时自动初始化子对象

### 错误处理约定

- 低层（`PeParser`）：文件读写问题抛 `IOException`，格式问题设 `TypeError=true`
- 高层（`PeShowParser`/`PeDataConverter`）：吞掉异常，通过 `magicStatus` 状态字符串传递
- 状态传播：`"读取异常"` → `"格式异常"` → `"有效 (MZ)"` / `"无效"`

### 节名解析

支持 COFF 字符串表解析超长节名。当节名以 `/` 开头时，通过符号表偏移定位到 COFF 字符串表获取真实名称（`PeDataConverter.getRealSectionName()`）。
