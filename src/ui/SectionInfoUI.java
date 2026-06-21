package ui;

/**
 * PE 文件节信息查看器 —— GUI 入口。
 *
 * 职责：
 * - 提供文件选择界面，让用户选择待分析的 PE 文件（.exe / .dll 等）
 * - 调用 {@link pe.PeShowParser#parse(String)} 获取 {@link model.ShowData}
 * - 将 DOS 头、文件头、可选头、节表等信息展示在界面上
 *
 * 数据流：
 *   用户选择文件 → PeShowParser.parse(path) → ShowData → UI 控件展示
 *
 * 异常展示约定（由 PeShowParser 保证，UI 只需读取 ShowData）：
 * - 当 show.dosHeader.magicStatus 为 "读取异常" 时，表示文件读取失败
 * - 为 "格式异常" 时表示文件不是合法 PE
 * - 为 "无效" 时表示 DOS 签名不正确
 *
 * 使用方式：
 *   java ui.SectionInfoUI
 */
public class SectionInfoUI { 

    /**
     * 程序入口：启动 GUI 主窗口。
     *
     * @param args 命令行参数（可选，预留用于直接传入 PE 文件路径）
     */
    public static void main(String[] args) {
        // TODO: 启动 GUI，后续实现
    }
}