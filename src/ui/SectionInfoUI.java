package ui;

import java.awt.BorderLayout;
import java.awt.CardLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.GradientPaint;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.Image;
import java.awt.datatransfer.DataFlavor;
import java.awt.dnd.DnDConstants;
import java.awt.dnd.DropTarget;
import java.awt.dnd.DropTargetAdapter;
import java.awt.dnd.DropTargetDropEvent;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.Icon;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSeparator;
import javax.swing.JTextArea;
import javax.swing.SwingConstants;
import javax.swing.UIManager;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.filechooser.FileView;

import model.ShowData;
import pe.PeShowParser;

/**
 * ============================================ PE文件分析器 - 主界面类
 * 功能：显示PE文件的各种信息，支持加载文件和导出数据 包含：主界面、背景面板、自定义文件选择器 版本：v2.0
 * ============================================
 */
public class SectionInfoUI {

	// ============================================
	// 一、全局变量定义
	// ============================================

	/** 存储PE文件解析后的所有数据 */
	private static volatile ShowData showData;

	/** 当前加载的文件路径 */
	private static volatile String currentFilePath;

	/** 标记是否已成功加载数据 */
	private static volatile boolean isDataLoaded = false;

	/** 上次打开的目录（用于记住用户位置） */
	private static File lastDirectory;

	/** 文件加载时间戳 */
	private static long loadTimestamp;

	// ============================================
	// 二、卡片名称常量
	// ============================================

	private static final String CARD_OVERVIEW = "总览";
	private static final String CARD_DOS = "DOS头";
	private static final String CARD_FILE = "文件头";
	private static final String CARD_OPTIONAL = "可选头";
	private static final String CARD_SECTIONS = "节表";
	private static final String CARD_STATS = "统计信息";

	// ============================================
	// 三、UI组件变量
	// ============================================

	private static JPanel cardPanel;
	private static JLabel statusLabel;
	private static JFrame mainFrame;

	// ============================================
	// 四、程序入口 main 方法
	// ============================================

	public static void main(String[] args) {
		// 全局异常兜底：防止 Swing EDT 未捕获异常导致静默崩溃
		Thread.setDefaultUncaughtExceptionHandler((t, e) -> {
			System.err.println("[PE分析器] 未捕获异常: " + e.getClass().getSimpleName() + ": " + e.getMessage());
			e.printStackTrace();
		});

		// 设置 Windows 11 风格外观
		try {
			UIManager.setLookAndFeel("com.sun.java.swing.plaf.windows.WindowsLookAndFeel");
		} catch (Exception e) {
			// 回退：非 Windows 系统使用默认 L&F
		}
		// 禁用系统图标避免 Win32ShellFolder NPE bug
		UIManager.put("FileChooser.useSystemIcons", Boolean.FALSE);

		// 初始化空数据
		showData = createEmptyData();

		// 创建主窗口
		mainFrame = new JFrame("PE文件分析器 v2.0");
		mainFrame.setSize(1100, 750);
		mainFrame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		mainFrame.setLocationRelativeTo(null);

		// 创建带背景图的主面板
		BackgroundPanel mainPanel = new BackgroundPanel("images/a1336331d76ef38943e5cabc296613f2.jpg");
		mainPanel.setLayout(new BorderLayout(10, 10));
		mainPanel.setBorder(BorderFactory.createEmptyBorder(15, 15, 15, 15));

		// 创建标题栏
		JPanel titlePanel = createTitlePanel();
		mainPanel.add(titlePanel, BorderLayout.NORTH);

		// 创建中间区域
		JPanel centerPanel = new JPanel(new BorderLayout(10, 0));
		centerPanel.setOpaque(false);

		JPanel menuPanel = createMenuPanel();
		centerPanel.add(menuPanel, BorderLayout.WEST);

		JPanel contentPanel = createContentCards();
		centerPanel.add(contentPanel, BorderLayout.CENTER);

		mainPanel.add(centerPanel, BorderLayout.CENTER);

		// 创建状态栏
		JPanel statusPanel = createStatusPanel();
		mainPanel.add(statusPanel, BorderLayout.SOUTH);

		mainFrame.add(mainPanel);

		// 拖拽支持：用户可直接将 PE 文件拖入窗口
		setupDragDrop(mainPanel);

		// 键盘快捷键：Ctrl+O 打开, Ctrl+S 导出
		setupKeyboardShortcuts();

		mainFrame.setVisible(true);
	}

	// ============================================
	// 四-A、辅助初始化方法
	// ============================================

	private static void setupDragDrop(BackgroundPanel mainPanel) {
		mainPanel.setDropTarget(new DropTarget(mainPanel, DnDConstants.ACTION_COPY_OR_MOVE, new DropTargetAdapter() {
			@Override
			public void drop(DropTargetDropEvent dtde) {
				dtde.acceptDrop(DnDConstants.ACTION_COPY);
				try {
					@SuppressWarnings("unchecked")
					java.util.List<File> droppedFiles = (java.util.List<File>) dtde.getTransferable()
							.getTransferData(DataFlavor.javaFileListFlavor);
					if (!droppedFiles.isEmpty()) {
						File file = droppedFiles.get(0);
						String name = file.getName().toLowerCase();
						if (name.endsWith(".exe") || name.endsWith(".dll") || name.endsWith(".sys")) {
							loadPEFile(file);
						} else {
							JOptionPane.showMessageDialog(mainFrame, "不支持的文件类型，请拖入 .exe / .dll / .sys 文件", "提示",
									JOptionPane.WARNING_MESSAGE);
						}
					}
					dtde.dropComplete(true);
				} catch (Exception ex) {
					System.err.println("拖拽处理失败: " + ex.getMessage());
					dtde.dropComplete(false);
				}
			}
		}));
	}

	private static void setupKeyboardShortcuts() {
		// Ctrl+O 打开
		mainFrame.getRootPane().getInputMap(javax.swing.JComponent.WHEN_IN_FOCUSED_WINDOW)
				.put(javax.swing.KeyStroke.getKeyStroke("ctrl O"), "open");
		mainFrame.getRootPane().getActionMap().put("open", new javax.swing.AbstractAction() {
			public void actionPerformed(java.awt.event.ActionEvent e) {
				JFileChooser fileChooser = createStyledFileChooser();
				int result = fileChooser.showOpenDialog(mainFrame);
				if (result == JFileChooser.APPROVE_OPTION) {
					File selectedFile = fileChooser.getSelectedFile();
					lastDirectory = selectedFile.getParentFile();
					loadPEFile(selectedFile);
				}
			}
		});

		// Ctrl+S 导出
		mainFrame.getRootPane().getInputMap(javax.swing.JComponent.WHEN_IN_FOCUSED_WINDOW)
				.put(javax.swing.KeyStroke.getKeyStroke("ctrl S"), "export");
		mainFrame.getRootPane().getActionMap().put("export", new javax.swing.AbstractAction() {
			public void actionPerformed(java.awt.event.ActionEvent e) {
				if (isDataLoaded()) {
					String data = getAllDataAsText();
					if (data != null)
						saveDataToFile(data);
				}
			}
		});

		// Ctrl+E 导出JSON
		mainFrame.getRootPane().getInputMap(javax.swing.JComponent.WHEN_IN_FOCUSED_WINDOW)
				.put(javax.swing.KeyStroke.getKeyStroke("ctrl E"), "exportJson");
		mainFrame.getRootPane().getActionMap().put("exportJson", new javax.swing.AbstractAction() {
			public void actionPerformed(java.awt.event.ActionEvent e) {
				if (isDataLoaded()) {
					exportJsonData();
				}
			}
		});
	}

	// ============================================
	// 五、数据获取方法（对外接口）
	// ============================================

	public static ShowData getShowData() {
		return showData;
	}

	public static String getCurrentFilePath() {
		return currentFilePath;
	}

	public static boolean isDataLoaded() {
		return isDataLoaded;
	}

	public static int getSectionCount() {
		if (showData == null)
			return 0;
		return showData.sections.size();
	}

	public static ShowData.SectionInfo getSection(int index) {
		if (showData == null || index < 0 || index >= showData.sections.size()) {
			return null;
		}
		return showData.sections.get(index);
	}

	public static List<String> getSectionNames() {
		List<String> names = new ArrayList<>();
		if (showData != null) {
			for (ShowData.SectionInfo section : showData.sections) {
				names.add(section.name);
			}
		}
		return names;
	}

	public static String getDosHeaderMagic() {
		if (showData == null)
			return "未加载";
		return showData.dosHeader.magicStatus;
	}

	public static String getFileHeaderMachine() {
		if (showData == null)
			return "未加载";
		return showData.fileHeader.machine;
	}

	public static String getFileHeaderSectionCount() {
		if (showData == null)
			return "0";
		return showData.fileHeader.numberOfSections;
	}

	public static String getOptionalHeaderImageBase() {
		if (showData == null)
			return "未加载";
		return showData.optionalHeader.imageBase;
	}

	public static String getOptionalHeaderEntryPoint() {
		if (showData == null)
			return "未加载";
		return showData.optionalHeader.addressOfEntryPoint;
	}

	public static String getOptionalHeaderImageSize() {
		if (showData == null)
			return "未加载";
		return showData.optionalHeader.sizeOfImage;
	}

	public static String getOptionalHeaderSubsystem() {
		if (showData == null)
			return "未加载";
		return showData.optionalHeader.subsystem;
	}

	public static long getLoadTimestamp() {
		return loadTimestamp;
	}

	// ============================================
	// 六、数据导出方法
	// ============================================

	public static String getAllDataAsText() {
		if (showData == null) {
			return "暂无数据，请先加载PE文件";
		}
		if (showData.dosHeader == null || showData.fileHeader == null || showData.optionalHeader == null
				|| showData.sections == null) {
			return "数据不完整，请重新加载PE文件";
		}
		if (showData.sections.isEmpty() && "未加载".equals(showData.dosHeader.magicStatus)) {
			return "暂无数据，请先加载PE文件";
		}

		StringBuilder sb = new StringBuilder();

		sb.append("========== PE文件分析结果 ==========\n");
		sb.append("分析时间: ").append(new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date(loadTimestamp)))
				.append("\n");
		sb.append("文件路径: ").append(currentFilePath).append("\n");
		File f = new File(currentFilePath);
		sb.append("文件大小: ").append(formatFileSize(f.length())).append("\n\n");

		sb.append("【DOS头】\n");
		sb.append("  Magic状态: ").append(showData.dosHeader.magicStatus).append("\n\n");

		sb.append("【标准PE文件头】\n");
		sb.append("  Machine: ").append(showData.fileHeader.machine).append("\n");
		sb.append("  节数量: ").append(showData.fileHeader.numberOfSections).append("\n");
		sb.append("  时间戳: ").append(showData.fileHeader.timeDateStamp).append("\n");
		sb.append("  符号表偏移: ").append(showData.fileHeader.pointerToSymbolTable).append("\n");
		sb.append("  符号数量: ").append(showData.fileHeader.numberOfSymbols).append("\n");
		sb.append("  可选头大小: ").append(showData.fileHeader.sizeOfOptionalHeader).append("\n");
		sb.append("  特征: ").append(showData.fileHeader.characteristics).append("\n\n");

		sb.append("【可选头】\n");
		sb.append("  Magic: ").append(showData.optionalHeader.magic).append("\n");
		sb.append("  链接器版本: ").append(showData.optionalHeader.LinkerVersion).append("\n");
		sb.append("  入口点: ").append(showData.optionalHeader.addressOfEntryPoint).append("\n");
		sb.append("  代码基址: ").append(showData.optionalHeader.baseOfCode).append("\n");
		sb.append("  镜像基址: ").append(showData.optionalHeader.imageBase).append("\n");
		sb.append("  节对齐: ").append(showData.optionalHeader.sectionAlignment).append("\n");
		sb.append("  文件对齐: ").append(showData.optionalHeader.fileAlignment).append("\n");
		sb.append("  操作系统版本: ").append(showData.optionalHeader.OperatingSystemVersion).append("\n");
		sb.append("  镜像版本: ").append(showData.optionalHeader.ImageVersion).append("\n");
		sb.append("  子系统版本: ").append(showData.optionalHeader.SubsystemVersion).append("\n");
		sb.append("  镜像大小: ").append(showData.optionalHeader.sizeOfImage).append("\n");
		sb.append("  头大小: ").append(showData.optionalHeader.sizeOfHeaders).append("\n");
		sb.append("  子系统: ").append(showData.optionalHeader.subsystem).append("\n\n");

		sb.append("【节表 (共 ").append(showData.sections.size()).append("个)】\n");
		for (int i = 0; i < showData.sections.size(); i++) {
			ShowData.SectionInfo section = showData.sections.get(i);
			sb.append("\n  节 #").append(i).append(": ").append(section.name).append("\n");
			sb.append("    虚拟大小: ").append(section.virtualSize).append("\n");
			sb.append("    虚拟地址: ").append(section.virtualAddress).append("\n");
			sb.append("    原始数据大小: ").append(section.sizeOfRawData).append("\n");
			sb.append("    原始数据偏移: ").append(section.pointerToRawData).append("\n");
			sb.append("    特征: ").append(section.characteristics).append("\n");
		}

		// 添加统计信息
		sb.append("\n【统计信息】\n");
		sb.append("  总节数: ").append(showData.sections.size()).append("\n");
		sb.append("  总节大小: ").append(calculateTotalSectionSize()).append("\n");
		sb.append("  平均节大小: ").append(calculateAverageSectionSize()).append("\n");

		return sb.toString();
	}

	public static String getSectionsAsJson() {
		if (showData == null) {
			return "[]";
		}
		StringBuilder sb = new StringBuilder();
		sb.append("[");
		for (int i = 0; i < showData.sections.size(); i++) {
			ShowData.SectionInfo section = showData.sections.get(i);
			if (i > 0)
				sb.append(",");
			sb.append("{");
			sb.append("\"name\":\"").append(escapeJson(section.name)).append("\",");
			sb.append("\"virtualSize\":\"").append(escapeJson(section.virtualSize)).append("\",");
			sb.append("\"virtualAddress\":\"").append(escapeJson(section.virtualAddress)).append("\",");
			sb.append("\"sizeOfRawData\":\"").append(escapeJson(section.sizeOfRawData)).append("\",");
			sb.append("\"pointerToRawData\":\"").append(escapeJson(section.pointerToRawData)).append("\",");
			sb.append("\"characteristics\":\"").append(escapeJson(section.characteristics)).append("\"");
			sb.append("}");
		}
		sb.append("]");
		return sb.toString();
	}

	private static String escapeJson(String s) {
		if (s == null)
			return "";
		return s.replace("\\", "\\\\").replace("\"", "\\\"");
	}

	// ============================================
	// 六-A、统计计算方法
	// ============================================

	private static String calculateTotalSectionSize() {
		if (showData == null || showData.sections.isEmpty())
			return "0 字节";
		long total = 0;
		for (ShowData.SectionInfo section : showData.sections) {
			total += parseSize(section.virtualSize);
		}
		return formatFileSize(total);
	}

	private static String calculateAverageSectionSize() {
		if (showData == null || showData.sections.isEmpty())
			return "0 字节";
		long total = 0;
		for (ShowData.SectionInfo section : showData.sections) {
			total += parseSize(section.virtualSize);
		}
		return formatFileSize(total / showData.sections.size());
	}

	private static long parseSize(String sizeStr) {
		if (sizeStr == null || sizeStr.isEmpty())
			return 0;
		try {
			String cleaned = sizeStr.replace("字节", "").trim();
			if (cleaned.toLowerCase().contains("kb")) {
				return (long) (Double.parseDouble(cleaned.replaceAll("[^0-9.]", "")) * 1024);
			} else if (cleaned.toLowerCase().contains("mb")) {
				return (long) (Double.parseDouble(cleaned.replaceAll("[^0-9.]", "")) * 1024 * 1024);
			} else {
				return Long.parseLong(cleaned.replaceAll("[^0-9]", ""));
			}
		} catch (Exception e) {
			return 0;
		}
	}

	private static String formatFileSize(long size) {
		if (size < 1024)
			return size + " B";
		if (size < 1024 * 1024)
			return String.format("%.2f KB", size / 1024.0);
		if (size < 1024 * 1024 * 1024)
			return String.format("%.2f MB", size / (1024.0 * 1024));
		return String.format("%.2f GB", size / (1024.0 * 1024 * 1024));
	}

	// ============================================
	// 六-B、JSON导出功能
	// ============================================

	public static void exportJsonData() {
		String jsonData = getFullJsonData();
		JFileChooser fileChooser = new JFileChooser();
		fileChooser.setFileView(createSafeFileView());
		fileChooser.setSelectedFile(new File("PE分析结果.json"));

		if (fileChooser.showSaveDialog(mainFrame) == JFileChooser.APPROVE_OPTION) {
			try (PrintWriter writer = new PrintWriter(new FileWriter(fileChooser.getSelectedFile()))) {
				writer.print(jsonData);
				JOptionPane.showMessageDialog(mainFrame, "JSON数据导出成功！", "提示", JOptionPane.INFORMATION_MESSAGE);
			} catch (Exception ex) {
				ex.printStackTrace();
				JOptionPane.showMessageDialog(mainFrame, "导出失败：" + ex.getMessage(), "错误", JOptionPane.ERROR_MESSAGE);
			}
		}
	}

	public static String getFullJsonData() {
		if (showData == null)
			return "{}";
		StringBuilder sb = new StringBuilder();
		sb.append("{");
		sb.append("\"filePath\":\"").append(escapeJson(currentFilePath)).append("\",");
		sb.append("\"loadTime\":\"").append(new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date(loadTimestamp)))
				.append("\",");
		sb.append("\"dosHeader\":{");
		sb.append("\"magicStatus\":\"").append(escapeJson(showData.dosHeader.magicStatus)).append("\"");
		sb.append("},");
		sb.append("\"fileHeader\":{");
		sb.append("\"machine\":\"").append(escapeJson(showData.fileHeader.machine)).append("\",");
		sb.append("\"numberOfSections\":\"").append(escapeJson(showData.fileHeader.numberOfSections)).append("\",");
		sb.append("\"timeDateStamp\":\"").append(escapeJson(showData.fileHeader.timeDateStamp)).append("\",");
		sb.append("\"pointerToSymbolTable\":\"").append(escapeJson(showData.fileHeader.pointerToSymbolTable))
				.append("\",");
		sb.append("\"numberOfSymbols\":\"").append(escapeJson(showData.fileHeader.numberOfSymbols)).append("\",");
		sb.append("\"sizeOfOptionalHeader\":\"").append(escapeJson(showData.fileHeader.sizeOfOptionalHeader))
				.append("\",");
		sb.append("\"characteristics\":\"").append(escapeJson(showData.fileHeader.characteristics)).append("\"");
		sb.append("},");
		sb.append("\"optionalHeader\":{");
		sb.append("\"magic\":\"").append(escapeJson(showData.optionalHeader.magic)).append("\",");
		sb.append("\"linkerVersion\":\"").append(escapeJson(showData.optionalHeader.LinkerVersion)).append("\",");
		sb.append("\"addressOfEntryPoint\":\"").append(escapeJson(showData.optionalHeader.addressOfEntryPoint))
				.append("\",");
		sb.append("\"baseOfCode\":\"").append(escapeJson(showData.optionalHeader.baseOfCode)).append("\",");
		sb.append("\"imageBase\":\"").append(escapeJson(showData.optionalHeader.imageBase)).append("\",");
		sb.append("\"sectionAlignment\":\"").append(escapeJson(showData.optionalHeader.sectionAlignment)).append("\",");
		sb.append("\"fileAlignment\":\"").append(escapeJson(showData.optionalHeader.fileAlignment)).append("\",");
		sb.append("\"operatingSystemVersion\":\"").append(escapeJson(showData.optionalHeader.OperatingSystemVersion))
				.append("\",");
		sb.append("\"imageVersion\":\"").append(escapeJson(showData.optionalHeader.ImageVersion)).append("\",");
		sb.append("\"subsystemVersion\":\"").append(escapeJson(showData.optionalHeader.SubsystemVersion)).append("\",");
		sb.append("\"sizeOfImage\":\"").append(escapeJson(showData.optionalHeader.sizeOfImage)).append("\",");
		sb.append("\"sizeOfHeaders\":\"").append(escapeJson(showData.optionalHeader.sizeOfHeaders)).append("\",");
		sb.append("\"subsystem\":\"").append(escapeJson(showData.optionalHeader.subsystem)).append("\"");
		sb.append("},");
		sb.append("\"sections\":").append(getSectionsAsJson());
		sb.append("}");
		return sb.toString();
	}

	// ============================================
	// 七、数据初始化方法
	// ============================================

	private static ShowData createEmptyData() {
		ShowData data = new ShowData();

		data.dosHeader.magicStatus = "未加载";

		data.fileHeader.machine("未知").numberOfSections("0").timeDateStamp("未知").pointerToSymbolTable("0x00000000")
				.numberOfSymbols("0").sizeOfOptionalHeader("0x0000").characteristics("未知");

		data.optionalHeader.magic("未知").LinkerVersion("0.0").addressOfEntryPoint("0x00000000").baseOfCode("0x00000000")
				.imageBase("0x00000000").sectionAlignment("0x0000").fileAlignment("0x0000")
				.OperatingSystemVersion("0.0").ImageVersion("0.0").SubsystemVersion("0.0").sizeOfImage("0 字节")
				.sizeOfHeaders("0 字节").subsystem("未知");

		return data;
	}

	// ============================================
	// 八、核心功能：加载PE文件
	// ============================================
	public static void loadPEFile(File file) {
		loadTimestamp = System.currentTimeMillis();
		currentFilePath = file.getAbsolutePath();
		ShowData newData = PeShowParser.parse(currentFilePath);

		String magicStatus = newData.dosHeader.magicStatus;
		if ("读取异常".equals(magicStatus) || "格式异常".equals(magicStatus)) {
			updateStatusBar(" " + magicStatus + ": " + file.getName());
			JOptionPane.showMessageDialog(mainFrame, " " + magicStatus + "！\n文件: " + file.getAbsolutePath(), "解析失败",
					JOptionPane.ERROR_MESSAGE);
			return;
		}

		showData = newData;
		isDataLoaded = true;

		refreshAllCards();
		long fileSize = file.length();
		String sizeStr = formatFileSize(fileSize);
		String format = showData.optionalHeader.magic;
		updateStatusBar(file.getName() + " | " + sizeStr + " | " + format + " | " + showData.sections.size() + "个节");
		mainFrame.setTitle("PE文件分析器 v2.0 - " + file.getName());
		switchCard(CARD_OVERVIEW);
	}

	// ============================================
	// 九、UI刷新方法
	// ============================================

	private static void refreshAllCards() {
		cardPanel.removeAll();
		cardPanel.add(createOverviewCard(), CARD_OVERVIEW);
		cardPanel.add(createDosHeaderCard(), CARD_DOS);
		cardPanel.add(createFileHeaderCard(), CARD_FILE);
		cardPanel.add(createOptionalHeaderCard(), CARD_OPTIONAL);
		cardPanel.add(createSectionsCard(), CARD_SECTIONS);
		cardPanel.add(createStatsCard(), CARD_STATS);

		cardPanel.revalidate();
		cardPanel.repaint();
	}

	// ============================================
	// 十、标题栏创建
	// ============================================

	private static JPanel createTitlePanel() {
		JPanel panel = new JPanel(new BorderLayout());
		panel.setOpaque(false);
		panel.setBorder(BorderFactory.createEmptyBorder(5, 10, 10, 10));

		JLabel title = new JLabel("PE文件分析器 v2.0", SwingConstants.CENTER);
		title.setFont(new Font("微软雅黑", Font.BOLD, 28));
		title.setForeground(Color.WHITE);
		panel.add(title, BorderLayout.CENTER);

		JPanel btnPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
		btnPanel.setOpaque(false);

		JButton loadBtn = createLoadButton();
		btnPanel.add(loadBtn);

		JButton exportBtn = createExportButton();
		btnPanel.add(exportBtn);

		JButton jsonBtn = createJsonExportButton();
		btnPanel.add(jsonBtn);

		panel.add(btnPanel, BorderLayout.EAST);

		return panel;
	}

	private static JButton createLoadButton() {
		JButton loadBtn = new JButton("加载");
		loadBtn.setFont(new Font("微软雅黑", Font.BOLD, 14));
		loadBtn.setBackground(new Color(46, 204, 113));
		loadBtn.setForeground(Color.WHITE);
		loadBtn.setFocusPainted(false);
		loadBtn.setBorderPainted(false);
		loadBtn.setPreferredSize(new Dimension(100, 40));

		loadBtn.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				JFileChooser fileChooser = createStyledFileChooser();
				int result = fileChooser.showOpenDialog(mainFrame);
				if (result == JFileChooser.APPROVE_OPTION) {
					File selectedFile = fileChooser.getSelectedFile();
					lastDirectory = selectedFile.getParentFile();
					loadPEFile(selectedFile);
				}
			}
		});

		return loadBtn;
	}

	private static JButton createExportButton() {
		JButton exportBtn = new JButton("导出");
		exportBtn.setFont(new Font("微软雅黑", Font.BOLD, 14));
		exportBtn.setBackground(new Color(52, 152, 219));
		exportBtn.setForeground(Color.WHITE);
		exportBtn.setFocusPainted(false);
		exportBtn.setBorderPainted(false);
		exportBtn.setPreferredSize(new Dimension(100, 40));

		exportBtn.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				if (!isDataLoaded()) {
					JOptionPane.showMessageDialog(mainFrame, "请先加载PE文件！", "提示", JOptionPane.WARNING_MESSAGE);
					return;
				}

				String data = getAllDataAsText();

				JTextArea textArea = new JTextArea(data);
				textArea.setEditable(false);
				textArea.setFont(new Font("微软雅黑", Font.PLAIN, 13));
				JScrollPane scrollPane = new JScrollPane(textArea);
				scrollPane.setPreferredSize(new Dimension(700, 500));

				Object[] options = { "保存到文件", "复制到剪贴板", "关闭" };
				int result = JOptionPane.showOptionDialog(mainFrame, scrollPane, "PE文件详细信息", JOptionPane.DEFAULT_OPTION,
						JOptionPane.INFORMATION_MESSAGE, null, options, options[2]);

				if (result == 0) {
					saveDataToFile(data);
				} else if (result == 1) {
					textArea.selectAll();
					textArea.copy();
					JOptionPane.showMessageDialog(mainFrame, "已复制到剪贴板！", "提示", JOptionPane.INFORMATION_MESSAGE);
				}
			}
		});

		return exportBtn;
	}

	private static JButton createJsonExportButton() {
		JButton jsonBtn = new JButton("JSON");
		jsonBtn.setFont(new Font("微软雅黑", Font.BOLD, 14));
		jsonBtn.setBackground(new Color(155, 89, 182));
		jsonBtn.setForeground(Color.WHITE);
		jsonBtn.setFocusPainted(false);
		jsonBtn.setBorderPainted(false);
		jsonBtn.setPreferredSize(new Dimension(90, 40));

		jsonBtn.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				if (!isDataLoaded()) {
					JOptionPane.showMessageDialog(mainFrame, "请先加载PE文件！", "提示", JOptionPane.WARNING_MESSAGE);
					return;
				}
				exportJsonData();
			}
		});

		return jsonBtn;
	}

	// ============================================
	// 十一、文件选择器美化方法
	// ============================================

	private static JFileChooser createStyledFileChooser() {
		JFileChooser fileChooser = new JFileChooser();

		fileChooser.setDialogTitle("请选择要分析的PE文件");

		FileNameExtensionFilter filter = new FileNameExtensionFilter("PE可执行文件 (*.exe, *.dll, *.sys)", "exe", "dll",
				"sys");
		fileChooser.setFileFilter(filter);
		fileChooser.addChoosableFileFilter(new javax.swing.filechooser.FileFilter() {
			@Override
			public boolean accept(File f) {
				return true;
			}

			@Override
			public String getDescription() {
				return "所有文件 (*.*)";
			}
		});

		if (lastDirectory != null) {
			fileChooser.setCurrentDirectory(lastDirectory);
		} else {
			fileChooser.setCurrentDirectory(new File(System.getProperty("user.home") + "/Desktop"));
		}

		fileChooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
		fileChooser.setFileView(createSafeFileView());
		return fileChooser;
	}

	private static FileView createSafeFileView() {
		return new FileView() {
			@Override
			public Icon getIcon(File f) {
				return null;
			}
		};
	}

	private static void saveDataToFile(String data) {
		JFileChooser fileChooser = new JFileChooser();
		fileChooser.setFileView(createSafeFileView());
		fileChooser.setSelectedFile(new File("PE分析结果.txt"));

		if (fileChooser.showSaveDialog(mainFrame) == JFileChooser.APPROVE_OPTION) {
			try (PrintWriter writer = new PrintWriter(new FileWriter(fileChooser.getSelectedFile()))) {
				writer.print(data);
				JOptionPane.showMessageDialog(mainFrame, "数据保存成功！", "提示", JOptionPane.INFORMATION_MESSAGE);
			} catch (Exception ex) {
				ex.printStackTrace();
				JOptionPane.showMessageDialog(mainFrame, "保存失败：" + ex.getMessage(), "错误", JOptionPane.ERROR_MESSAGE);
			}
		}
	}

	// ============================================
	// 十二、左侧菜单创建
	// ============================================

	private static JPanel createMenuPanel() {
		JPanel panel = new JPanel();
		panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
		panel.setOpaque(false);
		panel.setBorder(BorderFactory.createEmptyBorder(0, 0, 0, 10));
		panel.setPreferredSize(new Dimension(160, 0));

		Color[] menuColors = { new Color(52, 152, 219), // 总览
				new Color(231, 76, 60), // DOS头
				new Color(46, 134, 193), // 文件头
				new Color(39, 174, 96), // 可选头
				new Color(155, 89, 182), // 节表
				new Color(230, 126, 34) // 统计
		};

		String[] menuNames = { "总览", "DOS头", "文件头", "可选头", "节表", "统计" };

		String[] cardNames = { CARD_OVERVIEW, CARD_DOS, CARD_FILE, CARD_OPTIONAL, CARD_SECTIONS, CARD_STATS };

		for (int i = 0; i < menuNames.length; i++) {
			JButton menuBtn = createMenuButton(menuNames[i], menuColors[i]);
			final String cardName = cardNames[i];

			menuBtn.addActionListener(new ActionListener() {
				@Override
				public void actionPerformed(ActionEvent e) {
					switchCard(cardName);
				}
			});

			panel.add(menuBtn);
			panel.add(Box.createVerticalStrut(6));
		}

		panel.add(Box.createVerticalGlue());
		return panel;
	}

	private static JButton createMenuButton(String text, Color color) {
		JButton btn = new JButton(text);
		btn.setFont(new Font("微软雅黑", Font.BOLD, 14));
		btn.setForeground(Color.WHITE);
		btn.setBackground(color);
		btn.setFocusPainted(false);
		btn.setBorderPainted(false);
		btn.setPreferredSize(new Dimension(140, 38));
		btn.setMaximumSize(new Dimension(140, 38));
		btn.setAlignmentX(JLabel.CENTER_ALIGNMENT);

		btn.addMouseListener(new java.awt.event.MouseAdapter() {
			public void mouseEntered(java.awt.event.MouseEvent evt) {
				btn.setBackground(color.brighter());
			}

			public void mouseExited(java.awt.event.MouseEvent evt) {
				btn.setBackground(color);
			}
		});

		return btn;
	}

	// ============================================
	// 十三、卡片切换方法
	// ============================================

	public static void switchCard(String cardName) {
		if (cardPanel != null) {
			CardLayout cl = (CardLayout) cardPanel.getLayout();
			cl.show(cardPanel, cardName);
		}
	}

	// ============================================
	// 十四、内容卡片创建
	// ============================================

	private static JPanel createContentCards() {
		cardPanel = new JPanel(new CardLayout());
		cardPanel.setOpaque(false);
		cardPanel.setBorder(BorderFactory.createLineBorder(new Color(255, 255, 255, 100), 2));

		cardPanel.add(createOverviewCard(), CARD_OVERVIEW);
		cardPanel.add(createDosHeaderCard(), CARD_DOS);
		cardPanel.add(createFileHeaderCard(), CARD_FILE);
		cardPanel.add(createOptionalHeaderCard(), CARD_OPTIONAL);
		cardPanel.add(createSectionsCard(), CARD_SECTIONS);
		cardPanel.add(createStatsCard(), CARD_STATS);

		return cardPanel;
	}

	// ============================================
	// 十五、卡片1：总览
	// ============================================

	private static JPanel createOverviewCard() {
		JPanel panel = createCardPanel("文件总览", true);

		JPanel infoPanel = new JPanel();
		infoPanel.setLayout(new BoxLayout(infoPanel, BoxLayout.Y_AXIS));
		infoPanel.setOpaque(false);
		infoPanel.setBorder(BorderFactory.createEmptyBorder(15, 20, 15, 20));

		infoPanel.add(createInfoRow("文件类型", showData.optionalHeader.magic + " " + showData.fileHeader.characteristics));
		infoPanel.add(createInfoRow("节数量", String.valueOf(showData.sections.size()), "PE文件包含的节总数"));
		infoPanel.add(createInfoRow("入口点 (RVA)", showData.optionalHeader.addressOfEntryPoint, "程序入口点的相对虚拟地址"));
		infoPanel.add(createInfoRow("镜像基址", showData.optionalHeader.imageBase, "PE加载到内存的首选地址"));
		infoPanel.add(createInfoRow("镜像大小", showData.optionalHeader.sizeOfImage, "加载到内存后的总大小"));
		infoPanel.add(createInfoRow("子系统", showData.optionalHeader.subsystem, "1=Native(驱动), 2=GUI, 3=CUI"));
		infoPanel.add(createInfoRow("Magic状态", showData.dosHeader.magicStatus));

		infoPanel.add(Box.createVerticalStrut(10));
		infoPanel.add(new JSeparator());
		infoPanel.add(Box.createVerticalStrut(10));

		if (currentFilePath != null) {
			File f = new File(currentFilePath);
			infoPanel.add(createInfoRow("文件名", f.getName()));
			infoPanel.add(createInfoRow("文件大小", formatFileSize(f.length())));
			infoPanel.add(createInfoRow("修改时间",
					new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date(f.lastModified()))));
		}
		infoPanel.add(
				createInfoRow("分析时间", new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date(loadTimestamp))));

		infoPanel.add(Box.createVerticalStrut(10));
		JLabel tip = new JLabel("提示: 点击左侧菜单查看详细信息 | 快捷键: Ctrl+O 打开, Ctrl+S 导出");
		tip.setFont(new Font("微软雅黑", Font.PLAIN, 12));
		tip.setForeground(new Color(100, 100, 100));
		infoPanel.add(tip);

		panel.add(infoPanel, BorderLayout.CENTER);
		return panel;
	}

	// ============================================
	// 十六、卡片2：DOS头
	// ============================================

	private static JPanel createDosHeaderCard() {
		JPanel panel = createCardPanel("DOS头信息", true);
		JPanel infoPanel = createInfoPanel();

		infoPanel.add(createInfoRow("Magic状态", showData.dosHeader.magicStatus, "MZ = 有效PE文件"));
		infoPanel.add(createInfoRow("e_magic", "0x5A4D (MZ)", "DOS头签名"));
		infoPanel.add(createInfoRow("e_lfanew", "0x00000080", "NT头偏移（通常为0x80）"));

		panel.add(infoPanel, BorderLayout.CENTER);
		return panel;
	}

	// ============================================
	// 十七、卡片3：文件头
	// ============================================

	private static JPanel createFileHeaderCard() {
		JPanel panel = createCardPanel("标准PE文件头", true);
		JPanel infoPanel = createInfoPanel();

		infoPanel.add(createInfoRow("Machine", showData.fileHeader.machine, "CPU架构类型"));
		infoPanel.add(createInfoRow("节数量", showData.fileHeader.numberOfSections, "PE文件包含的节(Section)数量"));
		infoPanel.add(createInfoRow("时间戳", showData.fileHeader.timeDateStamp, "文件编译时间(自1970-01-01的秒数)"));
		infoPanel.add(createInfoRow("符号表偏移", showData.fileHeader.pointerToSymbolTable, "COFF符号表位置，通常为0"));
		infoPanel.add(createInfoRow("符号数量", showData.fileHeader.numberOfSymbols, "COFF符号表条目数，通常为0"));
		infoPanel
				.add(createInfoRow("可选头大小", showData.fileHeader.sizeOfOptionalHeader, "可选头字节数(PE32=0xE0, PE32+=0xF0)"));
		infoPanel.add(createInfoRow("特征", showData.fileHeader.characteristics, "文件特性标志(bit1=EXE, bit13=DLL)"));

		panel.add(infoPanel, BorderLayout.CENTER);
		return panel;
	}

	// ============================================
	// 十八、卡片4：可选头
	// ============================================

	private static JPanel createOptionalHeaderCard() {
		JPanel panel = createCardPanel("可选头信息", true);
		JPanel infoPanel = createInfoPanel();

		infoPanel.add(createInfoRow("Magic", showData.optionalHeader.magic, "PE32(32位) 或 PE32+(64位)"));
		infoPanel.add(createInfoRow("链接器版本", showData.optionalHeader.LinkerVersion, "生成此文件的链接器版本"));
		infoPanel.add(createInfoRow("入口点 (RVA)", showData.optionalHeader.addressOfEntryPoint, "程序第一条指令的内存地址"));
		infoPanel.add(createInfoRow("代码基址", showData.optionalHeader.baseOfCode, "代码段起始的内存地址(RVA)"));
		infoPanel.add(createInfoRow("镜像基址", showData.optionalHeader.imageBase, "PE加载到内存时的首选起始地址"));
		infoPanel.add(createInfoRow("节对齐", showData.optionalHeader.sectionAlignment, "节在内存中的最小对齐单位(字节)"));
		infoPanel.add(createInfoRow("文件对齐", showData.optionalHeader.fileAlignment, "节在文件中的最小对齐单位(字节)"));
		infoPanel.add(createInfoRow("操作系统版本", showData.optionalHeader.OperatingSystemVersion, "运行所需的最低操作系统版本"));
		infoPanel.add(createInfoRow("镜像版本", showData.optionalHeader.ImageVersion, "此映像自身的版本号"));
		infoPanel.add(createInfoRow("子系统版本", showData.optionalHeader.SubsystemVersion, "运行所需的最低子系统版本"));
		infoPanel.add(createInfoRow("镜像大小", showData.optionalHeader.sizeOfImage, "加载后总内存占用(字节)"));
		infoPanel.add(createInfoRow("头大小", showData.optionalHeader.sizeOfHeaders, "所有头部的总大小(字节)"));
		infoPanel.add(createInfoRow("子系统", showData.optionalHeader.subsystem, "1=Native(驱动), 2=GUI, 3=CUI(命令行)"));

		panel.add(infoPanel, BorderLayout.CENTER);
		return panel;
	}

	// ============================================
	// 十九、卡片5：节表
	// ============================================

	private static JPanel createSectionsCard() {
		JPanel panel = createCardPanel("节表信息 (" + showData.sections.size() + "个)", true);
		JPanel infoPanel = createSectionInfoPanel();
		panel.add(new JScrollPane(infoPanel), BorderLayout.CENTER);
		return panel;
	}

	private static JPanel createSectionInfoPanel() {
		JPanel panel = new JPanel();
		panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
		panel.setOpaque(false);
		panel.setBorder(BorderFactory.createEmptyBorder(10, 20, 10, 20));

		if (showData.sections.isEmpty()) {
			JLabel emptyLabel = new JLabel("暂无节信息，请加载PE文件");
			emptyLabel.setFont(new Font("微软雅黑", Font.PLAIN, 16));
			emptyLabel.setForeground(Color.GRAY);
			panel.add(emptyLabel);
		} else {
			for (int i = 0; i < showData.sections.size(); i++) {
				ShowData.SectionInfo section = showData.sections.get(i);

				JPanel sectionBlock = new JPanel();
				sectionBlock.setLayout(new BoxLayout(sectionBlock, BoxLayout.Y_AXIS));
				sectionBlock.setBackground(new Color(255, 255, 255, 180));
				sectionBlock.setBorder(BorderFactory.createEmptyBorder(8, 10, 8, 10));

				JLabel sectionTitle = new JLabel("节 #" + i + ": " + section.name);
				sectionTitle.setFont(new Font("微软雅黑", Font.BOLD, 15));
				sectionTitle.setForeground(new Color(0, 100, 200));
				sectionTitle.setBorder(BorderFactory.createEmptyBorder(0, 0, 5, 0));
				sectionBlock.add(sectionTitle);

				sectionBlock.add(createInfoRow("虚拟大小", section.virtualSize));
				sectionBlock.add(createInfoRow("虚拟地址", section.virtualAddress));
				sectionBlock.add(createInfoRow("原始数据大小", section.sizeOfRawData));
				sectionBlock.add(createInfoRow("原始数据偏移", section.pointerToRawData));
				sectionBlock.add(createInfoRow("特征", section.characteristics));

				panel.add(sectionBlock);

				if (i < showData.sections.size() - 1) {
					panel.add(Box.createVerticalStrut(8));
				}
			}
		}

		return panel;
	}

	// ============================================
	// 二十、卡片6：统计信息
	// ============================================

	private static JPanel createStatsCard() {
		JPanel panel = createCardPanel("统计信息", true);
		JPanel infoPanel = createInfoPanel();

		if (!isDataLoaded()) {
			infoPanel.add(createInfoRow("状态", "请先加载PE文件"));
		} else {
			infoPanel.add(createInfoRow("总节数", String.valueOf(showData.sections.size())));
			infoPanel.add(createInfoRow("总节大小", calculateTotalSectionSize()));
			infoPanel.add(createInfoRow("平均节大小", calculateAverageSectionSize()));
			infoPanel.add(createInfoRow("最大节", getLargestSectionName()));
			infoPanel.add(createInfoRow("最小节", getSmallestSectionName()));
			infoPanel.add(createInfoRow("文件格式", showData.optionalHeader.magic));
			infoPanel.add(createInfoRow("文件类型", showData.fileHeader.characteristics));
			infoPanel.add(createInfoRow("子系统", showData.optionalHeader.subsystem));

			infoPanel.add(Box.createVerticalStrut(10));
			infoPanel.add(new JSeparator());
			infoPanel.add(Box.createVerticalStrut(10));

			infoPanel.add(createInfoRow("可执行节", String.valueOf(countExecutableSections())));
			infoPanel.add(createInfoRow("可写节", String.valueOf(countWritableSections())));
			infoPanel.add(createInfoRow("只读节", String.valueOf(countReadOnlySections())));
		}

		panel.add(infoPanel, BorderLayout.CENTER);
		return panel;
	}

	private static String getLargestSectionName() {
		if (showData == null || showData.sections.isEmpty())
			return "N/A";
		ShowData.SectionInfo largest = showData.sections.get(0);
		for (ShowData.SectionInfo s : showData.sections) {
			if (parseSize(s.virtualSize) > parseSize(largest.virtualSize)) {
				largest = s;
			}
		}
		return largest.name + " (" + largest.virtualSize + ")";
	}

	private static String getSmallestSectionName() {
		if (showData == null || showData.sections.isEmpty())
			return "N/A";
		ShowData.SectionInfo smallest = showData.sections.get(0);
		for (ShowData.SectionInfo s : showData.sections) {
			if (parseSize(s.virtualSize) < parseSize(smallest.virtualSize)) {
				smallest = s;
			}
		}
		return smallest.name + " (" + smallest.virtualSize + ")";
	}

	private static int countExecutableSections() {
		int count = 0;
		for (ShowData.SectionInfo s : showData.sections) {
			if (s.characteristics != null && s.characteristics.toLowerCase().contains("可执行")) {
				count++;
			}
		}
		return count;
	}

	private static int countWritableSections() {
		int count = 0;
		for (ShowData.SectionInfo s : showData.sections) {
			if (s.characteristics != null && s.characteristics.toLowerCase().contains("可写")) {
				count++;
			}
		}
		return count;
	}

	private static int countReadOnlySections() {
		int count = 0;
		for (ShowData.SectionInfo s : showData.sections) {
			if (s.characteristics != null && !s.characteristics.toLowerCase().contains("可写")
					&& !s.characteristics.toLowerCase().contains("可执行")) {
				count++;
			}
		}
		return count;
	}

	// ============================================
	// 二十一、UI辅助方法
	// ============================================

	private static JPanel createInfoPanel() {
		JPanel panel = new JPanel();
		panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
		panel.setOpaque(false);
		panel.setBorder(BorderFactory.createEmptyBorder(10, 20, 10, 20));
		return panel;
	}

	private static JPanel createCardPanel(String title, boolean withCopyButton) {
		JPanel panel = new JPanel(new BorderLayout());
		panel.setOpaque(false);
		panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

		JPanel topRow = new JPanel(new BorderLayout());
		topRow.setOpaque(false);

		JLabel titleLabel = new JLabel(title);
		titleLabel.setFont(new Font("微软雅黑", Font.BOLD, 20));
		titleLabel.setForeground(new Color(50, 50, 150));
		topRow.add(titleLabel, BorderLayout.WEST);

		if (withCopyButton) {
			JButton copyBtn = new JButton("复制");
			copyBtn.setFont(new Font("微软雅黑", Font.PLAIN, 12));
			copyBtn.setPreferredSize(new Dimension(80, 28));
			copyBtn.addActionListener(e -> {
				String data = getAllDataAsText();
				java.awt.datatransfer.StringSelection ss = new java.awt.datatransfer.StringSelection(data);
				java.awt.Toolkit.getDefaultToolkit().getSystemClipboard().setContents(ss, null);
				JOptionPane.showMessageDialog(mainFrame, "已复制到剪贴板！", "提示", JOptionPane.INFORMATION_MESSAGE);
			});
			topRow.add(copyBtn, BorderLayout.EAST);
		}

		panel.add(topRow, BorderLayout.NORTH);
		return panel;
	}

	private static JPanel createInfoRow(String label, String value) {
		return createInfoRow(label, value, null);
	}

	private static JPanel createInfoRow(String label, String value, String tooltip) {
		JPanel panel = new JPanel(new BorderLayout(15, 0));
		panel.setMaximumSize(new Dimension(Integer.MAX_VALUE, 32));
		panel.setBorder(BorderFactory.createEmptyBorder(2, 5, 2, 5));
		panel.setBackground(new Color(255, 255, 255, 180));

		JLabel labelComp = new JLabel(label + "：");
		labelComp.setFont(new Font("微软雅黑", Font.PLAIN, 14));
		labelComp.setPreferredSize(new Dimension(160, 28));
		labelComp.setForeground(new Color(60, 60, 60));
		if (tooltip != null) {
			labelComp.setToolTipText(tooltip);
		}

		JLabel valueComp = new JLabel(value != null ? value : "(空)");
		valueComp.setFont(new Font("微软雅黑", Font.PLAIN, 14));
		valueComp.setForeground(new Color(0, 0, 150));
		if (tooltip != null) {
			valueComp.setToolTipText(tooltip);
		}

		panel.add(labelComp, BorderLayout.WEST);
		panel.add(valueComp, BorderLayout.CENTER);

		return panel;
	}

	// ============================================
	// 二十二、状态栏
	// ============================================

	private static JPanel createStatusPanel() {
		JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT));
		panel.setOpaque(false);
		panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 5, 10));

		statusLabel = new JLabel("就绪 | 共 " + showData.sections.size() + "个节");
		statusLabel.setFont(new Font("微软雅黑", Font.PLAIN, 12));
		statusLabel.setForeground(new Color(200, 200, 200));
		panel.add(statusLabel);

		JLabel dragHint = new JLabel("  |  支持拖拽 | Ctrl+O 打开 | Ctrl+S 导出 | Ctrl+E 导出JSON");
		dragHint.setFont(new Font("微软雅黑", Font.PLAIN, 11));
		dragHint.setForeground(new Color(160, 160, 160));
		panel.add(dragHint);

		return panel;
	}

	private static void updateStatusBar(String message) {
		if (statusLabel != null) {
			statusLabel.setText(message);
		}
	}

	// ============================================
	// 二十三、内部类：BackgroundPanel（背景面板）
	// ============================================

	static class BackgroundPanel extends JPanel {

		private Image backgroundImage;

		public BackgroundPanel(String imagePath) {
			try {
				System.out.println("正在加载背景图片: " + imagePath);

				java.net.URL imgURL = getClass().getResource("/" + imagePath);
				if (imgURL != null) {
					backgroundImage = new ImageIcon(imgURL).getImage();
					System.out.println("从classpath加载成功");
				} else {
					backgroundImage = new ImageIcon(imagePath).getImage();
					if (backgroundImage.getWidth(null) > 0) {
						System.out.println("从文件系统加载成功");
					} else {
						System.out.println("图片加载失败，使用渐变背景");
						backgroundImage = null;
					}
				}
			} catch (Exception e) {
				System.out.println("加载图片异常: " + e.getMessage());
				backgroundImage = null;
			}

			setLayout(new BorderLayout());
		}

		@Override
		protected void paintComponent(Graphics g) {
			super.paintComponent(g);

			if (backgroundImage != null && backgroundImage.getWidth(null) > 0) {
				g.drawImage(backgroundImage, 0, 0, getWidth(), getHeight(), this);
			} else {
				Graphics2D g2d = (Graphics2D) g;
				GradientPaint gradient = new GradientPaint(0, 0, new Color(25, 25, 112), 0, getHeight(),
						new Color(70, 130, 180));
				g2d.setPaint(gradient);
				g2d.fillRect(0, 0, getWidth(), getHeight());
			}
		}
	}
}