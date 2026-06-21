package pe;

import java.io.IOException;

import model.RawData;
import model.ShowData;

/**
 * 展示数据入口
 * 使用方式：
 * ShowData show = PeShowParser.parse(filePath);
 * 直接用于 UI 展示
 * 异常处理说明：
 * - 本类不向外抛异常，始终返回 ShowData。
 * - 读取异常：在 show.dosHeader.magicStatus 写入 "读取异常"。
 * - 格式异常：在 show.dosHeader.magicStatus 写入 "格式异常"。
 */
public final class PeShowParser {
    private PeShowParser() {
    }

    /**
     * 解析指定 PE 文件并返回可直接展示的数据。
     * @param filename PE 文件路径
     * @return 展示数据对象；发生读取/格式异常时返回带状态标记的对象
     */
    public static ShowData parse(String filename) {
        try {
            RawData raw = PeParser.parse(filename);
            return PeDataConverter.convert(raw);
        } catch (IOException ex) {
            ShowData show = ShowData.create();
            show.dosHeader.magicStatus("读取异常");
            return show;
        }
    }
}
