package test;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;

import model.ShowData;
import pe.PeShowParser;

public class PeFeatureTest {
    public static void main(String[] args) throws Exception {
        Path peFile = resolvePeFile(args);

        ShowData show = PeShowParser.parse(peFile.toString());
        assertNotNull(show, "show data");
        assertNotNull(show.dosHeader.magicStatus, "dos header");
        assertNotNull(show.fileHeader.machine, "file header machine");
        assertNotNull(show.optionalHeader.magic, "optional header magic");
        assertFalse(show.sections.isEmpty(), "sections should not be empty");

        printShowData(peFile, show);
        System.out.println("PeFeatureTest passed");
    }

    private static Path resolvePeFile(String[] args) throws Exception {
        String rawPath = null;
        if (args != null && args.length > 0 && args[0] != null && !args[0].isBlank()) {
            rawPath = args[0];
        } else {
            System.out.print("请输入 PE 文件路径: ");
            BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
            rawPath = reader.readLine();
        }
        if (rawPath == null || rawPath.isBlank()) {
            throw new IllegalArgumentException("PE file path is empty");
        }
        Path path = Path.of(rawPath.trim());
        if (!Files.exists(path)) {
            throw new IllegalArgumentException("PE file not found: " + path);
        }
        return path;
    }

    private static void printShowData(Path peFile, ShowData show) {
        System.out.println("==== ShowData from: " + peFile + " ====");
        System.out.println("[DOS]");
        System.out.println("magicStatus=" + show.dosHeader.magicStatus);

        System.out.println("[FileHeader]");
        System.out.println("machine=" + show.fileHeader.machine);
        System.out.println("numberOfSections=" + show.fileHeader.numberOfSections);
        System.out.println("timeDateStamp=" + show.fileHeader.timeDateStamp);
        System.out.println("pointerToSymbolTable=" + show.fileHeader.pointerToSymbolTable);
        System.out.println("numberOfSymbols=" + show.fileHeader.numberOfSymbols);
        System.out.println("sizeOfOptionalHeader=" + show.fileHeader.sizeOfOptionalHeader);
        System.out.println("characteristics=" + show.fileHeader.characteristics);

        System.out.println("[OptionalHeader]");
        System.out.println("magic=" + show.optionalHeader.magic);
        System.out.println("LinkerVersion=" + show.optionalHeader.LinkerVersion);
        System.out.println("addressOfEntryPoint=" + show.optionalHeader.addressOfEntryPoint);
        System.out.println("baseOfCode=" + show.optionalHeader.baseOfCode);
        System.out.println("imageBase=" + show.optionalHeader.imageBase);
        System.out.println("sectionAlignment=" + show.optionalHeader.sectionAlignment);
        System.out.println("fileAlignment=" + show.optionalHeader.fileAlignment);
        System.out.println("OperatingSystemVersion=" + show.optionalHeader.OperatingSystemVersion);
        System.out.println("ImageVersion=" + show.optionalHeader.ImageVersion);
        System.out.println("SubsystemVersion=" + show.optionalHeader.SubsystemVersion);
        System.out.println("sizeOfImage=" + show.optionalHeader.sizeOfImage);
        System.out.println("sizeOfHeaders=" + show.optionalHeader.sizeOfHeaders);
        System.out.println("subsystem=" + show.optionalHeader.subsystem);

        System.out.println("[Sections]");
        for (int i = 0; i < show.sections.size(); i++) {
            ShowData.SectionInfo section = show.sections.get(i);
            System.out.println("- section[" + i + "]");
            System.out.println("  name=" + section.name);
            System.out.println("  virtualSize=" + section.virtualSize);
            System.out.println("  virtualAddress=" + section.virtualAddress);
            System.out.println("  sizeOfRawData=" + section.sizeOfRawData);
            System.out.println("  pointerToRawData=" + section.pointerToRawData);
            System.out.println("  characteristics=" + section.characteristics);
        }
    }

    private static void assertNotNull(Object value, String message) {
        if (value == null) {
            throw new AssertionError(message + " should not be null");
        }
    }

    private static void assertFalse(boolean condition, String message) {
        if (condition) {
            throw new AssertionError(message);
        }
    }
}
