import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.address.Address;

/**
 * 批量反编译脚本 —— 给固件 CTF 用
 *
 * 用法:
 *   analyzeHeadless <projdir> <projname> -import <target> \
 *     -scriptPath ~/ctf/scripts -postScript Decompile.java [maxFuncs] [nameFilter]
 *
 * 参数:
 *   maxFuncs   最多反编译多少个函数（默认 40，避免大二进制跑太久）
 *   nameFilter 只反编译名字含该子串的函数（可选）
 *
 * 输出: 直接打到 stdout，包含函数名、入口地址、调用列表、C 伪代码
 */
public class DecompileScript extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        int maxFuncs = 40;
        String filter = null;
        if (args.length >= 1 && !args[0].isEmpty()) {
            try { maxFuncs = Integer.parseInt(args[0]); } catch (NumberFormatException e) { filter = args[0]; }
        }
        if (args.length >= 2 && !args[1].isEmpty()) filter = args[1];

        FunctionManager fm = currentProgram.getFunctionManager();
        long total = fm.getFunctionCount();

        println("### PROGRAM: " + currentProgram.getName());
        println("### FORMAT: " + currentProgram.getExecutableFormat());
        println("### LANGUAGE: " + currentProgram.getLanguageID());
        println("### IMAGE_BASE: " + currentProgram.getImageBase());
        println("### FUNCTIONS_TOTAL: " + total);

        // 入口点优先（Ghidra 12.x 移除了 Program.getEntryPoint()，改用符号表）
        StringBuilder eps = new StringBuilder();
        ghidra.program.model.address.AddressIterator epIt =
            currentProgram.getSymbolTable().getExternalEntryPointIterator();
        while (epIt.hasNext()) {
            if (eps.length() > 0) eps.append(", ");
            eps.append(epIt.next().toString());
            if (eps.length() > 400) { eps.append(" ..."); break; }
        }
        println("### ENTRY: " + (eps.length() == 0 ? "?" : eps.toString()));

        DecompInterface di = new DecompInterface();
        di.toggleCCode(true);
        di.toggleSyntaxTree(true);
        di.setSimplificationStyle("decompile");
        if (!di.openProgram(currentProgram)) {
            println("!!! decompiler open failed: " + di.getLastMessage());
            return;
        }

        println("\n### FUNCTION_INDEX");
        int shown = 0;
        for (Function f : fm.getFunctions(true)) {
            if (filter != null && !f.getName().contains(filter)) continue;
            println(String.format("  %s @ %s  (params=%d, size=%d)",
                f.getName(), f.getEntryPoint(), f.getParameterCount(), f.getBody().getNumAddresses()));
            shown++;
            if (shown >= 500) { println("  ... (索引截断)"); break; }
        }

        println("\n### DECOMPILED");
        int done = 0;
        for (Function f : fm.getFunctions(true)) {
            if (done >= maxFuncs) break;
            if (filter != null && !f.getName().contains(filter)) continue;
            try {
                DecompileResults r = di.decompileFunction(f, 45, monitor);
                if (r == null || !r.decompileCompleted()) {
                    println("--- " + f.getName() + " @ " + f.getEntryPoint() + " : DECOMPILE_FAILED");
                    continue;
                }
                println("\n=== " + f.getName() + " @ " + f.getEntryPoint() + " ===");
                String c = r.getDecompiledFunction().getC();
                println(c);
                done++;
            } catch (Exception ex) {
                println("--- " + f.getName() + " : EXCEPTION " + ex.getMessage());
            }
        }
        println("\n### DECOMPILED_COUNT: " + done);
        di.dispose();
    }
}
