package com.rootdetect.app;

import android.app.Activity;
import android.content.Intent;
import android.graphics.Color;
import android.graphics.Typeface;
import android.os.Build;
import android.os.Bundle;
import android.text.method.ScrollingMovementMethod;
import android.util.TypedValue;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/* NOTE: android.os.Process is *not* imported - it would shadow java.lang.Process
 * and make `Process p = pb.start()` a type error. myUid() is called fully
 * qualified below. */

/**
 * Minimal front end for the native scanner. The UI text is Simplified Chinese;
 * the report printed by the native engine stays English on purpose, because the
 * parsing below depends on that stable text contract (severity header line +
 * 11-space detail/evidence indent, and the "verdict:" line).
 *
 * The scanner is a statically linked ELF executable that ships inside this APK
 * as {@code lib/<abi>/librootdetect.so}, so the package manager extracts it into
 * the app's native library directory where it is executable. If executing it
 * there is refused (some OEM policies), it is copied into the app's files
 * directory and executed from there - that is why this app targets SDK 28.
 *
 * The UI is deliberately built in code (only the strings/icons are resources),
 * which keeps the APK buildable with nothing but aapt2 + javac + d8.
 *
 * On top of the raw report this front end adds two things the raw text makes
 * hard to read at a glance:
 *   1. a result banner - is the device rooted, is anything hidden, and *where*
 *      the problems are (the concrete paths/keys behind each finding);
 *   2. an "export log" button that writes the whole report to a file and opens
 *      the system share sheet, so the log can leave the device.
 */
public class MainActivity extends Activity {

    private TextView output;
    private TextView summary;
    private Button runButton;
    private Button exportButton;

    /** Full text of the last scan (header + summary + raw report): what we export. */
    private String lastLog = "";
    private static final String STATE_LOG = "lastLog";

    /** How long a scan may run before the scanner is killed. */
    private static final long SCAN_TIMEOUT_MS = 120000L;

    /* A scan runs on its own thread and outlives a configuration change, so the
     * in-flight state and its result live in statics: `sCurrent` is the Activity
     * the thread should deliver to (the newest one), `sScanning` lets a recreated
     * Activity keep showing "scanning" instead of "not scanned yet", and
     * `sPendingReport` holds a result that arrived while no Activity existed. */
    private static volatile MainActivity sCurrent;
    private static volatile boolean sScanning;
    private static volatile String sPendingReport;

    /* The scanner's finding header line looks like
     *   [HIGH    ] artefact-present       root artefacts present on the filesystem
     * (severity padded to 8 columns, id padded to 22). Detail lines are indented
     * by 11 spaces; evidence lines are indented and prefixed with "| ". */
    private static final Pattern FINDING =
            Pattern.compile("^\\[(CRITICAL|HIGH|MEDIUM|LOW|INFO)\\s*\\]\\s+(\\S+)\\s+(.*)$");
    /* An absolute path, but only when it starts at a boundary - otherwise
     * "stat/getdents" would look like the path "/getdents". */
    private static final Pattern PATH =
            Pattern.compile("(?:^|[\\s=\"'(])(/[A-Za-z0-9._+@:/-]{2,200})");

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        final int pad = (int) TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, 12,
                getResources().getDisplayMetrics());

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(pad, pad, pad, pad);

        TextView title = new TextView(this);
        title.setText("bunanana");
        title.setTypeface(Typeface.DEFAULT_BOLD);
        title.setTextSize(22f);
        root.addView(title);

        TextView sub = new TextView(this);
        sub.setText("root / 隐藏 root 检测工具\n"
                + "检测引擎：rootdetect - 静态编译，无第三方依赖，不联网");
        sub.setTextSize(12f);
        root.addView(sub);

        // Result banner: root yes/no + where the problems are.
        summary = new TextView(this);
        summary.setTypeface(Typeface.MONOSPACE);
        summary.setTextSize(12f);
        summary.setTextColor(Color.WHITE);
        summary.setBackgroundColor(0xFF455A64);
        int sp = (int) TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, 8,
                getResources().getDisplayMetrics());
        summary.setPadding(sp, sp, sp, sp);
        LinearLayout.LayoutParams slp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        slp.topMargin = pad;
        slp.bottomMargin = pad;
        root.addView(summary, slp);

        runButton = new Button(this);
        runButton.setText("开始检测");
        runButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                startScan();
            }
        });
        root.addView(runButton);

        exportButton = new Button(this);
        exportButton.setText("导出日志");
        exportButton.setEnabled(false);
        exportButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                exportLog();
            }
        });
        root.addView(exportButton);

        output = new TextView(this);
        output.setTypeface(Typeface.MONOSPACE);
        output.setTextSize(10f);
        output.setTextIsSelectable(true);
        output.setMovementMethod(new ScrollingMovementMethod());

        ScrollView scroll = new ScrollView(this);
        scroll.addView(output, new ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f);
        root.addView(scroll, lp);

        setContentView(root);
        summary.setText("结论：尚未检测\n点\"开始检测\"检查这台设备。");
        output.setText(header() + "\n点\"开始检测\"开始扫描这台设备。\n\n"
                + "退出码：0 干净 | 1 可疑 | 2 检测到 root | 3 检测到隐藏\n");

        /* A rotation (or any configuration change) recreates the Activity. The
         * in-flight scan (sScanning) and a finished one whose result arrived
         * meanwhile (sPendingReport) survive in statics; otherwise the report and
         * the export button were lost and the user had to rescan just to export. */
        sCurrent = this;
        String saved = savedInstanceState != null ? savedInstanceState.getString(STATE_LOG) : null;
        if (sScanning) {
            summary.setText("结论：正在检测……");
            output.setText("正在扫描……\n");
            runButton.setEnabled(false);
            exportButton.setEnabled(false);
        } else if (sPendingReport != null && !sPendingReport.isEmpty()) {
            String log = sPendingReport;
            String verdict = verdictOf(log);
            applyResult(buildSummary(verdict, parseFindings(log)), verdict, log);
        } else if (saved != null && !saved.isEmpty()) {
            lastLog = saved;
            String verdict = verdictOf(saved);
            summary.setText(buildSummary(verdict, parseFindings(saved)));
            summary.setBackgroundColor(colorFor(verdict));
            output.setText(saved);
            runButton.setText("重新检测");
            exportButton.setEnabled(true);
        }
    }

    @Override
    protected void onSaveInstanceState(Bundle outState) {
        super.onSaveInstanceState(outState);
        outState.putString(STATE_LOG, lastLog);
    }

    @Override
    protected void onDestroy() {
        if (sCurrent == this) sCurrent = null;
        super.onDestroy();
    }

    private String header() {
        return "uid " + android.os.Process.myUid() + "  |  " + Build.MANUFACTURER + " " + Build.MODEL
                + "  |  Android " + Build.VERSION.RELEASE + " (API " + Build.VERSION.SDK_INT + ")\n"
                + "主 ABI：" + (Build.SUPPORTED_ABIS.length > 0 ? Build.SUPPORTED_ABIS[0] : "?");
    }

    private void startScan() {
        sScanning = true;
        runButton.setEnabled(false);
        exportButton.setEnabled(false);
        summary.setBackgroundColor(0xFF455A64);
        summary.setText("结论：正在检测……");
        output.setText("正在扫描……\n");
        new Thread(new Runnable() {
            @Override
            public void run() {
                String verdict;
                String banner;
                String log;
                try {
                    String report = scan();
                    verdict = verdictOf(report);
                    banner = buildSummary(verdict, parseFindings(report));
                    log = header() + "\n\n" + banner + "\n\n"
                            + "----------------------------------------------\n" + report;
                } catch (Throwable t) {
                    /* Nothing caught an unchecked failure or an Error here
                     * before: no result was ever delivered, so the scan ended
                     * as a crash (the default uncaught handler ends the process)
                     * instead of a "扫描出错" banner - and where the process
                     * survived, sScanning stayed true and both buttons stayed
                     * disabled with no way to retry. Report it as a scan error
                     * so the UI always comes back. */
                    log = header() + "\n\n检测线程异常中止：" + t + "\n";
                    verdict = verdictOf(log);   // no verdict line -> SCAN_ERROR
                    banner = buildSummary(verdict, parseFindings(log));
                }
                final String fVerdict = verdict;
                final String fBanner = banner;
                final String fLog = log;
                runOnUiThread(new Runnable() {
                    @Override
                    public void run() {
                        sScanning = false;
                        sPendingReport = fLog;
                        /* Deliver to the current Activity: this one when the scan
                         * finished before a rotation, the recreated one when it
                         * did not (see sCurrent/onDestroy). */
                        MainActivity target = (isFinishing() || isDestroyed())
                                ? sCurrent : MainActivity.this;
                        if (target != null && !target.isFinishing() && !target.isDestroyed()) {
                            target.applyResult(fBanner, fVerdict, fLog);
                        }
                    }
                });
            }
        }).start();
    }

    /** Show a finished scan: banner, colour, log and the enabled buttons. */
    private void applyResult(String banner, String verdict, String log) {
        lastLog = log;
        sPendingReport = null;
        summary.setText(banner);
        summary.setBackgroundColor(colorFor(verdict));
        output.setText(log);
        runButton.setEnabled(true);
        runButton.setText("重新检测");
        exportButton.setEnabled(true);
    }

    /** The extracted scanner, or a copy in the app data dir if that fails. */
    private File scannerFile() throws Exception {
        File inLibs = new File(getApplicationInfo().nativeLibraryDir, "librootdetect.so");
        if (inLibs.isFile()) {
            return inLibs;
        }
        return stagedScanner(inLibs);
    }

    /**
     * Copy the scanner into the app's private files directory and make it
     * executable. The copy is refreshed on every scan: the old staleness check
     * only compared the length, so a same-sized but different binary (a rebuilt
     * APK whose versionCode and library size did not change) could be executed.
     * 2 MB is copied in milliseconds on a user-initiated scan.
     */
    private File stagedScanner(File inLibs) throws Exception {
        File local = new File(getFilesDir(), "rx");
        InputStream in = new java.io.FileInputStream(inLibs);
        try {
            OutputStream out = new FileOutputStream(local);
            try {
                byte[] buf = new byte[65536];
                int n;
                while ((n = in.read(buf)) > 0) {
                    out.write(buf, 0, n);
                }
            } finally {
                out.close();
            }
        } finally {
            in.close();
        }
        local.setExecutable(true, false);
        return local;
    }

    /** Run the scanner and return its report (no device header). */
    private String scan() {
        StringBuilder sb = new StringBuilder();
        File bin = null;
        try {
            bin = scannerFile();
        } catch (Exception e) {
            sb.append("无法准备扫描器：").append(e).append("\n");
        }
        if (bin == null) {
            return sb.toString() + fallbackInstructions();
        }

        List<String> cmd = new ArrayList<String>();
        cmd.add(bin.getAbsolutePath());
        cmd.add("-v");

        StringBuilder out = new StringBuilder();
        boolean ok = runProcess(cmd, out);
        if (!ok) {
            /* execve can refuse the native-library copy even though canExecute()
             * said yes (noexec mount, SELinux), which is why scannerFile() no
             * longer trusts canExecute(). Retry once from a fresh copy in the
             * app's files directory - the fallback the class comment describes. */
            try {
                File staged = stagedScanner(new File(getApplicationInfo().nativeLibraryDir,
                        "librootdetect.so"));
                if (!staged.getAbsolutePath().equals(bin.getAbsolutePath())) {
                    cmd.set(0, staged.getAbsolutePath());
                    out.setLength(0);
                    ok = runProcess(cmd, out);
                    if (ok) {
                        bin = staged;
                    }
                }
            } catch (Exception e) {
                out.append("无法准备备选扫描器：").append(e).append('\n');
            }
        }

        sb.append("扫描器：").append(bin).append('\n');
        sb.append("模式  ：详细输出 (uid ").append(android.os.Process.myUid()).append(")\n");
        sb.append("----------------------------------------------\n");
        sb.append(out);
        if (!ok) {
            sb.append(fallbackInstructions());
        }
        return sb.toString();
    }

    /**
     * Kill a scanner that is still running when the watchdog fires.
     *
     * destroyForcibly() is API 26+ while this app declares minSdkVersion 24, so on
     * Android 7.0/7.1 the call throws NoSuchMethodError. That is an Error, not an
     * Exception: it escaped the watchdog's catch (InterruptedException), so the
     * watchdog died without killing anything and the uncaught exception reached
     * Android's default handler, which ends the process - the app force-closed
     * exactly when the watchdog existed to recover from a wedged scanner. (Where
     * a handler is installed the process survives, but the reader stays blocked
     * in readLine() and the UI stays on "正在检测……" with both buttons disabled.)
     * Plain destroy() - SIGTERM, what the normal path already uses - is the
     * fallback on those two releases, and catch (Throwable) keeps any future
     * Error from disarming the one thread that can unblock the reader.
     */
    private static void killProcess(Process proc) {
        try {
            if (Build.VERSION.SDK_INT >= 26) {
                proc.destroyForcibly();
            } else {
                proc.destroy();
            }
        } catch (Throwable ignored) {
            /* Never let this throw: the watchdog is the only thing that can
             * unblock the reader. */
        }
    }

    /**
     * Run one command with stderr folded into stdout, appending everything to
     * `out`. Returns true when the process started and exited before the
     * timeout; the exit code (and its verdict) is appended in that case.
     */
    private boolean runProcess(List<String> cmd, StringBuilder out) {
        Process p = null;
        final AtomicBoolean finished = new AtomicBoolean(false);
        final AtomicBoolean timedOut = new AtomicBoolean(false);
        try {
            ProcessBuilder pb = new ProcessBuilder(cmd);
            pb.redirectErrorStream(true);
            p = pb.start();
            /* The scanner reads no input; closing stdin keeps a scanner that
             * probes stdin from waiting on a pipe that never closes. */
            try {
                p.getOutputStream().close();
            } catch (Exception ignored) {
            }

            /* readLine() blocks until the process closes stdout, so waitFor()
             * never gets to enforce a timeout: without a watchdog a wedged
             * scanner would hang the scan thread forever with the buttons
             * disabled. The watchdog kills it, which closes the pipe and
             * unblocks the reader below. */
            final Process proc = p;
            Thread watchdog = new Thread(new Runnable() {
                @Override
                public void run() {
                    try {
                        Thread.sleep(SCAN_TIMEOUT_MS);
                    } catch (InterruptedException e) {
                        return;   // the scan finished in time; expected
                    } catch (Throwable t) {
                        /* Anything else (an Error) must not stop the watchdog:
                         * it is the only thing that can unblock the reader. */
                    }
                    if (!finished.get()) {
                        timedOut.set(true);
                        killProcess(proc);
                    }
                }
            });
            watchdog.setDaemon(true);
            watchdog.start();

            BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()));
            try {
                String line;
                while ((line = r.readLine()) != null) {
                    out.append(line).append('\n');
                }
            } finally {
                r.close();
            }
            int rc = p.waitFor();
            finished.set(true);
            watchdog.interrupt();
            if (timedOut.get()) {
                out.append("\n[超时：扫描器超过 ").append(SCAN_TIMEOUT_MS / 1000)
                        .append(" 秒未退出，已强制终止]\n");
            }
            out.append("\n[退出码 ").append(rc).append("] ");
            switch (rc) {
                case 0: out.append("干净"); break;
                case 1: out.append("可疑"); break;
                case 2: out.append("检测到 root"); break;
                case 3: out.append("检测到隐藏"); break;
                default: out.append("扫描器错误"); break;
            }
            out.append('\n');
            return true;
        } catch (Exception e) {
            finished.set(true);
            out.append("无法执行 ").append(cmd.get(0)).append("：").append(e).append('\n');
            return false;
        } finally {
            if (p != null) {
                p.destroy();
            }
        }
    }

    /** One finding parsed out of the scanner's text report. */
    private static final class Finding {
        final String sev;
        final String id;
        final String title;
        final LinkedHashSet<String> where = new LinkedHashSet<String>();

        Finding(String sev, String id, String title) {
            this.sev = sev;
            this.id = id;
            this.title = title;
        }

        int rank() {
            if ("CRITICAL".equals(sev)) return 4;
            if ("HIGH".equals(sev)) return 3;
            if ("MEDIUM".equals(sev)) return 2;
            if ("LOW".equals(sev)) return 1;
            return 0;
        }
    }

    /** Extract severity / id / title and the concrete locations behind each finding. */
    private static List<Finding> parseFindings(String report) {
        List<Finding> out = new ArrayList<Finding>();
        Finding cur = null;
        for (String line : report.split("\n", -1)) {
            Matcher m = FINDING.matcher(line);
            if (m.matches()) {
                cur = new Finding(m.group(1), m.group(2), m.group(3));
                out.add(cur);
                continue;
            }
            // Indented continuation line: detail or evidence of the current finding.
            if (cur != null && line.startsWith("           ")) {
                String body = line.substring(11);
                if (body.startsWith("| ")) body = body.substring(2);
                Matcher pm = PATH.matcher(body);
                while (pm.find()) {
                    cur.where.add(pm.group(1));
                }
            }
        }
        return out;
    }

    private static String verdictOf(String report) {
        for (String line : report.split("\n", -1)) {
            if (line.startsWith("verdict:")) {
                return line.substring("verdict:".length()).trim();
            }
        }
        return "SCAN_ERROR";
    }

    /** Chinese display name for the engine's verdict codes. */
    private static String verdictName(String v) {
        if ("CLEAN".equals(v)) return "干净";
        if ("SUSPICIOUS".equals(v)) return "可疑";
        if ("ROOT_DETECTED".equals(v)) return "检测到 root";
        if ("HIDING_DETECTED".equals(v)) return "检测到隐藏";
        return "扫描出错";
    }

    /** The banner text: verdict + root/hiding booleans + where the problems are. */
    private static String buildSummary(String verdict, List<Finding> findings) {
        if ("SCAN_ERROR".equals(verdict)) {
            /* No "verdict:" line: the scanner could not be staged or it refused
             * to run. That is not a clean device, so the clean banner must not
             * be printed - on a security tool it is the worst possible false
             * negative. */
            return "结论        ：扫描出错\n"
                    + "是否 root   ：未知\n"
                    + "是否存在隐藏：未知\n"
                    + "扫描器没有给出结论（无法部署或执行）。\n"
                    + "请查看下方日志以及手动运行说明。\n";
        }
        boolean rooted = "ROOT_DETECTED".equals(verdict) || "HIDING_DETECTED".equals(verdict);
        boolean hiding = "HIDING_DETECTED".equals(verdict);
        String rootText = rooted ? "是" : ("SUSPICIOUS".equals(verdict) ? "可能" : "否");

        StringBuilder sb = new StringBuilder();
        sb.append("结论        ：").append(verdictName(verdict)).append('\n');
        sb.append("是否 root   ：").append(rootText).append('\n');
        sb.append("是否存在隐藏：").append(hiding ? "是" : "否").append('\n');
        sb.append("问题位置：\n");

        int shown = 0;
        for (Finding f : findings) {
            if (f.rank() < 2) continue; // MEDIUM and above are "problems"
            shown++;
            sb.append("  [").append(f.sev).append("] ").append(f.id);
            if (!f.where.isEmpty()) {
                sb.append("  ->  ");
                int i = 0;
                for (String p : f.where) {
                    if (i == 4) { sb.append(", ..."); break; }
                    if (i > 0) sb.append(", ");
                    sb.append(p);
                    i++;
                }
            }
            sb.append('\n');
        }
        if (shown == 0) {
            sb.append("  （没有 MEDIUM 及以上的问题，这台设备看起来是干净的）\n");
        }
        return sb.toString();
    }

    private static int colorFor(String verdict) {
        if ("HIDING_DETECTED".equals(verdict)) return 0xFFB71C1C;  // red 900
        if ("ROOT_DETECTED".equals(verdict)) return 0xFFD84315;    // deep orange 800
        if ("SUSPICIOUS".equals(verdict)) return 0xFFEF6C00;       // orange 800
        if ("CLEAN".equals(verdict)) return 0xFF2E7D32;            // green 800
        return 0xFF455A64;                                         // blue grey 700
    }

    /** Save the last report to a file, then open the system share sheet. */
    private void exportLog() {
        if (lastLog == null || lastLog.isEmpty()) {
            Toast.makeText(this, "请先运行一次检测", Toast.LENGTH_SHORT).show();
            return;
        }
        /* Writing the report must not run on the UI thread: it blocked the main
         * thread (and could ANR on a slow /sdcard). */
        final String text = lastLog;
        exportButton.setEnabled(false);
        new Thread(new Runnable() {
            @Override
            public void run() {
                File written = null;
                Throwable error = null;
                try {
                    written = writeLog(text);
                } catch (Throwable e) {
                    /* Throwable, not Exception: an Error here (OOM while
                     * serialising a big report, ...) also has to re-enable the
                     * button, otherwise the export button stays greyed out for
                     * the rest of the Activity's life. */
                    error = e;
                }
                final File file = written;
                final Throwable err = error;
                runOnUiThread(new Runnable() {
                    @Override
                    public void run() {
                        if (isFinishing() || isDestroyed()) {
                            return;
                        }
                        exportButton.setEnabled(true);
                        if (err != null) {
                            Toast.makeText(MainActivity.this, "无法保存日志：" + err,
                                    Toast.LENGTH_LONG).show();
                            return;
                        }
                        Toast.makeText(MainActivity.this, "日志已保存：" + file.getAbsolutePath(),
                                Toast.LENGTH_LONG).show();
                        share(text + "\n\n[已保存到设备：" + file.getAbsolutePath() + "]\n");
                    }
                });
            }
        }).start();
    }

    /**
     * Write the log into the app's external files directory when available
     * (readable by a file manager at
     * /sdcard/Android/data/com.rootdetect.app/files/, no permission needed),
     * otherwise into the app's private files directory.
     */
    private File writeLog(String text) throws Exception {
        /* Milliseconds plus a uniquifier: with second resolution two exports in
         * the same second silently overwrote each other. */
        String ts = new SimpleDateFormat("yyyyMMdd-HHmmss-SSS", Locale.US).format(new Date());
        File dir = getExternalFilesDir(null);
        if (dir == null) dir = getFilesDir();
        if (dir != null && !dir.exists()) dir.mkdirs();
        File file = new File(dir, "bunanana-report-" + ts + ".txt");
        for (int i = 2; i < 100 && file.exists(); i++) {
            file = new File(dir, "bunanana-report-" + ts + "-" + i + ".txt");
        }
        Writer w = new OutputStreamWriter(new FileOutputStream(file), "UTF-8");
        try {
            w.write(text);
        } finally {
            w.close();
        }
        return file;
    }

    private void share(String text) {
        Intent send = new Intent(Intent.ACTION_SEND);
        send.setType("text/plain");
        send.putExtra(Intent.EXTRA_SUBJECT, "bunanana 检测报告");
        send.putExtra(Intent.EXTRA_TEXT, text);
        try {
            startActivity(Intent.createChooser(send, "导出日志"));
        } catch (Exception e) {
            Toast.makeText(this, "没有可分享日志的应用：" + e, Toast.LENGTH_LONG).show();
        }
    }

    private String fallbackInstructions() {
        return "\n这个版本无法在应用内运行内置扫描器。同一个二进制也可以作为\n"
                + "命令行工具单独使用：\n\n"
                + "  adb push out/rootdetect-arm64 /data/local/rx\n"
                + "  adb shell chmod 700 /data/local/rx\n"
                + "  adb shell /data/local/rx -v        # shell 视角\n"
                + "  adb root && adb shell /data/local/rx -v   # 深度内核视角\n"
                + "\n（用 /data/local 而不是 /data/local/tmp：后者对 `shell` 用户\n"
                + "可写，root 身份运行的二进制可能在 push 与 exec 之间被替换。）\n";
    }
}
