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
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/* NOTE: android.os.Process is *not* imported - it would shadow java.lang.Process
 * and make `Process p = pb.start()` a type error. myUid() is called fully
 * qualified below. */

/**
 * Minimal front end for the native scanner.
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
 *   2. an "Export log" button that writes the whole report to a file and opens
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
        sub.setText("root / root-hiding detector\n"
                + "engine: rootdetect - static native build, no dependencies, no network");
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
        runButton.setText("Run detection");
        runButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                startScan();
            }
        });
        root.addView(runButton);

        exportButton = new Button(this);
        exportButton.setText("Export log");
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
        summary.setText("Result: not scanned yet\nPress \"Run detection\" to check this device.");
        output.setText(header() + "\nPress \"Run detection\" to scan this device.\n\n"
                + "Exit codes: 0 clean | 1 suspicious | 2 root detected | 3 hiding detected\n");

        /* A rotation (or any configuration change) recreates the Activity. Without
         * this the report and the export button were lost and the user had to
         * rescan just to export. */
        if (savedInstanceState != null) {
            String saved = savedInstanceState.getString(STATE_LOG);
            if (saved != null && !saved.isEmpty()) {
                lastLog = saved;
                String verdict = verdictOf(saved);
                summary.setText(buildSummary(verdict, parseFindings(saved)));
                summary.setBackgroundColor(colorFor(verdict));
                output.setText(saved);
                runButton.setText("Run detection again");
                exportButton.setEnabled(true);
            }
        }
    }

    @Override
    protected void onSaveInstanceState(Bundle outState) {
        super.onSaveInstanceState(outState);
        outState.putString(STATE_LOG, lastLog);
    }

    private String header() {
        return "uid " + android.os.Process.myUid() + "  |  " + Build.MANUFACTURER + " " + Build.MODEL
                + "  |  Android " + Build.VERSION.RELEASE + " (API " + Build.VERSION.SDK_INT + ")\n"
                + "primary abi: " + (Build.SUPPORTED_ABIS.length > 0 ? Build.SUPPORTED_ABIS[0] : "?");
    }

    private void startScan() {
        runButton.setEnabled(false);
        exportButton.setEnabled(false);
        summary.setBackgroundColor(0xFF455A64);
        summary.setText("Result: scanning...");
        output.setText("scanning...\n");
        new Thread(new Runnable() {
            @Override
            public void run() {
                final String report = scan();
                runOnUiThread(new Runnable() {
                    @Override
                    public void run() {
                        String verdict = verdictOf(report);
                        List<Finding> findings = parseFindings(report);
                        String banner = buildSummary(verdict, findings);

                        lastLog = header() + "\n\n" + banner + "\n\n"
                                + "----------------------------------------------\n" + report;
                        summary.setText(banner);
                        summary.setBackgroundColor(colorFor(verdict));
                        output.setText(lastLog);

                        runButton.setEnabled(true);
                        runButton.setText("Run detection again");
                        exportButton.setEnabled(true);
                    }
                });
            }
        }).start();
    }

    /** The extracted scanner, or a copy in the app data dir if that fails. */
    private File scannerFile() throws Exception {
        File inLibs = new File(getApplicationInfo().nativeLibraryDir, "librootdetect.so");
        if (inLibs.isFile() && inLibs.canExecute()) {
            return inLibs;
        }
        File local = new File(getFilesDir(), "rx");
        if (!local.isFile() || local.length() != inLibs.length()) {
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
            sb.append("could not stage the scanner: ").append(e).append("\n");
        }
        if (bin == null) {
            return sb.toString() + fallbackInstructions();
        }
        sb.append("scanner: ").append(bin).append('\n');
        sb.append("mode   : verbose (uid ").append(android.os.Process.myUid()).append(")\n");
        sb.append("----------------------------------------------\n");

        List<String> cmd = new ArrayList<String>();
        cmd.add(bin.getAbsolutePath());
        cmd.add("-v");
        Process p = null;
        try {
            ProcessBuilder pb = new ProcessBuilder(cmd);
            pb.redirectErrorStream(true);
            p = pb.start();
            BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()));
            try {
                String line;
                while ((line = r.readLine()) != null) {
                    sb.append(line).append('\n');
                }
            } finally {
                r.close();
            }
            int rc = p.waitFor();
            sb.append("\n[exit code ").append(rc).append("] ");
            switch (rc) {
                case 0: sb.append("CLEAN"); break;
                case 1: sb.append("SUSPICIOUS"); break;
                case 2: sb.append("ROOT DETECTED"); break;
                case 3: sb.append("HIDING DETECTED"); break;
                default: sb.append("scanner error"); break;
            }
            sb.append('\n');
        } catch (Exception e) {
            sb.append("could not execute ").append(bin).append(": ").append(e).append('\n');
            sb.append(fallbackInstructions());
        } finally {
            if (p != null) {
                p.destroy();
            }
        }
        return sb.toString();
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

    /** The banner text: verdict + root/hiding booleans + where the problems are. */
    private static String buildSummary(String verdict, List<Finding> findings) {
        if ("SCAN_ERROR".equals(verdict)) {
            /* No "verdict:" line: the scanner could not be staged or it refused
             * to run. That is not a clean device, so the clean banner must not
             * be printed - on a security tool it is the worst possible false
             * negative. */
            return "Result        : SCAN_ERROR\n"
                    + "Device rooted : unknown\n"
                    + "Root hiding   : unknown\n"
                    + "The scanner produced no verdict (it could not be staged or executed).\n"
                    + "See the log below and the manual instructions.\n";
        }
        boolean rooted = "ROOT_DETECTED".equals(verdict) || "HIDING_DETECTED".equals(verdict);
        boolean hiding = "HIDING_DETECTED".equals(verdict);
        String rootText = rooted ? "YES" : ("SUSPICIOUS".equals(verdict) ? "maybe" : "no");

        StringBuilder sb = new StringBuilder();
        sb.append("Result        : ").append(verdict).append('\n');
        sb.append("Device rooted : ").append(rootText).append('\n');
        sb.append("Root hiding   : ").append(hiding ? "YES" : "no").append('\n');
        sb.append("Where the problems are:\n");

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
            sb.append("  (none above MEDIUM - the device looks clean here)\n");
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
            Toast.makeText(this, "run a detection first", Toast.LENGTH_SHORT).show();
            return;
        }
        File file;
        try {
            file = writeLog(lastLog);
        } catch (Exception e) {
            Toast.makeText(this, "could not save the log: " + e, Toast.LENGTH_LONG).show();
            return;
        }
        Toast.makeText(this, "log saved: " + file.getAbsolutePath(), Toast.LENGTH_LONG).show();
        share(lastLog + "\n\n[saved on device: " + file.getAbsolutePath() + "]\n");
    }

    /**
     * Write the log into the app's external files directory when available
     * (readable by a file manager at
     * /sdcard/Android/data/com.rootdetect.app/files/, no permission needed),
     * otherwise into the app's private files directory.
     */
    private File writeLog(String text) throws Exception {
        String ts = new SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US).format(new Date());
        File dir = getExternalFilesDir(null);
        if (dir == null) dir = getFilesDir();
        if (dir != null && !dir.exists()) dir.mkdirs();
        File file = new File(dir, "bunanana-report-" + ts + ".txt");
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
        send.putExtra(Intent.EXTRA_SUBJECT, "bunanana root detection report");
        send.putExtra(Intent.EXTRA_TEXT, text);
        try {
            startActivity(Intent.createChooser(send, "Export log"));
        } catch (Exception e) {
            Toast.makeText(this, "no app can share the log: " + e, Toast.LENGTH_LONG).show();
        }
    }

    private String fallbackInstructions() {
        return "\nThis build could not run the bundled scanner in-process. The same\n"
                + "binary is also shipped as a plain command line tool:\n\n"
                + "  adb push out/rootdetect-arm64 /data/local/rx\n"
                + "  adb shell chmod 700 /data/local/rx\n"
                + "  adb shell /data/local/rx -v        # shell view\n"
                + "  adb root && adb shell /data/local/rx -v   # deep kernel view\n"
                + "\n(/data/local, not /data/local/tmp: the latter is group- and\n"
                + "other-writable by the `shell` user, so a root-run binary there can be\n"
                + "swapped out between the push and the exec.)\n";
    }
}
