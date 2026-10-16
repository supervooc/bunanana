package com.rootdetect.app;

import android.app.Activity;
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

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;

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
 * There are no resources at all: the UI is built in code, which keeps the APK
 * buildable with nothing but aapt2 + javac + d8.
 */
public class MainActivity extends Activity {

    private TextView output;
    private Button runButton;

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

        runButton = new Button(this);
        runButton.setText("Run detection");
        runButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                startScan();
            }
        });
        root.addView(runButton);

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
        output.setText(header() + "\nPress \"Run detection\" to scan this device.\n\n"
                + "Exit codes: 0 clean | 1 suspicious | 2 root detected | 3 hiding detected\n");
    }

    private String header() {
        return "uid " + android.os.Process.myUid() + "  |  " + Build.MANUFACTURER + " " + Build.MODEL
                + "  |  Android " + Build.VERSION.RELEASE + " (API " + Build.VERSION.SDK_INT + ")\n"
                + "primary abi: " + (Build.SUPPORTED_ABIS.length > 0 ? Build.SUPPORTED_ABIS[0] : "?");
    }

    private void startScan() {
        runButton.setEnabled(false);
        output.setText("scanning...\n");
        new Thread(new Runnable() {
            @Override
            public void run() {
                final String report = scan();
                runOnUiThread(new Runnable() {
                    @Override
                    public void run() {
                        output.setText(report);
                        runButton.setEnabled(true);
                        runButton.setText("Run detection again");
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

    /** Run the scanner and return its report. */
    private String scan() {
        StringBuilder sb = new StringBuilder(header()).append("\n\n");
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
            String line;
            while ((line = r.readLine()) != null) {
                sb.append(line).append('\n');
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

    private String fallbackInstructions() {
        return "\nThis build could not run the bundled scanner in-process. The same\n"
                + "binary is also shipped as a plain command line tool:\n\n"
                + "  adb push out/rootdetect-arm64 /data/local/tmp/rx\n"
                + "  adb shell chmod 755 /data/local/tmp/rx\n"
                + "  adb shell /data/local/tmp/rx -v        # shell view\n"
                + "  adb root && adb shell /data/local/tmp/rx -v   # deep kernel view\n";
    }
}
