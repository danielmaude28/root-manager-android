package id.daniel.rootmanager;

import android.app.Activity;
import android.os.Bundle;
import android.graphics.Typeface;
import android.graphics.Color;
import android.view.View;
import android.widget.*;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import java.io.*;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.concurrent.*;

public class MainActivity extends Activity {
    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private TextView rootStatus, deviceInfo, securityInfo, logView;
    private String latestReport = "Belum ada pemeriksaan.";
    private final int bg = Color.rgb(20, 27, 22);
    private final int panel = Color.rgb(48, 57, 49);
    private final int fg = Color.rgb(238, 242, 236);
    private final int muted = Color.rgb(190, 201, 190);
    private final int green = Color.rgb(133, 207, 153);

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        getWindow().setStatusBarColor(bg);
        getWindow().setNavigationBarColor(bg);
        LinearLayout page = new LinearLayout(this);
        page.setOrientation(LinearLayout.VERTICAL);
        page.setPadding(dp(20), dp(24), dp(20), dp(18));
        page.setBackgroundColor(bg);

        TextView title = text("Root Manager", 30, true, fg);
        page.addView(title);
        page.addView(text("Pemantau temporary root · versi 0.1.0", 14, false, muted));
        page.addView(space(20));

        ScrollView scroll = new ScrollView(this);
        LinearLayout content = new LinearLayout(this);
        content.setOrientation(LinearLayout.VERTICAL);

        rootStatus = text("Status root: belum diperiksa", 19, true, fg);
        card(content, rootStatus);
        deviceInfo = text("Informasi perangkat akan tampil setelah pemeriksaan.", 14, false, fg);
        card(content, deviceInfo);
        securityInfo = text("Status keamanan belum diperiksa.", 14, false, fg);
        card(content, securityInfo);

        Button refresh = button("Periksa sekarang");
        refresh.setOnClickListener(v -> refresh());
        content.addView(refresh, matchWrap());

        Button save = button("Simpan laporan");
        save.setOnClickListener(v -> saveReport());
        content.addView(save, matchWrap());

        Button copy = button("Salin laporan");
        copy.setOnClickListener(v -> {
            ClipboardManager cm = (ClipboardManager)getSystemService(Context.CLIPBOARD_SERVICE);
            cm.setPrimaryClip(ClipData.newPlainText("Root Manager report", latestReport));
            Toast.makeText(this, "Laporan disalin", Toast.LENGTH_SHORT).show();
        });
        content.addView(copy, matchWrap());

        logView = text("Log:\nAplikasi siap. Tekan Periksa sekarang.", 13, false, muted);
        card(content, logView);
        scroll.addView(content);
        page.addView(scroll, new LinearLayout.LayoutParams(-1, 0, 1));
        setContentView(page);
        refresh();
    }

    private void refresh() {
        rootStatus.setText("Status root: sedang diperiksa…");
        executor.execute(() -> {
            Cmd id = run("su -c id", 7000);
            Cmd getenforce = run("getenforce", 3000);
            String fingerprint = prop("ro.build.fingerprint");
            String model = prop("ro.product.model");
            String android = prop("ro.build.version.release") + " (SDK " + prop("ro.build.version.sdk") + ")";
            String kernel = run("uname -r", 3000).output;
            String abi = prop("ro.product.cpu.abi");
            String kmi = detectKmi(kernel);
            boolean root = id.output.contains("uid=0(") || id.output.matches("(?s).*\\buid=0\\b.*");
            String state = id.ok && root ? "AKTIF" : (id.ok ? "TIDAK AKTIF" : "TIDAK DIKETAHUI");
            String stamp = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(new Date());
            String report = "ROOT MANAGER REPORT\nWaktu: " + stamp +
                "\nStatus root: " + state +
                "\nPerintah su: " + id.output.trim() +
                "\nModel: " + model + "\nAndroid: " + android +
                "\nKernel: " + kernel + "\nKMI (perkiraan): " + kmi +
                "\nABI: " + abi + "\nSELinux: " + getenforce.output.trim() +
                "\nFingerprint: " + fingerprint +
                "\nCatatan: hasil diagnostik; bukan sertifikasi keamanan perangkat.\n";
            latestReport = report;
            runOnUiThread(() -> {
                rootStatus.setText("Status root: " + state + (root ? "\nUID 0 terkonfirmasi" : ""));
                rootStatus.setTextColor(root ? green : fg);
                deviceInfo.setText("PERANGKAT\nModel: " + model + "\nAndroid: " + android +
                    "\nKernel: " + kernel + "\nKMI (perkiraan): " + kmi + "\nABI: " + abi);
                securityInfo.setText("KEAMANAN\nSELinux: " + getenforce.output.trim() +
                    "\nSu check: " + (id.ok ? "perintah selesai" : "gagal / timeout") +
                    "\nBuild fingerprint: " + fingerprint);
                logView.setText("LOG TERAKHIR\n" + report);
            });
        });
    }

    private String detectKmi(String kernel) {
        if (kernel == null) return "tidak diketahui";
        if (kernel.contains("5.10")) return "android12-5.10 (indikasi dari kernel)";
        if (kernel.contains("5.15")) return "android13-5.15 (indikasi dari kernel)";
        if (kernel.contains("6.1")) return "android14-6.1 (indikasi dari kernel)";
        return "tidak dapat disimpulkan otomatis";
    }

    private static class Cmd { String output; boolean ok; Cmd(String o, boolean b){output=o;ok=b;} }
    private Cmd run(String command, int timeoutMs) {
        Process p = null;
        try {
            p = new ProcessBuilder("sh", "-c", command).redirectErrorStream(true).start();
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            InputStream in = p.getInputStream();
            long end = System.currentTimeMillis() + timeoutMs;
            while (System.currentTimeMillis() < end && p.isAlive()) {
                while (in.available() > 0) out.write(in.read());
                Thread.sleep(40);
            }
            while (in.available() > 0) out.write(in.read());
            if (p.isAlive()) { p.destroyForcibly(); return new Cmd(out.toString("UTF-8") + "\nTIMEOUT", false); }
            return new Cmd(out.toString("UTF-8"), p.exitValue() == 0);
        } catch (Exception e) { return new Cmd("ERROR: " + e.getClass().getSimpleName(), false); }
        finally { if (p != null) p.destroy(); }
    }

    private String prop(String key) {
        Cmd c = run("getprop " + key, 2000);
        return c.output.trim().isEmpty() ? "tidak tersedia" : c.output.trim();
    }

    private void saveReport() {
        try {
            File dir = new File(getExternalFilesDir(null), "reports");
            if (!dir.exists() && !dir.mkdirs()) throw new IOException("Tidak bisa membuat folder laporan");
            String name = "root-report-" + new SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US).format(new Date()) + ".txt";
            File f = new File(dir, name);
            try (FileOutputStream fos = new FileOutputStream(f)) {
                fos.write(latestReport.getBytes("UTF-8"));
            }
            Toast.makeText(this, "Tersimpan: " + f.getAbsolutePath(), Toast.LENGTH_LONG).show();
        } catch (Exception e) {
            Toast.makeText(this, "Gagal menyimpan: " + e.getMessage(), Toast.LENGTH_LONG).show();
        }
    }

    private void card(LinearLayout parent, View child) {
        LinearLayout box = new LinearLayout(this);
        box.setPadding(dp(16), dp(15), dp(16), dp(15));
        box.setBackgroundColor(panel);
        box.addView(child);
        LinearLayout.LayoutParams lp = matchWrap();
        lp.bottomMargin = dp(10);
        parent.addView(box, lp);
    }
    private TextView text(String s, int size, boolean bold, int color) {
        TextView t = new TextView(this); t.setText(s); t.setTextSize(size); t.setTextColor(color);
        t.setTypeface(Typeface.DEFAULT, bold ? Typeface.BOLD : Typeface.NORMAL);
        return t;
    }
    private Button button(String s) {
        Button b = new Button(this); b.setText(s); b.setAllCaps(false);
        b.setTextColor(Color.BLACK); b.setBackgroundTintList(android.content.res.ColorStateList.valueOf(green));
        return b;
    }
    private View space(int h) { View v = new View(this); v.setLayoutParams(new LinearLayout.LayoutParams(1, dp(h))); return v; }
    private LinearLayout.LayoutParams matchWrap() { return new LinearLayout.LayoutParams(-1, -2); }
    private int dp(int n) { return (int)(n * getResources().getDisplayMetrics().density + 0.5f); }
    @Override protected void onDestroy() { super.onDestroy(); executor.shutdownNow(); }
}
