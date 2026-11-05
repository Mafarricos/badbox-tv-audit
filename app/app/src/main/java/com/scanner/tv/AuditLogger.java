package com.scanner.tv;

import android.content.Context;
import android.os.Handler;
import android.os.Looper;

import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

public class AuditLogger {

    private static File sLogFile;
    private static File sExtLogFile;
    private static final SimpleDateFormat SDF = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS", Locale.US);
    private static final Handler sHandler = new Handler(Looper.getMainLooper());

    public static void init(Context context) {
        File dir = context.getFilesDir();
        sLogFile = new File(dir, "audit_events.log");
        File extDir = context.getExternalFilesDir(null);
        if (extDir != null) {
            sExtLogFile = new File(extDir, "audit_events.log");
        }
    }

    public static synchronized void log(String level, String tag, String message) {
        String timestamp = SDF.format(new Date());
        String logLine = String.format("[%s] [%s] [%s] %s\n", timestamp, level, tag, message);

        if (sLogFile != null) {
            try (FileWriter fw = new FileWriter(sLogFile, true);
                 PrintWriter pw = new PrintWriter(fw)) {
                pw.print(logLine);
            } catch (Exception ignored) {}
        }
        if (sExtLogFile != null) {
            try (FileWriter fw = new FileWriter(sExtLogFile, true);
                 PrintWriter pw = new PrintWriter(fw)) {
                pw.print(logLine);
            } catch (Exception ignored) {}
        }
    }

    public static void clear() {
        if (sLogFile != null && sLogFile.exists()) {
            sLogFile.delete();
        }
        if (sExtLogFile != null && sExtLogFile.exists()) {
            sExtLogFile.delete();
        }
    }
}
