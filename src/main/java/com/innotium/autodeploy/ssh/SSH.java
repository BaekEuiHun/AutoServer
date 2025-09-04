package com.innotium.autodeploy.ssh;

import com.jcraft.jsch.ChannelExec;
import com.jcraft.jsch.ChannelSftp;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.Session;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

public class SSH {
    public static Session open(String host, int port, String user, String password) throws Exception {
        JSch jsch = new JSch();
        Session s = jsch.getSession(user, host, port);
        s.setConfig("StrictHostKeyChecking", "no");
        if (password != null && !password.isBlank()) s.setPassword(password);
        s.connect(10000);
        return s;
    }

    /** bash -lc 로 실행 (사용자 권한) */
    public static Result exec(Session s, String cmd) throws Exception {
        return doExec(s, "bash -lc \"" + cmd.replace("\"","\\\"") + "\"");
    }

    /** sudo 필요 명령 실행. 먼저 -n(비번 없이) 시도 → 실패 시 -S 로 비번 전달 */
    public static Result execRoot(Session s, String cmd, String password) throws Exception {
        // 1) sudo -n (NOPASSWD)
        Result r = doExec(s, "sudo -n bash -lc \"" + cmd.replace("\"","\\\"") + "\"");
        if (r.code == 0) return r;

        // 2) sudo -S (password 필요)
        if (password == null || password.isBlank()) return r; // 비번 없으면 여기서 실패 반환
        String wrapped = "echo " + shellEscape(password) + " | sudo -S bash -lc \"" + cmd.replace("\"","\\\"") + "\"";
        return doExec(s, wrapped);
    }

    private static String shellEscape(String s){
        // 간단 escape
        return "'" + s.replace("'", "'\"'\"'") + "'";
    }

    private static Result doExec(Session s, String realCmd) throws Exception {
        ChannelExec ch = (ChannelExec) s.openChannel("exec");
        ch.setCommand(realCmd);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        ch.setOutputStream(out);
        ch.setErrStream(err);
        ch.connect();
        while (!ch.isClosed()) Thread.sleep(30);
        int code = ch.getExitStatus();
        ch.disconnect();
        String stdout = out.toString(StandardCharsets.UTF_8);
        String stderr = err.toString(StandardCharsets.UTF_8);
        return new Result(code, stdout, stderr, realCmd);
    }

    /** SFTP 업로드 */
    public static void upload(Session s, String localPath, String remotePath) throws Exception {
        ChannelSftp ch = (ChannelSftp) s.openChannel("sftp");
        ch.connect();
        try { ch.put(localPath, remotePath); }
        finally { ch.disconnect(); }
    }

    public record Result(int code, String out, String err, String cmd) {}
}
