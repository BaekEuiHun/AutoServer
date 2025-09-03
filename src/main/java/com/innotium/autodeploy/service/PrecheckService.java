package com.innotium.autodeploy.service;


import com.jcraft.jsch.ChannelExec;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.JSchException;
import com.jcraft.jsch.Session;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.Properties;

@Service
public class PrecheckService {
    // ping 체크 (ICMP 차단 환경에선 false일 수 있음)
    public boolean ping(String ip, int timeoutMs) {
        try {
            return InetAddress.getByName(ip).isReachable(timeoutMs);
        } catch (IOException e) {
            return false;
        }
    }

    // TCP 포트 체크 (22 기본)
    public boolean tcp(String ip, int port, int timeoutMs) {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(ip, port), timeoutMs);
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    // OS 판별 (SSH: /etc/os-release 읽기)
    public String detectOs(String host, int port, String user, String password) {
        Session session = null;
        ChannelExec ch = null;
        try {
            JSch jsch = new JSch();
            session = jsch.getSession(user, host, port);
            session.setPassword(password);

            Properties config = new Properties();
            config.put("StrictHostKeyChecking", "no");
            session.setConfig(config);
            session.connect(3000);

            ch = (ChannelExec) session.openChannel("exec");
            ch.setCommand("cat /etc/os-release");
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            ByteArrayOutputStream err = new ByteArrayOutputStream();
            ch.setOutputStream(out);
            ch.setErrStream(err);
            ch.connect();

            // 간단 대기 루프 (타임아웃 3초)
            long t0 = System.currentTimeMillis();
            while (!ch.isClosed() && System.currentTimeMillis() - t0 < 3000) {
                Thread.sleep(100);
            }

            String result = out.toString("UTF-8").toLowerCase();
            if (result.contains("ubuntu")) return "ubuntu";
            if (result.contains("rocky")) return "rocky";
            return "unknown";

        } catch (JSchException | InterruptedException | IOException e) {
            return "unknown";
        } finally {
            if (ch != null && ch.isConnected()) ch.disconnect();
            if (session != null && session.isConnected()) session.disconnect();
        }
    }
}
