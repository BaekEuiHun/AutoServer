package com.innotium.autodeploy.service;

import com.innotium.autodeploy.dto.DeployRequest;
import com.innotium.autodeploy.dto.DeployResponse;
import com.innotium.autodeploy.ssh.SSH;
import com.jcraft.jsch.Session;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.function.Consumer;

@Service
public class DeployService {

    /**
     * 기존 REST 방식: 끝나고 한 번에 결과 반환
     */
    public DeployResponse runAll(DeployRequest req) {
        var res = new DeployResponse();
        runInternal(req, res::log);
        res.ok = true;
        res.message = "배포 완료";
        return res;
    }

    /**
     * 실시간 스트리밍 방식: 한 줄씩 logger로 전달
     */
    public void runAllStreaming(DeployRequest req, Consumer<String> logger) {
        runInternal(req, logger);
    }

    // ───────────────────────────────────────────────────────────────
    // 실제 배포 로직 (logger 로 모든 로그를 push)
    // ───────────────────────────────────────────────────────────────
    private void runInternal(DeployRequest req, Consumer<String> logger) {
        Session s = null;
        try {
            s = SSH.open(req.ip(), req.port() == null ? 22 : req.port(), req.user(), req.password());

            String remoteDir = (req.remoteWorkDir() == null || req.remoteWorkDir().isBlank())
                    ? "/opt/app" : req.remoteWorkDir();

            // [1] OS 판별
            logger.accept("===== [1] OS 판별 시작 =====");
            var osr = SSH.exec(s, "awk -F= '/^ID=/{gsub(/\"/,\"\",$2); print $2}' /etc/os-release || echo unknown");
            String os = osr.out().trim().toLowerCase();
            logger.accept("    OS: " + (os.isBlank() ? "unknown" : os));
            logger.accept("✅  [1] OS 판별 완료");
            logger.accept("➡️   [2] WAS 패키지 단계를 시작합니다...");

            // [2] WAS 패키지
            logger.accept("===== [2] WAS 패키지 시작 =====");
            step02_was(logger, s, req.wasTarPath(), remoteDir, os, req.password());
            logger.accept("✅  [2] WAS 패키지 완료");
            logger.accept("➡️   [3] JDK8/Tomcat 단계를 시작합니다...");

            // [3] JDK8 + Tomcat
            logger.accept("===== [3] JDK8/Tomcat 시작 =====");
            step03_jdk8_tomcat(logger, s, os, req.password());
            logger.accept("✅  [3] JDK8/Tomcat 완료");
            logger.accept("🎉 전체 배포 완료 ✅");

        } catch (Exception e) {
            logger.accept("배포 실패 ❌: " + e.getMessage());
        } finally {
            if (s != null && s.isConnected()) s.disconnect();
        }
    }

    /**
     * 2단계: WAS 패키지 업로드 + 필수 패키지 설치 + 압축해제
     */
    private void step02_was(Consumer<String> log, Session s, String wasTarPath,
                            String remoteDir, String osIgnored, String sudoPw) throws Exception {
        log.accept("[2] WAS 패키지 단계 시작");

        var osr = SSH.exec(s, "awk -F= '/^ID=/{gsub(/\"/,\"\",$2); print $2}' /etc/os-release || echo unknown");
        String os = osr.out().trim().toLowerCase();
        log.accept("  - 감지된 OS: " + (os.isBlank() ? "unknown" : os));

        log.accept("  - 작업 디렉토리 준비: " + remoteDir);
        var r1 = SSH.execRoot(s,
                "mkdir -p " + remoteDir + " && chown " + s.getUserName() + ":" + s.getUserName() + " " + remoteDir,
                sudoPw);
        if (r1.code() != 0) throw new RuntimeException("작업 디렉토리 준비 실패: " + pickMsg(r1));

        String remoteTar = remoteDir + "/WAS.tar";
        log.accept("  - 파일 업로드: " + wasTarPath + " → " + remoteTar);
        SSH.upload(s, wasTarPath, remoteTar);

        String pkgApt = "apt-get update -y && DEBIAN_FRONTEND=noninteractive apt-get install -y "
                + "tar unzip vim net-tools curl wget nginx ufw";
        String pkgDnf = "dnf -y install tar unzip vim net-tools curl wget nginx firewalld";
        String pkgYum = "yum -y install tar unzip vim net-tools curl wget nginx firewalld";

        String detectAndInstall =
                "if command -v apt-get >/dev/null 2>&1; then echo '[install] use apt-get'; " + pkgApt + "; " +
                        "elif command -v dnf >/dev/null 2>&1; then echo '[install] use dnf'; " + pkgDnf + "; " +
                        "elif command -v yum >/dev/null 2>&1; then echo '[install] use yum'; " + pkgYum + "; " +
                        "else echo '[install] no pkg manager found' >&2; exit 1; fi";

        log.accept("  - 필수 패키지 설치 중...(패키지 매니저 자동 감지)");
        var r2 = SSH.execRoot(s, detectAndInstall, sudoPw);
        if (r2.code() != 0) throw new RuntimeException("필수 패키지 설치 실패: " + pickMsg(r2));
        log.accept("  - 패키지 설치 로그:\n" + pickMsg(r2));

        log.accept("  - 압축 해제: tar -xf WAS.tar");
        var r3 = SSH.execRoot(s, "tar -xf " + remoteTar + " -C " + remoteDir, sudoPw);
        if (r3.code() != 0) throw new RuntimeException("압축 해제 실패: " + pickMsg(r3));

        var r4 = SSH.exec(s, "ls -lah " + remoteDir);
        log.accept("  - 파일 목록:\n" + pickMsg(r4));

        log.accept("[2] WAS 패키지 단계 완료 ✅");
    }
    private void step03_jdk8_tomcat(java.util.function.Consumer<String> log,
                                    com.jcraft.jsch.Session s,
                                    String os, String sudoPw) throws Exception {
        log.accept("[3] JDK 8 + Tomcat 9.0.80 설치/기동 시작. 진행중입니다... ▶");

        String script = """
#!/usr/bin/env sh
set -eu

echo "[3] start"
TVER=9.0.80

# 1) 패키지 매니저 감지 + 기본 도구
PM=""
if command -v apt-get >/dev/null 2>&1; then
  PM=apt
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y || true
  apt-get install -y curl wget tar ca-certificates file || true
elif command -v dnf >/dev/null 2>&1; then
  PM=dnf
  dnf -y install curl wget tar ca-certificates file || true
elif command -v yum >/dev/null 2>&1; then
  PM=yum
  yum -y install curl wget tar ca-certificates file || true
else
  echo "[3] no package manager"; exit 1
fi

# 2) JDK8 설치 (패키지 → 실패 시 tarball)
JAVA_OK=0
if command -v javac >/dev/null 2>&1 && javac -version 2>&1 | grep -q "1\\.8\\."; then
  JAVA_OK=1
else
  if [ "$PM" = "apt" ]; then
    apt-get install -y openjdk-8-jdk || true
  else
    $PM -y install java-1.8.0-openjdk-devel || true
  fi
  if command -v javac >/dev/null 2>&1 && javac -version 2>&1 | grep -q "1\\.8\\."; then
    JAVA_OK=1
  fi
fi

# --- tarball 대체: 단순 다중 소스 + 검증 후에만 tar ---
if [ "$JAVA_OK" -ne 1 ]; then
  mkdir -p /opt/java
  rm -f /tmp/jdk8.tar.gz

  for URL in \
    "https://corretto.aws/downloads/latest/amazon-corretto-8-x64-linux-jdk.tar.gz" \
    "https://github.com/adoptium/temurin8-binaries/releases/latest/download/OpenJDK8U-jdk_x64_linux_hotspot.tar.gz" \
    "https://cdn.azul.com/zulu/bin/zulu8-latest-linux_x64.tar.gz"
  do
    echo "[3] try JDK8 from: $URL"
    if command -v curl >/dev/null 2>&1; then
      curl -fL --retry 5 --retry-delay 2 --retry-all-errors -o /tmp/jdk8.tar.gz "$URL" || true
    else
      wget -O /tmp/jdk8.tar.gz --tries=5 --waitretry=2 "$URL" || true
    fi
    if [ -s /tmp/jdk8.tar.gz ]; then
      MT=$(file -b --mime-type /tmp/jdk8.tar.gz || true)
      if [ "$MT" = "application/gzip" ] || [ "$MT" = "application/x-gzip" ]; then
        if tar -tzf /tmp/jdk8.tar.gz >/dev/null 2>&1; then
          break
        fi
      fi
      rm -f /tmp/jdk8.tar.gz
    fi
    sleep 2
  done

  if [ ! -s /tmp/jdk8.tar.gz ]; then
    echo "[3] JDK8 tarball download failed (all sources)"; exit 1
  fi

  tar -xf /tmp/jdk8.tar.gz -C /opt/java
  JDIR=$(tar -tf /tmp/jdk8.tar.gz | head -1 | cut -d/ -f1)
  [ -d "/opt/java/$JDIR" ] || { echo "[3] Unexpected JDK tar structure"; exit 1; }
  ln -sfn "/opt/java/$JDIR" /opt/java/jdk8
  ln -sfn /opt/java/jdk8/bin/java /usr/local/bin/java
  ln -sfn /opt/java/jdk8/bin/javac /usr/local/bin/javac
fi

# 최종 JAVA_HOME 계산
if command -v javac >/dev/null 2>&1; then
  JAVA_HOME=$(dirname "$(dirname "$(readlink -f "$(command -v javac)")")")
else
  echo "[3] javac not found"; exit 1
fi
echo "[3] JAVA_HOME=${JAVA_HOME}"
java -version || true

# 3) Tomcat 9.0.80 설치/기동 (간단 재시도)
id tomcat >/dev/null 2>&1 || useradd -r -m -U -d /opt/tomcat -s /bin/false tomcat
mkdir -p /opt/tomcat
cd /tmp

i=0
while [ $i -lt 3 ]; do
  if command -v curl >/dev/null 2>&1; then
    curl -fLO "https://archive.apache.org/dist/tomcat/tomcat-9/v${TVER}/bin/apache-tomcat-${TVER}.tar.gz" || true
  else
    wget -O "apache-tomcat-${TVER}.tar.gz" "https://archive.apache.org/dist/tomcat/tomcat-9/v${TVER}/bin/apache-tomcat-${TVER}.tar.gz" || true
  fi
  if [ -s "apache-tomcat-${TVER}.tar.gz" ]; then
    break
  fi
  i=`expr $i + 1`
  sleep 2
done
[ -s "apache-tomcat-${TVER}.tar.gz" ] || { echo "[3] Tomcat tarball download failed"; exit 1; }

rm -rf /opt/tomcat/latest
tar -xf "apache-tomcat-${TVER}.tar.gz"
mv "apache-tomcat-${TVER}" /opt/tomcat/latest
chown -R tomcat:tomcat /opt/tomcat
chmod +x /opt/tomcat/latest/bin/*.sh

cat >/etc/systemd/system/tomcat.service <<EOT
[Unit]
Description=Apache Tomcat ${TVER}
After=network.target

[Service]
Type=forking
User=tomcat
Group=tomcat
Environment=JAVA_HOME=${JAVA_HOME}
Environment=CATALINA_HOME=/opt/tomcat/latest
Environment=CATALINA_BASE=/opt/tomcat/latest
ExecStart=/opt/tomcat/latest/bin/startup.sh
ExecStop=/opt/tomcat/latest/bin/shutdown.sh
SuccessExitStatus=143
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOT

if command -v ufw >/dev/null 2>&1; then ufw allow 8080/tcp || true; fi
if command -v firewall-cmd >/dev/null 2>&1; then firewall-cmd --add-port=8080/tcp --permanent || true; firewall-cmd --reload || true; fi

systemctl daemon-reload
systemctl enable tomcat
systemctl restart tomcat || { journalctl -u tomcat --no-pager | tail -100; exit 1; }
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8080/ || true
echo "[3] STEP3 DONE OK"
""";

        // ★ heredoc 꼭 개행으로 닫기!
        // 1) 스크립트를 Base64로 안전하게 인코딩
        String b64 = Base64.getEncoder().encodeToString(script.getBytes(StandardCharsets.UTF_8));

// 2) 원격에서 디코딩→저장→실행 (heredoc 사용 안 함)
        String cmd =
                "base64 -d >/tmp/step3.sh <<'B64'\n" + b64 + "\nB64\n" +
                        "sed -i 's/\\r$//' /tmp/step3.sh\n" +
                        "chmod +x /tmp/step3.sh\n" +
                        "/bin/sh -x /tmp/step3.sh\n";

// 3) 루트로 실행
        var r = SSH.execRoot(s, "bash -lc \"" + cmd.replace("\"","\\\"") + "\"", sudoPw);

        String out = r.out() == null ? "" : r.out().trim();
        String err = r.err() == null ? "" : r.err().trim();
        String msg = (!out.isBlank() && !err.isBlank()) ? out + "\\n" + err : (!out.isBlank() ? out : err);

        if (r.code() != 0) throw new RuntimeException("JDK8/Tomcat 설치 실패: " + msg);
        log.accept("  - 설치/기동 로그:\\n" + msg);
        log.accept("[3] JDK 8 + Tomcat 9.0.80 설치/기동 완료 ✅ (브라우저: http://<서버IP>:8080)");
    }

    private String pickMsg(SSH.Result r) {
        String out = r.out() == null ? "" : r.out().trim();
        String err = r.err() == null ? "" : r.err().trim();
        if (!out.isBlank() && !err.isBlank()) return out + "\n" + err;
        return !out.isBlank() ? out : err;
    }
}