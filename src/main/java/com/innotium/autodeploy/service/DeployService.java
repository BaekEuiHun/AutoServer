package com.innotium.autodeploy.service;

import com.innotium.autodeploy.dto.DeployRequest;
import com.innotium.autodeploy.dto.DeployResponse;
import com.innotium.autodeploy.dto.Step6MariadbRequest;
import com.innotium.autodeploy.ssh.SSH;
import com.jcraft.jsch.Session;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.function.Consumer;

@Service
public class DeployService {

    private com.innotium.autodeploy.dto.Step6MariadbRequest toStep6Req(DeployRequest req) {
        var r = new com.innotium.autodeploy.dto.Step6MariadbRequest();
        r.ip = req.ip();
        r.user = req.user();
        r.sudoPw = req.password();         // sudo/ssh 동일 가정

        // 회사 정책 기본값
        r.mariadbMajorMinor = "10.11";
        r.mariadbPort = 43306;
        r.bindLocalOnly = true;

        // 앱 DB 계정 (원하면 여기 값 바꿔도 됨)
        r.appDbName = "innoapp";
        r.appDbUser = "innoapp";
        r.appDbPass = "S3cure!234";

        // (선택) root 비번을 DeployRequest에 넣었다면 세팅 (없으면 null/빈문자 그대로)
        // r.dbRootPassword = req.dbRootPassword();

        return r;
    }
    private com.innotium.autodeploy.dto.Step5RedisRequest toStep5Req(DeployRequest req) {
        var r = new com.innotium.autodeploy.dto.Step5RedisRequest();
        r.ip = req.ip();
        r.user = req.user();
        r.sudoPw = req.password();  // sudo/ssh 동일 가정
        r.redisPort = 46379;
        r.bindLocalOnly = true;     // 내부 전용 권장
        return r;
    }

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
            logger.accept("✅  [3] JDK8/Tomcat 완료");
            logger.accept("➡️   [4] MariaDB 단계를 시작합니다...");

// [6] MariaDB  ★ 추가
            logger.accept("===== [4] MariaDB 시작 =====");
            step06_mariadb(s, toStep6Req(req), line -> logger.accept(line));// ← 아래 보조 메서드 참고
            logger.accept("✅  [4] MariaDB 완료");
            // [5] Redis  ★ 추가
            logger.accept("===== [5] Redis 시작 =====");
            step05_redis(s, toStep5Req(req), line -> logger.accept(line));
            logger.accept("✅  [5] Redis 완료");
            logger.accept("➡️   [6] Nginx 리버스 프록시 단계를 시작합니다...");
            logger.accept("===== [6] Nginx Reverse Proxy 시작 =====");
            step04_nginx(logger, s, os, req.password());
            logger.accept("✅  [6] Nginx Reverse Proxy 완료");
            logger.accept("➡️   [7] Scouter 단계를 시작합니다...");
            logger.accept("===== [7] Scouter 시작 =====");
            step07_scouter(logger, s, os, req.password());
            logger.accept("✅  [7] Scouter 완료");


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
#!/usr/bin/env bash
set -Eeuo pipefail

echo "[3.0] STEP3 START"
TVER=9.0.80
TPORT=8081

# 1) 패키지 매니저 감지
PM=""
if command -v apt-get >/dev/null 2>&1; then
  PM=apt
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y curl wget tar ca-certificates file
elif command -v dnf >/dev/null 2>&1; then
  PM=dnf
  dnf -y install curl wget tar ca-certificates file
elif command -v yum >/dev/null 2>&1; then
  PM=yum
  yum -y install curl wget tar ca-certificates file
else
  echo "[3.1] no package manager"; exit 1
fi

# 2) JDK8 설치
if ! java -version 2>&1 | grep -q "1\\.8\\."; then
  if [ "$PM" = "apt" ]; then
    apt-get install -y openjdk-8-jdk
  else
    $PM -y install java-1.8.0-openjdk-devel
  fi
fi
java -version

# 3) Tomcat 설치
id tomcat >/dev/null 2>&1 || useradd -r -m -U -d /opt/tomcat -s /bin/false tomcat
mkdir -p /opt/tomcat
cd /opt/tomcat

rm -rf apache-tomcat-* latest
curl -fLO "https://archive.apache.org/dist/tomcat/tomcat-9/v${TVER}/bin/apache-tomcat-${TVER}.tar.gz"
tar -xzf "apache-tomcat-${TVER}.tar.gz"
mv "apache-tomcat-${TVER}" latest
chown -R tomcat:tomcat /opt/tomcat
chmod +x /opt/tomcat/latest/bin/*.sh

# 4) 포트 변경 (8080 → 8081)
sed -i 's/Connector port="8080"/Connector port="8081"/' /opt/tomcat/latest/conf/server.xml

# 5) systemd 서비스
cat >/etc/systemd/system/tomcat.service <<EOT
[Unit]
Description=Apache Tomcat ${TVER}
After=network.target

[Service]
Type=forking
User=tomcat
Group=tomcat
Environment=JAVA_HOME=$(dirname $(dirname $(readlink -f $(which javac))))
Environment=CATALINA_HOME=/opt/tomcat/latest
ExecStart=/opt/tomcat/latest/bin/startup.sh
ExecStop=/opt/tomcat/latest/bin/shutdown.sh
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOT

systemctl daemon-reload
systemctl enable tomcat
systemctl restart tomcat

echo "[3.9] Tomcat running on port ${TPORT}"
""";

        // ★ heredoc 꼭 개행으로 닫기!
        // 1) 스크립트를 Base64로 안전하게 인코딩
        String b64 = Base64.getEncoder().encodeToString(script.getBytes(StandardCharsets.UTF_8));

// 2) 원격에서 디코딩→저장→실행 (heredoc 사용 안 함)
        String cmd = String.join("\n",
                "base64 -d >/tmp/step3.sh <<'B64'",
                b64,
                "B64",
                "sed -i 's/\\r$//' /tmp/step3.sh",
                "chmod +x /tmp/step3.sh",
                "/bin/sh -x /tmp/step3.sh"
        );

// 3) 루트로 실행
        var r = SSH.execRoot(s, "bash -lc \"" + cmd.replace("\"","\\\"") + "\"", sudoPw);

        String out = r.out() == null ? "" : r.out().trim();
        String err = r.err() == null ? "" : r.err().trim();
        String msg = (!out.isBlank() && !err.isBlank()) ? out + "\\n" + err : (!out.isBlank() ? out : err);

        if (r.code() != 0) throw new RuntimeException("JDK8/Tomcat 설치 실패: " + msg);
        log.accept("  - 설치/기동 로그:\\n" + msg);
        log.accept("[3] JDK 8 + Tomcat 9.0.80 설치/기동 완료 ✅ (브라우저: http://<서버IP>:8080)");
    }
    private void step04_nginx(Consumer<String> log, Session s, String osIgnored, String sudoPw) throws Exception {
        log.accept("[6] Nginx 설치/설정/기동 시작 ▶");

        // 1) 쉘 스크립트(내부 sudo 금지!)
        String script = """
#!/usr/bin/env bash
set -Eeuo pipefail

echo "[4] STEP4 START"

# 0) 패키지 매니저 감지 + nginx 설치 보장
PM=""
if command -v apt-get >/dev/null 2>&1; then
  PM=apt
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y nginx curl sed
elif command -v dnf >/dev/null 2>&1; then
  PM=dnf
  dnf -y install nginx curl policycoreutils-python-utils sed
elif command -v yum >/dev/null 2>&1; then
  PM=yum
  yum -y install nginx curl policycoreutils-python-utils sed
else
  echo "[4] no package manager"; exit 1
fi

# nginx 바이너리 확인
command -v nginx >/dev/null 2>&1 || { echo "[4] nginx command not found after install"; exit 1; }

# 1) Tomcat 포트 8081 보장
CONF="/opt/tomcat/latest/conf/server.xml"
if [ -f "$CONF" ] && grep -q 'Connector port="8080"' "$CONF"; then
  sed -i 's/Connector port="8080"/Connector port="8081"/' "$CONF"
  systemctl restart tomcat || true
fi

# 2) Nginx 프록시 설정 (40000 → 8081)
mkdir -p /etc/nginx/conf.d
cat >/etc/nginx/conf.d/autodeploy.conf <<'NGX'
server {
    listen 40000 default_server;
    listen [::]:40000 default_server;
    server_name _;

    client_max_body_size 200m;
    proxy_read_timeout 120s;
    proxy_send_timeout 120s;

    location / {
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_pass http://127.0.0.1:8081;
    }
}
NGX

# Ubuntu에서 conf.d 미포함 환경 대비
if ! nginx -T 2>/dev/null | grep -q "/etc/nginx/conf.d/"; then
  mkdir -p /etc/nginx/sites-available /etc/nginx/sites-enabled
  cat >/etc/nginx/sites-available/autodeploy <<'NGX'
server {
    listen 40000 default_server;
    listen [::]:40000 default_server;
    server_name _;
    location / { proxy_pass http://127.0.0.1:8081; }
}
NGX
  ln -sfn /etc/nginx/sites-available/autodeploy /etc/nginx/sites-enabled/autodeploy
fi

# 3) 방화벽/SELinux
command -v ufw >/dev/null 2>&1 && ufw allow 40000/tcp || true
if command -v firewall-cmd >/dev/null 2>&1; then
  firewall-cmd --add-port=40000/tcp --permanent || true
  firewall-cmd --reload || true
fi
if command -v getenforce >/dev/null 2>&1 && [ "$(getenforce || true)" = "Enforcing" ]; then
  semanage port -l | grep -qE '^http_port_t.*\\b40000\\b' || semanage port -a -t http_port_t -p tcp 40000 || true
  setsebool -P httpd_can_network_connect 1 || true
fi

# 4) 로그 디렉터리 보장
mkdir -p /var/log/nginx
chown root:adm /var/log/nginx || true

# 5) Nginx 구문검사/기동
echo "[4] nginx -t"
nginx -t || { echo "[4][DIAG] nginx -T ====="; nginx -T || true; echo "[4] nginx -t failed"; exit 1; }

systemctl enable nginx || true
systemctl restart nginx || {
  echo "[4][DIAG] journalctl -u nginx ====="
  journalctl -u nginx --no-pager -n 200 || true
  echo "[4][DIAG] /var/log/nginx/error.log ====="
  tail -n 200 /var/log/nginx/error.log || true
  echo "[4] nginx restart failed"; exit 1;
}

# 6) 헬스체크
code=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:40000/ || true)
echo "[4] curl 127.0.0.1:40000 => HTTP ${code}"
case "$code" in
  200|302|403|404) echo "[4] STEP4 DONE OK";;
  *) echo "[4] Nginx proxy healthcheck failed (HTTP ${code})"; exit 1;;
esac
""";


        // 1) 스크립트 본문은 그대로 둡니다 (String script = """ ... """;)
        String safeScript = script.replace("sudo ", "");

// 2) Base64 인코딩
        String b64 = Base64.getEncoder()
                .encodeToString(safeScript.getBytes(StandardCharsets.UTF_8));

// 3) 원격에 디코딩하여 저장 → CRLF 제거 → 권한 부여 → 문법검사 → 실행
        String cmd = String.join("\n",
                "base64 -d >/tmp/step4.sh <<'B64'",
                b64,
                "B64",
                "tr -d '\\r' < /tmp/step4.sh > /tmp/.step4.tmp && mv /tmp/.step4.tmp /tmp/step4.sh",
                "chmod +x /tmp/step4.sh",
                "echo '[4] bash -n syntax check:'",
                "if ! bash -n /tmp/step4.sh; then",
                "  echo '[4][DIAG] ===== numbered dump (1..200) ====='; nl -ba /tmp/step4.sh | sed -n '1,200p' ;",
                "  exit 1;",
                "fi",
                "echo '[4] RUN /bin/bash -x /tmp/step4.sh'",
                "/bin/bash -x /tmp/step4.sh",
                "echo '[4] script DONE'"
        );

        var r = SSH.execRoot(s, "bash -lc \"" + cmd.replace("\"","\\\"") + "\"", sudoPw);
        String out = r.out() == null ? "" : r.out().trim();
        String err = r.err() == null ? "" : r.err().trim();
        String msg = (!out.isBlank() && !err.isBlank()) ? out + "\n" + err : (!out.isBlank() ? out : err);
        if (r.code() != 0) throw new RuntimeException("Nginx 설정 실패(code=" + r.code() + "): " + msg);

        log.accept("  - Nginx 설치/설정 로그:\n" + msg);
        log.accept("[6] Nginx 리버스 프록시 설정/기동 완료 ✅ (브라우저: http://<서버IP>:40000)");

    }
    public void step06_mariadb(Session s, Step6MariadbRequest req, java.util.function.Consumer<String> log) {
        log.accept("[4] MariaDB 설치/설정 시작 ▶");

        String ROOTPW = req.dbRootPassword == null ? "" : req.dbRootPassword;
        String APPDB  = req.appDbName == null ? "innoapp" : req.appDbName;
        String APPUSR = req.appDbUser == null ? "innoapp" : req.appDbUser;
        String APPPW  = req.appDbPass == null ? "S3cure!234" : req.appDbPass;
        int PORT      = (req.mariadbPort <= 0 ? 43306 : req.mariadbPort);
        String BIND   = (req.bindLocalOnly ? "127.0.0.1" : "0.0.0.0");

        String script = """
#!/usr/bin/env bash
set -Eeuo pipefail

echo "[6] STEP6 START"

PORT=%PORT%
BIND="%BIND%"
APPDB='%APPDB%'
APPUSR='%APPUSR%'
APPPW='%APPPW%'
ROOTPW='%ROOTPW%'

# 0) 패키지 매니저 감지 (Ubuntu/Rocky 자동)
PM=""
if command -v apt-get >/dev/null 2>&1; then
  PM=apt
  export DEBIAN_FRONTEND=noninteractive
elif command -v dnf >/dev/null 2>&1; then
  PM=dnf
elif command -v yum >/dev/null 2>&1; then
  PM=yum
else
  echo "[6] no package manager"; exit 1
fi

# 1) MariaDB 설치
if [ "$PM" = "apt" ]; then
  apt-get update -y || true
  apt-get install -y mariadb-server || true
else
  $PM -y install mariadb-server || true
fi

# 2) 설정 파일 (Debian/Ubuntu vs RHEL/Rocky 경로 차이 처리)
DEB_DIR="/etc/mysql/mariadb.conf.d"
RHEL_DIR="/etc/my.cnf.d"
mkdir -p "$DEB_DIR" "$RHEL_DIR" || true

if [ -d "$DEB_DIR" ]; then
  CONF="$DEB_DIR/99-autodeploy.cnf"
  SOCK="/var/run/mysqld/mysqld.sock"
else
  CONF="$RHEL_DIR/99-autodeploy.cnf"
  SOCK="/var/lib/mysql/mysql.sock"
fi

cat > "$CONF" <<EOF
[mysqld]
port = %PORT%
bind-address = %BIND%
socket = $SOCK
max_connections = 300
character-set-server = utf8mb4
collation-server = utf8mb4_general_ci
skip-name-resolve
EOF

# 3) 기동/활성화
systemctl enable mariadb || true
systemctl restart mariadb

# 4) 방화벽/SELinux (외부 바인딩시에만)
if [ "%BIND%" != "127.0.0.1" ]; then
  if command -v ufw >/dev/null 2>&1; then ufw allow %PORT%/tcp || true; fi
  if command -v firewall-cmd >/dev/null 2>&1; then
    firewall-cmd --add-port=%PORT%/tcp --permanent || true
    firewall-cmd --reload || true
  fi
  if command -v getenforce >/dev/null 2>&1 && [ "$(getenforce || true)" = "Enforcing" ]; then
    # http/nginx와 달리 mysqld는 별도 타입
    if ! semanage port -l | grep -qE '^mysqld_port_t.*\\b%PORT%\\b'; then
      semanage port -a -t mysqld_port_t -p tcp %PORT% || true
    fi
  fi
fi

# 5) 루트 접속/비번 처리 (ubuntu 기본 unix_socket 고려)
SQL() {
  if [ -n "$ROOTPW" ]; then mysql -u root -p"$ROOTPW" -e "$1"; else mysql -u root -e "$1" || mysql --protocol=socket -u root -e "$1"; fi
}

# 필요 시 루트 비번/플러그인 교체
if [ -n "$ROOTPW" ]; then
  mysql -u root -e "ALTER USER 'root'@'localhost' IDENTIFIED BY '$ROOTPW'; FLUSH PRIVILEGES;" \
    || mysql --protocol=socket -u root -e "ALTER USER 'root'@'localhost' IDENTIFIED BY '$ROOTPW'; FLUSH PRIVILEGES;" || true

  mysql -u root -e "UPDATE mysql.user SET plugin='mysql_native_password' WHERE User='root' AND Host='localhost'; FLUSH PRIVILEGES;" \
    || mysql --protocol=socket -u root -e "UPDATE mysql.user SET plugin='mysql_native_password' WHERE User='root' AND Host='localhost'; FLUSH PRIVILEGES;" || true
  systemctl restart mariadb || true
fi

# 6) 헬스체크
if [ -n "$ROOTPW" ]; then mysqladmin -u root -p"$ROOTPW" ping || true; else mysqladmin -u root ping || mysqladmin --protocol=socket -u root ping || true; fi

# 7) 앱DB/계정
if [ -n "$ROOTPW" ]; then
  mysql -u root -p"$ROOTPW" -e "CREATE DATABASE IF NOT EXISTS \\`$APPDB\\` DEFAULT CHARACTER SET utf8mb4;"
  mysql -u root -p"$ROOTPW" -e "CREATE USER IF NOT EXISTS '$APPUSR'@'%' IDENTIFIED BY '$APPPW';"
  mysql -u root -p"$ROOTPW" -e "GRANT ALL PRIVILEGES ON \\`$APPDB\\`.* TO '$APPUSR'@'%'; FLUSH PRIVILEGES;"
else
  mysql -u root -e "CREATE DATABASE IF NOT EXISTS \\`$APPDB\\` DEFAULT CHARACTER SET utf8mb4;" \
    || mysql --protocol=socket -u root -e "CREATE DATABASE IF NOT EXISTS \\`$APPDB\\` DEFAULT CHARACTER SET utf8mb4;"
  mysql -u root -e "CREATE USER IF NOT EXISTS '$APPUSR'@'%' IDENTIFIED BY '$APPPW';" \
    || mysql --protocol=socket -u root -e "CREATE USER IF NOT EXISTS '$APPUSR'@'%' IDENTIFIED BY '$APPPW';"
  mysql -u root -e "GRANT ALL PRIVILEGES ON \\`$APPDB\\`.* TO '$APPUSR'@'%'; FLUSH PRIVILEGES;" \
    || mysql --protocol=socket -u root -e "GRANT ALL PRIVILEGES ON \\`$APPDB\\`.* TO '$APPUSR'@'%'; FLUSH PRIVILEGES;"
fi

mysql --version || true
echo "[6] MariaDB PORT=%PORT%, BIND=%BIND%"
echo "[6] APP DB=$APPDB, USER=$APPUSR"
echo "[6] STEP6 DONE OK"
""";

        script = script
                .replace("%PORT%", String.valueOf(PORT))
                .replace("%BIND%", BIND)
                .replace("%APPDB%", APPDB)
                .replace("%APPUSR%", APPUSR)
                .replace("%APPPW%", APPPW)
                .replace("%ROOTPW%", ROOTPW);

        String b64 = java.util.Base64.getEncoder().encodeToString(script.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        String cmd = String.join("\n",
                "base64 -d >/tmp/step6.sh <<'B64'",
                b64,
                "B64",
                "tr -d '\\r' < /tmp/step6.sh > /tmp/.step6.tmp && mv /tmp/.step6.tmp /tmp/step6.sh",
                "chmod +x /tmp/step6.sh",
                "echo '[6] bash -n syntax check:'",
                "bash -n /tmp/step6.sh || { echo '[6][DIAG] numbered dump:'; nl -ba /tmp/step6.sh; exit 1; }",
                "echo '[6] RUN /bin/bash -x /tmp/step6.sh'",
                "/bin/bash -x /tmp/step6.sh",
                "echo '[6] script DONE'"
        );

        try {
            var r = SSH.execRoot(s, "bash -lc \"" + cmd.replace("\"","\\\"") + "\"", req.sudoPw);
            String out = r.out() == null ? "" : r.out().trim();
            String err = r.err() == null ? "" : r.err().trim();
            String msg = (!out.isBlank() && !err.isBlank()) ? out + "\n" + err : (!out.isBlank() ? out : err);
            if (r.code() != 0) throw new RuntimeException("MariaDB 설치/설정 실패(code=" + r.code() + "): " + msg);

            log.accept("  - MariaDB 설치/설정 로그:\n" + msg);
            log.accept("[4] MariaDB 설치/설정 완료 ✅ (포트: " + PORT + ", 바인딩: " + BIND + ")");
        } catch (Exception e) {
            throw new RuntimeException("MariaDB 설치/설정 실패: " + e.getMessage(), e);
        }
    }
    public void step05_redis(Session s, com.innotium.autodeploy.dto.Step5RedisRequest req,
                             java.util.function.Consumer<String> log) {
        log.accept("[5] Redis 설치/설정 시작 ▶");

        int PORT = (req.redisPort <= 0 ? 46379 : req.redisPort);
        String BIND = (req.bindLocalOnly ? "127.0.0.1" : "0.0.0.0");

        String script = """
#!/usr/bin/env bash
set -Eeuo pipefail

echo "[5] STEP5 START"

PORT=%PORT%
BIND="%BIND%"

# 0) 패키지 매니저 감지 (Ubuntu/Rocky 자동)
PM=""
if command -v apt-get >/dev/null 2>&1; then
  PM=apt
  export DEBIAN_FRONTEND=noninteractive
elif command -v dnf >/dev/null 2>&1; then
  PM=dnf
elif command -v yum >/dev/null 2>&1; then
  PM=yum
else
  echo "[5] no package manager"; exit 1
fi

# 1) Redis 설치
if [ "$PM" = "apt" ]; then
  apt-get update -y || true
  apt-get install -y redis-server || apt-get install -y redis || true
else
  $PM -y install redis || $PM -y install redis6 || true
fi

# 2) 설정파일 경로 확인 (Ubuntu/Rocky 공통적으로 /etc/redis/redis.conf 사용)
CONF="/etc/redis/redis.conf"
if [ ! -f "$CONF" ]; then
  # Debian/Ubuntu 일부는 /etc/redis/redis.conf, RHEL 계열도 동일이 일반적
  echo "[5] redis.conf not found at $CONF"; ls -l /etc/redis || true
fi

# 3) 설정 백업
cp -a "$CONF" "${CONF}.bak.$(date +%F-%H%M%S)" || true

# 4) 바인드/포트/관리 설정
# - 포트: 46379(권장)
# - 바인드: 127.0.0.1(내부 전용) 또는 0.0.0.0
# - supervised systemd, daemonize no
# - protected-mode 기본값은 보안상 on 유지
sed -i 's/^#\\? *port .*/port '"$PORT"'/g' "$CONF" || true
if grep -qE '^#?\\s*bind\\b' "$CONF"; then
  sed -i 's/^#\\?\\s*bind.*/bind '"$BIND"'/g' "$CONF" || true
else
  echo "bind $BIND" >> "$CONF"
fi
if grep -qE '^#?\\s*supervised\\b' "$CONF"; then
  sed -i 's/^#\\?\\s*supervised.*/supervised systemd/g' "$CONF" || true
else
  echo "supervised systemd" >> "$CONF"
fi
if grep -qE '^#?\\s*daemonize\\b' "$CONF"; then
  sed -i 's/^#\\?\\s*daemonize.*/daemonize no/g' "$CONF" || true
else
  echo "daemonize no" >> "$CONF"
fi

# 5) 서비스 이름 차이 고려(RHEL=redis, Ubuntu=redis-server). 둘 다 시도
systemctl daemon-reload || true
systemctl enable --now redis 2>/dev/null || systemctl enable --now redis-server 2>/dev/null || true
systemctl restart redis 2>/dev/null || systemctl restart redis-server 2>/dev/null || true

# 6) 방화벽/SELinux (외부 바인딩시에만)
if [ "$BIND" != "127.0.0.1" ]; then
  if command -v ufw >/dev/null 2>&1; then ufw allow "$PORT"/tcp || true; fi
  if command -v firewall-cmd >/dev/null 2>&1; then
    firewall-cmd --add-port="$PORT"/tcp --permanent || true
    firewall-cmd --reload || true
  fi
  if command -v getenforce >/dev/null 2>&1 && [ "$(getenforce || true)" = "Enforcing" ]; then
    # Redis는 보통 외부 포트에 대한 별도 SELinux 타입 설정 없이도 동작, 필요 시 추가 조치
    :
  fi
fi

# 7) 헬스체크
which redis-cli >/dev/null 2>&1 || { echo "[5] redis-cli not found"; exit 1; }
ss -lntp | sed -n '1,200p' | grep ":${PORT}\\b" || true
redis-cli -p "$PORT" ping || true

echo "[5] Redis PORT=$PORT, BIND=$BIND"
echo "[5] STEP5 DONE OK"
""";

        script = script
                .replace("%PORT%", String.valueOf(PORT))
                .replace("%BIND%", BIND);

        String b64 = java.util.Base64.getEncoder()
                .encodeToString(script.getBytes(java.nio.charset.StandardCharsets.UTF_8));

        String cmd = String.join("\n",
                "base64 -d >/tmp/step5.sh <<'B64'",
                b64,
                "B64",
                "tr -d '\\r' < /tmp/step5.sh > /tmp/.step5.tmp && mv /tmp/.step5.tmp /tmp/step5.sh",
                "chmod +x /tmp/step5.sh",
                "echo '[5] bash -n syntax check:'",
                "bash -n /tmp/step5.sh || { echo '[5][DIAG] numbered dump:'; nl -ba /tmp/step5.sh; exit 1; }",
                "echo '[5] RUN /bin/bash -x /tmp/step5.sh'",
                "/bin/bash -x /tmp/step5.sh",
                "echo '[5] script DONE'"
        );

        try {
            var r = com.innotium.autodeploy.ssh.SSH.execRoot(s,
                    "bash -lc \"" + cmd.replace("\"","\\\"") + "\"",
                    req.sudoPw);
            String out = r.out() == null ? "" : r.out().trim();
            String err = r.err() == null ? "" : r.err().trim();
            String msg = (!out.isBlank() && !err.isBlank()) ? out + "\n" + err : (!out.isBlank() ? out : err);
            if (r.code() != 0) throw new RuntimeException("Redis 설치/설정 실패(code=" + r.code() + "): " + msg);

            log.accept("  - Redis 설치/설정 로그:\n" + msg);
            log.accept("[5] Redis 설치/설정 완료 ✅ (포트: " + PORT + ", 바인딩: " + BIND + ")");
        } catch (Exception e) {
            throw new RuntimeException("Redis 설치/설정 실패: " + e.getMessage(), e);
        }
    }
    private void step07_scouter(java.util.function.Consumer<String> log,
                                com.jcraft.jsch.Session s,
                                String osIgnored, String sudoPw) throws Exception {
        log.accept("[7] Scouter 설치/에이전트 연동 시작 ▶");

        String script = """
#!/usr/bin/env bash
set -Eeuo pipefail

echo "[7] STEP7 START"

SCOUTER_DIR="/opt/scouter"
TOMCAT_HOME="/opt/tomcat/latest"
SCOUTER_PORT=6100
COLLECTOR_IP="127.0.0.1"   # 같은 서버에 Scouter Server 실행(기본)
OBJ_NAME="tomcat-$(hostname -s)"

# 0) 패키지 매니저 감지 + 필수 도구
PM=""
if command -v apt-get >/dev/null 2>&1; then
  PM=apt
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y || true
  apt-get install -y curl tar sed || true
elif command -v dnf >/dev/null 2>&1; then
  PM=dnf
  dnf -y install curl tar sed || true
elif command -v yum >/dev/null 2>&1; then
  PM=yum
  yum -y install curl tar sed || true
else
  echo "[7] no package manager"; exit 1
fi

# 1) Scouter 최신 릴리스 버전 탐색(실패 시 고정버전 사용)
VER="$(curl -fsSL https://api.github.com/repos/scouter-project/scouter/releases/latest | sed -n 's/.*"tag_name":[ \t]*"v\\?\\([0-9.]*\\)".*/\\1/p' | head -n1 || true)"
if [ -z "$VER" ]; then VER="2.20.0"; fi
URL="https://github.com/scouter-project/scouter/releases/download/v${VER}/scouter-all-${VER}.tar.gz"

mkdir -p "$SCOUTER_DIR"
cd "$SCOUTER_DIR"

echo "[7] 다운로드: $URL"
if ! curl -fL "$URL" -o scouter-all.tgz; then
  echo "[7] 최신 다운로드 실패 → 고정버전 2.20.0 재시도"
  VER="2.20.0"
  URL="https://github.com/scouter-project/scouter/releases/download/v${VER}/scouter-all-${VER}.tar.gz"
  curl -fL "$URL" -o scouter-all.tgz
fi

rm -rf "./scouter-all-${VER}" "./latest"
tar -xzf scouter-all.tgz
mv "scouter-all-${VER}" latest

# 2) Server 설치(systemd 등록)
# 디렉터리 구조: /opt/scouter/latest/server /opt/scouter/latest/agent.java
install -d /opt/scouter/server /opt/scouter/agent.java

# server/agent 복사
rsync -a --delete "/opt/scouter/latest/server/" "/opt/scouter/server/"
rsync -a --delete "/opt/scouter/latest/agent.java/" "/opt/scouter/agent.java/"

# 서버 환경 파일 보정(데몬 형태로 실행되도록)
# 최신 스크립트는 startup.sh 제공. systemd 단에서 실행 관리.
cat >/etc/systemd/system/scouter-server.service <<'UNIT'
[Unit]
Description=Scouter Collector Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/scouter/server
ExecStart=/opt/scouter/server/startup.sh
ExecStop=/opt/scouter/server/shutdown.sh
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable scouter-server || true
systemctl restart scouter-server || true

# 3) 방화벽/SELinux (Collector 6100/TCP)
command -v ufw >/dev/null 2>&1 && ufw allow ${SCOUTER_PORT}/tcp || true
if command -v firewall-cmd >/dev/null 2>&1; then
  firewall-cmd --add-port=${SCOUTER_PORT}/tcp --permanent || true
  firewall-cmd --reload || true
fi
if command -v getenforce >/dev/null 2>&1 && [ "$(getenforce || true)" = "Enforcing" ]; then
  # http_port_t가 아니라 별도 타입 필요 없음(일반 TCP listen). 필요한 경우 추가 정책 적용.
  :
fi

# 4) Tomcat Java Agent 연동
install -d /opt/scouter/agent.java/conf
cat >/opt/scouter/agent.java/conf/scouter.conf <<EOF
net_collector_ip=${COLLECTOR_IP}
net_collector_udp_port=${SCOUTER_PORT}
net_collector_tcp_port=${SCOUTER_PORT}
obj_name=${OBJ_NAME}
# 필요시 추가 옵션:
# hook_method_patterns=org.apache..*,com.innotium..*
EOF

SETENV="$TOMCAT_HOME/bin/setenv.sh"
touch "$SETENV"
chmod +x "$SETENV"

if ! grep -q "scouter.agent.jar" "$SETENV"; then
  cat >>"$SETENV" <<'EOT'
# ----- Scouter Java Agent -----
SCOUTER_AGENT=/opt/scouter/agent.java
export CATALINA_OPTS="$CATALINA_OPTS -javaagent:${SCOUTER_AGENT}/lib/scouter.agent.jar -Dscouter.config=${SCOUTER_AGENT}/conf/scouter.conf"
EOT
fi

# 5) Tomcat 재기동
systemctl restart tomcat || true

# 6) 헬스체크
echo "[7] listening ports (6100 expected):"
ss -lntp | sed -n '1,200p' | grep ':6100' || true

echo "[7] scouter-server status:"
systemctl --no-pager -l status scouter-server || true

echo "[7] TOMCAT JAVA_OPTS with agent?"
grep -n "scouter.agent.jar" "$SETENV" || true

echo "[7] STEP7 DONE OK"
""";

        String b64 = java.util.Base64.getEncoder()
                .encodeToString(script.getBytes(java.nio.charset.StandardCharsets.UTF_8));

        String cmd = String.join("\n",
                "base64 -d >/tmp/step7.sh <<'B64'",
                b64,
                "B64",
                "tr -d '\\r' < /tmp/step7.sh > /tmp/.step7.tmp && mv /tmp/.step7.tmp /tmp/step7.sh",
                "chmod +x /tmp/step7.sh",
                "echo '[7] bash -n syntax check:'",
                "bash -n /tmp/step7.sh || { echo '[7][DIAG] numbered dump:'; nl -ba /tmp/step7.sh; exit 1; }",
                "echo '[7] RUN /bin/bash -x /tmp/step7.sh'",
                "/bin/bash -x /tmp/step7.sh",
                "echo '[7] script DONE'"
        );

        var r = com.innotium.autodeploy.ssh.SSH.execRoot(s, "bash -lc \"" + cmd.replace("\"","\\\"") + "\"", sudoPw);
        String out = r.out() == null ? "" : r.out().trim();
        String err = r.err() == null ? "" : r.err().trim();
        String msg = (!out.isBlank() && !err.isBlank()) ? out + "\n" + err : (!out.isBlank() ? out : err);
        if (r.code() != 0) throw new RuntimeException("Scouter 설치/연동 실패(code=" + r.code() + "): " + msg);

        log.accept("  - Scouter 설치/연동 로그:\n" + msg);
        log.accept("[7] Scouter 설치/에이전트 연동 완료 ✅ (Collector: 127.0.0.1:6100, Agent: Tomcat)");
    }


    private String pickMsg(SSH.Result r) {
        String out = r.out() == null ? "" : r.out().trim();
        String err = r.err() == null ? "" : r.err().trim();
        if (!out.isBlank() && !err.isBlank()) return out + "\n" + err;
        return !out.isBlank() ? out : err;
    }
}