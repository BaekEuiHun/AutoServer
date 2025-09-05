package com.innotium.autodeploy.controller;

import com.innotium.autodeploy.dto.DeployRequest;
import com.innotium.autodeploy.dto.DeployResponse;
import com.innotium.autodeploy.dto.Step6MariadbRequest;
import com.innotium.autodeploy.service.DeployService;
import com.innotium.autodeploy.ssh.SSH;
import com.jcraft.jsch.Session;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import java.nio.file.Files;
import java.nio.file.Path;


@RestController
@RequestMapping("/api/deploy")
public class DeployController {
    private final DeployService service;

    public DeployController(DeployService service) {
        this.service = service;
    }

    @PostMapping(consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<DeployResponse> deploy(
            @RequestParam("file") MultipartFile file,
            @RequestParam String ip,
            @RequestParam Integer port,
            @RequestParam String user,
            @RequestParam String password,
            @RequestParam String remoteWorkDir
    ) {
        try {
            // 1. 파일을 임시 저장
            Path temp = Files.createTempFile("WAS-", ".tar");
            file.transferTo(temp.toFile());

            // 2. 서비스 호출
            DeployRequest req = new DeployRequest(ip, port, user, password, temp.toString(), remoteWorkDir);
            DeployResponse result = service.runAll(req);

            return ResponseEntity.ok(result);
        } catch (Exception e) {
            DeployResponse error = new DeployResponse();
            error.ok = false;
            error.message = "배포 실패: " + e.getMessage();
            error.logs.add("업로드/임시파일 처리 중 오류: " + e.getMessage());
            return ResponseEntity.internalServerError().body(error);
        }
    }
    @PostMapping("/step5/redis")
    public ResponseEntity<?> step5(@RequestBody com.innotium.autodeploy.dto.Step5RedisRequest req) {
        com.jcraft.jsch.Session s = null;
        try {
            s = com.innotium.autodeploy.ssh.SSH.open(req.ip, 22, req.user, req.sudoPw);
            service.step05_redis(s, req, System.out::println);
            return ResponseEntity.ok().build();
        } catch (Exception e) {
            return ResponseEntity.internalServerError().body("Step5 실패: " + e.getMessage());
        } finally {
            if (s != null && s.isConnected()) s.disconnect();
        }
    }
    @PostMapping("/step4/nginx")
    public ResponseEntity<?> step4(@RequestParam String ip,
                                   @RequestParam String user,
                                   @RequestParam String sudoPw) {
        com.jcraft.jsch.Session s = null;
        try {
            s = com.innotium.autodeploy.ssh.SSH.open(ip, 22, user, sudoPw);
            // OS 감지는 내부 스크립트에서 패키지 매니저로 자동 처리됨
            service.getClass(); // 서비스 인스턴스 존재 보장용 no-op
            // DeployService에 public 메서드면 직접 호출, private이면 runAll 내 순서로만 실행
            java.lang.reflect.Method m = service.getClass().getDeclaredMethod(
                    "step04_nginx", java.util.function.Consumer.class, com.jcraft.jsch.Session.class, String.class, String.class);
            m.setAccessible(true);
            m.invoke(service, (java.util.function.Consumer<String>)System.out::println, s, "unknown", sudoPw);
            return ResponseEntity.ok().build();
        } catch (Exception e) {
            return ResponseEntity.internalServerError().body("Step4 실패: " + e.getMessage());
        } finally {
            if (s != null && s.isConnected()) s.disconnect();
        }
    }
    @PostMapping("/step7/scouter")
    public ResponseEntity<?> step7(@RequestParam String ip,
                                   @RequestParam String user,
                                   @RequestParam String sudoPw) {
        com.jcraft.jsch.Session s = null;
        try {
            s = com.innotium.autodeploy.ssh.SSH.open(ip, 22, user, sudoPw);
            // OS는 스크립트 내부에서 패키지 매니저로 처리
            // 리플렉션 없이 public으로 빼도 되고, private이면 아래처럼 변경
            java.lang.reflect.Method m = service.getClass().getDeclaredMethod(
                    "step07_scouter",
                    java.util.function.Consumer.class,
                    com.jcraft.jsch.Session.class,
                    String.class,
                    String.class
            );
            m.setAccessible(true);
            m.invoke(service, (java.util.function.Consumer<String>)System.out::println, s, "unknown", sudoPw);
            return ResponseEntity.ok().build();
        } catch (Exception e) {
            return ResponseEntity.internalServerError().body("Step7 실패: " + e.getMessage());
        } finally {
            if (s != null && s.isConnected()) s.disconnect();
        }
    }

    @PostMapping("/step6/mariadb")
    public ResponseEntity<?> step6(@RequestBody Step6MariadbRequest req) {
        Session s = null;
        try {
            // 필요 시 req.port 사용 (없으면 22 기본)
            s = SSH.open(req.ip, 22, req.user, req.sudoPw);

            // 로그 콜백: 람다 대신 메서드 레퍼런스로 깔끔하게
            service.step06_mariadb(s, req, System.out::println);

            return ResponseEntity.ok().build();
        } catch (Exception e) {
            return ResponseEntity
                    .internalServerError()
                    .body("Step6 실패: " + e.getMessage());
        } finally {
            if (s != null && s.isConnected()) {
                s.disconnect();
            }
        }
    }
    @PostMapping("/step9/health")
    public ResponseEntity<?> step9(@RequestParam String ip,
                                   @RequestParam String user,
                                   @RequestParam String sudoPw) {
        com.jcraft.jsch.Session s = null;
        try {
            s = com.innotium.autodeploy.ssh.SSH.open(ip, 22, user, sudoPw);
            java.lang.reflect.Method m = service.getClass().getDeclaredMethod(
                    "step09_health",
                    java.util.function.Consumer.class,
                    com.jcraft.jsch.Session.class,
                    String.class,
                    String.class
            );
            m.setAccessible(true);
            m.invoke(service, (java.util.function.Consumer<String>)System.out::println, s, "unknown", sudoPw);
            return ResponseEntity.ok().build();
        } catch (Exception e) {
            return ResponseEntity.internalServerError().body("Step9 실패: " + e.getMessage());
        } finally {
            if (s != null && s.isConnected()) s.disconnect();
        }
    }
    // DeployController.java 내부에 추가
    @PostMapping("/step8/security")
    public ResponseEntity<?> step8(@RequestParam String ip,
                                   @RequestParam String user,
                                   @RequestParam String sudoPw) {
        com.jcraft.jsch.Session s = null;
        try {
            s = com.innotium.autodeploy.ssh.SSH.open(ip, 22, user, sudoPw);
            java.lang.reflect.Method m = service.getClass().getDeclaredMethod(
                    "step08_security",
                    java.util.function.Consumer.class,
                    com.jcraft.jsch.Session.class,
                    String.class,
                    String.class
            );
            m.setAccessible(true);
            m.invoke(service, (java.util.function.Consumer<String>)System.out::println, s, "unknown", sudoPw);
            return ResponseEntity.ok().build();
        } catch (Exception e) {
            return ResponseEntity.internalServerError().body("Step8 실패: " + e.getMessage());
        } finally {
            if (s != null && s.isConnected()) s.disconnect();
        }
    }
}
