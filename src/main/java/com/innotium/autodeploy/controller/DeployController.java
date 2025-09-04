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
}
