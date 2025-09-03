package com.innotium.autodeploy.controller;

import com.innotium.autodeploy.dto.DeployRequest;
import com.innotium.autodeploy.dto.DeployResponse;
import com.innotium.autodeploy.service.DeployService;
import com.innotium.autodeploy.support.StepResult;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

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
}