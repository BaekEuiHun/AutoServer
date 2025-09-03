package com.innotium.autodeploy.controller;

import com.innotium.autodeploy.dto.DeployRequest;
import com.innotium.autodeploy.service.DeployService;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.nio.file.Files;
import java.nio.file.Path;

@RestController
@RequestMapping("/api/deploy")
public class DeployStreamController {
    private final DeployService service;
    public DeployStreamController(DeployService service){ this.service = service; }

    @PostMapping(value = "/stream",
            consumes = MediaType.MULTIPART_FORM_DATA_VALUE,
            produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    public SseEmitter deployStream(@RequestParam("file") MultipartFile file,
                                   @RequestParam String ip,
                                   @RequestParam Integer port,
                                   @RequestParam String user,
                                   @RequestParam String password,
                                   @RequestParam String remoteWorkDir) {
        final SseEmitter emitter = new SseEmitter(0L); // 무제한 timeout
        try {
            // 1) 임시 파일 저장
            Path temp = Files.createTempFile("WAS-", ".tar");
            file.transferTo(temp.toFile());

            // 2) 요청 DTO
            var req = new DeployRequest(ip, port, user, password, temp.toString(), remoteWorkDir);

            // 3) 비동기로 실행 (이벤트 전송)
            new Thread(() -> {
                try {
                    service.runAllStreaming(req, line -> {
                        try { emitter.send(SseEmitter.event().data(line)); }
                        catch (Exception ignore) {}
                    });
                    emitter.complete();
                } catch (Exception e) {
                    try { emitter.send(SseEmitter.event().data("배포 실패 ❌: " + e.getMessage())); }
                    catch (Exception ignore) {}
                    emitter.completeWithError(e);
                } finally {
                    try { Files.deleteIfExists(temp); } catch (Exception ignore) {}
                }
            }, "deploy-stream-thread").start();

        } catch (Exception e) {
            emitter.completeWithError(e);
        }
        return emitter;
    }
}