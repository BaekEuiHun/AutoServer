package com.innotium.autodeploy.controller;

import com.innotium.autodeploy.dto.PrecheckRequest;
import com.innotium.autodeploy.service.PrecheckService;
import jakarta.validation.Valid;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 버튼1: 사전연결 및 점검 API
 * - GET: 간단 확인 (ip, port)
 * - POST: SSH 자격(user/password)까지 받아 OS 판별 포함
 *
 * 포트는 application.yml에서 server.port=8081 로 이미 설정했다고 가정.
 */

@RestController
@RequestMapping("/api/precheck")
public class PrecheckController {

    private final PrecheckService svc;

    public PrecheckController(PrecheckService svc) {
        this.svc = svc;
    }

    /**
     * 간단 GET 점검
     * 예) GET http://localhost:8081/api/precheck?ip=192.168.11.103&port=22
     * 반환: ping / tcp22 결과
     */
    @GetMapping(produces = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, Object> precheckGet(
            @RequestParam String ip,
            @RequestParam(defaultValue = "22") int port
    ) {
        boolean pingOk = svc.ping(ip, 1500);
        boolean tcpOk = svc.tcp(ip, port, 1500);

        Map<String, Object> res = new LinkedHashMap<>();
        res.put("targetIp", ip);
        res.put("pingOk", pingOk);
        res.put("tcpOk", tcpOk);
        res.put("osName", "unknown"); // GET은 SSH정보가 없으니 OS는 unknown
        return res;
    }

    /**
     * POST 점검 (SSH 정보 포함 → OS 판별)
     * 예) POST http://localhost:8081/api/precheck
     * Body:
     * {
     * "ip": "192.168.11.103",
     * "port": 22,
     * "user": "ehbaek",
     * "password": "******"
     * }
     */
    @PostMapping(consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, Object> precheckPost(@RequestBody @Valid PrecheckRequest req) {
        boolean pingOk = svc.ping(req.getIp(), 1500);
        boolean tcpOk = svc.tcp(req.getIp(), req.getPort(), 1500);

        // SSH로 /etc/os-release 읽어서 ubuntu/rocky 판별
        String os = "unknown";
        if (tcpOk) { // 22 열려 있을 때만 시도
            os = svc.detectOs(req.getIp(), req.getPort(), req.getUser(), req.getPassword());
        }

        Map<String, Object> res = new LinkedHashMap<>();
        res.put("targetIp", req.getIp());
        res.put("pingOk", pingOk);
        res.put("tcpOk", tcpOk);
        res.put("osName", os);
        return res;
    }
}