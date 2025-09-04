package com.innotium.autodeploy.dto;

import jakarta.validation.constraints.NotBlank;

public class Step6MariadbRequest {
    @NotBlank
    public String ip;
    @NotBlank public String user;       // 원격 리눅스 계정 (예: ehbaek)
    @NotBlank public String sudoPw;     // sudo 비밀번호

    // 기본값: 정책 준수
    public String mariadbMajorMinor = "10.11"; // 10.11 계열(10.11.2 이상)
    public int mariadbPort = 43306;            // 내부통신 포트

    // 선택(있으면 DB/User 생성)
    public String appDbName;   // 예: "innoapp"
    public String appDbUser;   // 예: "innoapp"
    public String appDbPass;   // 예: "S3cure!234"

    // 바인드 로컬 전용(내부통신): true 권장
    public boolean bindLocalOnly = true;
}
