package com.innotium.autodeploy.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class PrecheckRequest {
    @NotBlank
    private String ip;
    @NotBlank
    private String user;

    @NotNull
    private Integer port = 22; // 기본 SSH 포트
    @NotBlank
    private String password;   // 나중엔 키 인증도 추가 가능
}
