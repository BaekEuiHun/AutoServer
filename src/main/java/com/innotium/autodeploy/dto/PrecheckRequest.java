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

    @NotNull
    private Integer port = 22; // 기본 SSH 포트
}
