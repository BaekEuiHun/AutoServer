package com.innotium.autodeploy.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class PrecheckResponse {
    private String targetIp;
    private boolean pingOk;
    private boolean tcp22Ok;
}
