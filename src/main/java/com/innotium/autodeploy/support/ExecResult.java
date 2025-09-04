package com.innotium.autodeploy.support;

public record ExecResult(
        String title,   // 실행한 단계/명령의 간단한 이름
        boolean ok,     // 성공 여부
        String out      // 표준출력/표준에러 합친 로그(요약)
) {}