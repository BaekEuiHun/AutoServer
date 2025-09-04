package com.innotium.autodeploy.support;

import java.util.List;

public record StepResult(
        String title,           // "2단계: WAS 패키지" 같은 단계명
        boolean ok,             // 단계 성공/실패
        String message,         // "OK" 또는 실패 사유 메시지
        List<ExecResult> logs   // 하위 실행 로그 목록
) {
    public static StepResult ok(String title, List<ExecResult> logs) {
        return new StepResult(title, true, "OK", logs);
    }
    public static StepResult fail(String title, String msg, List<ExecResult> logs) {
        return new StepResult(title, false, msg, logs);
    }
}