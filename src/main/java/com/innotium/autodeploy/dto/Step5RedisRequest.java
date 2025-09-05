package com.innotium.autodeploy.dto;

public class Step5RedisRequest {
    public String ip;
    public String user;
    /** sudo 혹은 ssh 패스워드(동일 가정) */
    public String sudoPw;

    /** 기본 46379 (내부 통신용) */
    public int redisPort = 46379;

    /** true면 127.0.0.1만 바인딩(보안 권장). false면 0.0.0.0 */
    public boolean bindLocalOnly = true;
}

