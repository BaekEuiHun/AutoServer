package com.innotium.autodeploy.dto;

public record DeployRequest(
        String ip,            // 대상 서버 IP
        Integer port,         // SSH 포트 (기본 22)
        String user,          // SSH 계정
        String password,      // SSH 비밀번호 (sudo 필요 시 사용; 없으면 NOPASSWD 가정)
        String wasTarPath,    // (백엔드 로컬) 업로드할 WAS.tar 경로
        String remoteWorkDir  // (원격) 작업 디렉토리 예: /opt/app
) {}

