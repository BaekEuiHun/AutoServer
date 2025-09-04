package com.innotium.autodeploy.dto;

import java.util.ArrayList;
import java.util.List;

public class DeployResponse {
    public boolean ok;
    public String message;
    public List<String> logs = new ArrayList<>();

    public void log(String line) {
        logs.add(line);
    }
}
