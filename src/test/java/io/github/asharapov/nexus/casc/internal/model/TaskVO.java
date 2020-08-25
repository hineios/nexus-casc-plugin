package io.github.asharapov.nexus.casc.internal.model;

public class TaskVO {
    public String id;
    public String name;
    public String type;
    public String message;
    public String currentState; // eg: "waiting"
    public String lastRunResult;
    public String lastRun;
    public String nextRun;
}
