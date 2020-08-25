package io.github.asharapov.nexus.casc.internal.model;

import java.util.List;

public class RoutingRuleVO {

    public enum Mode {
        BLOCK, ALLOW
    }
    public String name;
    public String description;
    public Mode mode;
    public List<String> matchers;

}
