package io.github.asharapov.nexus.casc.internal.model;

import java.util.List;

public class PrivilegeVO {
    public enum Action {
        READ, BROWSE, EDIT, ADD, DELETE, RUN, ASSOCIATE, DISASSOCIATE, ALL
    }
    public String type;
    public String name;
    public String description;
    public List<Action> actions;
    public boolean readOnly;

    public String pattern;      // type="wildcard"

    public String domain;       // type="application"

    public String format;       // type="repository-admin", "repository-view"
    public String repository;

    public String scriptName;   // type="script"

}
