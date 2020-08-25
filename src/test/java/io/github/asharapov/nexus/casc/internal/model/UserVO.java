package io.github.asharapov.nexus.casc.internal.model;

import java.util.List;

public class UserVO {
    public enum Status {
        active, locked, disabled, changepassword
    }
    public String userId;
    public String firstName;
    public String lastName;
    public String emailAddress;
    public String source;
    public Status status;
    public boolean readOnly;
    public List<String> roles;
    public List<String> externalRoles;
}
