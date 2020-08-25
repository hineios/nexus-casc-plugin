package io.github.asharapov.nexus.casc.internal.model;

public class EmailVO {
    public boolean enabled;
    public String host;
    public int port;
    public String username;
    public String password;
    public String fromAddress;
    public String subjectPrefix;
    public boolean startTlsEnabled;
    public boolean startTlsRequired;
    public boolean sslOnConnectEnabled;
    public boolean sslServerIdentityCheckEnabled;
    public boolean nexusTrustStoreEnabled;
}
