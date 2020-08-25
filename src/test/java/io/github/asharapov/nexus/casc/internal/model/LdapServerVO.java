package io.github.asharapov.nexus.casc.internal.model;

public class LdapServerVO {
    public enum Protocol {
        LDAP, LDAPS
    }

    public enum AuthScheme {
        NONE, SIMPLE, DIGEST_MD5, CRAM_MD5
    }

    public enum GroupType {
        STATIC, DYNAMIC
    }

    public String id;
    public String name;
    public Protocol protocol;     // eg: LDAP
    public boolean useTrustStore;
    public String host;
    public int port;
    public String searchBase;
    public String authScheme;   // eg: SIMPLE
    public String authRealm;
    public String authUsername;
    public int connectionTimeoutSeconds;
    public int connectionRetryDelaySeconds;
    public int maxIncidentsCount;
    public String userBaseDn;
    public boolean userSubtree;
    public String userObjectClass;
    public String userLdapFilter;
    public String userIdAttribute;
    public String userRealNameAttribute;
    public String userEmailAddressAttribute;
    public String userPasswordAttribute;
    public boolean ldapGroupsAsRoles;
    public String groupType;    // eg: STATIC
    public String groupBaseDn;
    public boolean groupSubtree;
    public String groupObjectClass;
    public String groupIdAttribute;
    public String groupMemberAttribute;
    public String groupMemberFormat;
    public String userMemberOfAttribute;
    public int order;
}
