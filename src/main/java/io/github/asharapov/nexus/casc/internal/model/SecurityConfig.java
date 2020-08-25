package io.github.asharapov.nexus.casc.internal.model;

import io.github.asharapov.nexus.casc.internal.yaml.PropertyOrder;

import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * @author Anton Sharapov
 */
@PropertyOrder({"anonymousAccess", "trustedCerts", "ldapServers", "realms", "privileges", "privilegesToDelete",
        "roles", "rolesToDelete", "users", "usersToDelete", "pruneOtherUsers"})
public class SecurityConfig {

    public Boolean anonymousAccess;
    public TrustedStore trustedCerts;
    public List<LdapServer> ldapServers;
    public List<Realm> realms;
    public List<Privilege> privileges;
    public List<Key> privilegesToDelete;
    public List<Role> roles;
    public List<Key> rolesToDelete;
    public List<User> users;
    public List<Key> usersToDelete;
    public Boolean pruneOtherUsers;


    public static class TrustedStore {
        public List<URI> fromPEMFiles;
        public List<HostCertificate> fromServers;
    }


    public static class HostCertificate {
        public String host;
        public int port = 443;

        public HostCertificate() {
        }

        public HostCertificate(String host, int port) {
            this.host = host;
            this.port = port;
        }
    }


    @PropertyOrder({"name", "order", "connection", "mapping"})
    public static class LdapServer {
        public String name;
        public Integer order;
        public LdapConnection connection;
        public LdapMapping mapping;
    }

    public enum LdapProtocol {
        ldap, ldaps;
    }

    @PropertyOrder({"protocol", "host", "port", "searchBase", "authScheme", "user", "password", "useTrustStore", "saslRealm"})
    public static class LdapConnection {
        public LdapProtocol protocol;
        public String host;
        public Integer port;
        public String searchBase;
        public String authScheme;
        public String user;
        public String password;
        public Boolean useTrustStore;
        public String saslRealm;
        public Integer connectionTimeout;
        public Integer connectionRetryDelay;
        public Integer maxIncidentsCount;
    }

    @PropertyOrder({"userBaseDn", "userSubtree", "userObjectClass", "userIdAttr", "userNameAttr", "userEmailAttr", "userPasswordAttr", "ldapFilter",
            "groupBaseDn", "groupSubtree", "groupObjectClass", "groupIdAttr", "groupMemberAttr", "groupMemberFormat", "ldapGroupsAsRoles"})
    public static class LdapMapping {
        public String userBaseDn;
        public Boolean userSubtree;
        public String userObjectClass;
        public String userIdAttr;
        public String userNameAttr;
        public String userEmailAttr;
        public String userPasswordAttr;
        public String userMemberOfAttr;
        public String ldapFilter;
        public String groupBaseDn;
        public Boolean groupSubtree;
        public String groupObjectClass;
        public String groupIdAttr;
        public String groupMemberAttr;
        public String groupMemberFormat;
        public Boolean ldapGroupsAsRoles;
    }


    @PropertyOrder({"name", "enabled"})
    public static class Realm {
        public String name;
        public Boolean enabled;

        @Override
        public String toString() {
            return "[Realm{name:" + name + ", enabled:" + enabled + "}]";
        }
    }


    @PropertyOrder({"id", "authSource"})
    public static class Key {
        public final String id;
        public final String authSource;

        public Key(final String id, final String authSource) {
            this.id = id;
            this.authSource = authSource;
        }

        @Override
        public int hashCode() {
            return id != null ? id.hashCode() : 0;
        }

        @Override
        public boolean equals(final Object obj) {
            if (obj == this) {
                return true;
            }
            if (!(obj instanceof Key)) {
                return false;
            }
            final Key other = (Key) obj;
            return Objects.equals(id, other.id) && Objects.equals(authSource, other.authSource);
        }

        @Override
        public String toString() {
            return "{id:" + id + ", src:" + authSource + "}";
        }
    }


    @PropertyOrder({"id", "authSource", "name", "description", "type", "attrs", "readOnly"})
    public static class Privilege {
        public String id;
        public String authSource;
        public String name;
        public String description;
        public String type;
        public Map<String, String> attrs;
        public Boolean readOnly;

        @Override
        public String toString() {
            return "[Privilege{id:" + id + ", src:" + authSource + ", type:" + type + ", attrs:" + attrs + ", ro:" + readOnly + "}]";
        }
    }


    @PropertyOrder({"id", "authSource", "name", "description", "privileges", "roles", "readOnly"})
    public static class Role {
        public String id;
        public String authSource;
        public String name;
        public String description;
        public List<String> privileges;
        public List<String> roles;
        public Boolean readOnly;

        public Role() {
        }

        public Role(String id, String authSource) {
            this.id = id;
            this.authSource = authSource;
        }

        @Override
        public String toString() {
            return "[Role{id:" + id + ", src:" + authSource + ", priv:" + privileges + ", roles:" + roles + ", ro:" + readOnly + "}]";
        }
    }


    @PropertyOrder({"id", "authSource", "name", "firstName", "lastName", "email", "active", "roles", "readOnly"})
    public static class User {
        public String id;
        public String authSource;
        public String name;
        public String firstName;
        public String lastName;
        public String email;
        public Boolean active;
        public List<Key> roles;
        public Boolean readOnly;
        public String password;
        public Boolean updateExistingPassword;

        public User() {
        }

        public User(String id, String authSource) {
            this.id = id;
            this.authSource = authSource;
        }

        @Override
        public String toString() {
            return "[User{id:" + id + ", src:" + authSource + ", name:" + name + ", email:" + email + ", roles:" + roles + ", ro:" + readOnly + "}]";
        }
    }

}
