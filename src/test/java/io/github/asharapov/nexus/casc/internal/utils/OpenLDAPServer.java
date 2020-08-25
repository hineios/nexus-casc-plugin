package io.github.asharapov.nexus.casc.internal.utils;

import com.github.dockerjava.api.model.ContainerNetwork;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;

import java.util.Map;

/**
 * Represents dockerized OpenLDAP server instance with preloaded test data.
 *
 * @author Anton Sharapov
 */
public class OpenLDAPServer extends GenericContainer<OpenLDAPServer> {

    private static final String IMAGE_NAME = "osixia/openldap:1.4.0";
    private static final String ADMIN_PASSWORD = "admin123";
    private static final String LDAP_DOMAIN = "example.org";
    private static final String LDAP_BASE_DN = "dc=example,dc=org";

    public OpenLDAPServer() {
        super(IMAGE_NAME);
        withExposedPorts(389, 636);
        waitingFor(Wait.forListeningPort());
        withCopyFileToContainer(TestUtils.getLdapDataFile(), "/initdb.d/data.ldif");
        withEnv("LDAP_SEED_INTERNAL_LDIF_PATH", "/initdb.d");
        withEnv("LDAP_ADMIN_PASSWORD", ADMIN_PASSWORD);
        withEnv("LDAP_DOMAIN", LDAP_DOMAIN);
        withEnv("LDAP_BASE_DN", LDAP_BASE_DN);
    }

    public String getInternalHostName() {
        String host = this.getContainerInfo().getName();
        if (host.startsWith("/")) {
            host = host.substring(1);
        }
        return host;
    }

    public String getInternalIPAddress() {
        final Map<String, ContainerNetwork> networks = this.getContainerInfo().getNetworkSettings().getNetworks();
        if (networks == null || networks.size() != 1) {
            throw new IllegalStateException("Container not started");
        }
        final ContainerNetwork net = networks.values().iterator().next();
        return net.getIpAddress();
    }
}