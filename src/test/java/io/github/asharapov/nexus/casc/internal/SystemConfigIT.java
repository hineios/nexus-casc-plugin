package io.github.asharapov.nexus.casc.internal;

import io.github.asharapov.nexus.casc.internal.junit.IntegrationTest;
import io.github.asharapov.nexus.casc.internal.model.Config;
import io.github.asharapov.nexus.casc.internal.model.EmailVO;
import io.github.asharapov.nexus.casc.internal.model.IqConnectionVO;
import io.github.asharapov.nexus.casc.internal.model.ResultVO;
import io.github.asharapov.nexus.casc.internal.model.SystemConfig;
import io.github.asharapov.nexus.casc.internal.model.TaskListVO;
import io.github.asharapov.nexus.casc.internal.model.TaskVO;
import io.github.asharapov.nexus.casc.internal.utils.NexusAPI;
import io.github.asharapov.nexus.casc.internal.utils.NexusServer;
import io.qameta.allure.Description;
import io.qameta.allure.model.Status;
import okhttp3.RequestBody;
import okhttp3.ResponseBody;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.opentest4j.AssertionFailedError;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.yaml.snakeyaml.Yaml;
import retrofit2.Response;

import javax.inject.Inject;
import java.io.BufferedReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.TimeZone;
import java.util.TreeMap;

import static io.github.asharapov.nexus.casc.internal.model.Config.ExecutionPolicy.ALWAYS;
import static io.github.asharapov.nexus.casc.internal.utils.TestUtils.APPLICATION_JSON;
import static io.github.asharapov.nexus.casc.internal.utils.TestUtils.YAML_TYPE;
import static io.github.asharapov.nexus.casc.internal.utils.TestUtils.call;
import static io.qameta.allure.Allure.step;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Testing the system configuration of the Sonatype Nexus.
 *
 * @author Anton Sharapov
 */
@IntegrationTest
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@Tag("system")
public class SystemConfigIT {
    private static final Logger log = LoggerFactory.getLogger(SystemConfigIT.class);

    @Inject
    private Yaml yaml;
    @Inject
    private NexusServer nexusServer;
    private NexusAPI api;

    @BeforeEach
    void beforeEachTest() {
        api = nexusServer.getAdminAPI();
    }

    @Test
    @Order(1)
    @Description("Check nexus rest api is available to user with administrator role")
    void testStandardApiAccess() throws Exception {
        assertTrue(api.checkStatus().execute().isSuccessful());
    }

    @Test
    @Order(2)
    @Description("Checking the capabilities of the CASC plugin API to get the current Nexus settings")
    void testGetCascApiConfiguration() {
        step("Mode that does not provide information about immutable or system objects", () -> {
            final Config cfg = getCurrentConfiguration(false);
            assertNotNull(cfg.metadata, "'metadata' property should be specified");
            assertNotNull(cfg.metadata.version, "'metadata.version' property should be specified");
            assertNotNull(cfg.metadata.executionPolicy, "'metadata.executionPolicy' property should be specified");
            assertNotNull(cfg.systemConfig, "'systemConfig' property should be specified");
            assertNotNull(cfg.securityConfig, "'securityConfig' property should be specified");
            assertNotNull(cfg.repositoryConfig, "'repositoryConfig' property should be specified");
            assertNotNull(cfg.securityConfig.roles, "'securityConfig.roles' property should be specified");
            assertNotNull(cfg.securityConfig.users, "'securityConfig.users' property should be specified");
            assertTrue(cfg.securityConfig.users.size() > 0);
            assertNotNull(cfg.repositoryConfig.blobStores, "'repositoryConfig.blobStores' property should be specified");
            assertNotNull(cfg.repositoryConfig.repositories, "'repositoryConfig.repositories' property should be specified");
            assertFalse(
                    cfg.systemConfig.tasks.stream().anyMatch(t -> !t.exposed),
                    "System tasks found");
            assertFalse(
                    cfg.securityConfig.privileges.stream().anyMatch(p -> p.readOnly),
                    "Non modifiable privileges found");
            assertFalse(
                    cfg.securityConfig.roles.stream().anyMatch(r -> r.readOnly),
                    "Non modifiable user roles found");
            assertFalse(
                    cfg.securityConfig.users.stream().anyMatch(u -> u.readOnly),
                    "Non modifiable users found");
        });
        step("Mode that provides information about immutable and system objects", () -> {
            final Config cfg = getCurrentConfiguration(true);
            assertNotNull(cfg.metadata, "'metadata' property should be specified");
            assertNotNull(cfg.metadata.version, "'metadata.version' property should be specified");
            assertNotNull(cfg.metadata.executionPolicy, "'metadata.executionPolicy' property should be specified");
            assertNotNull(cfg.systemConfig, "'systemConfig' property should be specified");
            assertNotNull(cfg.securityConfig, "'securityConfig' property should be specified");
            assertNotNull(cfg.repositoryConfig, "'repositoryConfig' property should be specified");
            assertNotNull(cfg.securityConfig.roles, "'securityConfig.roles' property should be specified");
            assertNotNull(cfg.securityConfig.users, "'securityConfig.users' property should be specified");
            assertTrue(cfg.securityConfig.users.size() > 0);
            assertNotNull(cfg.repositoryConfig.blobStores, "'repositoryConfig.blobStores' property should be specified");
            assertNotNull(cfg.repositoryConfig.repositories, "'repositoryConfig.repositories' property should be specified");
            assertTrue(
                    cfg.systemConfig.tasks.stream().anyMatch(t -> !t.exposed),
                    "No system tasks found");
            assertTrue(
                    cfg.securityConfig.privileges.stream().anyMatch(p -> p.readOnly),
                    "No system privileges found");
        });
    }


    @Test
    @Order(3)
    @Description("Checking the capabilities of the CASC plugin API to HTTP settings configuration")
    void testHttp() {
        final Config cfg1 = new Config(ALWAYS);
        step("1. Create a new configuration, fill in all the properties associated with the HTTP settings, and apply them on the server", () -> {
            cfg1.systemConfig = new SystemConfig();
            cfg1.systemConfig.baseUrl = "http://localhost:" + nexusServer.getMappedPort(8081);
            cfg1.systemConfig.connRetries = 3;
            cfg1.systemConfig.connTimeout = 30;
            cfg1.systemConfig.userAgentFragment = "test";
            cfg1.systemConfig.httpProxy = new SystemConfig.Proxy("proxyhost", 3001, new SystemConfig.ProxyAuthentication("usr1", "pwd1"), true);
            cfg1.systemConfig.httpsProxy = new SystemConfig.Proxy("proxyhost", 3002, new SystemConfig.ProxyAuthentication("usr1", "pwd1"), true);
            cfg1.systemConfig.nonProxyHosts = Arrays.asList("localhost", nexusServer.getInternalHostName());
            final boolean modified = applyNewConfiguration(cfg1);
            assertTrue(modified, "The passed settings should be applied on the server");
        });
        step("Get the current configuration from the server and compare the HTTP settings with those sent earlier", () -> {
            final Config cfg = getCurrentConfiguration();
            assertNotNull(cfg.systemConfig);
            assertEquals(cfg1.systemConfig.baseUrl, cfg.systemConfig.baseUrl, "Unexpected 'systemConfig.baseUrl' property value");
            assertEquals(cfg1.systemConfig.connRetries, cfg.systemConfig.connRetries, "Unexpected 'systemConfig.connRetries' property value");
            assertEquals(cfg1.systemConfig.connTimeout, cfg.systemConfig.connTimeout, "Unexpected 'systemConfig.connTimeout' property value");
            assertEquals(cfg1.systemConfig.userAgentFragment, cfg.systemConfig.userAgentFragment, "Unexpected 'systemConfig.userAgentFragment' property value");
            assertEquals(cfg1.systemConfig.httpProxy, cfg.systemConfig.httpProxy, "Unexpected 'systemConfig.httpProxy' property value");
            assertEquals(cfg1.systemConfig.httpsProxy, cfg.systemConfig.httpsProxy, "Unexpected 'systemConfig.httpsProxy' property value");
            assertEquals(cfg1.systemConfig.nonProxyHosts, cfg.systemConfig.nonProxyHosts, "Unexpected 'systemConfig.httpsProxy' property value");
        });

        final Config cfg2 = new Config(ALWAYS);
        step("2. Create a new configuration where should be changed only part of the HTTP settings and apply them on the server", () -> {
            cfg2.systemConfig = new SystemConfig();
            cfg2.systemConfig.connRetries = 4;
            cfg2.systemConfig.httpProxy = new SystemConfig.Proxy("proxyhost.example.org", 3001, new SystemConfig.ProxyAuthentication("user", "pwd1"), true);
            cfg2.systemConfig.httpsProxy = new SystemConfig.Proxy(null, 0, null, false);
            final boolean modified = applyNewConfiguration(cfg2);
            assertTrue(modified, "The passed settings should be applied on the server");
        });
        step("Get the current configuration from the server and compare the HTTP settings with those sent earlier", () -> {
            final Config cfg = getCurrentConfiguration();
            assertNotNull(cfg.systemConfig);
            assertEquals(cfg1.systemConfig.baseUrl, cfg.systemConfig.baseUrl, "Unexpected 'systemConfig.baseUrl' property value");
            assertEquals(cfg2.systemConfig.connRetries, cfg.systemConfig.connRetries, "Unexpected 'systemConfig.connRetries' property value");
            assertEquals(cfg1.systemConfig.connTimeout, cfg.systemConfig.connTimeout, "Unexpected 'systemConfig.connTimeout' property value");
            assertEquals(cfg1.systemConfig.userAgentFragment, cfg.systemConfig.userAgentFragment, "Unexpected 'systemConfig.userAgentFragment' property value");
            assertEquals(cfg2.systemConfig.httpProxy, cfg.systemConfig.httpProxy, "Unexpected 'systemConfig.httpProxy' property value");
            assertNull(cfg.systemConfig.httpsProxy, "Unexpected 'systemConfig.httpsProxy' property value");
            assertEquals(cfg1.systemConfig.nonProxyHosts, cfg.systemConfig.nonProxyHosts, "Unexpected 'systemConfig.nonProxyHosts' property value");
        });

        final Config cfg3 = new Config(ALWAYS);
        step("3. Create an invalid configuration where HTTPS proxy specified without HTTP proxy and make attempt to apply them on the server", () -> {
            cfg3.systemConfig = new SystemConfig();
            cfg3.systemConfig.httpProxy = new SystemConfig.Proxy(null, 0, null, false);
            cfg3.systemConfig.httpsProxy = new SystemConfig.Proxy("proxyhost.example.org", 3001, new SystemConfig.ProxyAuthentication("user", "pwd1"), true);
            Assertions.assertThrows(Throwable.class, () -> applyNewConfiguration(cfg3), "HTTPS proxy specified without specifying HTTP proxy");
            // Confirm that the configuration has not changed ...
            final Config cfg = getCurrentConfiguration();
            assertNotNull(cfg.systemConfig);
            assertEquals(cfg1.systemConfig.baseUrl, cfg.systemConfig.baseUrl, "Unexpected 'systemConfig.baseUrl' property value");
            assertEquals(cfg2.systemConfig.connRetries, cfg.systemConfig.connRetries, "Unexpected 'systemConfig.connRetries' property value");
            assertEquals(cfg1.systemConfig.connTimeout, cfg.systemConfig.connTimeout, "Unexpected 'systemConfig.connTimeout' property value");
            assertEquals(cfg1.systemConfig.userAgentFragment, cfg.systemConfig.userAgentFragment, "Unexpected 'systemConfig.userAgentFragment' property value");
            assertNull(cfg.systemConfig.httpProxy, "Unexpected 'systemConfig.httpProxy' property value");
            assertNull(cfg.systemConfig.httpsProxy, "Unexpected 'systemConfig.httpsProxy' property value");
            assertNull(cfg.systemConfig.nonProxyHosts, "Unexpected 'systemConfig.nonProxyHosts' property value");
        });
    }


    @Test
    @Order(4)
    @Description("Checking the capabilities of the CASC plugin API to smtp settings configuration")
    void testSmtpServerIntegration() {
        final Map<String, String> settings = loadTestEmailSettings();
        final SystemConfig.SmtpServer smtp = new SystemConfig.SmtpServer();
        smtp.host = settings.getOrDefault("smtp.host", "smtp.mail.ru");
        smtp.port = Integer.parseInt(settings.getOrDefault("smtp.port", "465"));
        smtp.userName = settings.getOrDefault("smtp.userName", "testusr2020@mail.ru");
        smtp.password = settings.getOrDefault("smtp.password", "******");
        smtp.fromAddress = settings.getOrDefault("smtp.fromAddress", "testusr2020@mail.ru");
        smtp.subjectPrefix = "NEXUS";
        smtp.sslOnConnectEnabled = true;
        smtp.sslCheckServerIdentityEnabled = false;
        smtp.startTlsEnabled = false;
        smtp.startTlsRequired = false;
        smtp.nexusTrustStoreEnabled = false;

        step("1. Create a new configuration, fill in all the properties associated with the Email settings, and apply them on the server", () -> {
            final Config cfg = new Config(ALWAYS);
            cfg.systemConfig = new SystemConfig();
            cfg.systemConfig.smtp = smtp;
            final boolean modified = applyNewConfiguration(cfg);
            assertTrue(modified, "The passed settings should be applied on the server");
        });
        step("Get the current configuration using CASC plugin api and compare the Email settings with those sent earlier", () -> {
            final Config cfg = getCurrentConfiguration();
            assertNotNull(cfg.systemConfig);
            assertNotNull(cfg.systemConfig.smtp);
            assertEquals(false, cfg.systemConfig.smtp.enabled, "Unexpected 'systemConfig.smtp.enabled' property value");
            assertEquals(smtp.host, cfg.systemConfig.smtp.host, "Unexpected 'systemConfig.smtp.host' property value");
            assertEquals(smtp.port, cfg.systemConfig.smtp.port, "Unexpected 'systemConfig.smtp.port' property value");
            assertEquals(smtp.userName, cfg.systemConfig.smtp.userName, "Unexpected 'systemConfig.smtp.userName' property value");
            assertEquals(smtp.password, cfg.systemConfig.smtp.password, "Unexpected 'systemConfig.smtp.password' property value");
            assertEquals(smtp.fromAddress, cfg.systemConfig.smtp.fromAddress, "Unexpected 'systemConfig.smtp.fromAddress' property value");
            assertEquals(smtp.subjectPrefix, cfg.systemConfig.smtp.subjectPrefix, "Unexpected 'systemConfig.smtp.subjectPrefix' property value");
            assertEquals(smtp.sslOnConnectEnabled, cfg.systemConfig.smtp.sslOnConnectEnabled, "Unexpected 'systemConfig.smtp.sslOnConnectEnabled' property value");
            assertEquals(smtp.sslCheckServerIdentityEnabled, cfg.systemConfig.smtp.sslCheckServerIdentityEnabled, "Unexpected 'systemConfig.smtp.sslCheckServerIdentityEnabled' property value");
            assertEquals(smtp.startTlsEnabled, cfg.systemConfig.smtp.startTlsEnabled, "Unexpected 'systemConfig.smtp.startTlsEnabled' property value");
            assertEquals(smtp.startTlsRequired, cfg.systemConfig.smtp.startTlsRequired, "Unexpected 'systemConfig.smtp.startTlsRequired' property value");
            assertEquals(smtp.nexusTrustStoreEnabled, cfg.systemConfig.smtp.nexusTrustStoreEnabled, "Unexpected 'systemConfig.smtp.nexusTrustStoreEnabled' property value");
        });
        step("Get the current configuration using standard Nexus REST API and compare the Email settings with those sent earlier", () -> {
            final EmailVO email = call(api.getEmail());
            assertNotNull(email);
            assertFalse(email.enabled, "Unexpected 'systemConfig.smtp.enabled' property value");
            assertEquals(smtp.host, email.host, "Unexpected 'systemConfig.smtp.host' property value");
            assertEquals(smtp.port, email.port, "Unexpected 'systemConfig.smtp.port' property value");
            assertEquals(smtp.userName, email.username, "Unexpected 'systemConfig.smtp.userName' property value");
            assertNull(email.password, "Unexpected 'systemConfig.smtp.password' property value");
            assertEquals(smtp.fromAddress, email.fromAddress, "Unexpected 'systemConfig.smtp.fromAddress' property value");
            assertEquals(smtp.subjectPrefix, email.subjectPrefix, "Unexpected 'systemConfig.smtp.subjectPrefix' property value");
            assertEquals(smtp.sslOnConnectEnabled, email.sslOnConnectEnabled, "Unexpected 'systemConfig.smtp.sslOnConnectEnabled' property value");
            assertEquals(smtp.sslCheckServerIdentityEnabled, email.sslServerIdentityCheckEnabled, "Unexpected 'systemConfig.smtp.sslCheckServerIdentityEnabled' property value");
            assertEquals(smtp.startTlsEnabled, email.startTlsEnabled, "Unexpected 'systemConfig.smtp.startTlsEnabled' property value");
            assertEquals(smtp.startTlsRequired, email.startTlsRequired, "Unexpected 'systemConfig.smtp.startTlsRequired' property value");
            assertEquals(smtp.nexusTrustStoreEnabled, email.nexusTrustStoreEnabled, "Unexpected 'systemConfig.smtp.nexusTrustStoreEnabled' property value");
        });

        if (settings.containsKey("smtp.password")) {
            step("Send a test email to the email address provided in the property 'smtp.email.verify' of file 'test-email.properties'", () -> {
                final String email = settings.getOrDefault("smtp.email.verify", settings.getOrDefault("smtp.fromAddress", settings.get("smtp.userName")));
                final RequestBody reqBody = RequestBody.create(APPLICATION_JSON, email);
                final Response<ResultVO> response = api.verifyEmail(reqBody).execute();
                if (!response.isSuccessful()) {
                    final ResponseBody body = response.errorBody();
                    Assertions.fail("Sending test email was failed:\n" + (body != null ? body.string() : ""));
                }
                final ResultVO result = response.body();
                assertNotNull(result);
                assertTrue(result.success, result.reason);
            });
        } else {
            step("Send a test email to the email address provided in the property 'smtp.email.verify' of file 'test-email.properties'", Status.SKIPPED);
        }

        step("2. Create a new configuration where should be changed only part of the Email settings and apply them on the server", () -> {
            final Config cfg = new Config(ALWAYS);
            cfg.systemConfig = new SystemConfig();
            cfg.systemConfig.smtp = new SystemConfig.SmtpServer();
            cfg.systemConfig.smtp.enabled = true;
            cfg.systemConfig.smtp.subjectPrefix = "test nexus";
            final boolean modified = applyNewConfiguration(cfg);
            assertTrue(modified, "The passed settings should be applied on the server");
        });
        step("Get the current configuration from the server and compare the Email settings with those sent earlier", () -> {
            final Config cfg = getCurrentConfiguration();
            assertNotNull(cfg.systemConfig);
            assertNotNull(cfg.systemConfig.smtp);
            assertEquals(true, cfg.systemConfig.smtp.enabled, "Unexpected 'systemConfig.smtp.enabled' property value");
            assertEquals(smtp.host, cfg.systemConfig.smtp.host, "Unexpected 'systemConfig.smtp.host' property value");
            assertEquals(smtp.port, cfg.systemConfig.smtp.port, "Unexpected 'systemConfig.smtp.port' property value");
            assertEquals(smtp.userName, cfg.systemConfig.smtp.userName, "Unexpected 'systemConfig.smtp.userName' property value");
            assertEquals(smtp.password, cfg.systemConfig.smtp.password, "Unexpected 'systemConfig.smtp.password' property value");
            assertEquals(smtp.fromAddress, cfg.systemConfig.smtp.fromAddress, "Unexpected 'systemConfig.smtp.fromAddress' property value");
            assertEquals("test nexus", cfg.systemConfig.smtp.subjectPrefix, "Unexpected 'systemConfig.smtp.subjectPrefix' property value");
            assertEquals(smtp.sslOnConnectEnabled, cfg.systemConfig.smtp.sslOnConnectEnabled, "Unexpected 'systemConfig.smtp.sslOnConnectEnabled' property value");
            assertEquals(smtp.sslCheckServerIdentityEnabled, cfg.systemConfig.smtp.sslCheckServerIdentityEnabled, "Unexpected 'systemConfig.smtp.sslCheckServerIdentityEnabled' property value");
            assertEquals(smtp.startTlsEnabled, cfg.systemConfig.smtp.startTlsEnabled, "Unexpected 'systemConfig.smtp.startTlsEnabled' property value");
            assertEquals(smtp.startTlsRequired, cfg.systemConfig.smtp.startTlsRequired, "Unexpected 'systemConfig.smtp.startTlsRequired' property value");
            assertEquals(smtp.nexusTrustStoreEnabled, cfg.systemConfig.smtp.nexusTrustStoreEnabled, "Unexpected 'systemConfig.smtp.nexusTrustStoreEnabled' property value");
        });
    }


    @Test
    @Order(5)
    @Description("Checking the capabilities of the CASC plugin API to Sonatype Nexus IQ server integration")
    void testIqServerIntegration() {
        final String passwordPlaceholder = "#~NXRM~PLACEHOLDER~PASSWORD~#";
        final SystemConfig.IqServer server = new SystemConfig.IqServer();
        server.enabled = true;
        server.url = "http://iq:8070";
        server.username = "admin";
        server.password = "admin123";
        server.authType = SystemConfig.IqAuthType.USER;
        server.attrs = new TreeMap<>();
        server.attrs.put("attr1", "val1");
        server.showLink = true;
        server.useTrustStore = false;
        server.timeout = 10;
        step("1. Configure new connection settings to IQ server", () -> {
            step("Apply configuration on the server", () -> {
                final Config cfg = new Config(ALWAYS);
                cfg.systemConfig = new SystemConfig();
                cfg.systemConfig.iq = server;
                assertTrue(applyNewConfiguration(cfg), "The passed settings should be applied on the server");
            });
            step("Check configuration using CASC plugin's API", () -> {
                final Config cfg = getCurrentConfiguration();
                assertNotNull(cfg.systemConfig);
                assertNotNull(cfg.systemConfig.iq);
                final SystemConfig.IqServer iq = cfg.systemConfig.iq;
                assertEquals(server.enabled, iq.enabled, "Unexpected iq server integration status");
                assertEquals(server.url, iq.url, "Unexpected iq server url");
                assertEquals(server.username, iq.username, "Unexpected iq server username");
                assertEquals(server.password, iq.password, "Unexpected iq server password");
                assertEquals(server.authType, iq.authType, "Unexpected iq server auth type");
                assertEquals(server.showLink, iq.showLink, "Unexpected iq server showLink option");
                assertEquals(server.useTrustStore, iq.useTrustStore, "Unexpected iq server useTrustStore option");
                assertEquals(server.timeout, iq.timeout, "Unexpected iq server connection timeout");
                assertEquals(server.attrs, iq.attrs, "Unexpected iq server properties");
            });
            step("Check applied configuration using standard Nexus API", () -> {
                final IqConnectionVO iq = call(api.getIqConnection());
                assertNotNull(iq);
                assertEquals(server.enabled, iq.enabled, "Unexpected iq server integration status");
                assertEquals(server.url, iq.url, "Unexpected iq server url");
                assertEquals(server.username, iq.username, "Unexpected iq server username");
                assertEquals(passwordPlaceholder, iq.password, "Unexpected iq server password (mask)");
                assertNotNull(iq.authenticationType, "Iq server auth type not specified");
                assertEquals(server.authType.name(), iq.authenticationType.name(), "Unexpected iq server auth type");
                assertEquals(server.showLink == Boolean.TRUE, iq.showLink, "Unexpected iq server showLink option");
                assertEquals(server.useTrustStore == Boolean.TRUE, iq.useTrustStoreForUrl, "Unexpected iq server useTrustStore option");
                assertEquals(server.timeout, iq.timeoutSeconds, "Unexpected iq server connection timeout");
                assertEquals(server.attrs, iq.parseProperties(), "Unexpected iq server properties");
            });
        });
        step("2. Update some parameters of the connection to IQ server", () -> {
            final SystemConfig.IqServer server1 = new SystemConfig.IqServer();
            server1.enabled = false;
            server1.showLink = true;
            server1.attrs = new TreeMap<>();
            server1.attrs.put("attr2", "val2");
            server1.attrs.put("attr3", "val3");
            step("Apply configuration on the server", () -> {
                final Config cfg = new Config(ALWAYS);
                cfg.systemConfig = new SystemConfig();
                cfg.systemConfig.iq = server1;
                assertTrue(applyNewConfiguration(cfg), "The passed settings should be applied on the server");
            });
            step("Check configuration using CASC plugin's API", () -> {
                final Config cfg = getCurrentConfiguration();
                assertNotNull(cfg.systemConfig);
                assertNotNull(cfg.systemConfig.iq);
                final SystemConfig.IqServer iq = cfg.systemConfig.iq;
                assertEquals(server1.enabled, iq.enabled, "Unexpected iq server integration status");
                assertEquals(server.url, iq.url, "Unexpected iq server url");
                assertEquals(server.username, iq.username, "Unexpected iq server username");
                assertEquals(server.password, iq.password, "Unexpected iq server password");
                assertEquals(server.authType, iq.authType, "Unexpected iq server auth type");
                assertEquals(server1.showLink, iq.showLink, "Unexpected iq server showLink option");
                assertEquals(server.useTrustStore, iq.useTrustStore, "Unexpected iq server useTrustStore option");
                assertEquals(server.timeout, iq.timeout, "Unexpected iq server connection timeout");
                assertEquals(server1.attrs, iq.attrs, "Unexpected iq server properties");
            });
            step("Check applied configuration using standard Nexus API", () -> {
                final IqConnectionVO iq = call(api.getIqConnection());
                assertNotNull(iq);
                assertEquals(server1.enabled, iq.enabled, "Unexpected iq server integration status");
                assertEquals(server.url, iq.url, "Unexpected iq server url");
                assertEquals(server.username, iq.username, "Unexpected iq server username");
                assertEquals(passwordPlaceholder, iq.password, "Unexpected iq server password (mask)");
                assertNotNull(iq.authenticationType, "Iq server auth type not specified");
                assertEquals(server.authType.name(), iq.authenticationType.name(), "Unexpected iq server auth type");
                assertEquals(server1.showLink == Boolean.TRUE, iq.showLink, "Unexpected iq server showLink option");
                assertEquals(server.useTrustStore == Boolean.TRUE, iq.useTrustStoreForUrl, "Unexpected iq server useTrustStore option");
                assertEquals(server.timeout, iq.timeoutSeconds, "Unexpected iq server connection timeout");
                assertEquals(server1.attrs, iq.parseProperties(), "Unexpected iq server properties");
            });
        });
    }


    @Test
    @Order(6)
    @Description("Checking the CASC plugin API to configuring Sonatype Nexus capabilities")
    void testCapabilities() {
        step("1. Fill all properties associated with the selected capabilities settings, and apply them on the server", () -> {
            final SystemConfig.Capability cpb1 = new SystemConfig.Capability();
            cpb1.type = "rapture.settings";
            cpb1.notes = "Update default session timeouts";
            cpb1.attrs = new HashMap<>();
            cpb1.attrs.put("title", "Nexus Repository Manager 3");
            cpb1.attrs.put("longRequestTimeout", "180");
            cpb1.attrs.put("requestTimeout", "60");
            cpb1.attrs.put("statusIntervalAnonymous", "60");
            cpb1.attrs.put("statusIntervalAuthenticated", "5");
            cpb1.attrs.put("sessionTimeout", "300");
            cpb1.attrs.put("searchRequestTimeout", "0");
            cpb1.attrs.put("debugAllowed", "true");
            final SystemConfig.Capability cpb2 = new SystemConfig.Capability();
            cpb2.type = "OutreachManagementCapability";
            cpb2.notes = "Disable the survey on the main page";
            cpb2.enabled = false;

            final Config cfg = new Config(ALWAYS);
            cfg.systemConfig = new SystemConfig();
            cfg.systemConfig.capabilities = Arrays.asList(cpb1, cpb2);
            final boolean modified = applyNewConfiguration(cfg);
            assertTrue(modified, "The passed settings should be applied on the server");
        });
        step("Get the current configuration using CASC plugin API and compare the capabilities settings with those sent earlier", () -> {
            final Config cfg = getCurrentConfiguration();
            assertNotNull(cfg.systemConfig);
            assertNotNull(cfg.systemConfig.capabilities);
            final SystemConfig.Capability cpb1 = cfg.systemConfig.capabilities.stream()
                    .filter(c -> "rapture.settings".equals(c.type))
                    .findFirst()
                    .orElseThrow(() -> new AssertionFailedError("Capability 'rapture.settings' not found"));
            assertEquals("Nexus Repository Manager 3", cpb1.attrs.get("title"));
            assertEquals("180", cpb1.attrs.get("longRequestTimeout"));
            assertEquals("60", cpb1.attrs.get("requestTimeout"));
            assertEquals("60", cpb1.attrs.get("statusIntervalAnonymous"));
            assertEquals("5", cpb1.attrs.get("statusIntervalAuthenticated"));
            assertEquals("300", cpb1.attrs.get("sessionTimeout"));
            assertEquals("0", cpb1.attrs.get("searchRequestTimeout"));
            assertEquals("true", cpb1.attrs.get("debugAllowed"));
            assertEquals(8, cpb1.attrs.size(), "Unexpected properties " + cpb1.attrs + " found for capability 'rapture.settings'");
            final SystemConfig.Capability cpb2 = cfg.systemConfig.capabilities.stream()
                    .filter(c -> "OutreachManagementCapability".equals(c.type))
                    .findFirst()
                    .orElseThrow(() -> new AssertionFailedError("Capability 'OutreachManagementCapability' not found"));
            assertEquals(false, cpb2.enabled);
            assertTrue(cpb2.attrs == null || cpb2.attrs.isEmpty(), "Unexpected properties " + cpb2.attrs + " found for capability 'OutreachManagementCapability'");
        });

        step("2. Fill some properties associated with the selected capability, and apply them on the server", () -> {
            final SystemConfig.Capability cpb1 = new SystemConfig.Capability();
            cpb1.type = "rapture.settings";
            cpb1.notes = "Update default session timeouts";
            cpb1.attrs = new HashMap<>();
            cpb1.attrs.put("title", "The Nexus");

            final Config cfg = new Config(ALWAYS);
            cfg.systemConfig = new SystemConfig();
            cfg.systemConfig.capabilities = Collections.singletonList(cpb1);
            final boolean modified = applyNewConfiguration(cfg);
            assertTrue(modified, "The passed settings should be applied on the server");
        });
        step("Get the current configuration using CASC plugin api and compare the capabilities settings with those sent earlier. Omitted properties should have their default values", () -> {
            final Config cfg = getCurrentConfiguration();
            assertNotNull(cfg.systemConfig);
            assertNotNull(cfg.systemConfig.capabilities);
            final SystemConfig.Capability cpb1 = cfg.systemConfig.capabilities.stream()
                    .filter(c -> "rapture.settings".equals(c.type))
                    .findFirst()
                    .orElseThrow(() -> new AssertionFailedError("Capability 'rapture.settings' not found"));
            assertEquals("The Nexus", cpb1.attrs.get("title"));
            assertEquals("30", cpb1.attrs.get("sessionTimeout"));   // default session timeout
            assertEquals("180", cpb1.attrs.get("longRequestTimeout"));
            assertEquals("60", cpb1.attrs.get("requestTimeout"));
            assertEquals("60", cpb1.attrs.get("statusIntervalAnonymous"));
            assertEquals("5", cpb1.attrs.get("statusIntervalAuthenticated"));
            assertNull(cpb1.attrs.get("searchRequestTimeout"));     // default value for this property not specified
            assertEquals("true", cpb1.attrs.get("debugAllowed"));
            assertEquals(7, cpb1.attrs.size(), "Unexpected properties " + cpb1.attrs + " found for capability 'rapture.settings'");
        });

        step("3. Create an invalid configuration of the selected capability, and make attempt to apply them on the server", () -> {
            final SystemConfig.Capability cpb1 = new SystemConfig.Capability();
            cpb1.type = "rapture.settings";
            cpb1.notes = "Update default session timeouts";
            cpb1.attrs = new HashMap<>();
            cpb1.attrs.put("requestTimeout", "bad value");

            final Config cfg3 = new Config(ALWAYS);
            cfg3.systemConfig = new SystemConfig();
            cfg3.systemConfig.capabilities = Collections.singletonList(cpb1);
            Assertions.assertThrows(Throwable.class, () -> applyNewConfiguration(cfg3), "Invalid capabilities settings");
        });
    }


    @Test
    @Order(7)
    @Description("Checking the capabilities of the CASC plugin API for tasks scheduling")
    void testTasks() {
        final Map<String, String> emailSettings = loadTestEmailSettings();
        final SystemConfig.Task task1 = new SystemConfig.Task();
        task1.type = "casc.export";
        task1.name = "CASC - configuration export";
        task1.message = "configuration export message";
        task1.visible = true;
        task1.exposed = true;
        task1.recoverable = false;
        task1.alertEmail = emailSettings.getOrDefault("smtp.email.verify", emailSettings.getOrDefault("smtp.userName", "testusr2020@mail.ru"));
        task1.alertCondition = SystemConfig.TaskAlertCondition.FAILURE;
        task1.attrs = new HashMap<>();
        task1.attrs.put("casc.export.empty-properties", "false");
        task1.attrs.put("casc.export.empty-collections", "true");                   // default value
        task1.attrs.put("casc.export.hidden-tasks", "true");
        task1.attrs.put("casc.export.readonly-objects", "true");
        task1.attrs.put("casc.export.path", "/nexus-data/casc/export/nexus.yml");   // default value
        task1.schedule = new SystemConfig.TaskSchedule();
        task1.schedule.type = SystemConfig.ScheduleType.weekly;
        task1.schedule.startAt = Date.from(ZonedDateTime.of(2020, 1, 1, 8, 0, 0, 0, ZoneId.of("UTC")).toInstant());
        task1.schedule.weekDaysToRun = Arrays.asList(SystemConfig.Weekday.MON, SystemConfig.Weekday.THU);

        step("1. Checking the plugin's ability to schedule new tasks", () -> {
            step("Schedule new task using CASC plugin API", () -> {
                final Config cfg = new Config(ALWAYS);
                cfg.systemConfig = new SystemConfig();
                cfg.systemConfig.tasks = Collections.singletonList(task1);
                final boolean modified = applyNewConfiguration(cfg);
                assertTrue(modified, "The passed settings should be applied on the server");
            });
            step("Get the current configuration using CASC plugin api and compare the tasks settings with those sent earlier", () -> {
                final Config cfg = getCurrentConfiguration();
                assertNotNull(cfg.systemConfig);
                assertNotNull(cfg.systemConfig.tasks);
                final SystemConfig.Task task = cfg.systemConfig.tasks.stream()
                        .filter(t -> task1.type.equals(t.type) && task1.name.equals(t.name))
                        .findFirst()
                        .orElseThrow(() -> new AssertionFailedError("Task {type:'" + task1.type + "', name:'" + task1.name + "'} was not found"));
                assertEquals(task1.message, task.message, "Unexpected task message");
                assertEquals(task1.visible, task.visible, "Unexpected value of the 'visible' property");
                assertEquals(task1.exposed, task.exposed, "Unexpected value of the 'exposed' property");
                assertEquals(task1.recoverable, task.recoverable, "Unexpected value of the 'recoverable' property");
                assertEquals(task1.alertEmail, task.alertEmail, "Unexpected value of the 'alertEmail' property");
                assertEquals(task1.alertCondition, task.alertCondition, "Unexpected value of the 'alertCondition' property");
                assertEquals(task1.attrs, task.attrs, "Unexpected task attributes");
                assertNotNull(task.schedule, "No task schedule specified");
                assertEquals(task1.schedule.type, task.schedule.type, "Unexpected task schedule type");
                assertEquals(task1.schedule.startAt, task.schedule.startAt, "Unexpected task schedule 'startAt' property'");
                assertEquals(task1.schedule.weekDaysToRun, task.schedule.weekDaysToRun, "Unexpected task schedule 'weekDaysToRun' property'");
            });
            step("Get the current tasks configuration using standard Nexus REST API and compare it with the ones were sent earlier", () -> {
                final TaskListVO taskList = call(api.getTasks());
                assertNotNull(taskList);
                assertNotNull(taskList.items);
                final TaskVO task = taskList.items.stream()
                        .filter(t -> task1.type.equals(t.type) && task1.name.equals(t.name))
                        .findFirst()
                        .orElseThrow(() -> new AssertionFailedError("Task {type:'" + task1.type + "', name:'" + task1.name + "'} was not found"));
                assertEquals(task1.message, task.message, "Unexpected task message");
                assertEquals(2, taskList.items.size(), "Unexpected tasks count");
            });
        });
        step("2. Checking the plugin's ability to update and reschedule existing tasks", () -> {
            step("Update some characteristics of the task using CASC plugin API", () -> {
                task1.attrs.put("casc.export.empty-properties", "false");
                task1.schedule.type = SystemConfig.ScheduleType.manual;
                task1.schedule.startAt = null;
                task1.schedule.weekDaysToRun = null;
                final Config cfg = new Config(ALWAYS);
                cfg.systemConfig = new SystemConfig();
                cfg.systemConfig.tasks = Collections.singletonList(task1);
                assertTrue(applyNewConfiguration(cfg), "The passed settings should be applied on the server");
            });
            step("Get the current configuration using CASC plugin api and compare the tasks settings with those sent earlier", () -> {
                final Config cfg = getCurrentConfiguration();
                assertNotNull(cfg.systemConfig);
                assertNotNull(cfg.systemConfig.tasks);
                assertEquals(1, cfg.systemConfig.tasks.stream().filter(t -> task1.type.equals(t.type) && task1.name.equals(t.name)).count(), "Unexpected tasks count");
                final SystemConfig.Task task = cfg.systemConfig.tasks.stream()
                        .filter(t -> task1.type.equals(t.type) && task1.name.equals(t.name))
                        .findFirst()
                        .orElseThrow(() -> new AssertionFailedError("Task {type:'" + task1.type + "', name:'" + task1.name + "'} was not found"));
                assertEquals(task1.message, task.message, "Unexpected task message");
                assertEquals(task1.visible, task.visible, "Unexpected value of the 'visible' property");
                assertEquals(task1.exposed, task.exposed, "Unexpected value of the 'exposed' property");
                assertEquals(task1.recoverable, task.recoverable, "Unexpected value of the 'recoverable' property");
                assertEquals(task1.alertEmail, task.alertEmail, "Unexpected value of the 'alertEmail' property");
                assertEquals(task1.alertCondition, task.alertCondition, "Unexpected value of the 'alertCondition' property");
                assertEquals(task1.attrs, task.attrs, "Unexpected task attributes");
                assertNotNull(task.schedule, "No task schedule specified");
                assertEquals(task1.schedule.type, task.schedule.type, "Unexpected task schedule type");
                assertEquals(task1.schedule.startAt, task.schedule.startAt, "Unexpected task schedule 'startAt' property'");
                assertEquals(task1.schedule.weekDaysToRun, task.schedule.weekDaysToRun, "Unexpected task schedule 'weekDaysToRun' property'");
            });
        });
        step("3. Checking the plugin's ability to remove existing tasks", () -> {
            final SystemConfig.Task task2 = new SystemConfig.Task();
            task2.type = "casc.export";
            task2.name = "second copy of the task";
            task2.exposed = true;
            task2.visible = true;
            task2.recoverable = false;
            task2.schedule = new SystemConfig.TaskSchedule();
            task2.schedule.type = SystemConfig.ScheduleType.weekly;
            task2.schedule.startAt = new Date();
            task2.schedule.weekDaysToRun = Arrays.asList(SystemConfig.Weekday.MON, SystemConfig.Weekday.THU);
            final SystemConfig.Task task3 = new SystemConfig.Task();
            task3.type = "casc.export";
            task3.name = "third copy of the task";
            task3.exposed = true;
            task3.visible = true;
            task3.recoverable = false;
            task3.schedule = new SystemConfig.TaskSchedule();
            task3.schedule.type = SystemConfig.ScheduleType.monthly;
            task3.schedule.startAt = new Date();
            task3.schedule.monthDaysToRun = Arrays.asList(1, 8, 15, 22, 29);
            final SystemConfig.Task task4 = new SystemConfig.Task();
            task4.type = "casc.export";
            task4.name = "fourth copy of the task";
            task4.exposed = true;
            task4.visible = true;
            task4.recoverable = false;
            task4.schedule = new SystemConfig.TaskSchedule();
            task4.schedule.type = SystemConfig.ScheduleType.cron;
            task4.schedule.startAt = new Date();
            task4.schedule.timeZone = TimeZone.getDefault();
            task4.schedule.cronExpr = "0 0 1 * * ?";
            step("Scheduling new tasks", () -> {
                final Config cfg = new Config(ALWAYS);
                cfg.systemConfig = new SystemConfig();
                cfg.systemConfig.tasks = Arrays.asList(task2, task3, task4);
                assertTrue(applyNewConfiguration(cfg), "The passed settings should be applied on the server");
            });
            step("Make sure that tasks are registered", () -> {
                final Config cfg = getCurrentConfiguration();
                assertEquals(4,
                        cfg.systemConfig.tasks.stream().filter(t -> "casc.export".equals(t.type)).count(),
                        "Unexpected count of the 'casc.export' tasks");
                final TaskListVO taskList = call(api.getTasks());
                assertEquals(4,
                        taskList.items.stream().filter(t -> "casc.export".equals(t.type)).count(),
                        "Unexpected count of the 'casc.export' tasks");
            });
            step("Remove all exposed tasks except one", () -> {
                final Config cfg = new Config(ALWAYS);
                cfg.systemConfig = new SystemConfig();
                cfg.systemConfig.tasks = Collections.singletonList(task1);
                cfg.systemConfig.pruneOtherExposedTasks = true;
                assertTrue(applyNewConfiguration(cfg), "The passed settings should be applied on the server");
            });
            step("Make sure that all exposed tasks except the selected ones are removed", () -> {
                final Config cfg = getCurrentConfiguration();
                assertNotNull(cfg.systemConfig);
                assertNotNull(cfg.systemConfig.tasks);
                assertEquals(1,
                        cfg.systemConfig.tasks.stream().filter(t -> t.exposed).count(),
                        "Unexpected total count of the all exposed tasks");
                assertEquals(1,
                        cfg.systemConfig.tasks.stream()
                                .filter(t -> task1.type.equals(t.type) && task1.name.equals(t.name) && t.exposed)
                                .count(),
                        "Unexpected tasks count");
            });
        });
        step("4. Checking the work of the plugin's task (type: 'casc.export')", () -> {
            step("Check no previous results of this tasks exists", () -> {
                String text = nexusServer.getPluginTaskResult();
                assertNull(text);
            });
            step("Fire the task", () -> {
                final TaskListVO taskList = call(api.getTasks());
                final TaskVO task = taskList.items.stream()
                        .filter(t -> task1.type.equals(t.type) && task1.name.equals(t.name))
                        .findFirst()
                        .orElseThrow(() -> new AssertionFailedError("Task {type:'" + task1.type + "', name:'" + task1.name + "'} was not found"));
                final ResponseBody resp = call(api.fireTask(task.id));
                assertNull(resp);
            });
            step("Check the results of the task", () -> {
                Thread.sleep(5000);     // estimated time to perform task
                final String yamlText = nexusServer.getPluginTaskResult();
                assertNotNull(yamlText, "The 'casc.export' task result not found");
                final Config cfg = yaml.load(yamlText);
                assertNotNull(cfg);
            });
        });
    }


    private boolean applyNewConfiguration(final Config cfg) throws Exception {
        final String yamlText = yaml.dump(cfg);
        final RequestBody reqBody = RequestBody.create(YAML_TYPE, yamlText);
        final Response<ResponseBody> response = api.applyConfiguration(reqBody).execute();
        final ResponseBody respBody = response.isSuccessful() ? response.body() : response.errorBody();
        assertNotNull(respBody);
        final String result = respBody.string();
        assertTrue(response.isSuccessful(), "response from server:\n\n" + result);
        assertNotNull(result);
        switch (result) {
            case "modified":
                return true;
            case "not modified":
                return false;
            default:
                return Assertions.fail("Unexpected response from the server: '" + result + "'");
        }
    }

    private Config getCurrentConfiguration() throws Exception {
        return getCurrentConfiguration(false);
    }

    private Config getCurrentConfiguration(final boolean showReadonlyObjects) throws Exception {
        final ResponseBody respBody = call(api.getConfiguration(showReadonlyObjects));
        assertNotNull(respBody);
        final String text = respBody.string();
        assertNotNull(text);
        final Config cfg = yaml.load(text);
        assertNotNull(cfg);
        return cfg;
    }

    private static Map<String, String> loadTestEmailSettings() {
        try {
            final Path path = Paths.get("test-email.properties");
            if (!Files.isRegularFile(path)) {
                return Collections.emptyMap();
            }
            try (BufferedReader in = Files.newBufferedReader(path, StandardCharsets.UTF_8)) {
                final Map<String, String> result = new HashMap<>();
                in.lines().forEach(line -> {
                    line = line.trim();
                    if (!line.isEmpty() && !line.startsWith("#")) {
                        final int s = line.indexOf('=');
                        if (s > 0) {
                            final String key = line.substring(0, s);
                            final String value = line.substring(s + 1);
                            result.put(key, value);
                        }
                    }
                });
                return result;
            }
        } catch (IOException e) {
            log.error(e.getMessage(), e);
            return Collections.emptyMap();
        }
    }
}
