package io.github.asharapov.nexus.casc.internal;

import io.github.asharapov.nexus.casc.internal.junit.IntegrationTest;
import io.github.asharapov.nexus.casc.internal.model.AnonymousAccessVO;
import io.github.asharapov.nexus.casc.internal.model.BlobStoreVO;
import io.github.asharapov.nexus.casc.internal.model.CertificateVO;
import io.github.asharapov.nexus.casc.internal.model.Config;
import io.github.asharapov.nexus.casc.internal.model.ContentSelectorVO;
import io.github.asharapov.nexus.casc.internal.model.EmailVO;
import io.github.asharapov.nexus.casc.internal.model.LdapServerVO;
import io.github.asharapov.nexus.casc.internal.model.PrivilegeVO;
import io.github.asharapov.nexus.casc.internal.model.RealmVO;
import io.github.asharapov.nexus.casc.internal.model.RepositoryVO;
import io.github.asharapov.nexus.casc.internal.model.RoleVO;
import io.github.asharapov.nexus.casc.internal.model.RoutingRuleVO;
import io.github.asharapov.nexus.casc.internal.model.S3BlobStoreVO;
import io.github.asharapov.nexus.casc.internal.model.SecurityConfig;
import io.github.asharapov.nexus.casc.internal.model.TaskListVO;
import io.github.asharapov.nexus.casc.internal.model.UserVO;
import io.github.asharapov.nexus.casc.internal.utils.NexusAPI;
import io.github.asharapov.nexus.casc.internal.utils.NexusServer;
import io.github.asharapov.nexus.casc.internal.utils.TestUtils;
import io.qameta.allure.Description;
import okhttp3.MediaType;
import okhttp3.RequestBody;
import okhttp3.ResponseBody;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.yaml.snakeyaml.Yaml;
import retrofit2.Response;

import javax.inject.Inject;
import java.util.List;

import static io.github.asharapov.nexus.casc.internal.utils.TestUtils.call;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Testing the Sonatype Nexus REST API
 *
 * @author Anton Sharapov
 */
@IntegrationTest
@Tag("rest")
public class NexusApiIT {

    private static final Logger log = LoggerFactory.getLogger(NexusApiIT.class);

    @Inject
    private NexusServer nexusServer;
    private NexusAPI api;

    @BeforeEach
    void beforeEachTest() {
        final String defaultAdminPassword = nexusServer.getDefaultAdminPassword();
        api = nexusServer.getAPI("admin", defaultAdminPassword);
//        api = TestUtils.makeApi("localhost", 8081, "admin", "admin123");
    }

    @Test
    void testStatus() throws Exception {
        final Response<Void> response = api.checkStatus().execute();
        assertTrue(response.isSuccessful());
    }

    @Test
    void testEmail() throws Exception {
        final EmailVO email = call(api.getEmail());
        assertNotNull(email);
    }

    @Test
    void testAnonymousAccess() throws Exception {
        final AnonymousAccessVO result = call(api.getAnonymousStatus());
        assertNotNull(result);
    }

    @Test
    void testLdapServers() throws Exception {
        final List<LdapServerVO> result = call(api.getLdapServers());
        assertNotNull(result);
    }

    @Test
    void testRealms() throws Exception {
        final List<RealmVO> result = call(api.getAvailableRealms());
        assertNotNull(result);
        final List<String> activeRealms = call(api.getActiveRealmIds());
        assertNotNull(activeRealms);
    }

    @Test
    void testPrivileges() throws Exception {
        final List<PrivilegeVO> result = call(api.getPrivileges());
        assertNotNull(result);
    }

    @Test
    void testRoles() throws Exception {
        final List<RoleVO> result = call(api.getRoles(null));
        assertNotNull(result);
    }

    @Test
    void testUsers() throws Exception {
        final List<UserVO> result = call(api.getUsers(null, null));
        assertNotNull(result);
    }

    @Test
    void testTrustStoreCerts() throws Exception {
        final List<CertificateVO> result = call(api.getTrustedCertificates());
        assertNotNull(result);
    }

    @Test
    void testBlobStores() throws Exception {
        final List<BlobStoreVO> blobStores = call(api.getBlobStores());
        assertNotNull(blobStores);
        for (BlobStoreVO blobStore : blobStores) {
            if ("S3".equals(blobStore.type)) {
                final S3BlobStoreVO meta = call(api.getS3BlobStoreInfo(blobStore.name));
                assertNotNull(meta);
            }
        }
    }

    @Test
    void testContentSelectors() throws Exception {
        final List<ContentSelectorVO> result = call(api.getContentSelectors());
        assertNotNull(result);
    }

    @Test
    void testRoutingRules() throws Exception {
        final List<RoutingRuleVO> result = call(api.getRoutingRules());
        assertNotNull(result);
    }

    @Test
    void testRepositories() throws Exception {
        final List<RepositoryVO> result = call(api.getRepositories());
        assertNotNull(result);
    }

    @Test
    void testTasks() throws Exception {
        final TaskListVO taskList = call(api.getTasks());
        assertNotNull(taskList);
        assertNotNull(taskList.items);
    }

    @Test
    @Description("Checking the CASC plugin REST API to get all the service settings (short version)")
    void testGetConfiguration() throws Exception {
        final ResponseBody body = call(api.getConfiguration());
        assertNotNull(body);
        final String text = body.string();
        assertNotNull(text);
        final Yaml yaml = Utils.makeYaml(false, true);
        final Config cfg = yaml.load(text);
        assertNotNull(cfg);
        log.info("cfg = {}", cfg);
    }

    @Test
    @Description("Checking the CASC plugin REST API to get all the service settings (extended version)")
    void testGetConfiguration2() throws Exception {
        final ResponseBody body = call(api.getConfiguration(true));
        assertNotNull(body);
        final String text = body.string();
        assertNotNull(text);
        final Yaml yaml = Utils.makeYaml(false, true);
        final Config cfg = yaml.load(text);
        assertNotNull(cfg);
        log.info("cfg = {}", cfg);
    }

    @Test
    @Description("Checking the CASC plugin REST API to modify the service settings")
    void testPutConfiguration() throws Exception {
        final Config cfg = new Config();
        cfg.metadata = new Config.Metadata();
        cfg.metadata.executionPolicy = Config.ExecutionPolicy.IF_CHANGED;
        cfg.securityConfig = new SecurityConfig();
        cfg.securityConfig.anonymousAccess = false;
        final Yaml yaml = Utils.makeYaml(false, true);
        final String yamlText = yaml.dump(cfg);
        final Config cfg2 = yaml.load(yamlText);
        assertNotNull(cfg2);
        final MediaType yamlType = MediaType.get("text/vnd.yaml");
        final RequestBody rb1 = RequestBody.create(yamlType, yamlText);
        final Response<ResponseBody> response1 = api.applyConfiguration(rb1).execute();
        final ResponseBody body1 = response1.isSuccessful() ? response1.body() : response1.errorBody();
        assertNotNull(body1);
        log.info("body1 = {}", body1.string());

        final Response<ResponseBody> response2 = api.applyConfiguration(rb1).execute();
        final ResponseBody body2 = response2.isSuccessful() ? response2.body() : response1.errorBody();
        assertNotNull(body2);
        log.info("body2 = {}", body1.string());
    }
}
