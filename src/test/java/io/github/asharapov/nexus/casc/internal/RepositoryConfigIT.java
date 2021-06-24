package io.github.asharapov.nexus.casc.internal;

import io.github.asharapov.nexus.casc.internal.junit.IntegrationTest;
import io.github.asharapov.nexus.casc.internal.model.BlobStoreVO;
import io.github.asharapov.nexus.casc.internal.model.Config;
import io.github.asharapov.nexus.casc.internal.model.ContentSelectorVO;
import io.github.asharapov.nexus.casc.internal.model.RepositoryConfig;
import io.github.asharapov.nexus.casc.internal.model.RepositoryVO;
import io.github.asharapov.nexus.casc.internal.model.RoutingRuleVO;
import io.github.asharapov.nexus.casc.internal.model.S3BlobStoreVO;
import io.github.asharapov.nexus.casc.internal.utils.MinioServer;
import io.github.asharapov.nexus.casc.internal.utils.NexusAPI;
import io.github.asharapov.nexus.casc.internal.utils.NexusServer;
import io.github.asharapov.nexus.casc.internal.utils.TestUtils;
import io.qameta.allure.Description;
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
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

import static io.github.asharapov.nexus.casc.internal.model.Config.ExecutionPolicy.ALWAYS;
import static io.github.asharapov.nexus.casc.internal.model.RepositoryConfig.BlobStoreType.File;
import static io.github.asharapov.nexus.casc.internal.model.RepositoryConfig.BlobStoreType.S3;
import static io.github.asharapov.nexus.casc.internal.model.RepositoryConfig.RoutingMode.ALLOW;
import static io.github.asharapov.nexus.casc.internal.model.RepositoryConfig.RoutingMode.BLOCK;
import static io.github.asharapov.nexus.casc.internal.model.RepositoryVO.MavenAttrs.LayoutPolicy.PERMISSIVE;
import static io.github.asharapov.nexus.casc.internal.model.RepositoryVO.MavenAttrs.LayoutPolicy.STRICT;
import static io.github.asharapov.nexus.casc.internal.model.RepositoryVO.MavenAttrs.VersionPolicy.RELEASE;
import static io.github.asharapov.nexus.casc.internal.model.RepositoryVO.MavenAttrs.VersionPolicy.SNAPSHOT;
import static io.github.asharapov.nexus.casc.internal.model.RepositoryVO.Type.group;
import static io.github.asharapov.nexus.casc.internal.model.RepositoryVO.Type.hosted;
import static io.github.asharapov.nexus.casc.internal.model.RepositoryVO.Type.proxy;
import static io.github.asharapov.nexus.casc.internal.utils.TestUtils.call;
import static io.qameta.allure.Allure.step;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Testing the repositories configuration of the Sonatype Nexus.
 *
 * @author Anton Sharapov
 */
@IntegrationTest
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@Tag("repository")
public class RepositoryConfigIT {
    private static final Logger log = LoggerFactory.getLogger(RepositoryConfigIT.class);

    @Inject
    private Yaml yaml;
    @Inject
    private MinioServer minioServer;
    @Inject
    private NexusServer nexusServer;
    private NexusAPI api;

    @BeforeEach
    void beforeEachTest() {
        api = nexusServer.getAdminAPI();
    }

    @Test
    @Order(1)
    @Description("Checking the core capabilities of the CASC plugin for 'File' blob store management")
    void testFileBlobStores() {
        final RepositoryConfig.BlobStore dockerStore = new RepositoryConfig.BlobStore(File, "docker-store");
        dockerStore.putAttribute("file", "path", "docker");
        dockerStore.putAttribute("blobStoreQuotaConfig", "quotaLimitBytes", 536_870_912);
        dockerStore.putAttribute("blobStoreQuotaConfig", "quotaType", "spaceRemainingQuota");
        final RepositoryConfig.BlobStore mavenStore = new RepositoryConfig.BlobStore(File, "maven-store");
        mavenStore.putAttribute("file", "path", "maven");
        mavenStore.putAttribute("blobStoreQuotaConfig", "quotaLimitBytes", 1_073_741_824);
        mavenStore.putAttribute("blobStoreQuotaConfig", "quotaType", "spaceUsedQuota");
        final RepositoryConfig.BlobStore npmStore = new RepositoryConfig.BlobStore(File, "npm-store");
        npmStore.putAttribute("file", "path", "npm");

        step("1. Checking the plugin's ability to register new blob stores", () -> {
            step("Registering new blob stores", () -> {
                final Config cfg = new Config(ALWAYS);
                cfg.repositoryConfig = new RepositoryConfig();
                cfg.repositoryConfig.blobStores = Arrays.asList(dockerStore, mavenStore, npmStore);
                assertTrue(applyNewConfiguration(cfg), "The passed settings should be applied on the server");
            });
            step("Find registered blob stores using CASC plugin API", () -> {
                final Config cfg = getCurrentConfiguration();
                assertNotNull(cfg.repositoryConfig);
                assertNotNull(cfg.repositoryConfig.blobStores);
                assertTrue(cfg.repositoryConfig.blobStores.stream().anyMatch(s -> {
                            return s.type == File && "default".equals(s.name) &&
                                    "default".equals(s.attrs.getOrDefault("file", Collections.emptyMap()).get("path"));
                        }),
                        "Expected blob store 'default' not found");
                assertTrue(cfg.repositoryConfig.blobStores.stream().anyMatch(s -> {
                            return s.type == File && dockerStore.name.equals(s.name) && dockerStore.attrs.equals(s.attrs);
                        }),
                        "Expected blob store '" + dockerStore.name + "' not found");
                assertTrue(cfg.repositoryConfig.blobStores.stream().anyMatch(s -> {
                            return s.type == File && mavenStore.name.equals(s.name) && mavenStore.attrs.equals(s.attrs);
                        }),
                        "Expected blob store '" + mavenStore.name + "' not found");
                assertTrue(cfg.repositoryConfig.blobStores.stream().anyMatch(s -> {
                            return s.type == File && npmStore.name.equals(s.name) &&
                                    Objects.equals(npmStore.attrs.get("file"), s.attrs.get("file")) &&
                                    s.attrs.getOrDefault("blobStoreQuotaConfig", Collections.emptyMap()).isEmpty();
                        }),
                        "Expected blob store '" + npmStore.name + "' not found");
            });
            step("Find registered blob stores using standard Nexus REST API", () -> {
                final List<BlobStoreVO> blobstores = call(api.getBlobStores());
                assertNotNull(blobstores);
                assertTrue(blobstores.stream().anyMatch(s -> {
                            return "File".equals(s.type) && "default".equals(s.name);
                        }),
                        "Expected blob store 'default' not found");
                assertTrue(blobstores.stream().anyMatch(s -> {
                            return "File".equals(s.type) && dockerStore.name.equals(s.name) &&
                                    s.softQuota != null &&
                                    "spaceRemainingQuota".equals(s.softQuota.type) && s.softQuota.limit == 536_870_912;
                        }),
                        "Expected blob store '" + dockerStore.name + "' not found");
                assertTrue(blobstores.stream().anyMatch(s -> {
                            return "File".equals(s.type) && mavenStore.name.equals(s.name) &&
                                    s.softQuota != null &&
                                    "spaceUsedQuota".equals(s.softQuota.type) && s.softQuota.limit == 1_073_741_824;
                        }),
                        "Expected blob store '" + mavenStore.name + "' not found");
                assertTrue(blobstores.stream().anyMatch(s -> {
                            return "File".equals(s.type) && npmStore.name.equals(s.name) &&
                                    s.softQuota == null;
                        }),
                        "Expected blob store '" + npmStore.name + "' not found");
            });
        });
        step("2. Checking the plugin's ability to modify already registered blob stores", () -> {
            step("Update existed blob store", () -> {
                dockerStore.attrs = new HashMap<>();
                dockerStore.putAttribute("file", "path", "docker");
                npmStore.attrs = new HashMap<>();
                npmStore.putAttribute("file", "path", "npm");
                npmStore.putAttribute("blobStoreQuotaConfig", "quotaLimitBytes", 1_073_741_824);
                npmStore.putAttribute("blobStoreQuotaConfig", "quotaType", "spaceUsedQuota");
                final Config cfg = new Config(ALWAYS);
                cfg.repositoryConfig = new RepositoryConfig();
                cfg.repositoryConfig.blobStores = Arrays.asList(dockerStore, npmStore);
                assertTrue(applyNewConfiguration(cfg), "The passed settings should be applied on the server");
            });
            step("Find registered blob stores using CASC plugin API", () -> {
                final Config cfg = getCurrentConfiguration();
                assertNotNull(cfg.repositoryConfig);
                assertNotNull(cfg.repositoryConfig.blobStores);
                assertTrue(cfg.repositoryConfig.blobStores.stream().anyMatch(s -> {
                            return s.type == File && "default".equals(s.name) &&
                                    "default".equals(s.attrs.getOrDefault("file", Collections.emptyMap()).get("path"));
                        }),
                        "Expected blob store 'default' not found");
                assertTrue(cfg.repositoryConfig.blobStores.stream().anyMatch(s -> {
                            return s.type == File && dockerStore.name.equals(s.name) &&
                                    Objects.equals(dockerStore.attrs.get("file"), s.attrs.get("file")) &&
                                    s.attrs.getOrDefault("blobStoreQuotaConfig", Collections.emptyMap()).isEmpty();
                        }),
                        "Expected blob store '" + dockerStore.name + "' not found");
                assertTrue(cfg.repositoryConfig.blobStores.stream().anyMatch(s -> {
                            return s.type == File && mavenStore.name.equals(s.name) && mavenStore.attrs.equals(s.attrs);
                        }),
                        "Expected blob store '" + mavenStore.name + "' not found");
                assertTrue(cfg.repositoryConfig.blobStores.stream().anyMatch(s -> {
                            return s.type == File && npmStore.name.equals(s.name) && npmStore.attrs.equals(s.attrs);
                        }),
                        "Expected blob store '" + npmStore.name + "' not found");
            });
            step("Find registered blob stores using standard Nexus REST API", () -> {
                final List<BlobStoreVO> blobstores = call(api.getBlobStores());
                assertNotNull(blobstores);
                assertTrue(blobstores.stream().anyMatch(s -> {
                            return "File".equals(s.type) && "default".equals(s.name);
                        }),
                        "Expected blob store 'default' not found");
                assertTrue(blobstores.stream().anyMatch(s -> {
                            return "File".equals(s.type) && dockerStore.name.equals(s.name) &&
                                    s.softQuota == null;
                        }),
                        "Expected blob store '" + dockerStore.name + "' not found");
                assertTrue(blobstores.stream().anyMatch(s -> {
                            return "File".equals(s.type) && mavenStore.name.equals(s.name) &&
                                    s.softQuota != null &&
                                    "spaceUsedQuota".equals(s.softQuota.type) && s.softQuota.limit == 1_073_741_824;
                        }),
                        "Expected blob store '" + mavenStore.name + "' not found");
                assertTrue(blobstores.stream().anyMatch(s -> {
                            return "File".equals(s.type) && npmStore.name.equals(s.name) &&
                                    s.softQuota != null &&
                                    "spaceUsedQuota".equals(s.softQuota.type) && s.softQuota.limit == 1_073_741_824;
                        }),
                        "Expected blob store '" + npmStore.name + "' not found");
            });
            step("Make sure that incorrect storage attributes are handled correctly when updating it (the some attributes cannot be changed)", () -> {
                final RepositoryConfig.BlobStore npmStore2 = new RepositoryConfig.BlobStore(File, "npm-store");
                npmStore2.putAttribute("file", "path", "npm2");  // attempt to change path
                npmStore2.putAttribute("blobStoreQuotaConfig", "quotaLimitBytes", 1_073_741_824);
                npmStore2.putAttribute("blobStoreQuotaConfig", "quotaType", "spaceUsedQuota");
                final Config cfg = new Config(ALWAYS);
                cfg.repositoryConfig = new RepositoryConfig();
                cfg.repositoryConfig.blobStores = Collections.singletonList(npmStore2);
                assertThrows(Throwable.class, () -> applyNewConfiguration(cfg), "Incorrect configuration was accepted");
            });
        });
        step("3. Checking the plugin's ability to delete specified blob stores (which are not yet used in repositories)", () -> {
            step("Deleting blob stores", () -> {
                final Config cfg = new Config(ALWAYS);
                cfg.repositoryConfig = new RepositoryConfig();
                cfg.repositoryConfig.blobStoresToDelete = Arrays.asList(dockerStore.name, mavenStore.name, npmStore.name);
                assertTrue(applyNewConfiguration(cfg), "The passed settings should be applied on the server");
            });
            step("Make sure that specified blob stores are really deleted", () -> {
                final List<BlobStoreVO> blobstores = call(api.getBlobStores());
                assertNotNull(blobstores);
                assertTrue(blobstores.stream().anyMatch(s -> "File".equals(s.type) && "default".equals(s.name)),
                        "Expected blob store 'default' not found");
                assertFalse(blobstores.stream().anyMatch(s -> "File".equals(s.type) && dockerStore.name.equals(s.name)),
                        "Blob store '" + dockerStore.name + "' was found");
                assertFalse(blobstores.stream().anyMatch(s -> "File".equals(s.type) && mavenStore.name.equals(s.name)),
                        "Blob store '" + mavenStore.name + "' was found");
                assertFalse(blobstores.stream().anyMatch(s -> "File".equals(s.type) && npmStore.name.equals(s.name)),
                        "Blob store '" + npmStore.name + "' was found");
            });
        });
    }

    @Test
    @Order(2)
    @Description("Checking the core capabilities of the CASC plugin for 'S3' blob store management")
    void testS3BlobStores() {
        final String endpoint = "http://" + minioServer.getInternalIPAddress() + ":9000";
        final RepositoryConfig.BlobStore objectStore = new RepositoryConfig.BlobStore(S3, "object-store");
        objectStore.putAttribute("s3", "region", "us-east-1");
        objectStore.putAttribute("s3", "bucket", "store1");
        objectStore.putAttribute("s3", "prefix", "incoming");
        objectStore.putAttribute("s3", "expiration", "1");
        objectStore.putAttribute("s3", "accessKeyId", "admin");
        objectStore.putAttribute("s3", "secretAccessKey", "admin123");
        objectStore.putAttribute("s3", "endpoint", endpoint);
        objectStore.putAttribute("s3", "signertype", "S3SignerType");
        objectStore.putAttribute("s3", "forcepathstyle", "true");
        objectStore.putAttribute("blobStoreQuotaConfig", "quotaLimitBytes", 536_870_912);
        objectStore.putAttribute("blobStoreQuotaConfig", "quotaType", "spaceRemainingQuota");

        step("1. Checking the plugin's ability to register new blob stores", () -> {
            step("Registering new blob stores", () -> {
                final Config cfg = new Config(ALWAYS);
                cfg.repositoryConfig = new RepositoryConfig();
                cfg.repositoryConfig.blobStores = Collections.singletonList(objectStore);
                assertTrue(applyNewConfiguration(cfg), "The passed settings should be applied on the server");
            });
            step("Find registered blob stores using CASC plugin API", () -> {
                final Config cfg = getCurrentConfiguration();
                assertNotNull(cfg.repositoryConfig);
                assertNotNull(cfg.repositoryConfig.blobStores);
                assertTrue(cfg.repositoryConfig.blobStores.stream().anyMatch(s -> {
                            return s.type == S3 && objectStore.name.equals(s.name) && objectStore.attrs.equals(s.attrs);
                        }),
                        "Expected blob store '" + objectStore.name + "' not found");
            });
            step("Find registered blob stores using standard Nexus REST API", () -> {
                final List<BlobStoreVO> blobstores = call(api.getBlobStores());
                assertNotNull(blobstores);
                assertTrue(blobstores.stream().anyMatch(s -> {
                            return "S3".equals(s.type) && objectStore.name.equals(s.name) &&
                                    s.softQuota != null &&
                                    "spaceRemainingQuota".equals(s.softQuota.type) && s.softQuota.limit == 536_870_912;
                        }),
                        "Expected blob store '" + objectStore.name + "' not found");
                final S3BlobStoreVO info = call(api.getS3BlobStoreInfo(objectStore.name));
                assertNotNull(info, "No blob store '" + objectStore.name + "' info");
                assertEquals(objectStore.name, info.name, "Unexpected blob store name");
                assertNotNull(info.softQuota);
                final S3BlobStoreVO.Configuration cfg = info.bucketConfiguration;
                assertNotNull(cfg);
                assertNotNull(cfg.bucket);
                assertEquals("us-east-1", cfg.bucket.region, "Unexpected bucket region");
                assertEquals("store1", cfg.bucket.name, "Unexpected bucket name");
                assertEquals("incoming", cfg.bucket.prefix, "Unexpected bucket prefix");
                assertEquals(1, cfg.bucket.expiration, "Unexpected bucket expiration");
                assertNotNull(cfg.bucketSecurity);
                assertEquals("admin", cfg.bucketSecurity.accessKeyId, "Unexpected access key id");
                assertNotNull(cfg.advancedBucketConnection);
                assertEquals(endpoint, cfg.advancedBucketConnection.endpoint, "Unexpected endpoint");
                assertEquals("S3SignerType", cfg.advancedBucketConnection.signerType, "Unexpected signer type");
                assertTrue(cfg.advancedBucketConnection.forcePathStyle, "Unexpected path style");
            });
        });
        step("2. Checking the plugin's ability to modify already registered blob stores", () -> {
            step("Update existed blob store", () -> {
                objectStore.putAttribute("s3", "prefix", "in");
                objectStore.putAttribute("s3", "expiration", "2");
                final Config cfg = new Config(ALWAYS);
                cfg.repositoryConfig = new RepositoryConfig();
                cfg.repositoryConfig.blobStores = Collections.singletonList(objectStore);
                assertTrue(applyNewConfiguration(cfg), "The passed settings should be applied on the server");
            });
            step("Find registered blob stores using CASC plugin API", () -> {
                final Config cfg = getCurrentConfiguration();
                assertNotNull(cfg.repositoryConfig);
                assertNotNull(cfg.repositoryConfig.blobStores);
                assertTrue(cfg.repositoryConfig.blobStores.stream().anyMatch(s -> {
                            return s.type == S3 && objectStore.name.equals(s.name) && objectStore.attrs.equals(s.attrs);
                        }),
                        "Expected blob store '" + objectStore.name + "' not found");
            });
            step("Find registered blob stores using standard Nexus REST API", () -> {
                final List<BlobStoreVO> blobstores = call(api.getBlobStores());
                assertNotNull(blobstores);
                assertTrue(blobstores.stream().anyMatch(s -> {
                            return "S3".equals(s.type) && objectStore.name.equals(s.name) &&
                                    s.softQuota != null &&
                                    "spaceRemainingQuota".equals(s.softQuota.type) && s.softQuota.limit == 536_870_912;
                        }),
                        "Expected blob store '" + objectStore.name + "' not found");
                final S3BlobStoreVO info = call(api.getS3BlobStoreInfo(objectStore.name));
                assertNotNull(info, "No blob store '" + objectStore.name + "' info");
                assertEquals(objectStore.name, info.name, "Unexpected blob store name");
                assertNotNull(info.softQuota);
                final S3BlobStoreVO.Configuration cfg = info.bucketConfiguration;
                assertNotNull(cfg);
                assertNotNull(cfg.bucket);
                assertEquals("us-east-1", cfg.bucket.region, "Unexpected bucket region");
                assertEquals("store1", cfg.bucket.name, "Unexpected bucket name");
                assertEquals("in", cfg.bucket.prefix, "Unexpected bucket prefix");
                assertEquals(2, cfg.bucket.expiration, "Unexpected bucket expiration");
                assertNotNull(cfg.bucketSecurity);
                assertEquals("admin", cfg.bucketSecurity.accessKeyId, "Unexpected access key id");
                assertNotNull(cfg.advancedBucketConnection);
                assertEquals(endpoint, cfg.advancedBucketConnection.endpoint, "Unexpected endpoint");
                assertEquals("S3SignerType", cfg.advancedBucketConnection.signerType, "Unexpected signer type");
                assertTrue(cfg.advancedBucketConnection.forcePathStyle, "Unexpected path style");
            });
        });
        step("3. Checking the plugin's ability to delete specified blob stores (which are not yet used in repositories)", () -> {
            step("Deleting blob stores", () -> {
                final Config cfg = new Config(ALWAYS);
                cfg.repositoryConfig = new RepositoryConfig();
                cfg.repositoryConfig.blobStoresToDelete = Collections.singletonList(objectStore.name);
                assertTrue(applyNewConfiguration(cfg), "The passed settings should be applied on the server");
            });
            step("Make sure that specified blob stores are really deleted", () -> {
                final List<BlobStoreVO> blobstores = call(api.getBlobStores());
                assertNotNull(blobstores);
                assertFalse(blobstores.stream().anyMatch(s -> "S3".equals(s.type) && objectStore.name.equals(s.name)),
                        "Blob store '" + objectStore.name + "' was found");
            });
        });
    }

    @Test
    @Order(3)
    @Description("Checking the core capabilities of the CASC plugin for cleanup policies management")
    void testCleanupPolicies() {
        final RepositoryConfig.CleanupPolicy policy1 = new RepositoryConfig.CleanupPolicy("test-cleanup-docker-policy", "docker");
        policy1.mode = "delete";
        policy1.criteria.put("lastDownloaded", "864000");
        policy1.criteria.put("lastBlobUpdated", "2592000");
        policy1.notes = "cleanup policy #1 testing";
        final RepositoryConfig.CleanupPolicy policy2 = new RepositoryConfig.CleanupPolicy("test-cleanup-maven-policy", "maven2");
        policy2.mode = "delete";
        policy2.criteria.put("regex", "^.*test.*$");
        policy2.criteria.put("lastDownloaded", "864000");
        policy2.criteria.put("lastBlobUpdated", "2592000");
        policy2.criteria.put("isPrerelease", "true");
        policy2.notes = "cleanup policy #2 testing";

        step("1. Checking the plugin's ability to register new cleanup policies", () -> {
            step("Registering new cleanup policies", () -> {
                final Config cfg = new Config(ALWAYS);
                cfg.repositoryConfig = new RepositoryConfig();
                cfg.repositoryConfig.cleanupPolicies = Arrays.asList(policy1, policy2);
                assertTrue(applyNewConfiguration(cfg), "The passed settings should be applied on the server");
            });
            step("Find registered cleanup policies using CASC plugin API", () -> {
                final Config cfg = getCurrentConfiguration();
                assertNotNull(cfg.repositoryConfig);
                assertNotNull(cfg.repositoryConfig.cleanupPolicies);
                RepositoryConfig.CleanupPolicy policy = cfg.repositoryConfig.cleanupPolicies.stream()
                        .filter(p -> policy1.name.equals(p.name))
                        .findFirst()
                        .orElseThrow(() -> new AssertionFailedError("Can't find registered cleanup policy '" + policy1.name + "'"));
                assertEquals(policy1.format, policy.format, "Unexpected cleanup policy format");
                assertEquals(policy1.mode, policy.mode, "Unexpected cleanup policy mode");
                assertEquals(policy1.notes, policy.notes, "Unexpected cleanup policy notes");
                assertEquals(policy1.criteria, policy.criteria, "Unexpected cleanup policy criteria");
                policy = cfg.repositoryConfig.cleanupPolicies.stream()
                        .filter(p -> policy2.name.equals(p.name))
                        .findFirst()
                        .orElseThrow(() -> new AssertionFailedError("Can't find registered cleanup policy '" + policy2.name + "'"));
                assertEquals(policy2.format, policy.format, "Unexpected cleanup policy format");
                assertEquals(policy2.mode, policy.mode, "Unexpected cleanup policy mode");
                assertEquals(policy2.notes, policy.notes, "Unexpected cleanup policy notes");
                assertEquals(policy2.criteria, policy.criteria, "Unexpected cleanup policy criteria");
            });
        });
        step("2. Checking the plugin's ability to modify already registered cleanup policies", () -> {
            step("Update existing cleanup policies", () -> {
                policy2.criteria.put("regex", "^.*old.*$");
                policy2.criteria.put("lastDownloaded", "2592000");
                final Config cfg = new Config(ALWAYS);
                cfg.repositoryConfig = new RepositoryConfig();
                cfg.repositoryConfig.cleanupPolicies = Collections.singletonList(policy2);
                assertTrue(applyNewConfiguration(cfg), "The passed settings should be applied on the server");
            });
            step("Find registered cleanup policies using CASC plugin API", () -> {
                final Config cfg = getCurrentConfiguration();
                assertNotNull(cfg.repositoryConfig);
                assertNotNull(cfg.repositoryConfig.cleanupPolicies);
                RepositoryConfig.CleanupPolicy policy = cfg.repositoryConfig.cleanupPolicies.stream()
                        .filter(p -> policy1.name.equals(p.name))
                        .findFirst()
                        .orElseThrow(() -> new AssertionFailedError("Can't find registered cleanup policy '" + policy1.name + "'"));
                assertEquals(policy1.format, policy.format, "Unexpected cleanup policy format");
                assertEquals(policy1.mode, policy.mode, "Unexpected cleanup policy mode");
                assertEquals(policy1.notes, policy.notes, "Unexpected cleanup policy notes");
                assertEquals(policy1.criteria, policy.criteria, "Unexpected cleanup policy criteria");
                policy = cfg.repositoryConfig.cleanupPolicies.stream()
                        .filter(p -> policy2.name.equals(p.name))
                        .findFirst()
                        .orElseThrow(() -> new AssertionFailedError("Can't find registered cleanup policy '" + policy2.name + "'"));
                assertEquals(policy2.format, policy.format, "Unexpected cleanup policy format");
                assertEquals(policy2.mode, policy.mode, "Unexpected cleanup policy mode");
                assertEquals(policy2.notes, policy.notes, "Unexpected cleanup policy notes");
                assertEquals(policy2.criteria, policy.criteria, "Unexpected cleanup policy criteria");
            });
        });
        step("3. Make attempts to apply incorrect policy configuration", () -> {
            step("Use unsupported criteria", () -> {
                final RepositoryConfig.CleanupPolicy policy = new RepositoryConfig.CleanupPolicy("bad-test-cleanup-docker-policy", "docker");
                policy.mode = "delete";
                policy.criteria.put("lastDownloaded", "864000");
                policy.criteria.put("xxx", "2592000");      // unknown criteria
                final Config cfg = new Config(ALWAYS);
                cfg.repositoryConfig = new RepositoryConfig();
                cfg.repositoryConfig.cleanupPolicies = Collections.singletonList(policy);
                assertThrows(Throwable.class, () -> applyNewConfiguration(cfg), "Incorrect configuration was applied");
            });
            step("Use unsupported for given format criteria", () -> {
                final RepositoryConfig.CleanupPolicy policy = new RepositoryConfig.CleanupPolicy("bad-test-cleanup-docker-policy", "docker");
                policy.mode = "delete";
                policy.criteria.put("lastDownloaded", "864000");
                policy.criteria.put("isPrerelease", "true");    // not supported for 'docker' format
                final Config cfg = new Config(ALWAYS);
                cfg.repositoryConfig = new RepositoryConfig();
                cfg.repositoryConfig.cleanupPolicies = Collections.singletonList(policy);
                assertThrows(Throwable.class, () -> applyNewConfiguration(cfg), "Incorrect configuration was applied");
            });
        });
        step("4. Checking the plugin's ability to delete specified cleanup policies", () -> {
            step("Deleting cleanup policies", () -> {
                final Config cfg = new Config(ALWAYS);
                cfg.repositoryConfig = new RepositoryConfig();
                cfg.repositoryConfig.cleanupPoliciesToDelete = Arrays.asList(policy1.name, policy2.name);
                assertTrue(applyNewConfiguration(cfg), "The passed settings should be applied on the server");
            });
            step("Make sure that specified cleanup policies are really deleted", () -> {
                final Config cfg = getCurrentConfiguration();
                assertNotNull(cfg.repositoryConfig);
                assertNotNull(cfg.repositoryConfig.cleanupPolicies);
                assertFalse(cfg.repositoryConfig.cleanupPolicies.stream().anyMatch(p -> policy1.name.equals(p.name)), "Deleted policy '" + policy1.name + "' was found");
                assertFalse(cfg.repositoryConfig.cleanupPolicies.stream().anyMatch(p -> policy2.name.equals(p.name)), "Deleted policy '" + policy2.name + "' was found");
            });
        });
    }

    @Test
    @Order(4)
    @Description("Checking the core capabilities of the CASC plugin for content selectors management")
    void testContentSelectors() {
        final RepositoryConfig.Selector selector1 = new RepositoryConfig.Selector("test-selector-1", "csel");
        selector1.attrs.put("expression", "format == \"raw\"");
        selector1.description = "selector #1 testing";
        final RepositoryConfig.Selector selector2 = new RepositoryConfig.Selector("test-selector-2", "csel");
        selector2.attrs.put("expression", "format == \"npm\" or (format==\"maven2\" and path =~ \"^/org/apache/.*\")");
        selector2.description = "selector #2 testing";

        step("1. Checking the plugin's ability to register new content selectors", () -> {
            step("Registering new content selectors", () -> {
                final Config cfg = new Config(ALWAYS);
                cfg.repositoryConfig = new RepositoryConfig();
                cfg.repositoryConfig.selectors = Arrays.asList(selector1, selector2);
                assertTrue(applyNewConfiguration(cfg), "The passed settings should be applied on the server");
            });
            step("Find registered content selectors using CASC plugin API", () -> {
                final Config cfg = getCurrentConfiguration();
                assertNotNull(cfg.repositoryConfig);
                assertNotNull(cfg.repositoryConfig.selectors);
                RepositoryConfig.Selector selector = cfg.repositoryConfig.selectors.stream()
                        .filter(p -> selector1.name.equals(p.name))
                        .findFirst()
                        .orElseThrow(() -> new AssertionFailedError("Can't find registered selector '" + selector1.name + "'"));
                assertEquals(selector1.type, selector.type, "Unexpected selector type");
                assertEquals(selector1.description, selector.description, "Unexpected selector description");
                assertEquals(selector1.attrs, selector.attrs, "Unexpected selector criteria");
                selector = cfg.repositoryConfig.selectors.stream()
                        .filter(p -> selector2.name.equals(p.name))
                        .findFirst()
                        .orElseThrow(() -> new AssertionFailedError("Can't find registered selector '" + selector2.name + "'"));
                assertEquals(selector2.type, selector.type, "Unexpected selector type");
                assertEquals(selector2.description, selector.description, "Unexpected selector description");
                assertEquals(selector2.attrs, selector.attrs, "Unexpected selector criteria");
            });
            step("Find registered content selectors using standard Nexus REST API", () -> {
                final List<ContentSelectorVO> selectors = call(api.getContentSelectors());
                assertNotNull(selectors);
                ContentSelectorVO sel = selectors.stream()
                        .filter(s -> selector1.name.equals(s.name))
                        .findFirst()
                        .orElseThrow(() -> new AssertionFailedError("Can't find registered content selector '" + selector1.name + "'"));
                assertNotNull(sel.type, "Empty content selector type");
                assertEquals(selector1.type, sel.type.name(), "Unexpected content selector type");
                assertEquals(selector1.attrs.get("expression"), sel.expression, "Unexpected content selector expression");
                assertEquals(selector1.description, sel.description, "Unexpected content selector description");
                sel = selectors.stream()
                        .filter(s -> selector2.name.equals(s.name))
                        .findFirst()
                        .orElseThrow(() -> new AssertionFailedError("Can't find registered content selector '" + selector2.name + "'"));
                assertNotNull(sel.type, "Empty content selector type");
                assertEquals(selector2.type, sel.type.name(), "Unexpected content selector type");
                assertEquals(selector2.attrs.get("expression"), sel.expression, "Unexpected content selector expression");
                assertEquals(selector2.description, sel.description, "Unexpected content selector description");
            });
        });
        step("2. Checking the plugin's ability to modify already registered content selectors", () -> {
            step("Update existing content selectors", () -> {
                selector1.attrs.put("expression", "format==\"docker\"");
                final Config cfg = new Config(ALWAYS);
                cfg.repositoryConfig = new RepositoryConfig();
                cfg.repositoryConfig.selectors = Collections.singletonList(selector1);
                assertTrue(applyNewConfiguration(cfg), "The passed settings should be applied on the server");
            });
            step("Find registered content selectors using standard Nexus REST API", () -> {
                final List<ContentSelectorVO> selectors = call(api.getContentSelectors());
                assertNotNull(selectors);
                ContentSelectorVO sel = selectors.stream()
                        .filter(s -> selector1.name.equals(s.name))
                        .findFirst()
                        .orElseThrow(() -> new AssertionFailedError("Can't find registered content selector '" + selector1.name + "'"));
                assertNotNull(sel.type, "Empty content selector type");
                assertEquals(selector1.type, sel.type.name(), "Unexpected content selector type");
                assertEquals(selector1.attrs.get("expression"), sel.expression, "Unexpected content selector expression");
                assertEquals(selector1.description, sel.description, "Unexpected content selector description");
                sel = selectors.stream()
                        .filter(s -> selector2.name.equals(s.name))
                        .findFirst()
                        .orElseThrow(() -> new AssertionFailedError("Can't find registered content selector '" + selector2.name + "'"));
                assertNotNull(sel.type, "Empty content selector type");
                assertEquals(selector2.type, sel.type.name(), "Unexpected content selector type");
                assertEquals(selector2.attrs.get("expression"), sel.expression, "Unexpected content selector expression");
                assertEquals(selector2.description, sel.description, "Unexpected content selector description");
            });
        });
        step("3. Checking the plugin's ability to handle incorrect content selectors", () -> {
            step("Make attempts to apply configuration with incorrect selector type", () -> {
                final RepositoryConfig.Selector selector = new RepositoryConfig.Selector("bad-test-selector", "test");
                selector.attrs.put("expression", "format = \"raw\"");

                final Config cfg = new Config(ALWAYS);
                cfg.repositoryConfig = new RepositoryConfig();
                cfg.repositoryConfig.selectors = Collections.singletonList(selector);
                assertThrows(Throwable.class, () -> applyNewConfiguration(cfg), "Incorrect configuration was accepted");
            });
            step("Make attempts to apply configuration with incorrect expression syntax (1)", () -> {
                final RepositoryConfig.Selector selector = new RepositoryConfig.Selector("bad-test-selector-2", "csel");
                selector.attrs.put("expression", "format = \"raw\"");

                final Config cfg = new Config(ALWAYS);
                cfg.repositoryConfig = new RepositoryConfig();
                cfg.repositoryConfig.selectors = Collections.singletonList(selector);
                assertThrows(Throwable.class, () -> applyNewConfiguration(cfg), "Incorrect configuration was accepted");
            });
            step("Make attempts to apply configuration with incorrect expression syntax (2)", () -> {
                final RepositoryConfig.Selector selector = new RepositoryConfig.Selector("bad-test-selector-3", "csel");
                selector.attrs.put("expression", "format = raw");

                final Config cfg = new Config(ALWAYS);
                cfg.repositoryConfig = new RepositoryConfig();
                cfg.repositoryConfig.selectors = Collections.singletonList(selector);
                assertThrows(Throwable.class, () -> applyNewConfiguration(cfg), "Incorrect configuration was accepted");
            });
        });
        step("4. Checking the plugin's ability to delete specified content selectors", () -> {
            step("Deleting content selectors", () -> {
                final Config cfg = new Config(ALWAYS);
                cfg.repositoryConfig = new RepositoryConfig();
                cfg.repositoryConfig.selectorsToDelete = Arrays.asList(selector1.name, selector2.name);
                assertTrue(applyNewConfiguration(cfg), "The passed settings should be applied on the server");
            });
            step("Make sure that specified content selectors are really deleted", () -> {
                final Config cfg = getCurrentConfiguration();
                assertNotNull(cfg.repositoryConfig);
                assertNotNull(cfg.repositoryConfig.selectors);
                assertFalse(cfg.repositoryConfig.selectors.stream().anyMatch(p -> selector1.name.equals(p.name)), "Deleted selector '" + selector1.name + "' was found");
                assertFalse(cfg.repositoryConfig.selectors.stream().anyMatch(p -> selector2.name.equals(p.name)), "Deleted selector '" + selector2.name + "' was found");

                final List<ContentSelectorVO> selectors = call(api.getContentSelectors());
                assertNotNull(selectors);
                assertFalse(selectors.stream().anyMatch(s -> selector1.name.equals(s.name)), "Deleted selector '" + selector1.name + "' was found");
                assertFalse(selectors.stream().anyMatch(s -> selector2.name.equals(s.name)), "Deleted selector '" + selector2.name + "' was found");
            });
        });
    }


    @Test
    @Order(5)
    @Description("Checking the core capabilities of the CASC plugin for routing rules management")
    void testRoutingRules() {
        final RepositoryConfig.RoutingRule rule1 = new RepositoryConfig.RoutingRule("rule1", ALLOW, "^/io/github/.*$");
        rule1.description = "test rule #1";
        final RepositoryConfig.RoutingRule rule2 = new RepositoryConfig.RoutingRule("rule2", BLOCK, "^/com/example/.*$", "^/org/example/.*$");
        rule2.description = "test rule #2";

        step("1. Checking the plugin's ability to register new routing rule", () -> {
            step("Registering new routing rules", () -> {
                final Config cfg = new Config(ALWAYS);
                cfg.repositoryConfig = new RepositoryConfig();
                cfg.repositoryConfig.routingRules = Arrays.asList(rule1, rule2);
                assertTrue(applyNewConfiguration(cfg), "The passed settings should be applied on the server");
            });
            step("Find registered rules using CASC plugin API", () -> {
                final Config cfg = getCurrentConfiguration();
                assertNotNull(cfg.repositoryConfig);
                assertNotNull(cfg.repositoryConfig.routingRules);
                RepositoryConfig.RoutingRule rule = cfg.repositoryConfig.routingRules.stream()
                        .filter(p -> rule1.name.equals(p.name))
                        .findFirst()
                        .orElseThrow(() -> new AssertionFailedError("Can't find registered rule '" + rule1.name + "'"));
                assertEquals(rule1.mode, rule.mode, "Unexpected rule mode");
                assertEquals(rule1.description, rule.description, "Unexpected rule description");
                assertEquals(rule1.matchers, rule.matchers, "Unexpected rule matchers");
                rule = cfg.repositoryConfig.routingRules.stream()
                        .filter(p -> rule2.name.equals(p.name))
                        .findFirst()
                        .orElseThrow(() -> new AssertionFailedError("Can't find registered rule '" + rule2.name + "'"));
                assertEquals(rule2.mode, rule.mode, "Unexpected rule mode");
                assertEquals(rule2.description, rule.description, "Unexpected rule description");
                assertEquals(rule2.matchers, rule.matchers, "Unexpected rule matchers");
            });
            step("Find registered rules using standard Nexus REST API", () -> {
                final List<RoutingRuleVO> rules = call(api.getRoutingRules());
                assertNotNull(rules);
                RoutingRuleVO rule = rules.stream()
                        .filter(s -> rule1.name.equals(s.name))
                        .findFirst()
                        .orElseThrow(() -> new AssertionFailedError("Can't find registered routing rule '" + rule1.name + "'"));
                assertNotNull(rule.mode, "Empty content selector type");
                assertEquals(rule1.mode.name(), rule.mode.name(), "Unexpected rule mode");
                assertEquals(rule1.matchers, rule.matchers, "Unexpected rule matchers");
                assertEquals(rule1.description, rule.description, "Unexpected rule description");
                rule = rules.stream()
                        .filter(s -> rule2.name.equals(s.name))
                        .findFirst()
                        .orElseThrow(() -> new AssertionFailedError("Can't find registered routing rule '" + rule2.name + "'"));
                assertNotNull(rule.mode, "Empty content selector type");
                assertEquals(rule2.mode.name(), rule.mode.name(), "Unexpected rule mode");
                assertEquals(rule2.matchers, rule.matchers, "Unexpected rule matchers");
                assertEquals(rule2.description, rule.description, "Unexpected rule description");
            });
        });
        step("2. Checking the plugin's ability to modify already registered routing rules", () -> {
            step("Update existing routing rules", () -> {
                rule1.mode = BLOCK;
                rule1.matchers = Arrays.asList("^/com/github/.*", "^/io/github/.*$");
                rule2.matchers = Arrays.asList("^/com/example/demo/.*$", "^/org/example/.*$");
                rule2.description = "test #2";
                final Config cfg = new Config(ALWAYS);
                cfg.repositoryConfig = new RepositoryConfig();
                cfg.repositoryConfig.routingRules = Arrays.asList(rule1, rule2);
                assertTrue(applyNewConfiguration(cfg), "The passed settings should be applied on the server");
            });
            step("Find registered rules using standard Nexus REST API", () -> {
                final List<RoutingRuleVO> rules = call(api.getRoutingRules());
                assertNotNull(rules);
                RoutingRuleVO rule = rules.stream()
                        .filter(s -> rule1.name.equals(s.name))
                        .findFirst()
                        .orElseThrow(() -> new AssertionFailedError("Can't find registered routing rule '" + rule1.name + "'"));
                assertNotNull(rule.mode, "Empty content selector type");
                assertEquals(rule1.mode.name(), rule.mode.name(), "Unexpected rule mode");
                assertEquals(rule1.matchers, rule.matchers, "Unexpected rule matchers");
                assertEquals(rule1.description, rule.description, "Unexpected rule description");
                rule = rules.stream()
                        .filter(s -> rule2.name.equals(s.name))
                        .findFirst()
                        .orElseThrow(() -> new AssertionFailedError("Can't find registered routing rule '" + rule2.name + "'"));
                assertNotNull(rule.mode, "Empty content selector type");
                assertEquals(rule2.mode.name(), rule.mode.name(), "Unexpected rule mode");
                assertEquals(rule2.matchers, rule.matchers, "Unexpected rule matchers");
                assertEquals(rule2.description, rule.description, "Unexpected rule description");
            });
        });
        step("3. Checking the plugin's ability to delete specified routing rules", () -> {
            step("Deleting routing rules", () -> {
                final Config cfg = new Config(ALWAYS);
                cfg.repositoryConfig = new RepositoryConfig();
                cfg.repositoryConfig.routingRulesToDelete = Arrays.asList(rule1.name, rule2.name);
                assertTrue(applyNewConfiguration(cfg), "The passed settings should be applied on the server");
            });
            step("Make sure that specified routing rules are really deleted", () -> {
                final Config cfg = getCurrentConfiguration();
                assertNotNull(cfg.repositoryConfig);
                assertNotNull(cfg.repositoryConfig.routingRules);
                assertFalse(cfg.repositoryConfig.routingRules.stream().anyMatch(p -> rule1.name.equals(p.name)), "Deleted rule '" + rule1.name + "' was found");
                assertFalse(cfg.repositoryConfig.routingRules.stream().anyMatch(p -> rule2.name.equals(p.name)), "Deleted rule '" + rule2.name + "' was found");

                final List<RoutingRuleVO> rules = call(api.getRoutingRules());
                assertNotNull(rules);
                assertFalse(rules.stream().anyMatch(s -> rule1.name.equals(s.name)), "Deleted rule '" + rule1.name + "' was found");
                assertFalse(rules.stream().anyMatch(s -> rule2.name.equals(s.name)), "Deleted rule '" + rule2.name + "' was found");
            });
        });
    }


    @Test
    @Order(6)
    @Description("Checking the core capabilities of the CASC plugin for repositories management")
    void testRepositories() {
        final RepositoryConfig.BlobStore mavenStore = new RepositoryConfig.BlobStore(File, "maven-store");
        mavenStore.putAttribute("file", "path", "maven");
        mavenStore.putAttribute("blobStoreQuotaConfig", "quotaLimitBytes", 1_073_741_824);
        mavenStore.putAttribute("blobStoreQuotaConfig", "quotaType", "spaceUsedQuota");
        final RepositoryConfig.BlobStore mavenStore2 = new RepositoryConfig.BlobStore(File, "maven-store-ext");
        mavenStore2.putAttribute("file", "path", "maven-ext");

        final RepositoryConfig.Repository mavenSnapshots = new RepositoryConfig.Repository("test-maven-snapshots", "maven2-hosted", true);
        mavenSnapshots.putAttribute("storage", "blobStoreName", mavenStore.name);
        mavenSnapshots.putAttribute("storage", "strictContentTypeValidation", true);
        mavenSnapshots.putAttribute("storage", "writePolicy", "ALLOW");
        mavenSnapshots.putAttribute("maven", "versionPolicy", "SNAPSHOT");
        mavenSnapshots.putAttribute("maven", "layoutPolicy", "STRICT");
        mavenSnapshots.putAttribute("component", null, null);

        final RepositoryConfig.Repository mavenReleases = new RepositoryConfig.Repository("test-maven-releases", "maven2-hosted", true);
        mavenReleases.putAttribute("storage", "blobStoreName", mavenStore.name);
        mavenReleases.putAttribute("storage", "strictContentTypeValidation", true);
        mavenReleases.putAttribute("storage", "writePolicy", "ALLOW_ONCE");
        mavenReleases.putAttribute("maven", "versionPolicy", "RELEASE");
        mavenReleases.putAttribute("maven", "layoutPolicy", "STRICT");
        mavenReleases.putAttribute("component", "proprietaryComponents", true);

        final RepositoryConfig.Repository mavenCentral = new RepositoryConfig.Repository("test-maven-central", "maven2-proxy", true);
        mavenCentral.putAttribute("storage", "blobStoreName", mavenStore.name);
        mavenCentral.putAttribute("storage", "strictContentTypeValidation", false);
        mavenCentral.putAttribute("maven", "versionPolicy", "RELEASE");
        mavenCentral.putAttribute("maven", "layoutPolicy", "PERMISSIVE");
        mavenCentral.putAttribute("proxy", "remoteUrl", "https://repo1.maven.org/maven2/");
        mavenCentral.putAttribute("proxy", "contentMaxAge", -1);
        mavenCentral.putAttribute("proxy", "metadataMaxAge", 1440);
        mavenCentral.putAttribute("negativeCache", "enabled", true);
        mavenCentral.putAttribute("negativeCache", "timeToLive", 1);
        mavenCentral.putAttribute("httpclient", "blocked", false);
        mavenCentral.putAttribute("httpclient", "autoBlock", true);
        mavenCentral.putAttribute("httpclient", "connection.useTrustStore", false);

        final RepositoryConfig.Repository mavenGroup = new RepositoryConfig.Repository("test-maven-group", "maven2-group", true);
        mavenGroup.putAttribute("storage", "blobStoreName", mavenStore.name);
        mavenGroup.putAttribute("storage", "strictContentTypeValidation", true);
        mavenGroup.putAttribute("group", "memberNames", Arrays.asList(mavenCentral.name, mavenReleases.name, mavenSnapshots.name));

        step("1. Checking the plugin's ability to register new repositories", () -> {
            step("Registering new repositories", () -> {
                final Config cfg = new Config(ALWAYS);
                cfg.repositoryConfig = new RepositoryConfig();
                cfg.repositoryConfig.blobStores = Arrays.asList(mavenStore, mavenStore2);
                cfg.repositoryConfig.repositories = Arrays.asList(mavenSnapshots, mavenReleases, mavenCentral, mavenGroup);
                assertTrue(applyNewConfiguration(cfg), "The passed settings should be applied on the server");
            });
            step("Find registered repositories using CASC plugin API", () -> {
                final Config cfg = getCurrentConfiguration();
                assertNotNull(cfg.repositoryConfig);
                assertNotNull(cfg.repositoryConfig.repositories);
                RepositoryConfig.Repository repo = cfg.repositoryConfig.repositories.stream()
                        .filter(r -> mavenSnapshots.name.equals(r.name))
                        .findFirst()
                        .orElseThrow(() -> new AssertionFailedError("Can't find repository '" + mavenSnapshots.name + "'"));
                assertEquals(mavenSnapshots.recipeName, repo.recipeName, "Unexpected repository recipe name");
                assertEquals(mavenSnapshots.online, repo.online, "Unexpected repository online status");
                assertEquals(mavenSnapshots.attrs, repo.attrs, "Unexpected repository attributes");

                repo = cfg.repositoryConfig.repositories.stream()
                        .filter(r -> mavenReleases.name.equals(r.name))
                        .findFirst()
                        .orElseThrow(() -> new AssertionFailedError("Can't find repository '" + mavenReleases.name + "'"));
                assertEquals(mavenReleases.recipeName, repo.recipeName, "Unexpected repository recipe name");
                assertEquals(mavenReleases.online, repo.online, "Unexpected repository online status");
                assertEquals(mavenReleases.attrs, repo.attrs, "Unexpected repository attributes");

                repo = cfg.repositoryConfig.repositories.stream()
                        .filter(r -> mavenCentral.name.equals(r.name))
                        .findFirst()
                        .orElseThrow(() -> new AssertionFailedError("Can't find repository '" + mavenCentral.name + "'"));
                assertEquals(mavenCentral.recipeName, repo.recipeName, "Unexpected repository recipe name");
                assertEquals(mavenCentral.online, repo.online, "Unexpected repository online status");
                assertEquals(mavenCentral.attrs, skipEmptyGroups(repo.attrs), "Unexpected repository attributes");
            });
            step("Find registered repositories using standard Nexus REST API", () -> {
                final List<RepositoryVO> repos = call(api.getRepositories());
                assertNotNull(repos);
                RepositoryVO repo = repos.stream()
                        .filter(s -> mavenSnapshots.name.equals(s.name))
                        .findFirst()
                        .orElseThrow(() -> new AssertionFailedError("Can't find repository '" + mavenSnapshots.name + "'"));
                assertEquals(hosted, repo.type, "Unexpected repository type");
                assertEquals("maven2", repo.format, "Unexpected repository format");
                assertEquals(mavenSnapshots.online, repo.online, "Unexpected repository online status");
                assertNotNull(repo.storage);
                assertEquals(mavenStore.name, repo.storage.blobStoreName, "Unexpected repository attr: [storage]blobStoreName");
                assertEquals(true, repo.storage.strictContentTypeValidation, "Unexpected repository attr: [storage]strictContentTypeValidation");
                assertEquals("ALLOW", repo.storage.writePolicy.name(), "Unexpected repository attr: [storage]writePolicy");
                assertNotNull(repo.maven);
                assertEquals(SNAPSHOT, repo.maven.versionPolicy, "Unexpected repository attr: [maven]versionPolicy");
                assertEquals(STRICT, repo.maven.layoutPolicy, "Unexpected repository attr: [maven]layoutPolicy");
                assertNotNull(repo.component);
                assertEquals(false, repo.component.proprietaryComponents, "Unexpected repository attr: [component]proprietaryComponents");

                repo = repos.stream()
                        .filter(s -> mavenReleases.name.equals(s.name))
                        .findFirst()
                        .orElseThrow(() -> new AssertionFailedError("Can't find repository '" + mavenReleases.name + "'"));
                assertEquals(hosted, repo.type, "Unexpected repository type");
                assertEquals("maven2", repo.format, "Unexpected repository format");
                assertEquals(mavenReleases.online, repo.online, "Unexpected repository online status");
                assertNotNull(repo.storage);
                assertEquals(mavenStore.name, repo.storage.blobStoreName, "Unexpected repository attr: [storage]blobStoreName");
                assertEquals(true, repo.storage.strictContentTypeValidation, "Unexpected repository attr: [storage]strictContentTypeValidation");
                assertEquals("ALLOW_ONCE", repo.storage.writePolicy.name(), "Unexpected repository attr: [storage]writePolicy");
                assertNotNull(repo.maven);
                assertEquals(RELEASE, repo.maven.versionPolicy, "Unexpected repository attr: [maven]versionPolicy");
                assertEquals(STRICT, repo.maven.layoutPolicy, "Unexpected repository attr: [maven]layoutPolicy");
                assertNotNull(repo.component);
                assertEquals(true, repo.component.proprietaryComponents, "Unexpected repository attr: [component]proprietaryComponents");

                repo = repos.stream()
                        .filter(s -> mavenCentral.name.equals(s.name))
                        .findFirst()
                        .orElseThrow(() -> new AssertionFailedError("Can't find repository '" + mavenCentral.name + "'"));
                assertEquals(proxy, repo.type, "Unexpected repository type");
                assertEquals("maven2", repo.format, "Unexpected repository format");
                assertEquals(mavenCentral.online, repo.online, "Unexpected repository online status");
                assertNotNull(repo.storage);
                assertEquals(mavenStore.name, repo.storage.blobStoreName, "Unexpected repository attr: [storage]blobStoreName");
                assertEquals(false, repo.storage.strictContentTypeValidation, "Unexpected repository attr: [storage]strictContentTypeValidation");
                assertNotNull(repo.maven);
                assertEquals(RELEASE, repo.maven.versionPolicy, "Unexpected repository attr: [maven]versionPolicy");
                assertEquals(PERMISSIVE, repo.maven.layoutPolicy, "Unexpected repository attr: [maven]layoutPolicy");
                assertNotNull(repo.proxy);
                assertEquals("https://repo1.maven.org/maven2/", repo.proxy.remoteUrl, "Unexpected repository attr: [proxy]remoteUrl");
                assertEquals(-1, repo.proxy.contentMaxAge, "Unexpected repository attr: [proxy]contentMaxAge");
                assertEquals(1440, repo.proxy.metadataMaxAge, "Unexpected repository attr: [proxy]metadataMaxAge");
                assertNotNull(repo.negativeCache);
                assertEquals(true, repo.negativeCache.enabled, "Unexpected repository attr: [negativeCache]enabled");
                assertEquals(1, repo.negativeCache.timeToLive, "Unexpected repository attr: [negativeCache]timeToLive");
                assertNotNull(repo.httpClient);
                assertEquals(false, repo.httpClient.blocked, "Unexpected repository attr: [httpClient]blocked");
                assertEquals(true, repo.httpClient.autoBlock, "Unexpected repository attr: [httpClient]autoBlock");

                repo = repos.stream()
                        .filter(s -> mavenGroup.name.equals(s.name))
                        .findFirst()
                        .orElseThrow(() -> new AssertionFailedError("Can't find repository '" + mavenGroup.name + "'"));
                assertEquals(group, repo.type, "Unexpected repository type");
                assertEquals("maven2", repo.format, "Unexpected repository format");
                assertEquals(mavenGroup.online, repo.online, "Unexpected repository online status");
                assertNotNull(repo.storage);
                assertEquals(mavenStore.name, repo.storage.blobStoreName, "Unexpected repository attr: [storage]blobStoreName");
                assertEquals(true, repo.storage.strictContentTypeValidation, "Unexpected repository attr: [storage]strictContentTypeValidation");
                assertNotNull(repo.group);
                assertNotNull(repo.group.memberNames);
                assertTrue(repo.group.memberNames.size() == 3 && repo.group.memberNames.containsAll(Arrays.asList(mavenCentral.name, mavenReleases.name, mavenSnapshots.name)));
            });
        });
        step("2. Checking the plugin's ability to modify already registered repositories", () -> {
            step("Update attributes of the existing repository", () -> {
                mavenCentral.putAttribute("proxy", "remoteUrl", "https://maven.repository.redhat.com/ga/");
                mavenCentral.putAttribute("proxy", "metadataMaxAge", 240);
                mavenCentral.putAttribute("negativeCache", "timeToLive", 30);

                final Config cfg = new Config(ALWAYS);
                cfg.repositoryConfig = new RepositoryConfig();
                cfg.repositoryConfig.repositories = Collections.singletonList(mavenCentral);
                assertTrue(applyNewConfiguration(cfg), "The passed settings should be applied on the server");
            });
            step("Check applied modifications using standard Nexus REST API", () -> {
                final List<RepositoryVO> repos = call(api.getRepositories());
                assertNotNull(repos);
                RepositoryVO repo = repos.stream()
                        .filter(s -> mavenSnapshots.name.equals(s.name))
                        .findFirst()
                        .orElseThrow(() -> new AssertionFailedError("Can't find repository '" + mavenSnapshots.name + "'"));
                assertEquals(hosted, repo.type, "Unexpected repository type");
                assertEquals("maven2", repo.format, "Unexpected repository format");
                assertEquals(mavenSnapshots.online, repo.online, "Unexpected repository online status");
                assertNotNull(repo.storage);
                assertEquals(mavenStore.name, repo.storage.blobStoreName, "Unexpected repository attr: [storage]blobStoreName");
                assertEquals(true, repo.storage.strictContentTypeValidation, "Unexpected repository attr: [storage]strictContentTypeValidation");
                assertEquals("ALLOW", repo.storage.writePolicy.name(), "Unexpected repository attr: [storage]writePolicy");
                assertNotNull(repo.maven);
                assertEquals(SNAPSHOT, repo.maven.versionPolicy, "Unexpected repository attr: [maven]versionPolicy");
                assertEquals(STRICT, repo.maven.layoutPolicy, "Unexpected repository attr: [maven]layoutPolicy");

                repo = repos.stream()
                        .filter(s -> mavenReleases.name.equals(s.name))
                        .findFirst()
                        .orElseThrow(() -> new AssertionFailedError("Can't find repository '" + mavenReleases.name + "'"));
                assertEquals(hosted, repo.type, "Unexpected repository type");
                assertEquals("maven2", repo.format, "Unexpected repository format");
                assertEquals(mavenReleases.online, repo.online, "Unexpected repository online status");
                assertNotNull(repo.storage);
                assertEquals(mavenStore.name, repo.storage.blobStoreName, "Unexpected repository attr: [storage]blobStoreName");
                assertEquals(true, repo.storage.strictContentTypeValidation, "Unexpected repository attr: [storage]strictContentTypeValidation");
                assertEquals("ALLOW_ONCE", repo.storage.writePolicy.name(), "Unexpected repository attr: [storage]writePolicy");
                assertNotNull(repo.maven);
                assertEquals(RELEASE, repo.maven.versionPolicy, "Unexpected repository attr: [maven]versionPolicy");
                assertEquals(STRICT, repo.maven.layoutPolicy, "Unexpected repository attr: [maven]layoutPolicy");

                repo = repos.stream()
                        .filter(s -> mavenCentral.name.equals(s.name))
                        .findFirst()
                        .orElseThrow(() -> new AssertionFailedError("Can't find repository '" + mavenCentral.name + "'"));
                assertEquals(proxy, repo.type, "Unexpected repository type");
                assertEquals("maven2", repo.format, "Unexpected repository format");
                assertEquals(mavenCentral.online, repo.online, "Unexpected repository online status");
                assertNotNull(repo.storage);
                assertEquals(mavenStore.name, repo.storage.blobStoreName, "Unexpected repository attr: [storage]blobStoreName");
                assertEquals(false, repo.storage.strictContentTypeValidation, "Unexpected repository attr: [storage]strictContentTypeValidation");
                assertNotNull(repo.maven);
                assertEquals(RELEASE, repo.maven.versionPolicy, "Unexpected repository attr: [maven]versionPolicy");
                assertEquals(PERMISSIVE, repo.maven.layoutPolicy, "Unexpected repository attr: [maven]layoutPolicy");
                assertNotNull(repo.proxy);
                assertEquals("https://maven.repository.redhat.com/ga/", repo.proxy.remoteUrl, "Unexpected repository attr: [proxy]remoteUrl");
                assertEquals(-1, repo.proxy.contentMaxAge, "Unexpected repository attr: [proxy]contentMaxAge");
                assertEquals(240, repo.proxy.metadataMaxAge, "Unexpected repository attr: [proxy]metadataMaxAge");
                assertNotNull(repo.negativeCache);
                assertEquals(true, repo.negativeCache.enabled, "Unexpected repository attr: [negativeCache]enabled");
                assertEquals(30, repo.negativeCache.timeToLive, "Unexpected repository attr: [negativeCache]timeToLive");
                assertNotNull(repo.httpClient);
                assertEquals(false, repo.httpClient.blocked, "Unexpected repository attr: [httpClient]blocked");
                assertEquals(true, repo.httpClient.autoBlock, "Unexpected repository attr: [httpClient]autoBlock");

                repo = repos.stream()
                        .filter(s -> mavenGroup.name.equals(s.name))
                        .findFirst()
                        .orElseThrow(() -> new AssertionFailedError("Can't find repository '" + mavenGroup.name + "'"));
                assertEquals(group, repo.type, "Unexpected repository type");
                assertEquals("maven2", repo.format, "Unexpected repository format");
                assertEquals(mavenGroup.online, repo.online, "Unexpected repository online status");
                assertNotNull(repo.storage);
                assertEquals(mavenStore.name, repo.storage.blobStoreName, "Unexpected repository attr: [storage]blobStoreName");
                assertEquals(true, repo.storage.strictContentTypeValidation, "Unexpected repository attr: [storage]strictContentTypeValidation");
                assertNotNull(repo.group);
                assertNotNull(repo.group.memberNames);
                assertTrue(repo.group.memberNames.size() == 3 && repo.group.memberNames.containsAll(Arrays.asList(mavenCentral.name, mavenReleases.name, mavenSnapshots.name)));
            });
            step("Replace blob store for existing repository (leads to the repository being re-created)", () -> {
                mavenCentral.putAttribute("storage", "blobStoreName", mavenStore2.name);

                final Config cfg = new Config(ALWAYS);
                cfg.repositoryConfig = new RepositoryConfig();
                cfg.repositoryConfig.repositories = Collections.singletonList(mavenCentral);
                assertTrue(applyNewConfiguration(cfg), "The passed settings should be applied on the server");
            });
            step("Check applied modifications using standard Nexus REST API", () -> {
                final List<RepositoryVO> repos = call(api.getRepositories());
                assertNotNull(repos);
                RepositoryVO repo = repos.stream()
                        .filter(s -> mavenCentral.name.equals(s.name))
                        .findFirst()
                        .orElseThrow(() -> new AssertionFailedError("Can't find repository '" + mavenCentral.name + "'"));
                assertEquals(proxy, repo.type, "Unexpected repository type");
                assertEquals("maven2", repo.format, "Unexpected repository format");
                assertEquals(mavenCentral.online, repo.online, "Unexpected repository online status");
                assertNotNull(repo.storage);
                assertEquals(mavenStore2.name, repo.storage.blobStoreName, "Unexpected repository attr: [storage]blobStoreName");
                assertEquals(false, repo.storage.strictContentTypeValidation, "Unexpected repository attr: [storage]strictContentTypeValidation");
                assertNotNull(repo.maven);
                assertEquals(RELEASE, repo.maven.versionPolicy, "Unexpected repository attr: [maven]versionPolicy");
                assertEquals(PERMISSIVE, repo.maven.layoutPolicy, "Unexpected repository attr: [maven]layoutPolicy");
                assertNotNull(repo.proxy);
                assertEquals("https://maven.repository.redhat.com/ga/", repo.proxy.remoteUrl, "Unexpected repository attr: [proxy]remoteUrl");
                assertEquals(-1, repo.proxy.contentMaxAge, "Unexpected repository attr: [proxy]contentMaxAge");
                assertEquals(240, repo.proxy.metadataMaxAge, "Unexpected repository attr: [proxy]metadataMaxAge");
                assertNotNull(repo.negativeCache);
                assertEquals(true, repo.negativeCache.enabled, "Unexpected repository attr: [negativeCache]enabled");
                assertEquals(30, repo.negativeCache.timeToLive, "Unexpected repository attr: [negativeCache]timeToLive");
                assertNotNull(repo.httpClient);
                assertEquals(false, repo.httpClient.blocked, "Unexpected repository attr: [httpClient]blocked");
                assertEquals(true, repo.httpClient.autoBlock, "Unexpected repository attr: [httpClient]autoBlock");

                repo = repos.stream()
                        .filter(s -> mavenGroup.name.equals(s.name))
                        .findFirst()
                        .orElseThrow(() -> new AssertionFailedError("Can't find repository '" + mavenGroup.name + "'"));
                assertEquals(group, repo.type, "Unexpected repository type");
                assertEquals("maven2", repo.format, "Unexpected repository format");
                assertEquals(mavenGroup.online, repo.online, "Unexpected repository online status");
                assertNotNull(repo.storage);
                assertEquals(mavenStore.name, repo.storage.blobStoreName, "Unexpected repository attr: [storage]blobStoreName");
                assertEquals(true, repo.storage.strictContentTypeValidation, "Unexpected repository attr: [storage]strictContentTypeValidation");
                assertNotNull(repo.group);
                assertNotNull(repo.group.memberNames);
                assertTrue(repo.group.memberNames.size() == 3 && repo.group.memberNames.containsAll(Arrays.asList(mavenCentral.name, mavenReleases.name, mavenSnapshots.name)));
            });
        });
        step("3. Checking the plugin's ability to delete specified repositories", () -> {
            step("Deleting repositories", () -> {
                final Config cfg = new Config(ALWAYS);
                cfg.repositoryConfig = new RepositoryConfig();
                cfg.repositoryConfig.repositoriesToDelete = Collections.singletonList(mavenSnapshots.name);
                assertTrue(applyNewConfiguration(cfg), "The passed settings should be applied on the server");
            });
            step("Make sure that specified repositories are really deleted", () -> {
                final Config cfg = getCurrentConfiguration();
                assertNotNull(cfg.repositoryConfig.repositories);
                assertFalse(cfg.repositoryConfig.repositories.stream().anyMatch(r -> mavenSnapshots.name.equals(r.name)), "Deleted repository '" + mavenSnapshots.name + "' was found");
                assertTrue(cfg.repositoryConfig.repositories.stream().anyMatch(r -> mavenReleases.name.equals(r.name)), "Repository '" + mavenReleases.name + "' was not found");
                assertTrue(cfg.repositoryConfig.repositories.stream().anyMatch(r -> mavenCentral.name.equals(r.name)), "Repository '" + mavenCentral.name + "' was not found");
                assertTrue(cfg.repositoryConfig.repositories.stream().anyMatch(r -> mavenGroup.name.equals(r.name)), "Repository '" + mavenGroup.name + "' was not found");
                final Set<String> groupMembers = cfg.repositoryConfig.repositories.stream()
                        .filter(r -> mavenGroup.name.equals(r.name))
                        .map(r -> r.attrs.getOrDefault("group", Collections.emptyMap()))
                        .flatMap(g -> ((Collection<String>)g.getOrDefault("memberNames", Collections.emptyList())).stream())
                        .collect(Collectors.toSet());
                assertTrue(groupMembers.size() == 2 && groupMembers.containsAll(Arrays.asList(mavenReleases.name, mavenCentral.name)));

                final List<RepositoryVO> repos = call(api.getRepositories());
                assertNotNull(repos);
                assertFalse(repos.stream().anyMatch(r -> mavenSnapshots.name.equals(r.name)), "Deleted repository '" + mavenSnapshots.name + "' was found");
                assertTrue(repos.stream().anyMatch(r -> mavenReleases.name.equals(r.name)), "Repository '" + mavenReleases.name + "' was not found");
                assertTrue(repos.stream().anyMatch(r -> mavenCentral.name.equals(r.name)), "Repository '" + mavenCentral.name + "' was not found");
                RepositoryVO repo = repos.stream()
                        .filter(s -> mavenGroup.name.equals(s.name))
                        .findFirst()
                        .orElseThrow(() -> new AssertionFailedError("Can't find repository '" + mavenGroup.name + "'"));
                assertEquals(group, repo.type, "Unexpected repository type");
                assertEquals("maven2", repo.format, "Unexpected repository format");
                assertEquals(mavenGroup.online, repo.online, "Unexpected repository online status");
                assertNotNull(repo.storage);
                assertEquals(mavenStore.name, repo.storage.blobStoreName, "Unexpected repository attr: [storage]blobStoreName");
                assertEquals(true, repo.storage.strictContentTypeValidation, "Unexpected repository attr: [storage]strictContentTypeValidation");
                assertNotNull(repo.group);
                assertNotNull(repo.group.memberNames);
                assertTrue(repo.group.memberNames.size() == 2 && repo.group.memberNames.containsAll(Arrays.asList(mavenReleases.name, mavenCentral.name)));
            });
        });
        step("4. Checking the plugin's ability to delete blob stores that already used by repositories", () -> {
            step("Deleting specified blob store and all its associated repositories", () -> {
                final Config cfg = new Config(ALWAYS);
                cfg.repositoryConfig = new RepositoryConfig();
                cfg.repositoryConfig.blobStoresToDelete = Collections.singletonList(mavenStore.name);
                assertTrue(applyNewConfiguration(cfg), "The passed settings should be applied on the server");
            });
            step("Make sure that specified blobstore and related repositories are really deleted", () -> {
                final List<RepositoryVO> repos = call(api.getRepositories());
                assertNotNull(repos);
                assertFalse(repos.stream().anyMatch(r -> mavenSnapshots.name.equals(r.name)), "Deleted repository '" + mavenSnapshots.name + "' was found");
                assertFalse(repos.stream().anyMatch(r -> mavenReleases.name.equals(r.name)), "Deleted repository '" + mavenSnapshots.name + "' was found");
                assertFalse(repos.stream().anyMatch(r -> mavenGroup.name.equals(r.name)), "Deleted repository '" + mavenSnapshots.name + "' was found");
                assertTrue(repos.stream().anyMatch(r -> mavenCentral.name.equals(r.name)), "Repository '" + mavenCentral.name + "' was not found");
                RepositoryVO repo = repos.stream()
                        .filter(s -> mavenCentral.name.equals(s.name))
                        .findFirst()
                        .orElseThrow(() -> new AssertionFailedError("Can't find repository '" + mavenCentral.name + "'"));
                assertEquals(proxy, repo.type, "Unexpected repository type");
                assertEquals("maven2", repo.format, "Unexpected repository format");
                assertEquals(mavenCentral.online, repo.online, "Unexpected repository online status");
                assertNotNull(repo.storage);
                assertEquals(mavenStore2.name, repo.storage.blobStoreName, "Unexpected repository attr: [storage]blobStoreName");
                assertEquals(false, repo.storage.strictContentTypeValidation, "Unexpected repository attr: [storage]strictContentTypeValidation");
                assertNotNull(repo.maven);
                assertEquals(RELEASE, repo.maven.versionPolicy, "Unexpected repository attr: [maven]versionPolicy");
                assertEquals(PERMISSIVE, repo.maven.layoutPolicy, "Unexpected repository attr: [maven]layoutPolicy");
                assertNotNull(repo.proxy);
                assertEquals("https://maven.repository.redhat.com/ga/", repo.proxy.remoteUrl, "Unexpected repository attr: [proxy]remoteUrl");
                assertEquals(-1, repo.proxy.contentMaxAge, "Unexpected repository attr: [proxy]contentMaxAge");
                assertEquals(240, repo.proxy.metadataMaxAge, "Unexpected repository attr: [proxy]metadataMaxAge");
                assertNotNull(repo.negativeCache);
                assertEquals(true, repo.negativeCache.enabled, "Unexpected repository attr: [negativeCache]enabled");
                assertEquals(30, repo.negativeCache.timeToLive, "Unexpected repository attr: [negativeCache]timeToLive");
                assertNotNull(repo.httpClient);
                assertEquals(false, repo.httpClient.blocked, "Unexpected repository attr: [httpClient]blocked");
                assertEquals(true, repo.httpClient.autoBlock, "Unexpected repository attr: [httpClient]autoBlock");

                final List<BlobStoreVO> blobstores = call(api.getBlobStores());
                assertNotNull(blobstores);
                assertFalse(blobstores.stream().anyMatch(s -> mavenStore.name.equals(s.name)), "Deleted blobstore '" + mavenStore + "' was found");
                assertTrue(blobstores.stream().anyMatch(s -> mavenStore2.name.equals(s.name)), "Blob store '" + mavenStore2 + "' was not found");
            });
            step("Remove all remaining blob stores (and all repositories, respectively)", () -> {
                final List<BlobStoreVO> blobstores = call(api.getBlobStores());
                assertTrue(blobstores.size() > 0, "There are no blob stores left on the server");
                final List<RepositoryVO> repositories = call(api.getRepositories());
                assertTrue(repositories.size() > 0, "There are no repositories left on the server");

                final Config cfg = new Config(ALWAYS);
                cfg.repositoryConfig = new RepositoryConfig();
                cfg.repositoryConfig.blobStoresToDelete = blobstores.stream().map(s -> s.name).collect(Collectors.toList());
                assertTrue(applyNewConfiguration(cfg), "The passed settings should be applied on the server");
            });
            step("Make sure that all blob stores and related repositories are really deleted", () -> {
                final List<BlobStoreVO> blobstores = call(api.getBlobStores());
                assertNotNull(blobstores);
                assertTrue(blobstores.isEmpty(), "Blob stores list are not empty");

                final List<RepositoryVO> repos = call(api.getRepositories());
                assertNotNull(repos);
                assertTrue(repos.isEmpty(), "Repositories list are not empty");
            });
        });
        step("5. Checking the plugin's ability to delete all repositories except the specified ones", () -> {
            step("Register new repositories", () -> {
                mavenCentral.putAttribute("storage", "blobStoreName", mavenStore.name);
                mavenCentral.putAttribute("proxy", "remoteUrl", "https://repo1.maven.org/maven2/");
                mavenCentral.putAttribute("proxy", "metadataMaxAge", 1440);
                mavenCentral.putAttribute("negativeCache", "timeToLive", 1);

                final Config cfg = new Config(ALWAYS);
                cfg.repositoryConfig = new RepositoryConfig();
                cfg.repositoryConfig.blobStores = Collections.singletonList(mavenStore);
                cfg.repositoryConfig.repositories = Arrays.asList(mavenSnapshots, mavenReleases, mavenCentral, mavenGroup);
                assertTrue(applyNewConfiguration(cfg), "The passed settings should be applied on the server");
            });
            step("Check whether the created repositories exist on the server", () -> {
                final List<RepositoryVO> repos = call(api.getRepositories());
                assertTrue(repos.stream().anyMatch(r -> mavenSnapshots.name.equals(r.name)), "Repository '" + mavenSnapshots.name + "' was not found");
                assertTrue(repos.stream().anyMatch(r -> mavenReleases.name.equals(r.name)), "Repository '" + mavenReleases.name + "' was not found");
                assertTrue(repos.stream().anyMatch(r -> mavenCentral.name.equals(r.name)), "Repository '" + mavenCentral.name + "' was not found");
                assertTrue(repos.stream().anyMatch(r -> mavenGroup.name.equals(r.name)), "Repository '" + mavenGroup.name + "' was not found");
                RepositoryVO repo = repos.stream()
                        .filter(s -> mavenGroup.name.equals(s.name))
                        .findFirst()
                        .orElseThrow(() -> new AssertionFailedError("Can't find repository '" + mavenGroup.name + "'"));
                assertNotNull(repo.storage);
                assertEquals(mavenStore.name, repo.storage.blobStoreName, "Unexpected repository attr: [storage]blobStoreName");
                assertNotNull(repo.group);
                assertNotNull(repo.group.memberNames);
                assertTrue(repo.group.memberNames.size() == 3 && repo.group.memberNames.containsAll(Arrays.asList(mavenSnapshots.name, mavenReleases.name, mavenCentral.name)));
            });
            step("Make an attempt to remove all repositories, except the grouping repository, which refers to all other repositories", () -> {
                final Config cfg = new Config(ALWAYS);
                cfg.repositoryConfig = new RepositoryConfig();
                cfg.repositoryConfig.repositories = Collections.singletonList(mavenGroup);
                cfg.repositoryConfig.pruneOtherRepositories = true;
                assertTrue(applyNewConfiguration(cfg), "The passed settings should be applied on the server");
            });
            step("Make sure that no repositories are deleted", () -> {
                final List<RepositoryVO> repos = call(api.getRepositories());
                assertTrue(repos.stream().anyMatch(r -> mavenSnapshots.name.equals(r.name)), "Repository '" + mavenSnapshots.name + "' was not found");
                assertTrue(repos.stream().anyMatch(r -> mavenReleases.name.equals(r.name)), "Repository '" + mavenReleases.name + "' was not found");
                assertTrue(repos.stream().anyMatch(r -> mavenCentral.name.equals(r.name)), "Repository '" + mavenCentral.name + "' was not found");
                assertTrue(repos.stream().anyMatch(r -> mavenGroup.name.equals(r.name)), "Repository '" + mavenGroup.name + "' was not found");
                RepositoryVO repo = repos.stream()
                        .filter(s -> mavenGroup.name.equals(s.name))
                        .findFirst()
                        .orElseThrow(() -> new AssertionFailedError("Can't find repository '" + mavenGroup.name + "'"));
                assertNotNull(repo.storage);
                assertEquals(mavenStore.name, repo.storage.blobStoreName, "Unexpected repository attr: [storage]blobStoreName");
                assertNotNull(repo.group);
                assertNotNull(repo.group.memberNames);
                assertTrue(repo.group.memberNames.size() == 3 && repo.group.memberNames.containsAll(Arrays.asList(mavenSnapshots.name, mavenReleases.name, mavenCentral.name)));
            });
            step("Make an attempt to remove all repositories, except the grouping repository, which refers to only one other ('hosted') repository", () -> {
                mavenGroup.putAttribute("group", "memberNames", Collections.singletonList(mavenReleases.name));

                final Config cfg = new Config(ALWAYS);
                cfg.repositoryConfig = new RepositoryConfig();
                cfg.repositoryConfig.repositories = Collections.singletonList(mavenGroup);
                cfg.repositoryConfig.pruneOtherRepositories = true;
                assertTrue(applyNewConfiguration(cfg), "The passed settings should be applied on the server");
            });
            step("Make sure that all repositories except the two listed are removed.", () -> {
                final List<RepositoryVO> repos = call(api.getRepositories());
                assertFalse(repos.stream().anyMatch(r -> mavenSnapshots.name.equals(r.name)), "Deleted repository '" + mavenSnapshots.name + "' was found");
                assertTrue(repos.stream().anyMatch(r -> mavenReleases.name.equals(r.name)), "Repository '" + mavenReleases.name + "' was not found");
                assertFalse(repos.stream().anyMatch(r -> mavenCentral.name.equals(r.name)), "Deleted repository '" + mavenCentral.name + "' was found");
                assertTrue(repos.stream().anyMatch(r -> mavenGroup.name.equals(r.name)), "Repository '" + mavenGroup.name + "' was not found");
                RepositoryVO repo = repos.stream()
                        .filter(s -> mavenGroup.name.equals(s.name))
                        .findFirst()
                        .orElseThrow(() -> new AssertionFailedError("Can't find repository '" + mavenGroup.name + "'"));
                assertNotNull(repo.storage);
                assertEquals(mavenStore.name, repo.storage.blobStoreName, "Unexpected repository attr: [storage]blobStoreName");
                assertNotNull(repo.group);
                assertNotNull(repo.group.memberNames);
                assertTrue(repo.group.memberNames.size() == 1 && repo.group.memberNames.contains(mavenReleases.name));
            });
        });
    }

    private Map<String, Map<String, Object>> skipEmptyGroups(final Map<String, Map<String, Object>> attrs) {
        final Map<String, Map<String, Object>> result = new HashMap<>();
        for (Map.Entry<String, Map<String, Object>> entry : attrs.entrySet()) {
            Map<String, Object> map = entry.getValue();
            if (map != null && !map.isEmpty()) {
                result.put(entry.getKey(), map);
            }
        }
        return result;
    }

    private boolean applyNewConfiguration(final Config cfg) throws Exception {
        final String yamlText = yaml.dump(cfg);
        final RequestBody reqBody = RequestBody.create(TestUtils.YAML_TYPE, yamlText);
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
        final ResponseBody respBody = call(api.getConfiguration(false));
        assertNotNull(respBody);
        final String text = respBody.string();
        assertNotNull(text);
        final Config cfg = yaml.load(text);
        assertNotNull(cfg);
        return cfg;
    }

}
