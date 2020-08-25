package io.github.asharapov.nexus.casc.internal;

import io.github.asharapov.nexus.casc.internal.junit.IntegrationTest;
import io.github.asharapov.nexus.casc.internal.model.Config;
import io.github.asharapov.nexus.casc.internal.utils.DedicatedInstance;
import io.github.asharapov.nexus.casc.internal.utils.NexusAPI;
import io.github.asharapov.nexus.casc.internal.utils.NexusServer;
import io.qameta.allure.Description;
import okhttp3.RequestBody;
import okhttp3.ResponseBody;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.yaml.snakeyaml.Yaml;
import retrofit2.Response;

import javax.inject.Inject;

import static io.github.asharapov.nexus.casc.internal.model.Config.ExecutionPolicy.ALWAYS;
import static io.github.asharapov.nexus.casc.internal.model.Config.ExecutionPolicy.IF_CHANGED;
import static io.github.asharapov.nexus.casc.internal.model.Config.ExecutionPolicy.ONLY_ONCE;
import static io.github.asharapov.nexus.casc.internal.utils.TestUtils.YAML_TYPE;
import static io.github.asharapov.nexus.casc.internal.utils.TestUtils.call;
import static io.qameta.allure.Allure.step;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Contains tests, that can't be executed using a shared instance of the Nexus server due to various race conditions.
 *
 * @author Anton Sharapov
 */
@IntegrationTest
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class DedicatedServerIT {

    @Inject
    private Yaml yaml;

    @Inject
    @DedicatedInstance
    private NexusServer nexusServer;
    private NexusAPI api;

    @BeforeEach
    void beforeEachTest() {
        api = nexusServer.getAdminAPI();
    }

    @Test
    @Order(1)
    @Description("Checking whether metadata processing is correct when applying the new Sonatype Nexus configuration using CASC plugin REST api")
    void testCascMetadata() {
        step("1. Create a new configuration that should be applied on the server only once");
        final Config cfg1 = new Config(ONLY_ONCE);
        step("Send this settings twice on the server and make sure that the server configuration was applied only in the first case", () -> {
            final boolean modified1 = applyNewConfiguration(cfg1);
            assertTrue(modified1, "The passed settings should be applied on the server");
            final boolean modified2 = applyNewConfiguration(cfg1);
            assertFalse(modified2, "The passed settings should not be applied on the server");
        });
        step("Make any changes to this configuration and check again");
        cfg1.metadata.version = "some text";
        step("Send this settings twice on the server and make sure that the server configuration was not applied in both cases", () -> {
            final boolean modified1 = applyNewConfiguration(cfg1);
            assertFalse(modified1, "The passed settings should not be applied on the server");
            final boolean modified2 = applyNewConfiguration(cfg1);
            assertFalse(modified2, "The passed settings should not be applied on the server");
        });


        step("2. Create a new configuration that should be applied on the server in all cases");
        final Config cfg2 = new Config(ALWAYS);
        step("Send this settings twice on the server and make sure that the server configuration was updated in both cases", () -> {
            final boolean modified1 = applyNewConfiguration(cfg2);
            assertTrue(modified1, "The passed settings should be applied on the server");
            final boolean modified2 = applyNewConfiguration(cfg2);
            assertTrue(modified2, "The passed settings should be applied on the server");
        });


        step("3. Create a new configuration that should be applied on the server only if it differs from previous version");
        final Config cfg3 = new Config(IF_CHANGED);
        step("Send this settings twice on the server and make sure that the server configuration was applied only in the first case", () -> {
            final boolean modified1 = applyNewConfiguration(cfg3);
            assertTrue(modified1, "The passed settings should be applied on the server");
            final boolean modified2 = applyNewConfiguration(cfg3);
            assertFalse(modified2, "The passed settings should not be applied on the server");
        });
        step("Make any changes to this configuration and check again");
        cfg3.metadata.version = "some text";
        step("Send this settings twice on the server and make sure that the server configuration was applied only in the first case", () -> {
            final boolean modified1 = applyNewConfiguration(cfg3);
            assertTrue(modified1, "The passed settings should be applied on the server");
            final boolean modified2 = applyNewConfiguration(cfg3);
            assertFalse(modified2, "The passed settings should not be applied on the server");
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
        final ResponseBody respBody = call(api.getConfiguration(false));
        assertNotNull(respBody);
        final String text = respBody.string();
        assertNotNull(text);
        final Config cfg = yaml.load(text);
        assertNotNull(cfg);
        return cfg;
    }

}
