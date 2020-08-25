package io.github.asharapov.nexus.casc.internal;

import io.github.asharapov.nexus.casc.internal.junit.UnitTest;
import io.github.asharapov.nexus.casc.internal.model.Config;
import org.junit.jupiter.api.Test;
import org.yaml.snakeyaml.Yaml;

import javax.inject.Inject;
import java.io.BufferedReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@UnitTest
public class ModelTest {

    @Inject
    private Yaml yaml;

    @Test
    public void testParsing() throws Exception {
        final Path path = Paths.get("examples/nexus-demo.yml");
        assertTrue(Files.isRegularFile(path), "The demo configuration file for CASC plugin not found");
        final Config cfg;
        try (BufferedReader reader = Files.newBufferedReader(path, StandardCharsets.UTF_8)) {
            cfg = yaml.load(reader);
        }
        assertNotNull(cfg);
    }
}
