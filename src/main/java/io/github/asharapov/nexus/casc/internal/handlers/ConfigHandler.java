package io.github.asharapov.nexus.casc.internal.handlers;

import io.github.asharapov.nexus.casc.internal.Constants;
import io.github.asharapov.nexus.casc.internal.Interpolator;
import io.github.asharapov.nexus.casc.internal.Utils;
import io.github.asharapov.nexus.casc.internal.model.Config;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonatype.nexus.common.app.ApplicationDirectories;
import org.sonatype.nexus.common.app.ApplicationVersion;
import org.yaml.snakeyaml.Yaml;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import static java.nio.file.StandardOpenOption.CREATE;
import static java.nio.file.StandardOpenOption.TRUNCATE_EXISTING;
import static java.nio.file.StandardOpenOption.WRITE;

/**
 * @author Anton Sharapov
 */
@Named
@Singleton
public class ConfigHandler {
    private static final Logger log = LoggerFactory.getLogger(ConfigHandler.class);

    private final ApplicationVersion appVersion;
    private final ApplicationDirectories appDirs;
    private final SystemConfigHandler systemConfigHandler;
    private final SecurityConfigHandler securityConfigHandler;
    private final RepositoryConfigHandler repositoryConfigHandler;
    private final Interpolator interpolator;
    private final Object lock = new Object();

    @Inject
    ConfigHandler(
            final ApplicationVersion appVersion,
            final ApplicationDirectories appDirs,
            final SystemConfigHandler systemConfigHandler,
            final SecurityConfigHandler securityConfigHandler,
            final RepositoryConfigHandler repositoryConfigHandler,
            final Interpolator interpolator) {
        this.appVersion = appVersion;
        this.appDirs = appDirs;
        this.systemConfigHandler = systemConfigHandler;
        this.securityConfigHandler = securityConfigHandler;
        this.repositoryConfigHandler = repositoryConfigHandler;
        this.interpolator = interpolator;
    }

    public String load(final Options opts) {
        final Config model = new Config();
        model.metadata = new Config.Metadata();
        model.metadata.version = appVersion.getVersion();
        model.metadata.executionPolicy = Config.ExecutionPolicy.IF_CHANGED;
        synchronized (lock) {
            log.info("Reading current configuration ...");
            model.systemConfig = systemConfigHandler.load(opts);
            model.securityConfig = securityConfigHandler.load(opts);
            model.repositoryConfig = repositoryConfigHandler.load(opts);
        }

        final Yaml yaml = makeYaml(opts);
        return yaml.dump(model);
    }

    public boolean store(final String yamlText) throws IOException, NoSuchAlgorithmException {
        if (yamlText == null || yamlText.isEmpty()) {
            log.warn("empty configuration found");
            return false;
        }

        final String effectiveYaml = interpolator.interpolate(yamlText);
        final MessageDigest md = MessageDigest.getInstance("SHA-1");
        final byte[] currentHash = md.digest(effectiveYaml.getBytes(StandardCharsets.UTF_8));

        final Yaml yaml = makeYaml(null);

        final Config model = yaml.load(effectiveYaml);
        if (model == null) {
            log.warn("empty configuration found");
            return false;
        }

        synchronized (lock) {
            if (needToUpdate(model.metadata, currentHash)) {
                log.info("Applying the new configuration ...");
                systemConfigHandler.store(model.systemConfig);
                securityConfigHandler.store(model.securityConfig);
                repositoryConfigHandler.store(model.repositoryConfig);
                final Path dir = appDirs.getWorkDirectory(Constants.CASC_WORK_DIR, true).toPath();
                final Path configHashFile = dir.resolve(".config.sha1");
                Files.write(configHashFile, currentHash, CREATE, WRITE, TRUNCATE_EXISTING);
                log.info("The new configuration applied successfully.");
                return true;
            } else {
                log.info("Configuration not applied");
                return false;
            }
        }
    }

    private Yaml makeYaml(final Options opts) {
        return Utils.makeYaml(opts == null || opts.showEmptyProperties, opts == null || opts.showEmptyCollections);
    }

    private boolean needToUpdate(final Config.Metadata metadata, final byte[] currentHash) throws IOException {
        final Config.ExecutionPolicy policy = metadata != null && metadata.executionPolicy != null
                ? metadata.executionPolicy
                : Config.ExecutionPolicy.IF_CHANGED;
        final Path dir = appDirs.getWorkDirectory("casc", true).toPath();
        final Path configHashFile = dir.resolve(".config.sha1");
        final byte[] lastHash = Files.isReadable(configHashFile) ? Files.readAllBytes(configHashFile) : null;
        switch (policy) {
            case ALWAYS:
                return true;
            case IF_CHANGED:
                return lastHash == null || lastHash.length == 0 || !Arrays.equals(lastHash, currentHash);
            case ONLY_ONCE:
                return lastHash == null || lastHash.length == 0;
            default:
                return false;
        }
    }
}
