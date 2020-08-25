package io.github.asharapov.nexus.casc.internal;

import io.github.asharapov.nexus.casc.internal.handlers.ConfigHandler;
import org.eclipse.sisu.Description;
import org.sonatype.nexus.common.app.ManagedLifecycle;
import org.sonatype.nexus.common.stateguard.StateGuardLifecycleSupport;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

@Named("cascPlugin")
@Description("Casc Plugin")
// Plugin must run after CAPABILITIES phase as otherwise we can not load/patch existing capabilities
@ManagedLifecycle(phase = ManagedLifecycle.Phase.TASKS)
@Singleton
public class CascImportPlugin extends StateGuardLifecycleSupport {

    private final ConfigHandler configHandler;

    @Inject
    public CascImportPlugin(final ConfigHandler configHandler) {
        this.configHandler = configHandler;
    }

    @Override
    protected void doStart() {
        String pathsstr = System.getenv(Constants.CASC_IMPORT_PATH_ENV);
        if (pathsstr == null) {
            pathsstr = System.getenv(Constants.CASC_IMPORT_PATH_LEGACY_ENV);
        }
        if (pathsstr == null) {
            pathsstr = Constants.CASC_IMPORT_PATH_DEFAULT;
        }
        final Path path = Paths.get(pathsstr);
        if (!Files.isRegularFile(path)) {
            log.warn("CASC: file '{}' not found. Nothing to import.", path);
            return;
        }

        log.info("CASC: processing configuration file '{}' ...", path);
        try {
            final String text = new String(Files.readAllBytes(path), StandardCharsets.UTF_8);
            final boolean applied = configHandler.store(text);
            log.info("CASC: file '{}' processing completed {}.", path, (applied ? "successfully" : "without any changes"));
        } catch (Exception e) {
            log.error("CASC: file '" + path + "' processing failed with error: " + e.getMessage(), e);
        }
    }
}
