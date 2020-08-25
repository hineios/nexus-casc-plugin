package io.github.asharapov.nexus.casc.internal;

import io.github.asharapov.nexus.casc.internal.handlers.ConfigHandler;
import io.github.asharapov.nexus.casc.internal.handlers.Options;
import org.sonatype.nexus.common.app.ApplicationDirectories;
import org.sonatype.nexus.logging.task.TaskLogging;
import org.sonatype.nexus.scheduling.TaskConfiguration;
import org.sonatype.nexus.scheduling.TaskSupport;

import javax.inject.Inject;
import javax.inject.Named;
import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.text.SimpleDateFormat;
import java.util.Date;

import static java.nio.file.StandardOpenOption.CREATE;
import static java.nio.file.StandardOpenOption.TRUNCATE_EXISTING;
import static java.nio.file.StandardOpenOption.WRITE;
import static org.sonatype.nexus.logging.task.TaskLogType.BOTH;

/**
 * Task to export service configuration to file.
 *
 * @author Anton Sharapov
 */
@Named
@TaskLogging(BOTH)
public class CascExportTask extends TaskSupport {

    private final ApplicationDirectories appDirectories;
    private final ConfigHandler configHandler;

    @Inject
    public CascExportTask(final ApplicationDirectories appDirectories, final ConfigHandler configHandler) {
        this.appDirectories = appDirectories;
        this.configHandler = configHandler;
    }

    @Override
    protected Object execute() throws Exception {
        log.info("CASC: export started");
        try {
            final Options opts = getExportOptions();
            final String yamlText = configHandler.load(opts);
            log.debug("CASC: prepared configuration:\n{}", yamlText);

            preparePathToStore(opts.targetPath);
            try (BufferedWriter out = Files.newBufferedWriter(opts.targetPath, StandardCharsets.UTF_8, CREATE, WRITE, TRUNCATE_EXISTING)) {
                log.info("CASC: saving configuration to a '{}' file", opts.targetPath);
                out.write(yamlText);
            }
            log.info("CASC: export completed successfully.");
        } catch (Exception e) {
            log.info("CASC: export was failed", e);
            throw e;
        }
        return null;
    }

    @Override
    public String getMessage() {
        return CascExportTaskDescriptor.TYPE_NAME;
    }


    private Options getExportOptions() {
        final TaskConfiguration cfg = getConfiguration();
        final String pathstr = cfg.getString(CascExportTaskDescriptor.CASC_EXPORT_PATH_FIELD);
        final Path file = isValidPath(pathstr)
                ? Paths.get(pathstr)
                : Paths.get(Utils.getDefaultCascExportPath(appDirectories));
        return new Options(
                file,
                cfg.getBoolean(CascExportTaskDescriptor.CASC_EXPORT_EMPTY_FIELD, CascExportTaskDescriptor.CASC_EXPORT_EMPTY_DEFAULT_VALUE),
                cfg.getBoolean(CascExportTaskDescriptor.CASC_EXPORT_EMPTY_COLLECTIONS_FIELD, CascExportTaskDescriptor.CASC_EXPORT_EMPTY_COLLECTIONS_DEFAULT_VALUE),
                cfg.getBoolean(CascExportTaskDescriptor.CASC_EXPORT_RO_FIELD, CascExportTaskDescriptor.CASC_EXPORT_RO_DEFAULT_VALUE),
                cfg.getBoolean(CascExportTaskDescriptor.CASC_EXPORT_HIDDEN_TASKS_FIELD, CascExportTaskDescriptor.CASC_EXPORT_HIDDEN_TASKS_DEFAULT_VALUE)
        );
    }

    private void preparePathToStore(final Path file) throws IOException {
        final Path dir = file.getParent();
        if (!Files.isDirectory(dir)) {
            log.info("CASC: directory '{}' not found, try to create it.", dir);
            Files.createDirectories(dir);
        }
        if (Files.isRegularFile(file)) {
            final BasicFileAttributes attrs = Files.readAttributes(file, BasicFileAttributes.class);
            final Date lastModified = new Date(attrs.lastModifiedTime().toMillis());
            final String suffix = new SimpleDateFormat("yyyy-MM-dd").format(lastModified);
            final String name = file.getFileName().toString();
            final String prefix = Utils.getHead(name, '.');
            String extension = Utils.getTail(name, '.');
            if (extension == null) {
                extension = "yml";
            }
            final Path backupFile = file.resolveSibling(prefix + "-" + suffix + "." + extension);
            log.warn("CASC: target file '{}' already exists. Moving its content to '{}' ...", file, backupFile);
            Files.move(file, backupFile, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    private static boolean isValidPath(final String pathstr) {
        if (pathstr == null || pathstr.isEmpty())
            return false;
        try {
            final Path p = Paths.get(pathstr);
            return p.getParent() != null;
        } catch (Exception e) {
            return false;
        }
    }

}
