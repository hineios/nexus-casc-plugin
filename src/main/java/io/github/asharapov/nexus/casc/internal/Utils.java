package io.github.asharapov.nexus.casc.internal;

import io.github.asharapov.nexus.casc.internal.model.Config;
import io.github.asharapov.nexus.casc.internal.model.SecurityConfig;
import io.github.asharapov.nexus.casc.internal.model.SystemConfig;
import io.github.asharapov.nexus.casc.internal.yaml.YamlBuilder;
import io.github.asharapov.nexus.casc.internal.yaml.YamlTools;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonatype.nexus.common.app.ApplicationDirectories;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.nodes.Tag;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.URI;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.TimeZone;
import java.util.stream.Stream;

import static io.github.asharapov.nexus.casc.internal.Constants.CASC_EXPORT_PATH_ENV;

/**
 * @author Anton Sharapov
 */
public class Utils {

    private static final Logger log = LoggerFactory.getLogger(Utils.class);

    /**
     * Prepares Yaml parsing/serialiation builder.
     *
     * @param showNullableProperties serialize <code>null</code> properties or not
     * @param showEmptyCollections   serialize properties with empty collections or not
     */
    public static Yaml makeYaml(final boolean showNullableProperties, final boolean showEmptyCollections) {
        return new YamlBuilder(Config.class)
                .showNulls(showNullableProperties)
                .showEmptyCollections(showEmptyCollections)
                .addBeanTag(SystemConfig.Weekday.class, Tag.STR)
                .addBeanTag(TimeZone.class, Tag.MAP)
                .addBeanConstructor(TimeZone.class, YamlTools.TIME_ZONE_CONSTRUCTOR)
                .addBeanRepresenter(TimeZone.class, YamlTools.TIME_ZONE_REPRESENTER)
                .addBeanConstructor(SecurityConfig.Key.class, YamlTools.SECURITY_KEY_CONSTRUCTOR)
                .addBeanRepresenter(SecurityConfig.Key.class, YamlTools.SECURITY_KEY_REPPRESENTER)
                .addBeanRepresenter(SystemConfig.TaskSchedule.class, YamlTools.SYSTEM_TASK_SCHEDULER_REPRESENTER)
                .addBeanRepresenter(URI.class, YamlTools.URI_REPRESENTER)
                .build();
    }

    /**
     * Returns default path to target file where the Sonatype Nexus configuration will be written.
     *
     * @param appDirs Provides access to key Sonatype Nexus directories.
     * @return path to the target file.
     */
    public static String getDefaultCascExportPath(final ApplicationDirectories appDirs) {
        String result = System.getenv(CASC_EXPORT_PATH_ENV);
        if (result == null) {
            final Path installDir = appDirs.getWorkDirectory().toPath().toAbsolutePath();
            result = installDir.resolve(Constants.CASC_WORK_DIR).resolve("export/nexus.yml").toString();
        }
        return result;
    }

    public static Stream<URI> extendDirReferences(final URI uri, final String suffix) {
        if (uri == null) {
            return Stream.empty();
        }
        if (uri.getScheme() != null && uri.getHost() != null) {
            return Stream.of(uri);
        }
        if (uri.getPath() == null) {
            return Stream.empty();
        }
        final Path path = Paths.get(uri.getPath());
        if (Files.isRegularFile(path)) {
            return Stream.of(uri);
        }
        if (Files.isDirectory(path)) {
            try {
                return Files.walk(path)
                        .filter(Files::isRegularFile)
                        .filter(p -> suffix == null || p.toString().toLowerCase().endsWith(suffix))
                        .map(Path::toUri);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
        return Stream.empty();
    }

    public static byte[] load(final URI uri) throws IOException {
        if (uri.getScheme() != null && uri.getHost() != null) {
            final URL url = uri.toURL();
            try (InputStream in = url.openStream()) {
                return load(in);
            }
        } else {
            final Path path = Paths.get(uri.getPath());
            try (InputStream in = Files.newInputStream(path)) {
                return load(in);
            }
        }
    }

    public static byte[] load(final InputStream in) throws IOException {
        final ByteArrayOutputStream out = new ByteArrayOutputStream(2048);
        final byte[] buf = new byte[2048];
        for (int size = in.read(buf); size > 0; size = in.read(buf)) {
            out.write(buf, 0, size);
        }
        return out.toByteArray();
    }

    public static String getHead(final String text, final char delimiter) {
        if (text == null)
            return null;
        final int p = text.indexOf(delimiter);
        return p >= 0 ? text.substring(0, p) : text;
    }

    public static String getTail(final String text, final char delimiter) {
        if (text == null)
            return null;
        final int p = text.indexOf(delimiter);
        return p >= 0 ? text.substring(p + 1) : null;
    }

    public static String stackTrace(final Throwable th) {
        try {
            final StringWriter buf = new StringWriter(128);
            th.printStackTrace(new PrintWriter(buf, false));
            return buf.toString();
        } catch (Exception e) {
            return "Runtime error: " + e.getMessage();
        }
    }
}
