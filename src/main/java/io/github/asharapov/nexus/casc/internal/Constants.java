package io.github.asharapov.nexus.casc.internal;

/**
 * @author Anton Sharapov
 */
public class Constants {

    /**
     * Environment variable, that contains the path to the directory where the Sonatype Nexus configuration file
     * will be written (make sure that the Sonatype Nexus process has write permissions to this directory).
     */
    public static final String CASC_EXPORT_PATH_ENV = "NEXUS_CASC_EXPORT_PATH";

    /**
     * Environment variable that contains the full path to configuration file.
     */
    public static final String CASC_IMPORT_PATH_ENV = "NEXUS_CASC_IMPORT_PATH";

    /**
     * Environment variable that contains the full path to configuration file (added to support older versions of the plugin).
     */
    public static final String CASC_IMPORT_PATH_LEGACY_ENV = "NEXUS_CASC_CONFIG";

    /**
     * The default path to the Yaml configuration file, if the environment variables
     * 'CASC_IMPORT_PATH_ENV' or 'CASC_IMPORT_PATH_LEGACY_ENV' are not set.
     */
    public static final String CASC_IMPORT_PATH_DEFAULT = "/opt/nexus.yml";

    /**
     * CASC plugin working directory, given relative to root working directory of the Sonatype Nexus installation.
     */
    public static final String CASC_WORK_DIR = "casc";
}
