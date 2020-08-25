package io.github.asharapov.nexus.casc.internal.handlers;

import java.nio.file.Path;

/**
 * YAML parsing/serialization options for Nexus configurations model.
 *
 * @author Anton Sharapov
 */
public class Options {

    public final Path targetPath;
    public final boolean showEmptyProperties;
    public final boolean showEmptyCollections;
    public final boolean showReadOnlyObjects;
    public final boolean showHiddenTasks;

    public Options(final Path targetPath,
                   final boolean showEmptyProperties,
                   final boolean showEmptyCollections,
                   final boolean showReadOnlyObjects,
                   final boolean showHiddenTasks) {
        this.targetPath = targetPath;
        this.showEmptyProperties = showEmptyProperties;
        this.showEmptyCollections = showEmptyCollections;
        this.showReadOnlyObjects = showReadOnlyObjects;
        this.showHiddenTasks = showHiddenTasks;
    }

}