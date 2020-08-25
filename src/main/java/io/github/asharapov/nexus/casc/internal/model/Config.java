package io.github.asharapov.nexus.casc.internal.model;

import io.github.asharapov.nexus.casc.internal.yaml.PropertyOrder;

/**
 * @author Anton Sharapov
 */
@PropertyOrder({"metadata", "systemConfig", "securityConfig", "repositoryConfig"})
public class Config {
    public Metadata metadata;
    public SystemConfig systemConfig;
    public SecurityConfig securityConfig;
    public RepositoryConfig repositoryConfig;

    public Config() {
    }

    public Config(final ExecutionPolicy executionPolicy) {
        this.metadata = new Metadata(executionPolicy);
    }

    public enum ExecutionPolicy {
        ALWAYS,
        IF_CHANGED,
        ONLY_ONCE
    }

    @PropertyOrder({"version", "executionPolicy"})
    public static class Metadata {
        public String version;
        public ExecutionPolicy executionPolicy = ExecutionPolicy.IF_CHANGED;

        public Metadata() {
        }

        public Metadata(final ExecutionPolicy executionPolicy) {
            this.executionPolicy = executionPolicy;
        }
    }
}
