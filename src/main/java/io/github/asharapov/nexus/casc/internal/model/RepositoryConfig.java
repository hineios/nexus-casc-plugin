package io.github.asharapov.nexus.casc.internal.model;

import io.github.asharapov.nexus.casc.internal.yaml.PropertyOrder;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * @author Anton Sharapov
 */
@PropertyOrder({"blobStores", "blobStoresToDelete", "cleanupPolicies", "cleanupPoliciesToDelete", "selectors", "selectorsToDelete",
        "routingRules", "routingRulesToDelete", "repositories", "repositoriesToDelete", "pruneOtherRepositories"})
public class RepositoryConfig {

    public List<BlobStore> blobStores;
    public List<String> blobStoresToDelete;
    public List<CleanupPolicy> cleanupPolicies;
    public List<String> cleanupPoliciesToDelete;
    public List<Selector> selectors;
    public List<String> selectorsToDelete;
    public List<RoutingRule> routingRules;
    public List<String> routingRulesToDelete;
    public List<Repository> repositories;
    public List<String> repositoriesToDelete;
    public Boolean pruneOtherRepositories;


    public enum BlobStoreType {
        File, S3, Group
    }

    @PropertyOrder({"name", "type", "attrs"})
    public static class BlobStore {
        public String name;
        public BlobStoreType type;
        public Map<String, Map<String, Object>> attrs;

        public BlobStore() {
        }

        public BlobStore(final BlobStoreType type, final String name) {
            this.type = type;
            this.name = name;
            this.attrs = new HashMap<>();
        }

        public void putAttribute(final String attrGroup, final String attrName, final Object attrValue) {
            final Map<String, Object> map = this.attrs.computeIfAbsent(attrGroup, (k) -> new HashMap<>());
            map.put(attrName, attrValue);
        }

        @Override
        public String toString() {
            return "[BlobStore{type:" + type + ", name:" + name + ", attrs:" + attrs + "}]";
        }
    }


    @PropertyOrder({"name", "format", "mode", "criteria", "notes"})
    public static class CleanupPolicy {
        public String name;
        public String format;
        public String mode;
        public Map<String, String> criteria;
        public String notes;

        public CleanupPolicy() {
        }

        public CleanupPolicy(final String name, final String format) {
            this.name = name;
            this.format = format;
            this.criteria = new HashMap<>();
        }

        @Override
        public String toString() {
            return "[CleanupPolicy{name:" + name + ", fmt:" + format + ", mode:" + mode + ", criteria:" + criteria + "}]";
        }
    }


    @PropertyOrder({"name", "type", "description", "attrs"})
    public static class Selector {
        public String name;
        public String type;
        public String description;
        public Map<String, String> attrs;

        public Selector() {
        }

        public Selector(final String name, final String type) {
            this.name = name;
            this.type = type;
            this.attrs = new HashMap<>();
        }

        @Override
        public String toString() {
            return "[Selector{name:" + name + ", type:" + type + ", attrs:" + attrs + "}]";
        }
    }


    public enum RoutingMode {
        ALLOW, BLOCK
    }

    @PropertyOrder({"name", "mode", "matchers", "description"})
    public static class RoutingRule {
        public String name;
        public RoutingMode mode;
        public List<String> matchers;
        public String description;

        public RoutingRule() {
        }

        public RoutingRule(final String name, final RoutingMode mode, final String... matchers) {
            this.name = name;
            this.mode = mode;
            this.matchers = Arrays.asList(matchers);
        }

        @Override
        public String toString() {
            return "[RoutingRule{name:" + name + ", mode:" + mode + ", matchers:" + matchers + "}]";
        }
    }


    @PropertyOrder({"name", "recipeName", "online", "attrs", "routingRule"})
    public static class Repository {
        public String name;
        public String recipeName;
        public Boolean online;
        public Map<String, Map<String, Object>> attrs;
        public String routingRule;

        public Repository() {
        }

        public Repository(final String name, final String recipeName, final Boolean online) {
            this.name = name;
            this.recipeName = recipeName;
            this.online = online;
            this.attrs = new HashMap<>();
        }

        public void putAttribute(final String attrGroup, final String attrName, final Object attrValue) {
            final Map<String, Object> map = this.attrs.computeIfAbsent(attrGroup, (k) -> new HashMap<>());
            map.put(attrName, attrValue);
        }

        @Override
        public String toString() {
            return "[Repo{name:" + name + ", recipe:" + recipeName + ", attrs:" + attrs + "}]";
        }
    }
}
