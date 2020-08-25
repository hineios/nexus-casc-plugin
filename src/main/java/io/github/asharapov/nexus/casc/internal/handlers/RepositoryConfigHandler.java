package io.github.asharapov.nexus.casc.internal.handlers;

import io.github.asharapov.nexus.casc.internal.Utils;
import io.github.asharapov.nexus.casc.internal.model.RepositoryConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonatype.nexus.blobstore.api.BlobStore;
import org.sonatype.nexus.blobstore.api.BlobStoreConfiguration;
import org.sonatype.nexus.blobstore.api.BlobStoreManager;
import org.sonatype.nexus.blobstore.file.FileBlobStore;
import org.sonatype.nexus.cleanup.config.CleanupPolicyConfiguration;
import org.sonatype.nexus.cleanup.storage.CleanupPolicy;
import org.sonatype.nexus.cleanup.storage.CleanupPolicyStorage;
import org.sonatype.nexus.common.entity.EntityId;
import org.sonatype.nexus.repository.Recipe;
import org.sonatype.nexus.repository.Repository;
import org.sonatype.nexus.repository.config.Configuration;
import org.sonatype.nexus.repository.group.GroupFacet;
import org.sonatype.nexus.repository.manager.RepositoryManager;
import org.sonatype.nexus.repository.routing.RoutingMode;
import org.sonatype.nexus.repository.routing.RoutingRule;
import org.sonatype.nexus.repository.routing.RoutingRuleStore;
import org.sonatype.nexus.selector.SelectorConfiguration;
import org.sonatype.nexus.selector.SelectorFactory;
import org.sonatype.nexus.selector.SelectorManager;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * @author Anton Sharapov
 */
@Named
@Singleton
public class RepositoryConfigHandler {
    private static final Logger log = LoggerFactory.getLogger(RepositoryConfigHandler.class);
    private static final Comparator<RepositoryConfig.Repository> REPO_COMPARATOR = (r1, r2) -> {
        final String fmt1 = Utils.getHead(r1.recipeName, '-');
        final String fmt2 = Utils.getHead(r2.recipeName, '-');
        if (fmt1 == null && fmt2 != null) {
            return 1;
        }
        if (fmt1 != null && fmt2 == null) {
            return -1;
        }
        int result = Objects.compare(fmt1, fmt2, String::compareTo);
        if (result != 0) {
            return result;
        }
        final String typ1 = Utils.getTail(r1.recipeName, '-');
        final String typ2 = Utils.getTail(r2.recipeName, '-');
        if (typ1 == null && typ2 != null) {
            return 1;
        }
        if (typ1 != null && typ2 == null) {
            return -1;
        }
        if ("group".equals(typ1) && !"group".equals(typ2)) {
            return 1;
        }
        if (!"group".equals(typ1) && "group".equals(typ2)) {
            return -1;
        }
        return Objects.compare(typ1, typ2, String::compareTo);
    };

    private final BlobStoreManager blobStoreManager;
    private final CleanupPolicyStorage cleanupPolicyStorage;
    private final Map<String, CleanupPolicyConfiguration> cleanupPolicyConfigurations;
    private final CleanupPolicyConfiguration defaultCleanupPolicyConfiguration;
    private final SelectorFactory selectorFactory;
    private final SelectorManager selectorManager;
    private final RoutingRuleStore routingRuleStore;
    private final RepositoryManager repositoryManager;
    private final Map<String, Recipe> recipes;

    @Inject
    RepositoryConfigHandler(final BlobStoreManager blobStoreManager,
                            final CleanupPolicyStorage cleanupPolicyStorage,
                            final Map<String, CleanupPolicyConfiguration> cleanupPolicyConfigurations,
                            final SelectorFactory selectorFactory,
                            final SelectorManager selectorManager,
                            final RoutingRuleStore routingRuleStore,
                            final RepositoryManager repositoryManager,
                            final Map<String, Recipe> recipes) {
        this.blobStoreManager = blobStoreManager;
        this.cleanupPolicyStorage = cleanupPolicyStorage;
        this.cleanupPolicyConfigurations = cleanupPolicyConfigurations;
        this.defaultCleanupPolicyConfiguration = cleanupPolicyConfigurations.get("default");
        this.selectorFactory = selectorFactory;
        this.selectorManager = selectorManager;
        this.routingRuleStore = routingRuleStore;
        this.repositoryManager = repositoryManager;
        this.recipes = recipes;
    }

    public RepositoryConfig load(final Options opts) {
        final RepositoryConfig config = new RepositoryConfig();
        config.blobStores = getBlobStores();
        config.blobStoresToDelete = new ArrayList<>();
        config.cleanupPolicies = getCleanupPolicies();
        config.cleanupPoliciesToDelete = new ArrayList<>();
        config.selectors = getSelectors();
        config.selectorsToDelete = new ArrayList<>();
        config.routingRules = getRoutingRules();
        config.routingRulesToDelete = new ArrayList<>();
        config.repositories = getRepositories();
        config.repositoriesToDelete = new ArrayList<>();
        config.pruneOtherRepositories = null;
        return config;
    }

    public void store(final RepositoryConfig config) {
        if (config == null) {
            return;
        }
        updateBlobStores(config.blobStores);
        deleteBlobStores(config.blobStoresToDelete);
        updateCleanupPolicies(config.cleanupPolicies);
        deleteCleanupPolicies(config.cleanupPoliciesToDelete);
        updateSelectors(config.selectors);
        deleteSelectors(config.selectorsToDelete);
        updateRoutingRules(config.routingRules);
        deleteRoutingRules(config.routingRulesToDelete);
        updateRepositories(config.repositories);
        deleteRepositories(config.repositoriesToDelete);
        pruneOtherRepositories(config.pruneOtherRepositories, config.repositories);
    }


    private List<RepositoryConfig.BlobStore> getBlobStores() {
        final List<RepositoryConfig.BlobStore> result = new ArrayList<>();
        for (BlobStore blobStore : blobStoreManager.browse()) {
            final BlobStoreConfiguration cfg = blobStore.getBlobStoreConfiguration();
            final RepositoryConfig.BlobStore model = new RepositoryConfig.BlobStore();
            model.name = cfg.getName();
            model.type = RepositoryConfig.BlobStoreType.valueOf(cfg.getType());
            model.attrs = cfg.getAttributes();
            result.add(model);
        }
        return result;
    }

    private void updateBlobStores(final List<RepositoryConfig.BlobStore> blobStores) {
        if (blobStores == null) {
            return;
        }
        for (RepositoryConfig.BlobStore model : blobStores) {
            if (model.type == null) {
                throw new RuntimeException("Invalid blob store model: blob store type (File/S3) must be specified");
            }
            if (model.name == null) {
                throw new RuntimeException("Invalid blob store model: blob store name must be specified");
            }
            if (model.attrs == null) {
                throw new RuntimeException("Invalid blob store model: blob store attributes must be specified");
            }
            final BlobStore existingBlobStore = blobStoreManager.get(model.name);
            if (existingBlobStore != null) {
                // checks common to all types of storages ...
                final BlobStoreConfiguration existingCfg = existingBlobStore.getBlobStoreConfiguration();
                if (!existingCfg.getType().equals(model.type.name())) {
                    log.error("Can't update type of blob stores. Blob store: {}, current type: {}, new type: {}", model.name, existingCfg.getType(), model.type);
                    throw new RuntimeException("Can't update type of the blob store " + model.name);
                }
                // checks specific to different types of storages ...
                switch (model.type) {
                    case File: {
                        final Object oldPath = existingCfg.getAttributes()
                                .getOrDefault(FileBlobStore.CONFIG_KEY, Collections.emptyMap())
                                .get(FileBlobStore.PATH_KEY);
                        final Object newPath = model.attrs
                                .getOrDefault(FileBlobStore.CONFIG_KEY, Collections.emptyMap())
                                .get(FileBlobStore.PATH_KEY);
                        if (!Objects.equals(oldPath, newPath)) {
                            // TODO: in that case we should update orientdb records manually, see: https://support.sonatype.com/hc/en-us/articles/235816228-Relocating-Blob-Stores
                            throw new RuntimeException("Can't update 'file.path' attribute for blob store " + model.name + " (" + oldPath + " -> " + newPath + ")");
                        }
                        break;
                    }
                    case S3: {
                        final Map<String, Object> s3Attrs = model.attrs.get("s3");
                        if (s3Attrs == null) {
                            throw new RuntimeException("No S3 specific attrs for blob store " + model.name);
                        }
                        if (!s3Attrs.containsKey("bucket")) {
                            throw new RuntimeException("No bucket specified for blob store " + model.name);
                        }
                        if (!s3Attrs.containsKey("accessKeyId")) {
                            throw new RuntimeException("No 'accessKeyId' specified for blob store " + model.name);
                        }
                        if (!s3Attrs.containsKey("secretAccessKey")) {
                            throw new RuntimeException("No 'secretAccessKey' specified for blob store " + model.name);
                        }
                        // TODO: add more checks here ...
                        break;
                    }
                }
                boolean changed = false;
                if (!Objects.equals(model.attrs, existingCfg.getAttributes())) {
                    existingCfg.setAttributes(model.attrs);
                    changed = true;
                }
                try {
                    if (changed) {
                        log.info("Updating blob store {name:{}, type:{}} ...", model.name, model.type);
                        blobStoreManager.update(existingCfg);
                    }
                } catch (Exception e) {
                    throw new RuntimeException("Could not update blob store " + model.name + " : " + e.getMessage(), e);
                }
            } else {
                final BlobStoreConfiguration cfg = blobStoreManager.newConfiguration();
                cfg.setName(model.name);
                cfg.setType(model.type.name());
                cfg.setAttributes(model.attrs);
                try {
                    log.info("Adding new blob store {name:{}, type:{}} ...", model.name, model.type);
                    blobStoreManager.create(cfg);
                } catch (Exception e) {
                    log.error("Could not create blob store {type:" + model.type + ", name:" + model.name + "} : " + e.getMessage(), e);
                    throw new RuntimeException(e.getMessage(), e);
                }
            }
        }
    }

    private void deleteBlobStores(final List<String> blobStoresToDelete) {
        if (blobStoresToDelete == null || blobStoresToDelete.isEmpty()) {
            return;
        }
        for (String storeName : blobStoresToDelete) {
            final BlobStore blobStore = blobStoreManager.get(storeName);
            if (blobStore == null) {
                continue;
            }
            for (Repository repo : repositoryManager.browseForBlobStore(storeName)) {
                try {
                    log.info("Deleting repository '{}' ...", storeName);
                    repositoryManager.delete(repo.getName());
                } catch (Exception e) {
                    log.error("Can't delete repository '" + repo.getName() + "' : " + e.getMessage(), e);
                    throw new RuntimeException(e);
                }
            }
            try {
                log.info("Deleting blob store '{}' ...", storeName);
                blobStoreManager.delete(storeName);
            } catch (Exception e) {
                log.error("Can't delete bob store '" + storeName + "' : " + e.getMessage(), e);
                throw new RuntimeException(e);
            }
        }
    }


    private List<RepositoryConfig.CleanupPolicy> getCleanupPolicies() {
        final List<RepositoryConfig.CleanupPolicy> result = new ArrayList<>();
        for (CleanupPolicy policy : cleanupPolicyStorage.getAll()) {
            final RepositoryConfig.CleanupPolicy model = new RepositoryConfig.CleanupPolicy();
            model.name = policy.getName();
            model.format = policy.getFormat();
            model.mode = policy.getMode();
            model.criteria = policy.getCriteria();
            model.notes = policy.getNotes();
            result.add(model);
        }
        return result;
    }

    private void updateCleanupPolicies(final List<RepositoryConfig.CleanupPolicy> policies) {
        if (policies == null) {
            return;
        }
        for (RepositoryConfig.CleanupPolicy model : policies) {
            if (model == null || model.name == null) {
                throw new RuntimeException("Cleanup policy name must be specified");
            }
            if (model.format == null) {
                throw new RuntimeException("Cleanup policy format must be specified");
            }
            if (!cleanupPolicyConfigurations.containsKey(model.format)) {
                throw new RuntimeException("Unsupported format of the cleanup policy: " + model.format);
            }
            if (model.criteria != null) {
                final CleanupPolicyConfiguration cfg = cleanupPolicyConfigurations.get(model.format);
                for (String attr : model.criteria.keySet()) {
                    Boolean ok = cfg.getConfiguration().get(attr);
                    if (ok == null && defaultCleanupPolicyConfiguration != null) {
                        ok = defaultCleanupPolicyConfiguration.getConfiguration().get(attr);
                    }
                    if (ok == null || !ok) {
                        throw new RuntimeException("Unsupported criterion '" + attr + "' in the cleanup policy '" + model.name + "'");
                    }
                }
            }
            CleanupPolicy policy = cleanupPolicyStorage.get(model.name);
            if (policy != null) {
                boolean changed = false;
                if (model.mode != null && !model.mode.equals(policy.getMode())) {
                    policy.setMode(model.mode);
                    changed = true;
                }
                if (model.notes != null && !model.notes.equals(policy.getNotes())) {
                    policy.setNotes(model.notes);
                    changed = true;
                }
                if (model.criteria != null && (policy.getCriteria() == null || !Objects.equals(model.criteria, policy.getCriteria()))) {
                    policy.setCriteria(model.criteria);
                    changed = true;
                }
                if (changed) {
                    log.info("Updating cleanup policy {name:{}, format:{}} ...", model.name, model.format);
                    cleanupPolicyStorage.update(policy);
                }
            } else {
                policy = cleanupPolicyStorage.newCleanupPolicy();
                policy.setName(model.name);
                policy.setFormat(model.format);
                policy.setMode(model.mode);
                if (model.criteria != null) {
                    policy.setCriteria(model.criteria);
                }
                policy.setNotes(model.notes);
                log.info("Adding cleanup policy {name:{}, format:{}} ...", model.name, model.format);
                cleanupPolicyStorage.add(policy);
            }
        }
    }

    private void deleteCleanupPolicies(final List<String> cleanupPoliciesToDelete) {
        if (cleanupPoliciesToDelete == null || cleanupPoliciesToDelete.isEmpty()) {
            return;
        }
        for (String policyName : cleanupPoliciesToDelete) {
            final CleanupPolicy policy = cleanupPolicyStorage.get(policyName);
            if (policy != null) {
                log.info("Deleting cleanup policy '{}' ...", policyName);
                cleanupPolicyStorage.remove(policy);
            }
        }
    }


    private List<RepositoryConfig.Selector> getSelectors() {
        final List<RepositoryConfig.Selector> result = new ArrayList<>();
        for (SelectorConfiguration selector : selectorManager.browse()) {
            final RepositoryConfig.Selector model = new RepositoryConfig.Selector();
            model.name = selector.getName();
            model.type = selector.getType();
            model.description = selector.getDescription();
            model.attrs = selector.getAttributes();
            result.add(model);
        }
        return result;
    }

    private void updateSelectors(final List<RepositoryConfig.Selector> selectors) {
        if (selectors == null) {
            return;
        }
        for (RepositoryConfig.Selector model : selectors) {
            if (model.name == null) {
                throw new RuntimeException("Content selector name should be specified");
            }
            if (model.type == null) {
                throw new RuntimeException("Content selector type should be specified");
            }
            if (model.attrs == null) {
                throw new RuntimeException("Content selector attributes should be specified");
            }
            selectorFactory.validateSelector(model.type, model.attrs.get("expression"));
            final SelectorConfiguration scfg = selectorManager.findByName(model.name).orElse(null);
            if (scfg != null) {
                boolean changed = false;
                if (!Objects.equals(model.attrs, scfg.getAttributes())) {
                    scfg.setAttributes(model.attrs);
                    changed = true;
                }
                if (model.description != null && !model.description.equals(scfg.getDescription())) {
                    scfg.setDescription(model.description);
                    changed = true;
                }
                if (changed) {
                    log.info("Updating content selector {name:{}, type:{}} ...", model.name, model.type);
                    selectorManager.update(scfg);
                }
            } else {
                log.info("Adding new content selector {name:{}, type:{}} ...", model.name, model.type);
                selectorManager.create(model.name, model.type, model.description, model.attrs);
            }
        }
    }

    private void deleteSelectors(final List<String> selectorsToDelete) {
        if (selectorsToDelete == null || selectorsToDelete.isEmpty()) {
            return;
        }
        for (String selectorName : selectorsToDelete) {
            final SelectorConfiguration scfg = selectorManager.findByName(selectorName).orElse(null);
            if (scfg != null) {
                log.info("Deleting selector '{}' ...", selectorName);
                selectorManager.delete(scfg);
            }
        }
    }


    private List<RepositoryConfig.RoutingRule> getRoutingRules() {
        final List<RepositoryConfig.RoutingRule> result = new ArrayList<>();
        for (RoutingRule rule : routingRuleStore.list()) {
            final RepositoryConfig.RoutingRule model = new RepositoryConfig.RoutingRule();
            model.name = rule.name();
            model.description = rule.description();
            model.mode = RepositoryConfig.RoutingMode.valueOf(rule.mode().name());
            model.matchers = rule.matchers();
            result.add(model);
        }
        return result;
    }

    private void updateRoutingRules(final List<RepositoryConfig.RoutingRule> routingRules) {
        if (routingRules == null) {
            return;
        }
        for (RepositoryConfig.RoutingRule model : routingRules) {
            if (model.name == null) {
                throw new RuntimeException("Routing rule name should be specified");
            }
            if (model.mode == null) {
                throw new RuntimeException("Routing rule '" + model.name + "' mode should be specified");
            }
            if (model.matchers == null || model.matchers.isEmpty()) {
                throw new RuntimeException("Routing rule '" + model.name + "' matchers should be specified");
            }
            RoutingRule rule = routingRuleStore.getByName(model.name);
            if (rule != null) {
                boolean changed = false;
                if (model.description != null && !model.description.equals(rule.description())) {
                    rule.description(model.description);
                    changed = true;
                }
                if (!Objects.equals(model.mode.name(), rule.mode().name())) {
                    rule.mode(RoutingMode.valueOf(model.mode.name()));
                    changed = true;
                }
                if (!Objects.equals(model.matchers, rule.matchers())) {
                    rule.matchers(model.matchers);
                    changed = true;
                }
                if (changed) {
                    log.info("Updating routing rule {} ...", model.name);
                    routingRuleStore.update(rule);
                }
            } else {
                log.info("Adding new routing rule {} ...", model.name);
                rule = routingRuleStore.newRoutingRule()
                        .name(model.name)
                        .description(model.description)
                        .mode(RoutingMode.valueOf(model.mode.name()))
                        .matchers(model.matchers);
                routingRuleStore.create(rule);
            }
        }
    }

    private void deleteRoutingRules(final List<String> routingRulesToDelete) {
        if (routingRulesToDelete == null || routingRulesToDelete.isEmpty()) {
            return;
        }
        for (String ruleName : routingRulesToDelete) {
            final RoutingRule rule = routingRuleStore.getByName(ruleName);
            if (rule != null) {
                log.info("Deleting routing rule '{}' ...", ruleName);
                routingRuleStore.delete(rule);
            }
        }
    }


    private List<RepositoryConfig.Repository> getRepositories() {
        final List<RepositoryConfig.Repository> result = new ArrayList<>();
        for (Repository repo : repositoryManager.browse()) {
            final Configuration repoCfg = repo.getConfiguration();
            final RepositoryConfig.Repository model = new RepositoryConfig.Repository();
            model.name = repoCfg.getRepositoryName();
            model.recipeName = repoCfg.getRecipeName();
            model.online = repoCfg.isOnline();
            model.attrs = repoCfg.getAttributes();
            patchRepoAttrsBeforeSerialization(model.attrs);
            final EntityId rid = repoCfg.getRoutingRuleId();
            if (rid != null) {
                final RoutingRule rule = routingRuleStore.getById(rid.getValue());
                if (rule != null) {
                    model.routingRule = rule.name();
                }
            }
            result.add(model);
        }
        result.sort(REPO_COMPARATOR);
        return result;
    }

    private void updateRepositories(final List<RepositoryConfig.Repository> repositories) {
        if (repositories == null) {
            return;
        }
        repositories.sort(REPO_COMPARATOR);
        for (RepositoryConfig.Repository model : repositories) {
            if (model.name == null) {
                throw new RuntimeException("Repository name should be specified");
            }
            if (model.recipeName == null) {
                throw new RuntimeException("Repository '" + model.name + "' recipeName should be specified");
            }
            if (model.attrs == null) {
                throw new RuntimeException("Repository '" + model.name + "' attributes should be specified");
            }
            if (!recipes.containsKey(model.recipeName)) {
                throw new RuntimeException("Unknown recipe '" + model.recipeName + "' specified for repository '" + model.name + "'");
            }
            final RoutingRule routingRule;
            if (model.routingRule != null) {
                routingRule = routingRuleStore.getByName(model.routingRule);
                if (routingRule == null) {
                    throw new RuntimeException("Bad reference to routing rule '" + model.routingRule + "' in the repository '" + model.name + "'");
                }
            } else {
                routingRule = null;
            }
            patchRepoAttrsBeforeParsing(model.attrs);
            Object cleanupPolicyNames = model.attrs.getOrDefault("cleanup", Collections.emptyMap()).get("policyName");
            if (cleanupPolicyNames instanceof Collection) {
                for (Object policyName : (Collection<?>) cleanupPolicyNames) {
                    if (!cleanupPolicyStorage.exists(String.valueOf(policyName))) {
                        throw new RuntimeException("Bad reference to cleanup policy '" + policyName + "' in the repository '" + model.name + "'");
                    }
                }
            }
            final String newStoreName = (String) model.attrs.getOrDefault("storage", Collections.emptyMap()).get("blobStoreName");
            if (newStoreName != null && blobStoreManager.get(newStoreName) == null) {
                throw new RuntimeException("Unknown blob store '" + newStoreName + "' specified for repository '" + model.name + "'");
            }
            Repository repo = repositoryManager.get(model.name);
            List<Repository> groups = Collections.emptyList();
            if (repo != null && newStoreName != null) {
                final String oldStoreName = (String) getRepoAttribute(repo, "storage", "blobStoreName");
                if (oldStoreName != null && !oldStoreName.equals(newStoreName)) {
                    log.warn("Deleting existing repository {} to blob store change from {} to {}", model.name, oldStoreName, newStoreName);
                    try {
                        groups = findGroupRepositoriesWithMember(repo);
                        repositoryManager.delete(repo.getName());
                        repo = null;
                    } catch (Exception e) {
                        throw new RuntimeException("Can't delete repository " + model.name + " : " + e.getMessage(), e);
                    }
                }
            }
            if (repo != null) {
                final Configuration repoCfg = repo.getConfiguration();
                if (!Objects.equals(model.recipeName, repoCfg.getRecipeName())) {
                    throw new RuntimeException("Can't change recipeName for repository '" + model.name + "'");
                }
                boolean changed = false;
                if (model.online != null && model.online != repoCfg.isOnline()) {
                    repoCfg.setOnline(model.online);
                    changed = true;
                }
                if (!Objects.equals(model.attrs, repoCfg.getAttributes())) {
                    repoCfg.setAttributes(model.attrs);
                    changed = true;
                }
                if (routingRule != null && !Objects.equals(routingRule.id(), repoCfg.getRoutingRuleId())) {
                    repoCfg.setRoutingRuleId(routingRule.id());
                    changed = true;
                }
                if (changed) {
                    try {
                        log.info("Updating repository {name: {}, recipe: {}} ...", model.name, model.recipeName);
                        repositoryManager.update(repoCfg);
                    } catch (Exception e) {
                        log.error("Failed to create repo '" + model.name + "' : " + e.getMessage(), e);
                        throw new RuntimeException(e.getMessage(), e);
                    }
                }
            } else {
                final Configuration repoCfg = repositoryManager.newConfiguration();
                repoCfg.setRepositoryName(model.name);
                repoCfg.setRecipeName(model.recipeName);
                repoCfg.setOnline(model.online == null || model.online);
                repoCfg.setAttributes(model.attrs);
                if (routingRule != null) {
                    repoCfg.setRoutingRuleId(routingRule.id());
                }
                try {
                    log.info("Adding new repository {name: {}, recipe: {}} ...", model.name, model.recipeName);
                    final Repository newRepo = repositoryManager.create(repoCfg);
                    for (Repository group : groups) {
                        final Configuration grpcfg = group.getConfiguration();
                        final Collection<String> memberNames = grpcfg.attributes("group").get("memberNames", Collection.class);
                        if (memberNames != null) {
                            log.info("Add repository {} to group {} ...", newRepo.getName(), group.getName());
                            memberNames.add(newRepo.getName());
                            repositoryManager.update(grpcfg);
                        }
                    }
                } catch (Exception e) {
                    log.error("Failed to create repo '" + model.name + "' : " + e.getMessage(), e);
                    throw new RuntimeException(e.getMessage(), e);
                }
            }
        }
    }

    private void deleteRepositories(final List<String> repositoriesToDelete) {
        if (repositoriesToDelete == null || repositoriesToDelete.isEmpty()) {
            return;
        }
        for (String repoName : repositoriesToDelete) {
            final Repository repo = repositoryManager.get(repoName);
            if (repo != null) {
                log.info("Deleting repository '{}' ...", repoName);
                try {
                    repositoryManager.delete(repoName);
                } catch (Exception e) {
                    log.error("Can't delete repository '" + repoName + "' : " + e.getMessage(), e);
                }
            }
        }
    }

    private void pruneOtherRepositories(final Boolean pruneOtherRepositories, final List<RepositoryConfig.Repository> repositories) {
        if (pruneOtherRepositories == null || !pruneOtherRepositories) {
            return;
        }
        if (repositories == null || repositories.isEmpty()) {
            log.error("'repositoryConfig.pruneOtherRepositories' has no effect when no 'repositoryConfig.repositories' are configured!");
            return;
        }
        final Set<String> allowedRepoNames = repositories.stream()
                .map(m -> m.name)
                .filter(Objects::nonNull)
                .collect(Collectors.toSet());
        for (Repository repo : repositoryManager.browse()) {
            if (!allowedRepoNames.contains(repo.getName())) {
                continue;
            }
            final Object members = getRepoAttribute(repo, "group", "memberNames");
            if (members instanceof Collection) {
                for (Object member : (Collection<?>) members) {
                    allowedRepoNames.add(String.valueOf(member));
                }
            }
        }
        for (Repository repo : repositoryManager.browse()) {
            final String repoName = repo.getName();
            if (!allowedRepoNames.contains(repoName)) {
                try {
                    log.info("Deleting repository '{}' ...", repoName);
                    repositoryManager.delete(repoName);
                } catch (Exception e) {
                    log.error("Can't delete repository '" + repoName + "' : " + e.getMessage(), e);
                }
            }
        }
    }

    private List<Repository> findGroupRepositoriesWithMember(final Repository member) {
        final List<Repository> groups = new ArrayList<>();
        for (Repository group : repositoryManager.browse()) {
            final Optional<GroupFacet> groupFacet = group.optionalFacet(GroupFacet.class);
            if (groupFacet.isPresent() && groupFacet.get().member(member)) {
                groups.add(group);
            }
        }
        return groups;
    }


    private static void patchRepoAttrsBeforeSerialization(final Map<String, Map<String, Object>> repoAttrs) {
        if (repoAttrs == null) {
            return;
        }
        final Map<String, Object> cleanup = repoAttrs.get("cleanup");
        if (cleanup != null) {
            Object policyName = cleanup.get("policyName");
            if (policyName != null) {
                if (policyName instanceof String) {
                    cleanup.put("policyName", Collections.singletonList((String) policyName));
                } else if (policyName instanceof Set) {
                    cleanup.put("policyName", new ArrayList<>((Collection<?>) policyName));
                }
            }
        }
    }

    private static void patchRepoAttrsBeforeParsing(final Map<String, Map<String, Object>> repoAttrs) {
        if (repoAttrs == null) {
            return;
        }
        final Map<String, Object> cleanup = repoAttrs.get("cleanup");
        if (cleanup != null) {
            Object policyName = cleanup.get("policyName");
            if (policyName != null) {
                if (policyName instanceof String) {
                    log.warn("repositoryConfig.repositories[].attrs.cleanup.policyName should be a list as of Nexus 3.19.1, converting it for you");
                    cleanup.put("policyName", new HashSet<>(Collections.singletonList((String) policyName)));
                } else if (policyName instanceof List) {
                    cleanup.put("policyName", new HashSet<>((Collection<?>) policyName));
                }
            }
        }
    }

    private static Object getRepoAttribute(final Repository repo, final String groupAttr, final String attr) {
        final Map<String, Map<String, Object>> attrs = repo.getConfiguration().getAttributes();
        return attrs != null ? attrs.getOrDefault(groupAttr, Collections.emptyMap()).get(attr) : null;
    }
}
