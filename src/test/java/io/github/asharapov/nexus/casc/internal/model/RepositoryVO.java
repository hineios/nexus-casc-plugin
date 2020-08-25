package io.github.asharapov.nexus.casc.internal.model;

import java.util.List;

public class RepositoryVO {
    public enum Type {
        hosted, proxy, group
    }
    public String name;
    public String format;
    public Type type;
    public String url;
    public boolean online;
    public Storage storage;
    public Cleanup cleanup;
    public Proxy proxy;
    public Group group;
    public NegativeCache negativeCache;
    public Http httpClient;
    public MavenAttrs maven;
    public DockerAttrs docker;
    public DockerProxyAttrs dockerProxy;
    public YumAttrs yum;
    public AptAttrs apt;
    public AptSigningAttrs aptSigning;
    public BowerAttrs bower;
    public NugetAttrs nugetProxy;
    public String routingRuleName;


    public static class Storage {
        public enum WritePolicy {
            ALLOW, ALLOW_ONCE, DENY
        }
        public String blobStoreName;
        public boolean strictContentTypeValidation;
        public WritePolicy writePolicy;
    }

    public static class Cleanup {
        public List<String> policyNames;
    }

    public static class Proxy {
        public String remoteUrl;
        public int contentMaxAge;
        public int metadataMaxAge;
    }

    public static class Group {
        public List<String> memberNames;
    }

    public static class NegativeCache {
        public boolean enabled;
        public int timeToLive;
    }

    public static class Http {
        public boolean blocked;
        public boolean autoBlock;
        public Connection connection;
        public Authentication authentication;
    }

    public static class Connection {
        public Integer retries;
        public String userAgentSuffix;
        public Integer timeout;
        public boolean enableCircularRedirects;
        public boolean enableCookies;
    }

    public static class Authentication {
        public enum Type {
            username, ntlm, bearerToken
        }
        public Type type;
        public String username;
        public String ntlmHost;
        public String ntlmDomain;
    }

    public static class MavenAttrs {
        public enum VersionPolicy {
            RELEASE, SNAPSHOT, MIXED
        }
        public enum LayoutPolicy {
            STRICT, PERMISSIVE
        }
        public VersionPolicy versionPolicy;
        public LayoutPolicy layoutPolicy;
    }

    public static class DockerAttrs {
        public boolean v1Enabled;
        public boolean forceBasicAuth;
        public Integer httpPort;
        public Integer httpsPort;
    }

    public static class DockerProxyAttrs {
        public String indexType;
        public String indexUrl;
    }

    public static class YumAttrs {
        public enum DeployPolicy {
             PERMISSIVE, STRICT
        }
        public int repodataDepth;
        public DeployPolicy deployPolicy;
    }

    public static class AptAttrs {
        public String distribution;
        public boolean flat;
    }

    public static class AptSigningAttrs {
        public String keypair;
        public String passphrase;
    }

    public static class BowerAttrs {
        public boolean rewritePackageUrls;
    }

    public static class NugetAttrs {
        public Integer queryCacheItemMaxAge;
    }
}
