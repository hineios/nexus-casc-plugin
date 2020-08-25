package io.github.asharapov.nexus.casc.internal.model;

public class S3BlobStoreVO {
    public String name;
    public BlobStoreVO.Quota softQuota;
    public Configuration bucketConfiguration;

    public static class Configuration {
        public Bucket bucket;
        public Security bucketSecurity;
        public Connection advancedBucketConnection;
    }

    public static class Bucket {
        public String region;
        public String name;
        public String prefix;
        public int expiration;
    }

    public static class Security {
        public String accessKeyId;
        public String role;
        public String sessionToken;
    }

    public static class Connection {
        public String endpoint;
        public String signerType;           // eg: "S3SignerType"
        public boolean forcePathStyle;
    }
}
