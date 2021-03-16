package io.github.asharapov.nexus.casc.internal.model;

public class BlobStoreVO {

    public String name;
    public String type;
    public boolean unavailable;
    public int blobCount;
    public long totalSizeInBytes;
    public long availableSpaceInBytes;
    public Quota softQuota;

    public static class Quota {
        public String type;
        public long limit;
    }
}
