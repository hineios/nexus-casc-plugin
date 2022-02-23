package io.github.asharapov.nexus.casc.internal.utils;

import com.github.dockerjava.api.model.ContainerNetwork;
import com.github.dockerjava.api.model.HostConfig;
import io.minio.BucketExistsArgs;
import io.minio.MakeBucketArgs;
import io.minio.MinioClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.DockerImageName;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * Represents dockerized minio S3 server instance.
 *
 * @author Anton Sharapov
 */
public class MinioServer extends GenericContainer<MinioServer> {

    private static final Logger log = LoggerFactory.getLogger(MinioServer.class);

    private static final DockerImageName IMAGE = DockerImageName.parse("minio/minio:latest");
    private static final String ACCESS_KEY = "admin";
    private static final String SECRET_KEY = "admin123";
    private static final List<String> TEST_BUCKETS = Arrays.asList("store1", "store2");

    public MinioServer() {
        super(IMAGE);
        withExposedPorts(9000);
        withCreateContainerCmdModifier(cmd -> {
            // required for root-less containers working with the Podman and SELinux environment.
            HostConfig hc = cmd.getHostConfig();
            if (hc == null) {
                hc = new HostConfig();
                cmd.withHostConfig(hc);
            }
            hc.withSecurityOpts(Collections.singletonList("label=disable"));
        });
        waitingFor(Wait.forHttp("/minio/health/live").forStatusCodeMatching(it -> it >= 200 && it < 300));
        withCommand("server", "/data");
        withEnv("MINIO_ACCESS_KEY", ACCESS_KEY);
        withEnv("MINIO_SECRET_KEY", SECRET_KEY);
    }

    public String getInternalHostName() {
        String host = this.getContainerInfo().getName();
        if (host.startsWith("/")) {
            host = host.substring(1);
        }
        return host;
    }

    public String getInternalIPAddress() {
        final Map<String, ContainerNetwork> networks = this.getContainerInfo().getNetworkSettings().getNetworks();
        if (networks == null || networks.size() != 1) {
            throw new IllegalStateException("Container not started");
        }
        final ContainerNetwork net = networks.values().iterator().next();
        return net.getIpAddress();
    }

    public void configureAfterStart() throws Exception {
        final MinioClient minioClient = MinioClient.builder()
                .endpoint("http://localhost:" + getMappedPort(9000))
                .credentials(ACCESS_KEY, SECRET_KEY)
                .build();

        for (String bucketName : TEST_BUCKETS) {
            final BucketExistsArgs bucketExistsArgs = BucketExistsArgs.builder()
                    .bucket(bucketName)
                    .build();
            final boolean exists = minioClient.bucketExists(bucketExistsArgs);
            if (!exists) {
                log.info("Make new bucket '{}' ...", bucketName);
                final MakeBucketArgs makeBucketArgs = MakeBucketArgs.builder()
                        .bucket(bucketName)
                        .build();
                minioClient.makeBucket(makeBucketArgs);
            } else {
                log.info("Bucket '{}' already exists", bucketName);
            }
        }
    }
}
