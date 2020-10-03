package io.github.asharapov.nexus.casc.internal.utils;

import com.google.inject.AbstractModule;
import com.google.inject.Provides;
import io.github.asharapov.nexus.casc.internal.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.Network;
import org.yaml.snakeyaml.Yaml;

import javax.inject.Singleton;

public class ContainersModule extends AbstractModule {

    private static final Logger log = LoggerFactory.getLogger(ContainersModule.class);

    @Override
    protected void configure() {
    }

    @Provides
    @Singleton
    protected Network provideNetwork() {
        log.info("construct network ...");
        return Network.newNetwork();
    }

    @Provides
    @Singleton
    protected OpenLDAPServer provideOpenLDAPServer(final Network network) {
        log.info("deploy openldap server instance ...");
        final long started = System.currentTimeMillis();
        final OpenLDAPServer container = new OpenLDAPServer();
        try {
            container.withNetwork(network);
            container.start();
            final long time = System.currentTimeMillis() - started;
            log.debug("openldap init time: {} ms", time);
            return container;
        } catch (Exception e) {
            addError(e);
            throw new RuntimeException(e);
        }
    }

    @Provides
    @Singleton
    protected MinioServer provideMinioServer(final Network network) {
        log.info("deploy minio server instance ...");
        final long started = System.currentTimeMillis();
        final MinioServer container = new MinioServer();
        try {
            container.withNetwork(network);
            container.start();
            container.configureAfterStart();
            final long time = System.currentTimeMillis() - started;
            log.debug("minio init time: {} ms", time);
            return container;
        } catch (Exception e) {
            addError(e);
            throw new RuntimeException(e);
        }
    }

    @Provides
    @DedicatedInstance
    protected NexusServer provideCustomNexusServer(final Network network) {
        return makeNexusServer(network);
    }

    @Provides
    @Singleton
    protected NexusServer provideCommonNexusServer(final Network network) {
        return makeNexusServer(network);
    }

    private NexusServer makeNexusServer(final Network network) {
        log.info("deploy nexus server instance ...");
        final long started = System.currentTimeMillis();
        final NexusServer container = new NexusServer();
        try {
            container.withNetwork(network);
            container.start();
            final long time = System.currentTimeMillis() - started;
            log.debug("nexus init time: {} ms", time);
            return container;
        } catch (Exception e) {
            addError(e);
            throw new RuntimeException(e);
        }
    }

    @Provides
    protected Yaml provideYaml() {
        return Utils.makeYaml(true, true);
    }
}
