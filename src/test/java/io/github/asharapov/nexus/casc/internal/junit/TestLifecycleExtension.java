package io.github.asharapov.nexus.casc.internal.junit;

import com.google.inject.Guice;
import com.google.inject.Injector;
import io.github.asharapov.nexus.casc.internal.utils.ContainersModule;
import io.github.asharapov.nexus.casc.internal.utils.DedicatedInstance;
import io.github.asharapov.nexus.casc.internal.utils.TestUtils;
import org.junit.jupiter.api.extension.AfterAllCallback;
import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.ExtensionConfigurationException;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.ParameterContext;
import org.junit.jupiter.api.extension.ParameterResolutionException;
import org.junit.jupiter.api.extension.ParameterResolver;
import org.junit.jupiter.api.extension.TestInstancePostProcessor;
import org.junit.jupiter.api.extension.TestInstancePreDestroyCallback;
import org.junit.platform.commons.support.AnnotationSupport;
import org.junit.platform.commons.util.ReflectionUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.ContainerState;
import org.testcontainers.containers.GenericContainer;

import javax.inject.Inject;
import java.lang.reflect.Field;
import java.util.function.Predicate;

/**
 * JUnit extension, that controls integration tests lifecycle.
 *
 * @author Anton Sharapov
 */
public class TestLifecycleExtension implements BeforeAllCallback, AfterAllCallback, TestInstancePostProcessor, TestInstancePreDestroyCallback, ParameterResolver {

    private static final Logger log = LoggerFactory.getLogger(TestLifecycleExtension.class);
    private static final ExtensionContext.Namespace ns = ExtensionContext.Namespace.create("nexus-casc-plugin");

    @Override
    public void beforeAll(final ExtensionContext ectx) throws Exception {
        log.debug("*** before all: {ctx:{}, pid:{}, thread:{}, obj:{}}", ectx.getDisplayName(), TestUtils.getProcessId(), Thread.currentThread().getName(), this);
        final ExtensionContext.Store store = ectx.getRoot().getStore(ns);
        final Injector injector = store.getOrComputeIfAbsent("guice", this::init, Injector.class);
    }

    private Injector init(final String key) {
        log.debug("guice initialization ...");
        return Guice.createInjector(new ContainersModule());
    }

    @Override
    public void afterAll(ExtensionContext ectx) throws Exception {
        log.debug("*** after all: {ctx:{}, pid:{}, thread:{}}", ectx.getDisplayName(), TestUtils.getProcessId(), Thread.currentThread().getName());
    }

    @Override
    public void postProcessTestInstance(final Object testInstance, final ExtensionContext ectx) throws Exception {
        log.debug("post process test instance {} ...", testInstance);
        final Injector injector = ectx.getRoot().getStore(ns).getOrComputeIfAbsent("guice", this::init, Injector.class);
        injector.injectMembers(testInstance);
    }

    @Override
    public void preDestroyTestInstance(final ExtensionContext ectx) throws Exception {
        final Object testInstance = ectx.getTestInstance().get();
        log.debug("pre destroy test instance {} ...", testInstance);
        // Destroys all running containers whose lifecycle is limited by the lifetime of the specified test instance ...
        ReflectionUtils.findFields(testInstance.getClass(), isInjectedDedicatedContainers(), ReflectionUtils.HierarchyTraversalMode.TOP_DOWN)
                .stream()
                .map(field -> getContainerInstance(testInstance, field))
                .filter(ContainerState::isCreated)
                .forEach(cntr -> {
                    log.info("destroy container {} ...", cntr);
                    cntr.close();
                });
    }

    private static Predicate<Field> isInjectedDedicatedContainers() {
        return field -> {
            return AnnotationSupport.isAnnotated(field, Inject.class) &&
                    AnnotationSupport.isAnnotated(field, DedicatedInstance.class) &&
                    GenericContainer.class.isAssignableFrom(field.getType());
        };
    }

    private static GenericContainer<?> getContainerInstance(final Object testInstance, final Field field) {
        try {
            field.setAccessible(true);
            return (GenericContainer<?>) field.get(testInstance);
        } catch (IllegalAccessException e) {
            throw new ExtensionConfigurationException("Can not access container defined in field " + field.getName());
        }
    }


    @Override
    public boolean supportsParameter(final ParameterContext pctx, final ExtensionContext ectx) throws ParameterResolutionException {
        final Class<?> cls = pctx.getParameter().getType();
        if (ExtensionContext.class.isAssignableFrom(cls)) {
            return true;
        }
        return false;
    }

    @Override
    public Object resolveParameter(final ParameterContext pctx, final ExtensionContext ectx) throws ParameterResolutionException {
        final Class<?> cls = pctx.getParameter().getType();
        if (ExtensionContext.class.isAssignableFrom(cls)) {
            return ectx;
        }
        throw new IllegalStateException("Can't resolve value for " + pctx);
    }

}
