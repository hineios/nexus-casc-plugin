package io.github.asharapov.nexus.casc.internal.junit;

import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.platform.commons.annotation.Testable;

import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * An annotation that is used for declaring integration tests
 * and registering all relevant extensions of the test lifecycle.
 *
 * @author Anton Sharapov
 */
@Target({ElementType.TYPE, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@Inherited
@Testable
@ExtendWith(TestLifecycleExtension.class)
@Tag("integration")
public @interface IntegrationTest {
}
