package io.github.asharapov.nexus.casc.internal.yaml;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * @author Anton Sharapov
 */
@Target({ElementType.ANNOTATION_TYPE, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
public @interface PropertyOrder {

    /**
     * Order in which properties of annotated object are to be serialized in.
     */
    String[] value() default {};

}
