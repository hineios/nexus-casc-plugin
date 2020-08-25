package io.github.asharapov.nexus.casc.internal.yaml;

import org.yaml.snakeyaml.introspector.Property;
import org.yaml.snakeyaml.nodes.NodeTuple;
import org.yaml.snakeyaml.nodes.Tag;
import org.yaml.snakeyaml.representer.Represent;
import org.yaml.snakeyaml.representer.Representer;

import java.lang.reflect.Modifier;
import java.util.Collection;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/**
 * @author Anton Sharapov
 */
public class ExtensibleRepresenter extends Representer {

    private final Map<Class<?>, Set<Property>> orderedProperties;
    private boolean nullValuesRepresented;
    private boolean emptyCollectionsRepresented;

    public ExtensibleRepresenter() {
        this.orderedProperties = new HashMap<>();
        this.nullValuesRepresented = true;
        this.emptyCollectionsRepresented = true;
    }

    public boolean isNullValuesRepresented() {
        return nullValuesRepresented;
    }

    public void setNullValuesRepresented(final boolean value) {
        this.nullValuesRepresented = value;
    }

    public boolean isEmptyCollectionsRepresented() {
        return emptyCollectionsRepresented;
    }

    public void setEmptyCollectionsRepresented(final boolean value) {
        this.emptyCollectionsRepresented = value;
    }

    /**
     * Used for custom bean serialization
     *
     * @param type      bean class
     * @param represent function that creates a nodes graph based on this java bean.
     */
    public void addRepresenter(final Class<?> type, final Represent represent) {
        final int mod = type.getModifiers();
        if (!Modifier.isInterface(mod) && !Modifier.isAbstract(mod)) {
            representers.put(type, represent);
        }
        multiRepresenters.put(type, represent);
    }

    @Override
    protected NodeTuple representJavaBeanProperty(final Object bean, final Property property, final Object value, final Tag tag) {
        if (value == null) {
            return nullValuesRepresented
                    ? super.representJavaBeanProperty(bean, property, value, tag)
                    : null;
        } else if ((value instanceof Collection) && ((Collection<?>) value).isEmpty()) {
            return emptyCollectionsRepresented
                    ? super.representJavaBeanProperty(bean, property, value, tag)
                    : null;
        } else if ((value instanceof Map) && ((Map<?, ?>) value).isEmpty()) {
            return emptyCollectionsRepresented
                    ? super.representJavaBeanProperty(bean, property, value, tag)
                    : null;
        } else {
            return super.representJavaBeanProperty(bean, property, value, tag);
        }
    }

    @Override
    protected Set<Property> getProperties(final Class<?> type) {
        return orderedProperties.computeIfAbsent(type, this::computeOrderedProperties);
    }

    private Set<Property> computeOrderedProperties(final Class<?> type) {
        final Set<Property> src = super.getProperties(type);
        final PropertyOrder ann = type.getAnnotation(PropertyOrder.class);
        if (ann == null) {
            return src;
        } else {
            final Comparator<Property> comparator = new PropertyComparator(ann.value());
            final TreeSet<Property> ordered = new TreeSet<>(comparator);
            ordered.addAll(src);
            return ordered;
        }
    }


    private static class PropertyComparator implements Comparator<Property> {
        private final Map<String, Integer> index;

        PropertyComparator(final String[] orderedNames) {
            index = new HashMap<>();
            int cost = 0;
            for (String name : orderedNames) {
                index.put(name, ++cost);
            }
        }

        @Override
        public int compare(final Property p1, final Property p2) {
            final int i1 = index.getOrDefault(p1.getName(), Integer.MAX_VALUE);
            final int i2 = index.getOrDefault(p2.getName(), Integer.MAX_VALUE);
            if (i1 == i2) {
                return p1.getName().compareTo(p2.getName());
            } else {
                return i1 < i2 ? -1 : 1;
            }
        }
    }
}
