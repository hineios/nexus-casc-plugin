package io.github.asharapov.nexus.casc.internal.yaml;

import org.yaml.snakeyaml.DumperOptions;
import org.yaml.snakeyaml.TypeDescription;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.Constructor;
import org.yaml.snakeyaml.nodes.Node;
import org.yaml.snakeyaml.nodes.Tag;
import org.yaml.snakeyaml.representer.Representer;

import java.util.HashMap;
import java.util.Map;
import java.util.TimeZone;
import java.util.function.BiFunction;
import java.util.function.Function;

/**
 * @author Anton Sharapov
 */
public class YamlBuilder {

    private final Class<?> rootCls;
    private final Map<Class<?>, TypeInfo> types;
    private boolean showNulls;
    private boolean showEmptyCollections;

    public YamlBuilder(final Class<?> rootCls) {
        this.rootCls = rootCls;
        this.types = new HashMap<>();
        this.types.put(rootCls, new TypeInfo(rootCls));
        this.showNulls = true;
        this.showEmptyCollections = true;
    }

    public YamlBuilder showNulls(final boolean showNulls) {
        this.showNulls = showNulls;
        return this;
    }

    public YamlBuilder showEmptyCollections(final boolean showEmptyCollections) {
        this.showEmptyCollections = showEmptyCollections;
        return this;
    }

    public YamlBuilder addBeanConstructor(final Class<?> cls, final Function<Node, Object> constructor) {
        final TypeInfo typeInfo = types.computeIfAbsent(cls, TypeInfo::new);
        typeInfo.constructor = constructor;
        return this;
    }

    public YamlBuilder addBeanConstructor(final Class<?> cls, final BiFunction<String, Node, Object> constructor) {
        final TypeInfo typeInfo = types.computeIfAbsent(cls, TypeInfo::new);
        typeInfo.constructor2 = constructor;
        return this;
    }

    public YamlBuilder addBeanRepresenter(final Class<?> cls, final BiFunction<Representer, Object, Node> representer) {
        final TypeInfo typeInfo = types.computeIfAbsent(cls, TypeInfo::new);
        typeInfo.representer = representer;
        return this;
    }

    public YamlBuilder addBeanTag(final Class<?> cls, final Tag tag) {
        final TypeInfo typeInfo = types.computeIfAbsent(cls, TypeInfo::new);
        typeInfo.tag = tag;
        return this;
    }

    public Yaml build() {
        final DumperOptions options = new DumperOptions();
        options.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK);
        options.setTimeZone(TimeZone.getDefault());

        final ExtensibleRepresenter representer = new ExtensibleRepresenter();
        representer.setNullValuesRepresented(showNulls);
        representer.setEmptyCollectionsRepresented(showEmptyCollections);

        final Constructor ctor = new Constructor(rootCls);

        for (TypeInfo typeInfo : types.values()) {
            final Tag effectiveTag = typeInfo.tag != null ? typeInfo.tag : Tag.MAP;

            final TypeDescription td = new TypeDescription(typeInfo.cls, effectiveTag) {
                @Override
                public Object newInstance(final Node node) {
                    if (typeInfo.constructor != null) {
                        return typeInfo.constructor.apply(node);
                    } else {
                        return super.newInstance(node);
                    }
                }

                @Override
                public Object newInstance(final String propertyName, final Node node) {
                    if (typeInfo.constructor2 != null) {
                        return typeInfo.constructor2.apply(propertyName, node);
                    } else {
                        return super.newInstance(propertyName, node);
                    }
                }
            };

            ctor.addTypeDescription(td);
            representer.addTypeDescription(td);
            if (typeInfo.representer != null) {
                representer.addRepresenter(typeInfo.cls, data -> typeInfo.representer.apply(representer, data));
            }
        }

        return new Yaml(ctor, representer, options);
    }

    private static class TypeInfo {
        private final Class<?> cls;
        private Tag tag;
        private Function<Node, Object> constructor;
        private BiFunction<String, Node, Object> constructor2;
        private BiFunction<Representer, Object, Node> representer;

        private TypeInfo(final Class<?> cls) {
            this.cls = cls;
        }
    }
}
