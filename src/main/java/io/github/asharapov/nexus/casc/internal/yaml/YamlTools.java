package io.github.asharapov.nexus.casc.internal.yaml;

import io.github.asharapov.nexus.casc.internal.model.SecurityConfig;
import io.github.asharapov.nexus.casc.internal.model.SystemConfig;
import org.yaml.snakeyaml.DumperOptions;
import org.yaml.snakeyaml.nodes.MappingNode;
import org.yaml.snakeyaml.nodes.Node;
import org.yaml.snakeyaml.nodes.NodeTuple;
import org.yaml.snakeyaml.nodes.ScalarNode;
import org.yaml.snakeyaml.nodes.Tag;
import org.yaml.snakeyaml.representer.Representer;

import java.net.URI;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.TimeZone;
import java.util.function.BiFunction;
import java.util.function.Function;

/**
 * @author Anton Sharapov
 */
public class YamlTools {

    public static final Function<Node, Object> TIME_ZONE_CONSTRUCTOR = new Function<Node, Object>() {
        @Override
        public Object apply(final Node node) {
            if (node instanceof ScalarNode) {
                final String txt = ((ScalarNode) node).getValue();
                return TimeZone.getTimeZone(txt);
            } else {
                throw new IllegalStateException("Scalar node expected for TimeZone object construction");
            }
        }
    };

    public static final BiFunction<Representer, Object, Node> TIME_ZONE_REPRESENTER = new BiFunction<Representer, Object, Node>() {
        @Override
        public Node apply(final Representer representer, final Object obj) {
            final TimeZone tz = (TimeZone) obj;
            return makeNode(tz.getID());
        }
    };


    public static final BiFunction<Representer, Object, Node> SYSTEM_TASK_SCHEDULER_REPRESENTER = new BiFunction<Representer, Object, Node>() {
        @Override
        public Node apply(final Representer representer, final Object obj) {
            final SystemConfig.TaskSchedule schedule = (SystemConfig.TaskSchedule) obj;
            final List<NodeTuple> properties = new ArrayList<>();
            properties.add(new NodeTuple(makeNode("type"), makeNode(schedule.type.name())));
            switch (schedule.type) {
                case cron:
                    properties.add(new NodeTuple(makeNode("startAt"), representer.represent(schedule.startAt)));
                    properties.add(new NodeTuple(makeNode("timeZone"), representer.represent(schedule.timeZone)));
                    properties.add(new NodeTuple(makeNode("cronExpr"), representer.represent(schedule.cronExpr)));
                    break;
                case monthly:
                    properties.add(new NodeTuple(makeNode("startAt"), representer.represent(schedule.startAt)));
                    properties.add(new NodeTuple(makeNode("monthDaysToRun"), representer.represent(schedule.monthDaysToRun)));
                    break;
                case weekly:
                    properties.add(new NodeTuple(makeNode("startAt"), representer.represent(schedule.startAt)));
                    properties.add(new NodeTuple(makeNode("weekDaysToRun"), representer.represent(schedule.weekDaysToRun)));
                    break;
                case daily:
                case hourly:
                case once:
                    properties.add(new NodeTuple(makeNode("startAt"), representer.represent(schedule.startAt)));
                    break;
                case now:
                case manual:
                default:
            }
            return new MappingNode(Tag.MAP, properties, DumperOptions.FlowStyle.AUTO);
        }
    };


    public static final Function<Node, Object> SECURITY_KEY_CONSTRUCTOR = new Function<Node, Object>() {
        @Override
        public Object apply(final Node node) {
            if (node instanceof ScalarNode) {
                final String id = ((ScalarNode) node).getValue();
                return new SecurityConfig.Key(id, null);
            } else if (node instanceof MappingNode) {
                final MappingNode map = (MappingNode) node;
                final String id = findStringValue(map, "id");
                final String authSource = findStringValue(map, "authSource");
                return new SecurityConfig.Key(id, authSource);
            } else
                throw new IllegalStateException("Scalar or mapping node expected for this object type");
        }
    };

    public static final BiFunction<Representer, Object, Node> SECURITY_KEY_REPPRESENTER = new BiFunction<Representer, Object, Node>() {
        @Override
        public Node apply(final Representer representer, final Object obj) {
            final SecurityConfig.Key key = (SecurityConfig.Key) obj;
            if (key.authSource == null) {
                return makeNode(key.id);
            } else {
                final List<NodeTuple> values = Arrays.asList(
                        new NodeTuple(makeNode("id"), makeNode(key.id)),
                        new NodeTuple(makeNode("authSource"), makeNode(key.authSource))
                );
                return new MappingNode(Tag.MAP, values, DumperOptions.FlowStyle.AUTO);
            }
        }
    };


    public static final BiFunction<Representer, Object, Node> URI_REPRESENTER = new BiFunction<Representer, Object, Node>() {
        @Override
        public Node apply(final Representer representer, final Object obj) {
            final URI uri = (URI) obj;
            return makeNode(uri.toString());
        }
    };


    private static ScalarNode makeNode(final String value) {
        return new ScalarNode(Tag.STR, value, null, null, DumperOptions.ScalarStyle.PLAIN);
    }

    private static String expectString(final Node node) {
        if (node instanceof ScalarNode) {
            return ((ScalarNode) node).getValue();
        } else if (node == null) {
            return null;
        } else
            throw new IllegalStateException("Scalar node expected");
    }

    private static Node findValue(final MappingNode mappingNode, final String key) {
        for (NodeTuple tuple : mappingNode.getValue()) {
            final Node keyNode = tuple.getKeyNode();
            if (keyNode instanceof ScalarNode && Objects.equals(key, ((ScalarNode) keyNode).getValue())) {
                return tuple.getValueNode();
            }
        }
        return null;
    }

    private static String findStringValue(final MappingNode mappingNode, final String key) {
        return expectString(findValue(mappingNode, key));
    }
}
