package io.github.asharapov.nexus.casc.internal.model;

import io.github.asharapov.nexus.casc.internal.yaml.PropertyOrder;

import java.net.URI;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TimeZone;

/**
 * @author Anton Sharapov
 */
@PropertyOrder({"baseUrl", "connTimeout", "connRetries", "userAgentFragment",
        "httpProxy", "httpsProxy", "nonProxyHosts",
        "smtp", "iq", "tasks", "pruneOtherTasks", "capabilities", "license"})
public class SystemConfig {

    public String baseUrl;
    public Integer connTimeout;
    public Integer connRetries;
    public String userAgentFragment;
    public Proxy httpProxy;
    public Proxy httpsProxy;
    public List<String> nonProxyHosts;
    public SmtpServer smtp;
    public IqServer iq;
    public List<Task> tasks;
    public Boolean pruneOtherExposedTasks;
    public List<Capability> capabilities;
    public License license;


    @PropertyOrder({"host", "port", "auth", "enabled"})
    public static class Proxy {
        public String host;
        public int port;
        public ProxyAuthentication auth;
        public boolean enabled;

        public Proxy() {
        }

        public Proxy(String host, int port, ProxyAuthentication auth, boolean enabled) {
            this.host = host;
            this.port = port;
            this.auth = auth;
            this.enabled = enabled;
        }

        @Override
        public int hashCode() {
            return host != null ? host.hashCode() : 0;
        }

        @Override
        public boolean equals(final Object obj) {
            if (!(obj instanceof Proxy))
                return false;
            final Proxy other = (Proxy) obj;
            return Objects.equals(host, other.host) && port == other.port && Objects.equals(auth, other.auth) && enabled == other.enabled;
        }

        @Override
        public String toString() {
            return "[Proxy{host:" + host + ", port:" + port + ", auth:" + auth + "}]";
        }
    }


    @PropertyOrder({"user", "password"})
    public static class ProxyAuthentication {
        public String user;
        public String password;
        public String ntlmDomain;
        public String ntlmHost;

        public ProxyAuthentication() {
        }

        public ProxyAuthentication(String user, String password) {
            this.user = user;
            this.password = password;
        }

        public ProxyAuthentication(String user, String password, String ntlmDomain, String ntlmHost) {
            this.user = user;
            this.password = password;
            this.ntlmDomain = ntlmDomain;
            this.ntlmHost = ntlmHost;
        }

        @Override
        public int hashCode() {
            return user != null ? user.hashCode() : 0;
        }

        @Override
        public boolean equals(final Object obj) {
            if (!(obj instanceof ProxyAuthentication))
                return false;
            final ProxyAuthentication other = (ProxyAuthentication) obj;
            return Objects.equals(user, other.user) && Objects.equals(password, other.password) &&
                    Objects.equals(ntlmDomain, other.ntlmDomain) && Objects.equals(ntlmHost, other.ntlmHost);
        }

        @Override
        public String toString() {
            return "[Proxy.Auth{user:" + user + ", pwd:" + password + ", ntlmDomain:" + ntlmDomain + ", ntlmHost:" + ntlmHost + "}]";
        }
    }


    @PropertyOrder({"enabled", "host", "port", "userName", "password", "fromAddress", "subjectPrefix",
            "sslOnConnectEnabled", "sslCheckServerIdentityEnabled", "startTlsEnabled", "startTlsRequired",
            "nexusTrustStoreEnabled"})
    public static class SmtpServer {
        public Boolean enabled;
        public String host;
        public Integer port;
        public String userName;
        public String password;
        public String fromAddress;
        public String subjectPrefix;
        public Boolean sslOnConnectEnabled;
        public Boolean sslCheckServerIdentityEnabled;
        public Boolean startTlsEnabled;
        public Boolean startTlsRequired;
        public Boolean nexusTrustStoreEnabled;
    }


    public enum IqAuthType {
        USER, PKI
    }

    @PropertyOrder({"enabled", "url", "username", "password", "authType", "attrs", "showLink", "useTrustStore", "timeout"})
    public static class IqServer {
        public Boolean enabled;
        public String url;
        public String username;
        public String password;
        public IqAuthType authType;
        public Map<String, String> attrs;
        public Boolean showLink;
        public Boolean useTrustStore;
        public Integer timeout;
    }


    @PropertyOrder({"type", "name", "message", "enabled", "visible", "exposed", "recoverable", "alertEmail", "alertCondition", "attrs", "schedule"})
    public static class Task {
        public String type;
        public String name;
        public String message;
        public Boolean enabled;
        public Boolean visible;
        public Boolean exposed;
        public Boolean recoverable;
        public String alertEmail;
        public TaskAlertCondition alertCondition;
        public Map<String, String> attrs;
        public TaskSchedule schedule;

        @Override
        public String toString() {
            return "[Task{type:" + type + ", name:" + name + ", enabled:" + enabled + ", visible:" + visible + ", exposed:" + exposed + "}]";
        }
    }

    public enum TaskAlertCondition {
        FAILURE, SUCCESS_FAILURE;
    }

    public enum ScheduleType {
        cron, monthly, weekly, daily, hourly, once, now, manual
    }

    public enum Weekday {
        SUN, MON, TUE, WED, THU, FRI, SAT
    }

    @PropertyOrder({"type", "startAt"})
    public static class TaskSchedule {
        public ScheduleType type;
        public Date startAt;
        public List<Weekday> weekDaysToRun;
        public List<Integer> monthDaysToRun;
        public String cronExpr;
        public TimeZone timeZone;
    }


    @PropertyOrder({"type", "enabled", "notes", "attrs"})
    public static class Capability {
        public String type;
        public Boolean enabled;
        public String notes;
        public Map<String, String> attrs;

        @Override
        public int hashCode() {
            return type != null ? type.hashCode() : 0;
        }

        @Override
        public boolean equals(final Object obj) {
            if (!(obj instanceof Capability))
                return false;
            final Capability other = (Capability) obj;
            return Objects.equals(type, other.type) &&
                    (enabled == null || other.enabled == null || enabled == other.enabled) &&
                    Objects.equals(notes, other.notes) &&
                    (attrs != null ? attrs : Collections.emptyMap()).equals(other.attrs != null ? other.attrs : Collections.emptyMap());
        }

        @Override
        public String toString() {
            return "[Capability{type:" + type + ", attrs:" + attrs + ", enabled:" + enabled + "}]";
        }
    }


    @PropertyOrder({"installFrom"})
    public static class License {
        public URI installFrom;
    }
}
