package io.github.asharapov.nexus.casc.internal.model;

import java.io.IOException;
import java.io.StringReader;
import java.util.Map;
import java.util.Properties;
import java.util.TreeMap;

public class IqConnectionVO {

    public enum AuthType {
        USER, PKI
    }

    public boolean enabled;
    public boolean showLink;
    public String url;
    public AuthType authenticationType;
    public String username;
    public String password;
    public boolean useTrustStoreForUrl;
    public Integer timeoutSeconds;
    public String properties;

    public Map<String,String> parseProperties() {
        final Map<String, String> result = new TreeMap<>();
        if (properties != null) {
            try {
                final Properties props = new Properties();
                props.load(new StringReader(properties));
                for (Map.Entry<?,?> entry : props.entrySet()) {
                    result.put(String.valueOf(entry.getKey()), entry.getValue() != null ? String.valueOf(entry.getValue()) : null);
                }
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
        return result;
    }

}
