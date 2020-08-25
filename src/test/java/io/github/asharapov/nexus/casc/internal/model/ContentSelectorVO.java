package io.github.asharapov.nexus.casc.internal.model;

public class ContentSelectorVO {
    public enum Type {
        csel, jexl
    }
    public String name;
    public Type type;
    public String description;
    public String expression;
}
