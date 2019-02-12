package com.baeldung.resourceserverauth0.model;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;

@Entity
public class Color {

    @Id
    @GeneratedValue
    private Long id;

    private String value;

    protected Color() {
    }

    public Color(String value) {
        this.value = value;
    }

    public String getValue() {
        return this.value;
    }

    public Long getId() {
        return id;
    }
}
