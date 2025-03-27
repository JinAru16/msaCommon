package com.msa.common.entity;

import jakarta.persistence.Embeddable;
import lombok.Builder;
import lombok.Getter;

@Embeddable
@Getter
public class Address {

    private String address1;
    private String address2;
    private String city;
    private String state;
    private String country;
    private String postalCode;

    @Builder
    public Address(String address1, String address2, String city, String state, String country, String postalCode) {
        this.address1 = address1;
        this.address2 = address2;
        this.city = city;
        this.state = state;
        this.country = country;
        this.postalCode = postalCode;
    }

    public Address() {

    }
}
