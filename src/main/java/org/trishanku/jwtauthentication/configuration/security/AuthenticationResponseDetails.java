package org.trishanku.jwtauthentication.configuration.security;

import java.io.Serializable;

public class AuthenticationResponseDetails implements Serializable {

    private final String jwt;

    public AuthenticationResponseDetails(String jwt) {
        this.jwt = jwt;
    }

    public String getJwt() {
        return jwt;
    }
}
