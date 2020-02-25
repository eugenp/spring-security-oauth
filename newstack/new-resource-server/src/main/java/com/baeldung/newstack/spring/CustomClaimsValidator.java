package com.baeldung.newstack.spring;

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

public class CustomClaimsValidator implements OAuth2TokenValidator<Jwt> {

    private static final String EMAIL_DOMAIN = "@baeldung.com";
    private static final String PREFERRED_USERNAME_CLAIM = "preferred_username";

    OAuth2Error error = new OAuth2Error("invalid_token", "Email domain is not supported", null);

    @Override
    public OAuth2TokenValidatorResult validate(Jwt jwt) {
        String preferredUsername = jwt.getClaimAsString(PREFERRED_USERNAME_CLAIM);
        if (preferredUsername.endsWith(EMAIL_DOMAIN)) {
            return OAuth2TokenValidatorResult.success();
        } else {
            return OAuth2TokenValidatorResult.failure(error);
        }
    }
}
