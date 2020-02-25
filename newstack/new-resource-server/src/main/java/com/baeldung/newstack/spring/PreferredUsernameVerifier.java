package com.baeldung.newstack.spring;

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

public class PreferredUsernameVerifier implements OAuth2TokenValidator<Jwt> {

    @Override
    public OAuth2TokenValidatorResult validate(Jwt token) {
        final String CLAIM_TO_VERIFY = "preferred_username";
        OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.ACCESS_DENIED,"user not authorized",null);

        String username = token.getClaimAsString(CLAIM_TO_VERIFY);

        return username.matches("(\\w|\\d)+@baeldung.com") ?
                OAuth2TokenValidatorResult.success() : OAuth2TokenValidatorResult.failure(error);

    }
}
