package org.baeldung.config;

import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.token.store.JwtClaimsSetVerifier;
import org.springframework.util.StringUtils;

import java.util.Map;

public class CustomClaimVerifier implements JwtClaimsSetVerifier {
    @Override
    public void verify(Map<String, Object> claims) throws InvalidTokenException {
        final String username = (String) claims.get("user_name");
        if (StringUtils.isEmpty(username)) {
            throw new InvalidTokenException("user_name claim is empty");
        }
    }
}
