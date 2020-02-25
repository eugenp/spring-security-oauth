package com.baeldung.newstack.config;

import com.baeldung.newstack.filter.JwtClaimTokenFilter;
import com.baeldung.newstack.validator.JwtClaimTokenValidator;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class JwtClaimConfiguration {

    @Value("${spring.security.oauth2.resourceserver.jwt.jwk-set-uri}")
    String jwkUrl;


    @Value("${spring.security.oauth2.resourceserver.jwt.user-name-attribute}")
    String jwtClaim;

    @Bean
    public JwtClaimTokenFilter keycloakTokenFilterBean() throws Exception {
        return new JwtClaimTokenFilter(JwtClaimTokenValidator.builder()
                .build(jwkUrl, jwtClaim));
    }
}
