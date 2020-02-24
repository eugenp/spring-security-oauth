package com.baeldung.newstack.spring;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}")
    private String issuerUri;

    @Override
    protected void configure(HttpSecurity http) throws Exception {// @formatter:off
        http.authorizeRequests().antMatchers(HttpMethod.GET, "/user/info", "/api/projects/**")
                .hasAuthority("SCOPE_read").antMatchers(HttpMethod.POST, "/api/projects").hasAuthority("SCOPE_write")
                .anyRequest().authenticated().and().oauth2ResourceServer().jwt();//.decoder(jwtDecoder);
    }//@formatter:on

    @Bean
    public JwtDecoder jwtDecoder() {
        NimbusJwtDecoder jwtDecoder = (NimbusJwtDecoder) JwtDecoders.fromIssuerLocation(issuerUri);
        OAuth2TokenValidator<Jwt> audienceValidator = new EmailValidator();
        OAuth2TokenValidator<Jwt> withIssuer = JwtValidators.createDefaultWithIssuer(issuerUri);
        OAuth2TokenValidator<Jwt> withAudience = new DelegatingOAuth2TokenValidator<>(withIssuer, audienceValidator);

        jwtDecoder.setJwtValidator(withAudience);
        return jwtDecoder;
    }
}