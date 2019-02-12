package com.baeldung.resourceserverauth0.configs;

import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
            .antMatchers(HttpMethod.OPTIONS, "/colors/**")
            .permitAll()
            .antMatchers("/colors/create")
            .hasAuthority("SCOPE_profile")
            .antMatchers("/colors/delete/*")
            .hasAuthority("SCOPE_nonExistent")
            .antMatchers("/colors/list")
            .permitAll()
            .and()
            .oauth2ResourceServer()
            .jwt();
    }
}
