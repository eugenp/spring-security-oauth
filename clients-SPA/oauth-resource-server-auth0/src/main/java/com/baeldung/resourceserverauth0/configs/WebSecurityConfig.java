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
            .antMatchers(HttpMethod.OPTIONS, "/colors", "/colors/**")
            .permitAll()
            .antMatchers(HttpMethod.POST, "/colors")
            .hasAuthority("SCOPE_colors:create")
            .antMatchers(HttpMethod.DELETE, "/colors/*")
            .hasAuthority("SCOPE_colors:delete")
            .antMatchers(HttpMethod.GET, "/colors")
            .permitAll()
            .and()
            .oauth2ResourceServer()
            .jwt();
    }
}
