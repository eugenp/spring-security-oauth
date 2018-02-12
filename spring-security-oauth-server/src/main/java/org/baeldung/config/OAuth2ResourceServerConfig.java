package org.baeldung.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;

@EnableResourceServer
@Configuration
@Profile("mvc")
// This isn't the main/standard Resource Server of the project (that's in a different module)
// This is the Resource Server for the Testing OAuth2 with Spring MVC article: http://www.baeldung.com/oauth-api-testing-with-spring-mvc 
// Notice that it's only active via the mvc profile
public class OAuth2ResourceServerConfig extends ResourceServerConfigurerAdapter {
    @Override
    public void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests().antMatchers("/employee").hasRole("ADMIN");
    }

}
