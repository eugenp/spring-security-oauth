package org.baeldung.config;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.context.annotation.PropertySource;
import org.springframework.core.env.Environment;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JdbcTokenStore;

@Configuration
@PropertySource({ "classpath:persistence.properties" })
@EnableResourceServer
public class OAuth2ResourceServerConfig extends ResourceServerConfigurerAdapter {

    @Autowired
    private Environment env;

    //

    @Override
    public void configure(final HttpSecurity http) throws Exception {
        // @formatter:off
		http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED).and().authorizeRequests()
				.anyRequest().permitAll();
		// .requestMatchers().antMatchers("/foos/**","/bars/**")
		// .and()
		// .authorizeRequests()
		// .antMatchers(HttpMethod.GET,"/foos/**").access("#oauth2.hasScope('foo')
		// and #oauth2.hasScope('read')")
		// .antMatchers(HttpMethod.POST,"/foos/**").access("#oauth2.hasScope('foo')
		// and #oauth2.hasScope('write')")
		// .antMatchers(HttpMethod.GET,"/bars/**").access("#oauth2.hasScope('bar')
		// and #oauth2.hasScope('read')")
		// .antMatchers(HttpMethod.POST,"/bars/**").access("#oauth2.hasScope('bar')
		// and #oauth2.hasScope('write') and hasRole('ROLE_ADMIN')")
		;
		// @formatter:on
    }

    // Remote token service
    /*
    @Primary
    @Bean
    public RemoteTokenServices tokenService() {
        final RemoteTokenServices tokenService = new RemoteTokenServices();
        tokenService.setCheckTokenEndpointUrl("http://localhost:8081/spring-security-oauth-server/oauth/check_token");
        tokenService.setClientId("fooClientIdPassword");
        tokenService.setClientSecret("secret");
        return tokenService;
    }
    */

    // JWT token store

    @Override
    public void configure(final ResourceServerSecurityConfigurer config) {
        config.tokenServices(tokenServices());
    }

    /*
    @Bean
    public TokenStore tokenStore() {
    return new JwtTokenStore(accessTokenConverter());
    }
    
    @Bean
    public JwtAccessTokenConverter accessTokenConverter() {
    final JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
    // converter.setSigningKey("123");
    final Resource resource = new ClassPathResource("public.txt");
    String publicKey = null;
    try {
        publicKey = IOUtils.toString(resource.getInputStream());
    } catch (final IOException e) {
        throw new RuntimeException(e);
    }
    converter.setVerifierKey(publicKey);
    return converter;
    }
    */
    @Bean
    @Primary
    public DefaultTokenServices tokenServices() {
        final DefaultTokenServices defaultTokenServices = new DefaultTokenServices();
        defaultTokenServices.setTokenStore(tokenStore());
        return defaultTokenServices;
    }

    // JDBC token store configuration

    @Bean
    public DataSource dataSource() {
        final DriverManagerDataSource dataSource = new DriverManagerDataSource();
        dataSource.setDriverClassName(env.getProperty("jdbc.driverClassName"));
        dataSource.setUrl(env.getProperty("jdbc.url"));
        dataSource.setUsername(env.getProperty("jdbc.user"));
        dataSource.setPassword(env.getProperty("jdbc.pass"));
        return dataSource;
    }

    @Bean
    public TokenStore tokenStore() {
        return new JdbcTokenStore(dataSource());
    }

}
