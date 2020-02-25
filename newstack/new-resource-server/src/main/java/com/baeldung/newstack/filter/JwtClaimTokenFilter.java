package com.baeldung.newstack.filter;

import com.baeldung.newstack.validator.JwtClaimTokenValidator;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class JwtClaimTokenFilter extends OncePerRequestFilter {

    private static final Log log = LogFactory.getLog(JwtClaimTokenFilter.class);

    private static final String BEARER = "Bearer ";
    private final static String AUTHORIZATION_HEADER = "Authorization";
    private static final String ACCOUNT_SEPARATOR = "@";
    private static final String AUTHORIZED_DOMAIN = "baeldung.com";
    private JwtClaimTokenValidator tokenValidator;
    private String username;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        String token = request.getHeader(AUTHORIZATION_HEADER);

        if (token!=null && !token.toUpperCase().startsWith("BASIC")) {
            try {

                if (token.length() > BEARER.length() && token.startsWith(BEARER)) {
                    token = token.substring(BEARER.length());
                }

                username = tokenValidator.getJwtClaim(token);

                if (!getDomainName(username).equals(AUTHORIZED_DOMAIN)) {
                    log.error("Invalid Request: email domain is not supported");
                    response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid Request: email domain is not supported");
                }

                if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                    setContext(request, username);

                } else {
                    log.error("Invalid Request: Token is expired or tampered");
                    response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized: Token is expired or tampered");
                }
            } catch (Exception e) {
                log.error(e);

            }

        } else {
            log.info("Authorization Token not being sent in Headers:"+token);
        }

        filterChain.doFilter(request, response);
    }

    private void setContext(HttpServletRequest request, String username) {
        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(username, null, null);
        authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        log.debug("authenticated user " + username + ", setting security context");
        SecurityContextHolder.getContext().setAuthentication(authentication);
        request.setAttribute("username", username);
    }

    private  String getDomainName(String username) {
        if (username == null) {
            throw new IllegalArgumentException("username is null");
        }
        int separatorIndex = username.lastIndexOf(ACCOUNT_SEPARATOR);
        if (separatorIndex <= 0 || separatorIndex == username.length() - 1) {
            String errorMessage = "Cannot get account from username %s, it should end with @accountName";
            throw new IllegalArgumentException(String.format(errorMessage, username));
        }
        return username.substring(separatorIndex + 1);
    }

    public JwtClaimTokenFilter(JwtClaimTokenValidator tokenValidator) {
        this.tokenValidator = tokenValidator;
    }

}