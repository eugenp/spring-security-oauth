package org.baeldung.config;

import java.io.IOException;
import java.io.InputStream;
import java.util.Map;

import javax.servlet.http.Cookie;

import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.netflix.zuul.ZuulFilter;
import com.netflix.zuul.context.RequestContext;

@Component
public class CustomPostZuulFilter extends ZuulFilter {

    private final Logger logger = LoggerFactory.getLogger(this.getClass());
    private final ObjectMapper mapper = new ObjectMapper();

    @Override
    public Object run() {
        final RequestContext ctx = RequestContext.getCurrentContext();
        logger.info("in zuul filter " + ctx.getRequest().getRequestURI());

        String requestURI = ctx.getRequest().getRequestURI();
        String requestMethod = ctx.getRequest().getMethod();

        try {
            final InputStream is = ctx.getResponseDataStream();
            String responseBody = IOUtils.toString(is, "UTF-8");
            if (responseBody.contains("refresh_token")) {
                final Map<String, Object> responseMap = mapper.readValue(responseBody, new TypeReference<Map<String, Object>>() {
                });
                final String refreshToken = responseMap.get("refresh_token").toString();
                responseMap.remove("refresh_token");
                responseBody = mapper.writeValueAsString(responseMap);

                final Cookie cookie = new Cookie("refreshToken", refreshToken);
                cookie.setHttpOnly(true);
                // cookie.setSecure(true);
                cookie.setPath(ctx.getRequest().getContextPath() + "/oauth/token");
                cookie.setMaxAge(2592000); // 30 days
                ctx.getResponse().addCookie(cookie);
                logger.info("refresh token = " + refreshToken);

            } else if (requestURI.contains("oauth/token") && requestMethod.equals("DELETE")) {
                Cookie cookie = new Cookie("refreshToken", "");
                cookie.setMaxAge(0);
                cookie.setPath(ctx.getRequest().getContextPath() + "/oauth/token");
                ctx.getResponse().addCookie(cookie);
            }
            ctx.setResponseBody(responseBody);

        } catch (final IOException e) {
            logger.error("Error occured in zuul post filter", e);
        }
        return null;
    }

    @Override
    public boolean shouldFilter() {
        return true;
    }

    @Override
    public int filterOrder() {
        return 10;
    }

    @Override
    public String filterType() {
        return "post";
    }

}
