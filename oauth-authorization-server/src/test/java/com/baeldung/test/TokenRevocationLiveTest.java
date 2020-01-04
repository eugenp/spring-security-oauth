package com.baeldung.test;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;

import java.util.HashMap;
import java.util.Map;

import org.junit.Test;

import io.restassured.RestAssured;
import io.restassured.response.Response;

// need both oauth-authorization-server and oauth-resource-server-1 to be running

public class TokenRevocationLiveTest {

    private static final String FOO_CLIENT_ID_PASSWORD = "fooClientIdPassword";
    private static final String ACCESS_TOKEN = "access_token";
    private static final String AUTHORIZATION = "Authorization";
    public static final String BEARER = "Bearer ";

    @Test
    public void whenObtainingAccessToken_thenCorrect() {
        final Response authServerResponse = obtainAccessToken(FOO_CLIENT_ID_PASSWORD, "john", "123");
        final String accessToken = authServerResponse.jsonPath().getString(ACCESS_TOKEN);
        assertNotNull(accessToken);

        final Response resourceServerResponse = RestAssured.given().header(AUTHORIZATION, BEARER + accessToken).get("http://localhost:8082/spring-security-oauth-resource/foos/100");
        assertThat(resourceServerResponse.getStatusCode(), equalTo(200));
    }

    @Test
    public void shouldRefreshToken() {
        final Response authServerResponse = obtainAccessToken(FOO_CLIENT_ID_PASSWORD, "test", "dedicatedTestUser");
        final String accessToken = authServerResponse.jsonPath().getString(ACCESS_TOKEN);
        final String refreshToken = authServerResponse.jsonPath().getString("refresh_token");
        assertNotNull(accessToken);
        assertNotNull(refreshToken);

        final Response resourceServerResponse = RestAssured.given().header(AUTHORIZATION, BEARER + accessToken).get("http://localhost:8082/spring-security-oauth-resource/foos/100");
        assertThat(resourceServerResponse.getStatusCode(), equalTo(200));

        final String refreshedToken = obtainRefreshToken(FOO_CLIENT_ID_PASSWORD, refreshToken);
        assertNotNull(refreshedToken);

        final Response refreshedTokenServerResponse = RestAssured.given().header(AUTHORIZATION, BEARER + refreshedToken).get("http://localhost:8082/spring-security-oauth-resource/foos/100");
        assertThat(refreshedTokenServerResponse.getStatusCode(), equalTo(200));
    }

    //

    private Response obtainAccessToken(String clientId, String username, String password) {
        final Map<String, String> params = new HashMap<String, String>();
        params.put("grant_type", "password");
        params.put("client_id", clientId);
        params.put("username", username);
        params.put("password", password);
        return RestAssured.given().auth().preemptive().basic(clientId, "secret").and().with().params(params).when().post("http://localhost:8081/spring-security-oauth-server/oauth/token");
        // response.jsonPath().getString("refresh_token");
        // response.jsonPath().getString("access_token")
    }

    private String obtainRefreshToken(String clientId, final String refreshToken) {
        final Map<String, String> params = new HashMap<String, String>();
        params.put("grant_type", "refresh_token");
        params.put("client_id", clientId);
        params.put("refresh_token", refreshToken);
        final Response response = RestAssured.given().auth().preemptive().basic(clientId, "secret").and().with().params(params).when().post("http://localhost:8081/spring-security-oauth-server/oauth/token");
        return response.jsonPath().getString(ACCESS_TOKEN);
    }

    private void authorizeClient(String clientId) {
        final Map<String, String> params = new HashMap<String, String>();
        params.put("response_type", "code");
        params.put("client_id", clientId);
        params.put("scope", "read,write");
        final Response response = RestAssured.given().auth().preemptive().basic(clientId, "secret").and().with().params(params).when().post("http://localhost:8081/spring-security-oauth-server/oauth/authorize");
    }
}