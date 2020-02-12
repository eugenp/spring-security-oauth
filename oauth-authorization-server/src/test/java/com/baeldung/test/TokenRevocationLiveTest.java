package com.baeldung.test;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.*;

import java.util.HashMap;
import java.util.Map;

import io.restassured.response.ResponseBody;
import org.apache.http.HttpHeaders;
import org.junit.Test;

import io.restassured.RestAssured;
import io.restassured.response.Response;

// need both oauth-authorization-server and oauth-resource-server-1 to be running

public class TokenRevocationLiveTest {

    @Test
    public void whenObtainingAccessToken_thenCorrect() {
        final Response authServerResponse = obtainAccessToken("fooClientIdPassword", "john", "123");
        final String accessToken = authServerResponse.jsonPath().getString("access_token");
        assertNotNull(accessToken);

        final Response resourceServerResponse = RestAssured.given().header("Authorization", "Bearer " + accessToken).get("http://localhost:8082/spring-security-oauth-resource/foos/100");
        assertThat(resourceServerResponse.getStatusCode(), equalTo(200));
    }

    @Test
    public void refreshAccessTokenWithRefreshToken() {
        final String clientId = "fooClientIdPassword";
        // Obtain access token
        final Response tokens = obtainAccessToken(clientId, "john", "123");
        assertThat(tokens.getStatusCode(), equalTo(200));

        final String accessToken = tokens.jsonPath().getString("access_token");
        final String refreshToken = tokens.jsonPath().getString("refresh_token");
        assertNotNull(accessToken);
        assertNotNull(refreshToken);

        final Response responseWithInitialAccessToken = RestAssured
                .given()
                .header("Authorization", "Bearer "+ accessToken)
                .get("http://localhost:8082/spring-security-oauth-resource/foos/100");

        assertThat(responseWithInitialAccessToken.getStatusCode(), equalTo(200));

        String newAccessToken = obtainRefreshToken(clientId, refreshToken);
        assertNotNull(newAccessToken);

        assertNotEquals("Access Token is Unchanged", accessToken, newAccessToken);

        final Response responseWithNewAccessToken  = RestAssured
                .given()
                .header("Authorization", "Bearer "+ newAccessToken)
                .get("http://localhost:8082/spring-security-oauth-resource/foos/100");

        assertThat(responseWithNewAccessToken.getStatusCode(), equalTo(200));
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
        return response.jsonPath().getString("access_token");
    }

    private void authorizeClient(String clientId) {
        final Map<String, String> params = new HashMap<String, String>();
        params.put("response_type", "code");
        params.put("client_id", clientId);
        params.put("scope", "read,write");
        final Response response = RestAssured.given().auth().preemptive().basic(clientId, "secret").and().with().params(params).when().post("http://localhost:8081/spring-security-oauth-server/oauth/authorize");
    }
}