package org.baeldung.test;

import static org.junit.Assert.*;

import java.util.HashMap;
import java.util.Map;

import org.junit.Test;

import com.jayway.restassured.RestAssured;
import com.jayway.restassured.response.Response;

public class TokenRevocationLiveTest {

    private String refreshToken;

    private String obtainAccessToken(String clientId, String username, String password) {
        final Map<String, String> params = new HashMap<String, String>();
        params.put("grant_type", "password");
        params.put("client_id", clientId);
        params.put("username", username);
        params.put("password", password);
        final Response response = RestAssured.given().auth().preemptive().basic(clientId, "secret").and().with().params(params).when().post("http://localhost:8081/spring-security-oauth-server/oauth/token");
        refreshToken = response.jsonPath().getString("refresh_token");
        return response.jsonPath().getString("access_token");
    }

    private String obtainRefreshToken(String clientId) {
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

    @Test
    public void givenDBUser_whenRevokeToken_thenAuthorized() {
        final String accessToken = obtainAccessToken("fooClientIdPassword", "john", "123");
        assertNotNull(accessToken);
    }

    // @Test
    // public void givenUser_whenRevokeToken_thenTokenInvalidError() {
    // final String accessToken1 = obtainAccessToken("fooClientIdPassword", "john", "123");
    // final String accessToken2 = obtainAccessToken("fooClientIdPassword", "tom", "111");
    // authorizeClient("fooClientIdPassword");
    //
    // final Response tokenResponse1 = RestAssured.given().header("Authorization", "Bearer " + accessToken2).get("http://localhost:8082/spring-security-oauth-resource/tokens");
    // assertEquals(200, tokenResponse1.getStatusCode());
    //
    // final Response revokeResponse = RestAssured.given().header("Authorization", "Bearer " + accessToken1).post("http://localhost:8082/spring-security-oauth-resource/tokens/revoke/"+accessToken2);
    // assertEquals(200, revokeResponse.getStatusCode());
    //
    // final Response tokenResponse2 = RestAssured.given().header("Authorization", "Bearer " + accessToken2).get("http://localhost:8082/spring-security-oauth-resource/tokens");
    // assertEquals(401, tokenResponse2.getStatusCode());
    // }

    // @Test
    // public void givenUser_whenRevokeRefreshToken_thenRefreshTokenInvalidError() {
    // final String accessToken1 = obtainAccessToken("fooClientIdPassword", "john", "123");
    // final String accessToken2 = obtainAccessToken("fooClientIdPassword", "tom", "111");
    // authorizeClient("fooClientIdPassword");
    //
    // final String accessToken3 = obtainRefreshToken("fooClientIdPassword");
    // authorizeClient("fooClientIdPassword");
    // final Response refreshTokenResponse = RestAssured.given().header("Authorization", "Bearer " + accessToken3).get("http://localhost:8082/spring-security-oauth-resource/tokens");
    // assertEquals(200, refreshTokenResponse.getStatusCode());
    //
    // final Response revokeRefreshTokenResponse = RestAssured.given().header("Authorization", "Bearer " + accessToken1).post("http://localhost:8082/spring-security-oauth-resource/tokens/revokeRefreshToken/"+refreshToken);
    // assertEquals(200, revokeRefreshTokenResponse.getStatusCode());
    //
    // final String accessToken4 = obtainRefreshToken("fooClientIdPassword");
    // authorizeClient("fooClientIdPassword");
    // final Response refreshTokenResponse2 = RestAssured.given().header("Authorization", "Bearer " + accessToken4).get("http://localhost:8082/spring-security-oauth-resource/tokens");
    // assertEquals(401, refreshTokenResponse2.getStatusCode());
    // }
}