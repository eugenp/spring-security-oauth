package org.baeldung.test;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;

import java.util.HashMap;
import java.util.Map;

import org.junit.Test;

import com.jayway.restassured.RestAssured;
import com.jayway.restassured.response.Response;

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
    public void refreshAccessTokenSuccess() {
    	final Response authServerResponse = obtainAccessToken("fooClientIdPassword", "john", "123");
    	final String accessToken = authServerResponse.jsonPath().getString("access_token");
    	final String refreshToken = authServerResponse.jsonPath().getString("refresh_token");
    	assertNotNull(accessToken);
    	assertNotNull(refreshToken);
    	Response resourceServerResponse = RestAssured.given().header("Authorization", "Bearer " + accessToken).get("http://localhost:8082/spring-security-oauth-resource/foos/100");
        assertThat(resourceServerResponse.getStatusCode(), equalTo(200));
    	
    	String newAccessToken = obtainRefreshToken("fooClientIdPassword", refreshToken);
    	assertNotNull(newAccessToken);
    	resourceServerResponse = RestAssured.given().header("Authorization", "Bearer " + newAccessToken).get("http://localhost:8082/spring-security-oauth-resource/foos/100");
        assertThat(resourceServerResponse.getStatusCode(), equalTo(200));
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