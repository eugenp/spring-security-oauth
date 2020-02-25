package com.baeldung.newstack;


import io.restassured.response.Response;
import org.apache.http.entity.ContentType;
import org.junit.Test;

import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import static io.restassured.RestAssured.given;

public class ClaimsValidatorIntegrationTest {
    private static final String CLIENT_ID = "newClient";
    private static final String CLIENT_SECRET = "newClientSecret";
    private static final String TOKEN_URI = "http://localhost:8083/auth/realms/baeldung/protocol/openid-connect/token";
    private static final String RESOURCE_URI = "http://localhost:8081/new-resource-server/api/projects";

    @Test
    public void givenTokenContainsInvalidClaim_thenUnauthorised() {
        final String accessToken = getAccessToken("mike@other.com", "pass");

        given().auth()
                .oauth2(accessToken)
                .when()
                .get(RESOURCE_URI)
                .then()
                .assertThat()
                .statusCode(401);

    }

    @Test
    public void givenTokenContainsValidClaim_thenOK() {
        final String accessToken = getAccessToken("messi@baeldung.com", "pass");

        given().auth()
                .oauth2(accessToken)
                .when()
                .get(RESOURCE_URI)
                .then()
                .assertThat()
                .statusCode(200);

    }

    private String getAccessToken(String username, String password) {

        final String authorization = CLIENT_ID + ':' + CLIENT_SECRET;

        String encodedAuthHeader = Base64.getEncoder()
                .encodeToString(authorization.getBytes());

        Map<String, Object> requestHeaders = new HashMap<>();
        requestHeaders.put("Authorization", "Basic " + encodedAuthHeader);

        Map<String, String> requestParams = new HashMap<>();
        requestParams.put("grant_type", "password");
        requestParams.put("username", username);
        requestParams.put("password", password);
        requestParams.put("scope", "read write");

        return given()
                .headers(requestHeaders)
                .contentType("application/x-www-form-urlencoded")
                .params(requestParams)
                .when().post(TOKEN_URI)
                .then().extract().path("access_token");
    }
}
