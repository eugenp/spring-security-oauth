package com.baeldung.newstack;

import static io.restassured.RestAssured.given;

import org.apache.commons.codec.binary.Base64;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;

public class OauthValidationTest {

    private static final String CLIENT_ID = "newClient";
    private static final String SECRET = "newClientSecret";
    private static final String AUTH_TOKEN_URL = "http://localhost:8083/auth/realms/baeldung/protocol/openid-connect/token";
    private static final String RESOURCE_URL = "http://localhost:8082/new-client/projects";

    @Test
    public void givenValidUsername_ExpectValidResponse() {
        //Arrange
        String accessToken = getToken("john@baeldung.com","123");

        //Act & Assert
        given().auth()
                .oauth2(accessToken)
                .when()
                .get(RESOURCE_URL)
                .then()
                .assertThat()
                .statusCode(HttpStatus.OK.value());
    }

    @Test
    public void givenInvalidUsername_ExpectInvalidResponse() {
        //Arrange
        String accessToken = getToken("john@test.com","123");

        //Act & Assert
        given().auth()
                .oauth2(accessToken)
                .when()
                .get(RESOURCE_URL)
                .then()
                .assertThat()
                .statusCode(HttpStatus.UNAUTHORIZED.value());
    }

    private String getToken(String username, String password){
        String authCookie = (CLIENT_ID + ":" + SECRET);
        String authCookieEncoded = new String(Base64.encodeBase64(authCookie.getBytes()));
        return given().log().all().header("Content-Type", "application/x-www-form-urlencoded")
                .contentType("application/x-www-form-urlencoded").header("Authorization", "Basic " + authCookieEncoded)
                .param("grant_type", "password").param("username", username).param("password", password)

                .when().post(AUTH_TOKEN_URL)
                .then()
                .assertThat()
                .statusCode(HttpStatus.OK.value())
                .extract()
                .path("access_token");
    }
}
