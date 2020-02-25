package com.baeldung.newstack;

import com.baeldung.newstack.web.model.Project;
import io.restassured.RestAssured;
import io.restassured.response.Response;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;


//Run this test only when authorization and resource server are running

@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class JwtCustomClaimTest {

    @Autowired
    private WebTestClient webTestClient;

    private static final String CLIENT_ID = "newClient";
    private static final String CLIENT_SECRET = "newClientSecret";
    private static final String CONTENT_TYPE = "application/json;charset=UTF-8";

    private static final String TOKEN_URL = "http://localhost:8083/auth/realms/baeldung/protocol/openid-connect/token";
    private static final String RESOURCE_URL = "http://localhost:8081/new-resource-server/api/projects";

    private static final String EMAIL_VALID = "john@baeldung.com";
    private static final String EMAIL_NOT_VALID = "john@test.com";
    private static final String NAME = "john";


    private String obtainAccessToken(String username, String password) throws Exception {
        final MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("grant_type", "password");
        params.add("client_id", CLIENT_ID);
        params.add("username", username);
        params.add("scope", "profile read write");
        params.add("password", password);

        final Response response = RestAssured.given().auth().preemptive().basic(CLIENT_ID, CLIENT_SECRET)
                .with().params(params).when().post(TOKEN_URL);

        return response.jsonPath().getString("access_token");

    }

    @Test
    public void givenBaeldungUser_whenGetSecureRequest_thenOk() throws Exception {
        final String accessToken = obtainAccessToken(EMAIL_VALID, "123");
        this.webTestClient.get()
                .uri(RESOURCE_URL)
                .header("Authorization", "Bearer " + accessToken)
                .exchange()
                .expectStatus().isOk()
                .expectBodyList(Project.class);
    }

    @Test
    public void givenNotBaeldungUser_whenGetSecureRequest_thenNotOk() throws Exception {
        final String accessToken = obtainAccessToken(EMAIL_NOT_VALID, "123");
        this.webTestClient.get()
                .uri(RESOURCE_URL)
                .header("Authorization", "Bearer " + accessToken)
                .exchange()
                .expectStatus().isUnauthorized();
    }

}
