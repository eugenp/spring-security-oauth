package org.baeldung.test;

import com.jayway.restassured.RestAssured;
import com.jayway.restassured.response.Response;
import org.assertj.core.util.Strings;
import org.baeldung.config.AuthorizationServerApplication;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.json.JacksonJsonParser;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.context.WebApplicationContext;

import java.util.HashMap;
import java.util.Map;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@WebAppConfiguration
@SpringBootTest(classes = AuthorizationServerApplication.class)
@ActiveProfiles("mvc")
public class TokenRevocationLiveTest {

    private static final String CONTENT_TYPE = MediaType.APPLICATION_JSON_UTF8_VALUE;
    private static final String CLIENT_ID = "fooClientIdPassword";
    private static final String CLIENT_SECRET = "secret";

    @Autowired
    private WebApplicationContext wac;

    @Autowired
    private FilterChainProxy springSecurityFilterChain;

    private MockMvc mockMvc;

    @Before
    public void setUp() throws Exception {
        this.mockMvc = MockMvcBuilders.webAppContextSetup(this.wac).addFilter(springSecurityFilterChain).build();
    }

    @After
    public void tearDown() throws Exception {
        this.wac = null;
        this.springSecurityFilterChain = null;
        this.mockMvc = null;
    }

    @Test
    public void whenObtainingAccessTokenThenCorrectLiveTest() {
        final Response authServerResponse = obtainAccessToken("fooClientIdPassword", "john", "123");
        final String accessToken = authServerResponse.jsonPath().getString("access_token");
        assertNotNull(accessToken);

        final Response resourceServerResponse = RestAssured.given().header("Authorization", "Bearer " + accessToken).get("http://localhost:8082/spring-security-oauth-resource/foos/100");
        assertThat(resourceServerResponse.getStatusCode(), equalTo(200));
    }

    @Test
    public void whenObtainingAccessTokenByRefreshTokenThenCorrectLiveTest() {
        final String refreshToken = obtainAccessToken("fooClientIdPassword", "john", "123").jsonPath().getString("refresh_token");
        final String newAccessToken = obtainAccessTokenByRefreshTokenLive(CLIENT_ID, refreshToken);
        assertTrue(!Strings.isNullOrEmpty(newAccessToken));
    }

    @Test
    public void whenObtainingAccessTokenThenCorrectMockTest() throws Exception {
        final String accessToken = new JacksonJsonParser().parseMap(obtainJWTToken("admin", "nimda")).get("access_token").toString();
        assertTrue(!Strings.isNullOrEmpty(accessToken));
    }

    @Test
    public void whenObtainingAccessTokenByRefreshTokenThenCorrectMockTest() throws Exception {
        final String refreshToken = new JacksonJsonParser().parseMap(obtainJWTToken("admin", "nimda")).get("refresh_token").toString();
        final String newAccessToken = obtainAccessTokenByRefreshToken(CLIENT_ID, refreshToken);
        assertTrue(!Strings.isNullOrEmpty(newAccessToken));
    }

    private Response obtainAccessToken(String clientId, String username, String password) {
        final Map<String, String> params = new HashMap<>();
        params.put("grant_type", "password");
        params.put("client_id", clientId);
        params.put("username", username);
        params.put("password", password);

        return RestAssured.given().auth().preemptive().basic(clientId, "secret").and().with().params(params).when().post("http://localhost:8081/spring-security-oauth-server/oauth/token");
    }

    private String obtainJWTToken(String username, String password) throws Exception {
        final MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("grant_type", "password");
        params.add("client_id", CLIENT_ID);
        params.add("username", username);
        params.add("password", password);

        ResultActions result = mockMvc.perform(post("/oauth/token")
                .params(params)
                .with(httpBasic(CLIENT_ID, CLIENT_SECRET))
                .accept(CONTENT_TYPE))
                .andExpect(status().isOk())
                .andExpect(content().contentType(CONTENT_TYPE));

        return result.andReturn().getResponse().getContentAsString();
    }

    private String obtainAccessTokenByRefreshToken(String clientId, final String refreshToken) throws Exception {
        final MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("grant_type", "refresh_token");
        params.add("client_id", clientId);
        params.add("refresh_token", refreshToken);
        ResultActions result = mockMvc.perform(post("/oauth/token")
                .params(params)
                .with(httpBasic(CLIENT_ID, CLIENT_SECRET))
                .accept(CONTENT_TYPE))
                .andExpect(status().isOk())
                .andExpect(content().contentType(CONTENT_TYPE));

        return new JacksonJsonParser().parseMap(result.andReturn().getResponse().getContentAsString()).get("access_token").toString();
    }

    private String obtainAccessTokenByRefreshTokenLive(String clientId, final String refreshToken) {
        final Map<String, String> params = new HashMap<>();
        params.put("grant_type", "refresh_token");
        params.put("client_id", clientId);
        params.put("refresh_token", refreshToken);
        final Response response = RestAssured.given().auth().preemptive().basic(clientId, "secret").and().with().params(params).when().post("http://localhost:8081/spring-security-oauth-server/oauth/token");

        return response.jsonPath().getString("access_token");
    }

}