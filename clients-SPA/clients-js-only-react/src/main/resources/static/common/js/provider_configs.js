const AUTH0_APP_DOMAIN = 'https://bael-jsonly-pkce.auth0.com';
const PROVIDER_CONFIGS = {
  AUTH0: {
    AUTH_URL: AUTH0_APP_DOMAIN + "/authorize",
    CLIENT_ID: "R7L3XpkJrwcGEkuxrUdSpGAA9NgX9ouQ",
    CONFIGURED_REDIRECT_URIS:{
      STEP_BY_STEP: "http://localhost:8080/pkce-stepbystep/popup_code_handler.html",
      REAL_CASE: "http://localhost:8080/pkce-realcase/popup_code_handler.html",
      SIMPLE: "http://localhost:8080/pkce-simple/callback.html"
    },
    TOKEN_URI: AUTH0_APP_DOMAIN + "/oauth/token",
    SCOPES: 'openid profile email',
    AUDIENCE: "pkceclient.baeldung.com",
    PROFILE_URL: AUTH0_APP_DOMAIN + "/userinfo",
    PROFILE_FIELDS: {
      NAME: "nickname",
      EMAIL: "email",
      PICTURE: "picture"
    },
    // Renew Token Period for in seconds:
    RENEW_TOKEN_PERIOD: 60
  }
}

window.PROVIDER_CONFIGS = PROVIDER_CONFIGS;