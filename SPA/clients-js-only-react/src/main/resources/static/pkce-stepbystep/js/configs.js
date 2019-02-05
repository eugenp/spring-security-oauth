const CONFIGS = {
  AUTH0: {
    authUrl: "bael-jsonly-pkce.auth0.com/authorize",
    clientId: "R7L3XpkJrwcGEkuxrUdSpGAA9NgX9ouQ",
    redirectUri: "http://localhost:8080/pkce-stepbystep/popup_code_handler.html",
    tokenUrl: "bael-jsonly-pkce.auth0.com/oauth/token",
    scopes: 'openid profile email read:users',
    audience: "https://bael-jsonly-pkce.auth0.com/api/v2/",
    profileUrl: "bael-jsonly-pkce.auth0.com/userinfo",
    profileFields: {
      name: "nickname",
      email: "email",
      picture: "picture"
    }
  },
  /* By the time we created this tutorial, Okta didn't support PKCE for SPA; CORS was not enabled for the Token endpoint,
  therefore we can't be sure if everything will run correctly if you select this option */
  // OKTA: {
  //   authUrl: "dev-983970.okta.com/oauth2/default/v1/authorize",
  //   clientId: "0oa9xvo04ogNQjR8o356",
  //   redirectUri: "http://localhost:8080/pkce-stepbystep/popup_code_handler.html",
  //   tokenUrl: "dev-983970.okta.com/oauth2/default/v1/token",
  //   scopes: 'openid profile',
  //   profileUrl: "dev-983970.okta.com/api/v1/users/me",
  //   profileFields: {
  //     name: "profile.firstName",
  //     lastName: "profile.lastName",
  //     email: "profile.email",
  //   }
  // },
  /* By the time we created this tutorial, Google didn't support PKCE for SPA; CORS was not enabled for the Token endpoint,
  therefore we can't be sure if everything will run correctly if you select this option */
  // GOOGLE: {
  //   authUrl: "accounts.google.com/o/oauth2/v2/auth",
  //   clientId: "246072928137-0cdfigcmkmm0ikeq7k4fan69883hn915.apps.googleusercontent.com",
  //   redirectUri: "http://localhost:8080/pkce-stepbystep/popup_code_handler.html",
  //   tokenUrl: "googleapis.com/oauth2/v4/token",
  //   scopes: 'https://www.googleapis.com/auth/plus.login',
  //   profileUrl: "googleapis.com/plus/v1/people/me",
  //   profileFields: {
  //     name: "name.givenName",
  //     lastName: "name.familyName",
  //     email: "emails.0.value",
  //     picture: "image.url"
  //   }
  // },
}

window.CONFIGS = CONFIGS;