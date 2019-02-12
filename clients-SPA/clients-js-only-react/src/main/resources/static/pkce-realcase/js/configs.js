const CONFIGS = {
  AUTH0: {
    authUrl: "bael-jsonly-pkce.auth0.com/authorize",
    clientId: "R7L3XpkJrwcGEkuxrUdSpGAA9NgX9ouQ",
    redirectUri: "http://localhost:8080/pkce-realcase/popup_code_handler.html",
    tokenUrl: "bael-jsonly-pkce.auth0.com/oauth/token",
    scopes: 'openid profile email',
    audience: "https://bael-jsonly-pkce.auth0.com/api/v2/",
    profileUrl: "bael-jsonly-pkce.auth0.com/userinfo",
    profileFields: {
      name: "nickname",
      email: "email",
      picture: "picture"
    }
  },
  resourceServer: {
    saveColorUrl: 'http://localhost:8081/colors/create',
    deleteColorUrl: 'http://localhost:8081/colors/delete/{id}',
    getColorsUrl: 'http://localhost:8081/colors/list',
  }
}

window.CONFIGS = CONFIGS;