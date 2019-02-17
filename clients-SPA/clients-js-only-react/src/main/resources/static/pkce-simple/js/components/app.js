class App extends React.Component {
  state = {
    codeVerifier: '',
    codeChallenge: '',
    state: '',
    accessToken: '',
    userName: ''
  };

  createCodes = () => {
    const state = this.generateRandomString(32);
    const codeVerifier = this.generateRandomString(32);
    this.generateCodeChallenge(codeVerifier).then((codeChallenge) => {
      this.setState({
        state,
        codeVerifier,
        codeChallenge
      })
    })
  }

  generateRandomString = (length) => {
    var randomByteArray = new Uint8Array(length);
    window.crypto.getRandomValues(randomByteArray);
    var randomString = btoa(String.fromCharCode.apply(null, randomByteArray));
    var code = randomString.replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
    return code;
  }

  generateCodeChallenge = async (codeVerifier) => {
    const strBuffer = new TextEncoder('utf-8').encode(codeVerifier);
    const hashBuffer = await window.crypto.subtle.digest('SHA-256', strBuffer);
    const byteArray = Array.from(new Uint8Array(hashBuffer));
    var base64String = btoa(String.fromCharCode.apply(null, byteArray));
    var code = base64String.replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
    return code;
  }

  authorizeApplication = () => {
    const { AUTH_URL,
      CLIENT_ID,
      CONFIGURED_REDIRECT_URIS: { SIMPLE: redirectUri },
      SCOPES,
      AUDIENCE } = PROVIDER_CONFIGS.AUTH0;
    const authorizationUrl = AUTH_URL
      + '?client_id=' + CLIENT_ID
      + "&response_type=code"
      + '&scope=' + SCOPES
      + '&redirect_uri=' + redirectUri
      + '&state=' + this.state.state
      + '&code_challenge_method=S256'
      + '&code_challenge=' + this.state.codeChallenge
      + (AUDIENCE ? ('&audience=' + AUDIENCE) : '');
    var popup = window.open(authorizationUrl, 'external_auth_page', 'width=800,height=600');
    window.addEventListener('message', this.onPopupResponseFn, false);
    this.setState({
      popup
    })
  }

  onPopupResponseFn = (e) => {
    const eventType = e.data && e.data.type;
    switch (eventType) {
      case 'state':
        if (e.data.state !== this.state.state) {
          window.alert("Retrieved state [" + e.data.state + "] didn't match stored one! Try again");
          return;
        }
        this.state.popup.postMessage({ codeVerifier: this.state.codeVerifier }, "*");
        break;
      case 'accessToken':
        const accessToken = e.data.accessToken;
        this.setState({
          accessToken,
          popup: null,
        });
        break;
    }
  }

  requestResource = () => {
    const profileInfoUrl = PROVIDER_CONFIGS.AUTH0.PROFILE_URL;
    const headers = { headers: { Authorization: 'Bearer ' + this.state.accessToken } };
    var self = this;
    axios.get(profileInfoUrl, headers).then(function (response) {
      self.setState({
        userName: response.data.nickname
      })
    });
  }

  render() {
    return (
      <div>
        <button onClick={this.createCodes}>Create codes</button>
        {this.state.codeChallenge
          && <button onClick={this.authorizeApplication}>Authenticate</button>}
        {this.state.accessToken
          && <button onClick={this.requestResource}>Request secured resource</button>}
        {this.state.userName
          && <div>Welcome {this.state.userName}</div>}
      </div>
    )
  }
}

window.App = App;