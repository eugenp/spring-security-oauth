// App component:
class App extends React.Component {
  state = {
    user: null,
    auth: null,
    authRequest: {
      codeVerifier: '',
      codeChallenge: '',
      state: ''
    },
    currentView: 'listing',
    popup: null,
    iframe: React.createRef(),
    iframeComponent: null,
    scopes: {
      create: true,
      delete: true
    },
  };

  componentWillUnmount() {
    window.removeEventListener("message", this.onChildResponseFn);
  }

  _generateAuthUrl = (isSilentAuth) => {
    const { AUTH_URL,
      CLIENT_ID,
      CONFIGURED_REDIRECT_URIS: { REAL_CASE: redirectUri },
      SCOPES,
      AUDIENCE } = PROVIDER_CONFIGS.AUTH0;
    const state = generate_state();
    const codeVerifier = generate_code_verifier();
    const codeChallenge = generate_code_challenge(codeVerifier);
    const customScopesString = (this.state.scopes.create ? ' colors:create' : '')
      + (this.state.scopes.delete ? ' colors:delete' : '');
    const authorizationUrl = AUTH_URL
      + '?client_id=' + CLIENT_ID
      + "&response_type=code"
      + '&scope=' + SCOPES + customScopesString
      + '&redirect_uri=' + redirectUri
      + '&state=' + state
      + '&code_challenge_method=S256'
      + '&code_challenge=' + codeChallenge
      + (AUDIENCE ? ('&audience=' + AUDIENCE) : '')
      + (isSilentAuth ? '&prompt=none' : '');

    return { state, codeVerifier, codeChallenge, authorizationUrl };
  }

  onLoginFn = () => {
    const { state, codeVerifier, codeChallenge, authorizationUrl } = this._generateAuthUrl();
    window.addEventListener('message', this.onChildResponseFn, false);
    var popup = window.open(authorizationUrl, 'external_login_page', 'width=800,height=600,left=200,top=100');
    this.setState({
      popup,
      authRequest: {
        codeVerifier,
        codeChallenge,
        state
      }
    });
  }

  onChildResponseFn = (e) => {
    const eventType = e.data && e.data.type;
    switch (eventType) {
      case 'authCode':
        if (e.data.state !== this.state.authRequest.state) {
          window.alert("Retrieved state [" + e.data.state + "] didn't match stored one! Try again");
          return;
        }
        const authCodeUpdate = {
          codeVerifier: this.state.authRequest.codeVerifier
        }
        var childWindow = this.state[e.data.source].current ? this.state[e.data.source].current.contentWindow : this.state[e.data.source];
        childWindow.postMessage(authCodeUpdate, "*");
        break;
      case 'accessToken':
        const auth = e.data.auth;
        this._setTimeoutForRenewToken(auth);
        this.fetchUserInfo(auth);
        var expiryDate = new Date();
        expiryDate.setSeconds(expiryDate.getSeconds() + auth.expires_in);
        console.log("Setting new token", "Access Token " + auth.access_token, "Expires: " + expiryDate);
        this.setState({
          auth,
          popup: null,
          iframeComponent: null
        });
        break;
    }
  }

  _setTimeoutForRenewToken = (auth) => {
    const defaultRenewTokenPeriod = PROVIDER_CONFIGS.AUTH0.RENEW_TOKEN_PERIOD;
    const renewTokenIn = auth.expires_in < defaultRenewTokenPeriod
      ? auth.expires_in
      : defaultRenewTokenPeriod;
    this.tokenRenewTimeout = setTimeout(this.renewTokenFn, renewTokenIn * 1000);
  }


  renewTokenFn = () => {
    const { state, codeVerifier, codeChallenge, authorizationUrl } = this._generateAuthUrl(true);
    const iframeComponent = <iframe style={{ display: 'none' }} src={authorizationUrl} ref={this.state.iframe} />;
    this.setState({
      iframeComponent,
      authRequest: {
        codeVerifier,
        codeChallenge,
        state
      }
    });
  }

  extractProfileField = (data, fieldString) => {
    if (!fieldString) return;
    var fields = fieldString.split('.');
    var dataValue = { ...data };
    for (var field of fields) {
      dataValue = dataValue[field];
    }
    return dataValue;
  }

  fetchUserInfo(auth) {
    const { PROFILE_URL, PROFILE_FIELDS } = PROVIDER_CONFIGS.AUTH0;
    const headers = auth
      ? {
        headers: {
          'Authorization': 'Bearer ' + auth.access_token
        }
      }
      : {};
    var self = this;
    axios.get(PROFILE_URL, headers).then(function (response) {
      const name = self.extractProfileField(response.data, PROFILE_FIELDS.NAME);
      const lastName = self.extractProfileField(response.data, PROFILE_FIELDS.LAST_NAME);
      const email = self.extractProfileField(response.data, PROFILE_FIELDS.EMAIL);
      const picture = self.extractProfileField(response.data, PROFILE_FIELDS.PICTURE);
      const user = { name, lastName, email, picture };
      self.setState({
        user
      })
    })
      .catch(function (error) {
        const errorMessage = "Error retrieving user information" + error;
        window.alert(errorMessage);
      })
  }

  onLogoutFn = () => {
    clearTimeout(this.tokenRenewTimeout);
    window.removeEventListener("message", this.onChildResponseFn);
    this.setState({
      user: null,
      auth: null,
      authRequest: {
        codeVerifier: '',
        codeChallenge: '',
        state: ''
      },
      currentView: 'listing',
      popup: null,
      iframeComponent: null
    })
  }

  changeView = (view) => {
    this.setState({
      currentView: view
    })
  }

  scopeChangeFn = (field, e) => {
    const scopes = { ...this.state.scopes };
    scopes[field] = !scopes[field];
    this.setState({
      scopes
    });
  }

  render() {
    var CurrentView = null;
    switch (this.state.currentView) {
      case 'listing':
        CurrentView = Listing
        break;
      case 'profile':
        CurrentView = Profile;
        break;
    }
    const { user, auth, popup, iframeComponent } = { ...this.state };
    return (
      <div>
        {popup && <div className="dimmer"></div>}
        <div className="baeldung-container">
          <Navbar user={user} auth={auth} onLoginFn={this.onLoginFn} onLogoutFn={this.onLogoutFn} changeView={this.changeView} />
          <div className="content-container">
            <CurrentView {...this.state} scopeChangeFn={this.scopeChangeFn} renewTokenFn={this.renewTokenFn} />
          </div>
        </div>
        {iframeComponent || ''}
      </div>

    )
  }
}

window.App = App;