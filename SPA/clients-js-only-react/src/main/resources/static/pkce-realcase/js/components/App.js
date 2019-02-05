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
    popup: null
  };

  onLoginFn = () => {
    const { authUrl, clientId, redirectUri, scopes, audience } = CONFIGS.AUTH0;
    const state = generate_state();
    const codeVerifier = generate_code_verifier();
    const codeChallenge = generate_code_challenge(codeVerifier);
    const authorizationUrl = 'https://' + authUrl
      + '?client_id=' + clientId
      + "&response_type=code"
      + '&scope=' + scopes
      + '&redirect_uri=' + encodeURI(redirectUri)
      + '&state=' + state
      + '&code_challenge_method=S256'
      + '&code_challenge=' + codeChallenge
      + (audience ? ('&audience=' + audience) : '');
    window.addEventListener('message', this.onPopupResponseFn, false);
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

  onPopupResponseFn = (e) => {
    const eventType = e.data && e.data.type;
    switch (eventType) {
      case 'authCode':
        if (e.data.state !== this.state.authRequest.state) {
          window.alert("Retrieved state [" + e.data.state + "] didn't match stored one! Try again");
          return;
        }
        const popupUpdate = {
          codeVerifier: this.state.authRequest.codeVerifier
        }
        this.state.popup.postMessage(popupUpdate, "*");
        break;
      case 'accessToken':
        const auth = e.data.auth;
        this.fetchUserInfo(auth);
        this.setState({
          auth,
          popup: null,
        });
        break;
    }
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
    const { profileUrl, profileFields } = CONFIGS.AUTH0;
    const profileInfoUrl = 'https://' + profileUrl;
    const headers = auth
      ? {
        headers: {
          'Authorization': 'Bearer ' + auth.access_token
        }
      }
      : { };
    var self = this;
    axios.get(profileInfoUrl, headers).then(function (response) {
      const name = self.extractProfileField(response.data, profileFields.name);
      const lastName = self.extractProfileField(response.data, profileFields.lastName);
      const email = self.extractProfileField(response.data, profileFields.email);
      const picture = self.extractProfileField(response.data, profileFields.picture);
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
    this.setState({
      user: null,
      auth: null,
      authRequest: {
        codeVerifier: '',
        codeChallenge: '',
        state: ''
      },
      currentView: 'listing',
      popup: null
    })
  }

  changeView = (view) => {
    this.setState({
      currentView: view
    })
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
    const { user, auth } = { ...this.state };
    return (
      <div>
        {this.state.popup && <div className="dimmer"></div>}
        <div className="baeldung-container">
          <Navbar user={user} auth={auth} onLoginFn={this.onLoginFn} onLogoutFn={this.onLogoutFn} changeView={this.changeView} />
          <div className="content-container">
            <CurrentView auth={this.state.auth} user={this.state.user} />
          </div>
        </div>
      </div>

    )
  }
}

window.App = App;