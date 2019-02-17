// PopupWindow component:
class PopupWindow extends React.Component {

  state = {
    codeVerifier: '',
    accessToken: '',
    requestedAccessToken: false,
    provider: 'AUTH0'
  };

  componentDidMount() {
    if (!this.props.error) {
      window.addEventListener('message', this.onMainWindowMessageFn, false);
      const authCodeStatus = {
        authCode: this.props.authCode,
        state: this.props.state,
        type: 'authCode'
      }
      window.opener ? window.opener.postMessage(authCodeStatus, "*") : window.alert("This is not a popup window!");
    }
    else {
      window.alert("Error: " + this.props.error);
    }
  }

  onMainWindowMessageFn = (e) => {
    const { codeVerifier, provider } = e.data;
    if (codeVerifier) this.setState({
      codeVerifier,
      provider
    })
  }

  requestAccessTokenFn = () => {
    const { TOKEN_URI,
      CLIENT_ID,
      CONFIGURED_REDIRECT_URIS: { STEP_BY_STEP: redirectUri },
      AUDIENCE } = PROVIDER_CONFIGS[this.state.provider];
    const tokenRequestBody = {
      grant_type: 'authorization_code',
      redirect_uri: redirectUri,
      code: this.props.authCode,
      code_verifier: this.state.codeVerifier,
      client_id: CLIENT_ID
    }
    if (AUDIENCE) tokenRequestBody.audience = AUDIENCE;
    var headers = {
      'Content-type': 'application/x-www-form-urlencoded; charset=UTF-8'
    }
    console.log("Making POST request to URL [" + TOKEN_URI + "] with Headers:");
    console.log(headers);
    console.log("and body:");
    console.log(tokenRequestBody);
    console.log("=========================");
    var self = this;
    axios.post(TOKEN_URI, new URLSearchParams(tokenRequestBody), { headers })
      .then(function (response) {
        console.log("Retrieved response with data:")
        console.log(response.data);
        console.log("=========================");
        const accessToken = response.data.access_token;
        const tokenStatus = {
          type: 'accessToken',
          accessToken
        }
        window.opener ? window.opener.postMessage(tokenStatus, "*") : window.alert("This is not a popup window!");
        self.setState({
          accessToken
        })
      })
      .catch(function (error) {
        const errorMessage = "Error retrieving token: Provider probably doesn't have CORS enabled for the Token endpoint...try another provider. " + error
        window.alert(errorMessage);
      })
    this.setState({
      requestedAccessToken: true
    })
  }

  closeWindow = () => {
    const closeMessage = {
      type: 'closed'
    }
    window.opener ? window.opener.postMessage(closeMessage, "*") : window.alert("This is not a popup window!");
    window.close();
  }


  render() {
    const { authCode, error, errorDescription } = this.props;
    const { accessToken, requestedAccessToken } = this.state;
    return (error
      ? <div className="popup-container step-container">Error: {error} - {errorDescription}</div>
      : <div className="popup-container step-container">
        <h2>Popup - OAuth 2 Dance</h2>
        <div className="summary">Auth Server retrieved auth code:</div>
        <div className="result large"><span>{authCode}</span></div>
        {(!accessToken)
          ? <div>
            <div className="summary">We got just a couple of minutes before the Auth Code expires...</div>
            <div className="action">
              <button onClick={this.requestAccessTokenFn} disabled={requestedAccessToken}>Request Access Token!</button>
            </div>
          </div>
          : <div>
            <div className="summary">Auth Server retrieved Access Token:</div>
            <div className="result large"><span>{accessToken}</span></div>
            <div className="action">
              <button onClick={this.closeWindow}>Return</button>
            </div>
          </div>
        }
      </div>
    )
  }
}

window.PopupWindow = PopupWindow;