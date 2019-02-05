// PopupWindow component:
class PopupWindow extends React.Component {

  state = {
    codeChallenge: '',
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
    const { tokenUrl, redirectUri, clientId, audience } = CONFIGS[this.state.provider];
    const tokenRequestUrl = 'https://' + tokenUrl;
    const tokenRequestBody = {
      grant_type: 'authorization_code',
      redirect_uri: redirectUri,
      code: this.props.authCode,
      code_verifier: this.state.codeVerifier,
      client_id: clientId
    }
    if (audience) tokenRequestBody.audience = audience;
    var headers = {
      'Content-type': 'application/x-www-form-urlencoded; charset=UTF-8'
    }
    var self = this;
    axios.post(tokenRequestUrl, new URLSearchParams(tokenRequestBody), { headers })
      .then(function (response) {
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