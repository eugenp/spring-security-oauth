// PopupWindow component:
class PopupWindow extends React.Component {

  componentDidMount() {
    if (!this.props.error) {
      window.addEventListener('message', this.onMainWindowMessageFn, false);
      const authCodeStatus = {
        state: this.props.state,
        type: 'authCode',
        source: this.props.typeOfWindow
      }
      this.props.parentWindow ? this.props.parentWindow.postMessage(authCodeStatus, "*") : window.alert("This is not a popup or iframe window!");
    }
    else {
      window.alert("Error: " + this.props.error);
    }
  }

  onMainWindowMessageFn = (e) => {
    const { codeVerifier } = e.data;
    if (!codeVerifier) { return };
    const { TOKEN_URI,
      CLIENT_ID,
      CONFIGURED_REDIRECT_URIS: { REAL_CASE: redirectUri },
      AUDIENCE } = PROVIDER_CONFIGS.AUTH0;
    const tokenRequestUrl = TOKEN_URI;
    const tokenRequestBody = {
      grant_type: 'authorization_code',
      redirect_uri: redirectUri,
      code: this.props.authCode,
      code_verifier: codeVerifier,
      client_id: CLIENT_ID
    }
    if (AUDIENCE) tokenRequestBody.audience = AUDIENCE;
    var headers = {
      'Content-type': 'application/x-www-form-urlencoded; charset=UTF-8'
    }
    var self = this;
    axios.post(tokenRequestUrl, new URLSearchParams(tokenRequestBody), { headers })
      .then(function (response) {
        const auth = response.data;
        const tokenStatus = {
          type: 'accessToken',
          auth,
          source: self.props.typeOfWindow
        }
        self.props.parentWindow ? self.props.parentWindow.postMessage(tokenStatus, "*") : window.alert("This is not a popup or iframe window!");
        window.close();
      })
      .catch(function (error) {
        const errorMessage = "Error retrieving token: Provider probably doesn't have CORS enabled for the Token endpoint...try another provider. " + error
        window.alert(errorMessage);
      })
  }

  render() {
    const { error, errorDescription } = this.props;
    return (error && <div className="popup-container step-container">Error: {error} - {errorDescription}</div>)
  }
}

window.PopupWindow = PopupWindow;