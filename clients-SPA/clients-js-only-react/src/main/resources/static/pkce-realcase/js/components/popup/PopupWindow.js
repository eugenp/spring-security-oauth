// PopupWindow component:
class PopupWindow extends React.Component {

  componentDidMount() {
    if (!this.props.error) {
      window.addEventListener('message', this.onMainWindowMessageFn, false);
      const authCodeStatus = {
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
    const { codeVerifier } = e.data;
    if (!codeVerifier) { return };
    const { tokenUrl, redirectUri, clientId, audience } = CONFIGS.AUTH0;
    const tokenRequestUrl = 'https://' + tokenUrl;
    const tokenRequestBody = {
      grant_type: 'authorization_code',
      redirect_uri: redirectUri,
      code: this.props.authCode,
      code_verifier: codeVerifier,
      client_id: clientId
    }
    if (audience) tokenRequestBody.audience = audience;
    var headers = {
      'Content-type': 'application/x-www-form-urlencoded; charset=UTF-8'
    }
    axios.post(tokenRequestUrl, new URLSearchParams(tokenRequestBody), { headers })
      .then(function (response) {
        const auth = response.data;
        const tokenStatus = {
          type: 'accessToken',
          auth
        }
        window.opener ? window.opener.postMessage(tokenStatus, "*") : window.alert("This is not a popup window!");
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