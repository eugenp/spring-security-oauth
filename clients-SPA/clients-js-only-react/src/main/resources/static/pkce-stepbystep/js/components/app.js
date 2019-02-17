// App component:
class App extends React.Component {
  state = {
    step1: {
      started: false,
      codeVerifier: '',
      codeChallenge: '',
      state: '',
      provider: 'AUTH0'
    },
    step2: {
      started: false,
      popup: null,
      authCode: '',
      accessToken: ''
    },
    step3: {
      started: false,
      profile: {}
    }
  };

  componentDidUpdate() {
    this.lastElement.scrollIntoView({ block: "end", behavior: "smooth" });
  }

  executeStep1CreateCodes = (provider) => {
    const state = generate_state();
    const codeVerifier = generate_code_verifier();
    const codeChallenge = generate_code_challenge(codeVerifier);
    this.setState({
      step1: {
        ...this.state.step1,
        started: true,
        codeVerifier,
        codeChallenge,
        state,
        provider
      }
    })
  }

  executeStep2RequestCode = () => {
    const { AUTH_URL,
      CLIENT_ID,
      CONFIGURED_REDIRECT_URIS: { STEP_BY_STEP: redirectUri },
      SCOPES,
      AUDIENCE } = PROVIDER_CONFIGS[this.state.step1.provider];
    const authorizationUrl = AUTH_URL
      + '?client_id=' + CLIENT_ID
      + "&response_type=code"
      + '&scope=' + SCOPES
      + '&redirect_uri=' + redirectUri
      + '&state=' + this.state.step1.state
      + '&code_challenge_method=S256'
      + '&code_challenge=' + this.state.step1.codeChallenge
      + (AUDIENCE ? ('&audience=' + AUDIENCE) : '');
    console.log("Opening popup sending user to authorization URL with QueryParams:", AUTH_URL, authorizationUrl.split("&").slice(1));
    console.log("=========================");
    window.addEventListener('message', this.onPopupResponseFn, false);
    var popup = window.open(authorizationUrl, 'external_login_page', 'width=800,height=600,left=200,top=100');
    this.setState({
      step2: {
        ...this.state.step2,
        started: true,
        popup
      }
    })
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

  executeStep3RequestResource = () => {
    const { PROFILE_URL, PROFILE_FIELDS } = PROVIDER_CONFIGS[this.state.step1.provider];
    const headers = { headers: { Authorization: 'Bearer ' + this.state.step2.accessToken } };
    var self = this;
    axios.get(PROFILE_URL, headers).then(function (response) {
      const name = self.extractProfileField(response.data, PROFILE_FIELDS.NAME);
      const lastName = self.extractProfileField(response.data, PROFILE_FIELDS.LAST_NAME);
      const email = self.extractProfileField(response.data, PROFILE_FIELDS.EMAIL);
      const picture = self.extractProfileField(response.data, PROFILE_FIELDS.PICTURE);
      const profile = { name, lastName, email, picture };
      self.setState({
        step3: {
          ...self.state.step3,
          profile
        }
      })
    })
      .catch(function (error) {
        const errorMessage = "Error retrieving user information" + error;
        window.alert(errorMessage);
      })

    this.setState({
      step3: {
        ...this.state.step3,
        started: true,
      }
    })
  }

  onPopupResponseFn = (e) => {
    const eventType = e.data && e.data.type;
    switch (eventType) {
      case 'authCode':
        if (e.data.state !== this.state.step1.state) {
          window.alert("Retrieved state [" + e.data.state + "] didn't match stored one! Try again");
          break;
        }
        const popupUpdate = {
          codeVerifier: this.state.step1.codeVerifier,
          provider: this.state.step1.provider
        }
        this.state.step2.popup.postMessage(popupUpdate, "*");
        this.setState({
          step2: {
            ...this.state.step2,
            authCode: e.data.authCode
          }
        });
        break;
      case 'accessToken':
        this.setState({
          step2: {
            ...this.state.step2,
            accessToken: e.data.accessToken
          }
        });
        break;
      case 'closed':
        this.setState({
          step2: {
            ...this.state.step2,
            popup: null
          }
        });
        break;
    }

  }

  render() {
    const { step1, step2, step3 } = { ...this.state };
    return (
      <div className="baeldung-container">
        <Step0 providers={Object.keys(PROVIDER_CONFIGS)} nextStepStarted={step1.started} nextStepFn={this.executeStep1CreateCodes} />
        {step1.started && <Step1 {...step1} nextStepStarted={step2.started} nextStepFn={this.executeStep2RequestCode} />}
        {step2.started && <Step2 {...step2} nextStepStarted={step3.started} nextStepFn={this.executeStep3RequestResource} />}
        {step3.started && <Step3 {...step3} />}
        <div ref={(ref) => { this.lastElement = ref; }}>
        </div>
      </div>
    )
  }
}

window.App = App;