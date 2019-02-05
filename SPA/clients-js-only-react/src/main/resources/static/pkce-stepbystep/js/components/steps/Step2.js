// Step 2 - Login & obteain access token
const Step2 = ({ accessToken, authCode, popup, nextStepFn, nextStepStarted }) => {

  return (<div className="step2 step-container">
    <h2>Step 2 - Login</h2>
    {authCode
      && (<div>
        <div className="summary">Provider retrieved authorization code:</div>
        <div className="result large"><span>{authCode}</span></div>
      </div>)
    }
    {accessToken
      && (<div>
        <div className="summary">Used 'Code Verifier' to obtain the Access Token!</div>
        <div className="result large"><span>{accessToken}</span></div>
      </div>)
    }
    {!!popup
      ? <Spinner spinnerText='Waiting for Login process...' />
      : (<div className="action">
        <button onClick={nextStepFn} disabled={nextStepStarted}>Retrieve Secured User Information!</button>
      </div>)
    }
  </div>
  )
};

window.Step2 = Step2;