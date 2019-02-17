// Step 0 - Initiate Process
const Step0 = ({ providers, nextStepFn, nextStepStarted }) => (
  <div className="step0 step-container">
    <h2>JS OAuth Client using PKCE - Step By Step</h2>
    <div className="summary">Click to start the authentication process, step by step.</div>
    <div className="note">Note: Most providers don't support PKCE for SPA yet,
      resulting in an error retrieving when retrieving the Token (CORS not enabled for that endpoint).
      <br />
      At the moment of creating the tutorial, only Auth0 works properly</div>
    <div className="action">
      {providers.map((provider) =>
        (<button key={provider} onClick={nextStepFn.bind(this, provider)} disabled={nextStepStarted}>Use {provider}</button>))
      }
    </div>
  </div>
)

window.Step0 = Step0;