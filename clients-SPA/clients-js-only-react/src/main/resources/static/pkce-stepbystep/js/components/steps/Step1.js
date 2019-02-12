// Step 1 - Create Codes
const Step1 = ({ codeVerifier, codeChallenge, state, nextStepFn, nextStepStarted }) => (
  <div className="step1 step-container">
    <h2>Step 1 - Create the codes</h2>
    <div className="summary">The client must generate the tipical 'state' value to compare later and avoid CSRF:</div>
    <div className="result"><span>{state}</span></div>
    <div className="summary">We also generate a "Code Verifier" per request:</div>
    <div className="result"><span>{codeVerifier}</span></div>
    <div className="summary">Additionally, it should transform the previous code using a S256 transfromation method. This is called the "Code Challenge":</div>
    <div className="result"><span>{codeChallenge}</span></div>
    <div className="action">
      <button onClick={nextStepFn} disabled={nextStepStarted}>Request Auth Code!</button>
    </div>
  </div>
)

window.Step1 = Step1;