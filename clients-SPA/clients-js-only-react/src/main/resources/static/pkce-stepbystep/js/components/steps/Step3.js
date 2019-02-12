// Step 3 - Secured User Information
const Step3 = ({ profile }) => {
  const { name, lastName, email, picture } = profile;
  return (
    <div className="step3 step-container">
      <h2>Step 3 - Retrieving Secured Resource</h2>
      <div className="user-info">
        <div className="name">
          {name ? name + ' ' : ''} {lastName || ''}
        </div>
        <div className="picture">
          <img src={picture || '/common/images/default-profile.png'} />
        </div>
        <div className="email">
          {email || ''}
        </div>
      </div>
    </div>
  )
};

window.Step3 = Step3;