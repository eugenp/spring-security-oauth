// Profile
const Profile = ({ user, scopes, scopeChangeFn, renewTokenFn }) => {
  const { name, lastName, email, picture } = user;
  return (
    <div className="profile">
      <h2>Profile</h2>
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
      <div className="scopes-container" >
        <div> Here we can modify the scopes that the application will ask when requesting the Access Token</div>
        <div className="scope-options-container">
          <div className="scope-option">
            <input key='create' type='checkbox' checked={scopes.create} onChange={scopeChangeFn.bind(this, 'create')} />
            Create Color Scope (colors:create)
            </div>
          <div className="scope-option">
            <input key='delete' id='deleteCb' type='checkbox' checked={scopes.delete} onChange={scopeChangeFn.bind(this, 'delete')} />
            Delete Color Scope (colors:delete)
            </div>
        </div>
        <div className="refresh-container">
          <button onClick={renewTokenFn}>Refresh Token and Scopes</button>
        </div>
      </div>
    </div>
  )
}

window.Profile = Profile;