// Profile
const Profile = ({ user }) => {
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
    </div>
  )
}

window.Profile = Profile;