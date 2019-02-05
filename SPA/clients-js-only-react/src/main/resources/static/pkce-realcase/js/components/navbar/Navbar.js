// Navbar Section

class Navbar extends React.Component {

  state = {
    logoutVisible: false
  }

  toggleLogout = () => {
    this.setState({
      logoutVisible: !this.state.logoutVisible
    })
  }

  render() {
    const { user, auth } = this.props;
    const { name, lastName, picture } = user || {};
    return (<nav>
      <div className="menu">
        <ul>
          <il onClick={this.props.changeView.bind(this, 'listing')}>Listing</il>
          {user && <il onClick={this.props.changeView.bind(this, 'profile')}>Profile</il>}
        </ul>
      </div>
      <div className="login-container">
        {auth
          ? <div onClick={this.toggleLogout}>
            <div className="user-info">
              <div className="picture">
                <img src={picture || '/common/images/default-profile.png'} />
              </div>
              <div className="greeting">Welcome {name ? name + ' ' : ''} {lastName || ''}!</div>
            </div>
            {this.state.logoutVisible && <div className="logout">
              <button onClick={this.props.onLogoutFn}>Logout</button>
            </div>}
          </div>
          : <div className="login"><button onClick={this.props.onLoginFn}>Login</button></div>}
      </div>
    </nav>)
  };
}

window.Navbar = Navbar;