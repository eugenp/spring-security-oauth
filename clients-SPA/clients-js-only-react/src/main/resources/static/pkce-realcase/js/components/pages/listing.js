// Listing Page

class Listing extends React.Component {

  state = {
    listing: null,
    currentColor: '',
    loading: true
  }

  componentDidMount() {
    this.refreshListing();
  }

  refreshListing = () => {
    var self = this;
    axios.get(RESOURCE_CONFIGS.GET_COLORS_URL).then(function (response) {
      self.setState({
        listing: response.data,
        loading: false
      })
    }).catch(function (error) {
      console.error(error);
      const alertMessage = `Error retrieving colors. Please make sure:
        • the resource server is accessible\n

      ${error}`;
      window.alert(alertMessage);
    })
    this.setState({
      loading: true
    })
  }

  onDeleteFn = (id) => {
    const headers = this.props.auth
      ? {
        headers: {
          'Authorization': 'Bearer ' + this.props.auth.access_token
        }
      }
      : {};
    var self = this;
    axios.delete(RESOURCE_CONFIGS.DELETE_COLOR_URL.replace("{id}", id), headers).then(function () {
      self.refreshListing()
    }).catch(function (error) {
      console.error(error);
      const alertMessage = `Error deleting color. Please make sure:
        • the resource server is accessible
        • you're logged
        • you have the 'colors:delete' scope checked on the Profile page
        
      ${error}`;
      window.alert(alertMessage);
    })
  }

  onCreateFn = () => {
    var self = this;
    const headers = this.props.auth
      ? {
        headers: {
          'Authorization': 'Bearer ' + this.props.auth.access_token,
          'Content-type': 'text/plain; charset=UTF-8'
        }
      }
      : { headers: { 'Content-type': 'text/plain; charset=UTF-8' } };
    axios.post(RESOURCE_CONFIGS.SAVE_COLOR_URL, this.state.currentColor, headers).then(function () {
      self.refreshListing()
    }).catch(function (error) {
      console.error(error);
      const alertMessage = `Error creating color. Please make sure:
          • the resource server is accessible
          • you're logged
          • you have the 'colors:create' scope checked on the Profile page
          
        ${error}`;
      window.alert(alertMessage);
    })
  }

  handleChange = (e) => {
    this.setState({ currentColor: e.target.value });
  }

  render() {
    return (
      <div className="listing-container">
        {this.state.listing
          && <div>
            <div className="listing">
              {!this.state.loading
                ? this.state.listing.map((element) => (
                  <ListingItem key={element.id} value={element.value} onDeleteFn={this.onDeleteFn.bind(this, element.id)} />
                ))
                : <Spinner />
              }
            </div>
            <div className="create-color" disabled={this.state.loading}>
              <input type="text" value={this.state.currentColor} onChange={this.handleChange.bind(this)} />
              <button onClick={this.onCreateFn}>Create!</button>
            </div>
          </div>
        }
      </div>
    );
  }
}

window.Listing = Listing;