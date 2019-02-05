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
    axios.get(CONFIGS.resourceServer.getColorsUrl).then(function (response) {
      self.setState({
        listing: response.data,
        loading: false
      })
    }).catch(function (error) {
      console.error(error);
      window.alert("Error retrieving Colors. Please make sure the resource server is accessible." + error);
    })
    this.setState({
      loading: true
    })
  }

  onDeleteFn = (id) => {
    var self = this;
    axios.delete(CONFIGS.resourceServer.deleteColorUrl.replace("{id}", id)).then(function () {
      self.refreshListing()
    }).catch(function (error) {
      console.error(error);
      window.alert("Error deleting Color. Please make sure the resource server is accessible and application has been granted permissions with the proper scopes." + error);
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
    axios.post(CONFIGS.resourceServer.saveColorUrl, this.state.currentColor, headers).then(function () {
      self.refreshListing()
    }).catch(function (error) {
      console.error(error);
      window.alert("Error creating Color. Please make sure the resource server is accessible and application has been granted permissions with the proper scopes." + error);
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
                  <ListingItem key={element.id} value={element.value} onDeleteFn={this.onDeleteFn} />
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