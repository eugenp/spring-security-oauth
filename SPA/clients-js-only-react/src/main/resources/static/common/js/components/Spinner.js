// Spiner indicating something is being processed
const Spinner = ({ spinnerText }) => (
  <div className="spinner-container">
    <p className="spinner-text">{spinnerText || 'Waiting...'}</p>
    <div className="spinner-icon"></div>
  </div>
)

window.Spinner = Spinner;