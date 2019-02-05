// Listing Item
const ListingItem = ({ id, value, onDeleteFn }) => (
  <div key={id} className="listing-item">
  <div style={{backgroundColor:value}} className="color-demo"></div>
    <div className="color-name">{value}</div>
    <div onClick={onDeleteFn.bind(this,id)} className="fas fa-trash-alt"></div>
  </div>
)

window.ListingItem = ListingItem;