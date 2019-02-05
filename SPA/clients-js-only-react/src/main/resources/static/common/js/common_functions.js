function base64_urlencode(str) {
  return btoa(str)
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '');
}

function generate_state() {
  return random_string(48);
}

function random_string(len) {
  var arr = new Uint8Array(len);
  window.crypto.getRandomValues(arr);
  var str = base64_urlencode(dec2bin(arr));
  return str.substring(0, len);
}

function dec2hex(dec) {
  return ('0' + dec.toString(16)).substr(-2)
}

function dec2bin(arr) {
  return hex2bin(Array.from(arr, dec2hex).join(''));
}

function getParameterByName(name, url) {
  if (!url) url = window.location.href;
  name = name.replace(/[\[\]]/g, '\\$&');
  var regex = new RegExp('[?&]' + name + '(=([^&#]*)|&|#|$)'),
      results = regex.exec(url);
  if (!results) return null;
  if (!results[2]) return '';
  return decodeURIComponent(results[2].replace(/\+/g, ' '));
}