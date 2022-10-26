import ERRORS from "./constants/errors.js";
import PAGE_PATHS from "./constants/pagePaths.js";
import validate from './validate.mjs';

const API_URL = 'http://localhost:5000';

async function api(endpoint, options = { method: 'GET' }) {
  const { body, method } = options;

  try {
    let stringified;

    if (body) {
      stringified = JSON.stringify(body);
    }

    const request = await fetch(`${API_URL}${endpoint}`, { method, body: stringified });

    if (request.ok) {
      return;
    }
  } catch {
    // window.location.pathname = '/500'
  }
}

function onFormEncryptingSubmit(event) {
  event.preventDefault();

  const plaintext = document.querySelector('input.main__form__plaintext').value;

  const err = validate.aes.plaintext(plaintext);

  switch (err) {
    case ERRORS.AES.PLAINTEXT.IS_EMPTY:
      alert('Digite uma frase para ser criptografada.')
      return;
    case ERRORS.AES.PLAINTEXT.INVALID_CHARACTERS:
      alert('Digite uma frase que não contenha caracteres especíais ou números.')
      return;
    default:
      break;
  }

  const body = {
    plaintext
  };

  return api('/encryption-result', { body, method: 'POST' })
}

function main() {
  if (window.location.pathname === PAGE_PATHS.HOME) {
    const form = document.querySelector('form');

    form.addEventListener('submit', onFormEncryptingSubmit);

    // TODO attach form
    // TODO get values from input
    // TODO validate values of inputs
    // TODO show error messages, if necessary
    // TODO dynamic import helpers
    // TODO send to /encryption-results/{cryptograph} by body { plaintext: <string>, key: <string> }
    // TODO request new page
    return;
  }

  if (window.location.href === PAGE_PATHS.RESULT) {
    return;
  }
}

main();
