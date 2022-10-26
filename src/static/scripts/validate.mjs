import ENCRYPTIONS_ERRORS from "./constants/errors.js";
import { hasOnlyLetters, isAESKeyLengthValid } from "./utils/string.js";

const { AES: ERRORS } = ENCRYPTIONS_ERRORS;

function validatePlaintextForAESCryptography(plaintext) {
  if (!plaintext) {
    return ERRORS.PLAINTEXT.IS_EMPTY;
  }

  if (!hasOnlyLetters(plaintext)) {
    return ERRORS.PLAINTEXT.INVALID_CHARACTERS;
  }
}

function validateKeyForAESCryptography(key) {
  if (!key) {
    return ERRORS.KEY.IS_EMPTY;
  }

  if (!isAESKeyLengthValid(key)) {
    return ERRORS.KEY.INVALID_LENGTH;
  }

  if (!hasOnlyLetters(key)) {
    return ERRORS.KEY.INVALID_CHARACTERS;
  }
}

export default Object.freeze({
  aes: {
    plaintext: validatePlaintextForAESCryptography,
    key: validateKeyForAESCryptography,
  },
});
