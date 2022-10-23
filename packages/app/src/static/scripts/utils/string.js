const hasNumbers = (str) => /[0-9]/.test(str);

const hasSymbols = (str) => /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(str);

export const isAESKeyLengthValid = (key) => key.length === 16;

export function hasOnlyLetters(str) {
  if (hasNumbers(str)) {
    return false;
  }

  if (hasSymbols(str)) {
    return false;
  }

  return true;
}
