'use strict';

const DEFAULT_PASSWORD_LENGTH = 32;
const ALL_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz123456789';
const MIN_GENERATED_LENGTH = 12;

function generatePassword(length, passwordFieldId, confirmFieldId) { // eslint-disable-line no-unused-vars

  // IDs of password field and confirm field
  const passwordField = document.getElementById(passwordFieldId);
  const confirmField = document.getElementById(confirmFieldId);
  const cryptoProvider = window.crypto || window.msCrypto;
  if (!passwordField || !confirmField) {
    return '';
  }
  if (!cryptoProvider || typeof cryptoProvider.getRandomValues !== 'function') {
    return '';
  }

  let requestedLength = Number.parseInt(length, 10);
  if (!Number.isFinite(requestedLength) || requestedLength < MIN_GENERATED_LENGTH) {
    requestedLength = DEFAULT_PASSWORD_LENGTH;
  }

  const generatedPasswordArray = [];

  while (generatedPasswordArray.length < requestedLength) {
    generatedPasswordArray.push(randomCharacter(ALL_CHARS));
  }
  const this_password = generatedPasswordArray.join('');

  passwordField.type = 'text';
  passwordField.value = this_password;

  confirmField.type = 'text';
  confirmField.value = this_password;

  // Copy to the clipboard
  const clipboard = window.navigator && window.navigator.clipboard;
  if (clipboard && typeof clipboard.writeText === 'function') {
    clipboard.writeText(this_password).catch(() => {});
  }

  passwordField.focus();
  passwordField.select();
  document.execCommand('copy');

  return this_password;
}


function randomCharacter(charset) {
  return charset[cryptoRandomInt(charset.length)];
}

function cryptoRandomInt(maxExclusive) {
  if (maxExclusive <= 0) {
    return 0;
  }

  const cryptoProvider = window.crypto || window.msCrypto;
  if (!cryptoProvider || typeof cryptoProvider.getRandomValues !== 'function') {
    throw new Error('Secure random generator unavailable');
  }

  const maxUint32 = 0x100000000;
  const cutoff = Math.floor(maxUint32 / maxExclusive) * maxExclusive;
  const randomValue = new Uint32Array(1);

  do {
    cryptoProvider.getRandomValues(randomValue);
  } while (randomValue[0] >= cutoff);

  return randomValue[0] % maxExclusive;
}
