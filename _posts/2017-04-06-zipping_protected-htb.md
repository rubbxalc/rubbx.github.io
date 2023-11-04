---
layout: post
title: Zipping - PROTECTED
date: 2023-08-26
description:
img:
fig-caption:
tags: []
---
___

<html class="staticrypt-html">
    <head>
        <meta charset="utf-8" />
        <title>Writeup Protegido</title>
        <meta name="viewport" content="width=device-width, initial-scale=1" />

        <!-- do not cache this page -->
        <meta http-equiv="cache-control" content="max-age=0" />
        <meta http-equiv="cache-control" content="no-cache" />
        <meta http-equiv="expires" content="0" />
        <meta http-equiv="expires" content="Tue, 01 Jan 1980 1:00:00 GMT" />
        <meta http-equiv="pragma" content="no-cache" />

        <style>
            .staticrypt-hr {
                margin-top: 20px;
                margin-bottom: 20px;
                border: 0;
                border-top: 1px solid #eee;
            }

            .staticrypt-page {
                width: 360px;
                padding: 8% 0 0;
                margin: auto;
                box-sizing: border-box;
            }

            .staticrypt-form {
                position: relative;
                z-index: 1;
                background: #ffffff;
                max-width: 360px;
                margin: 0 auto 100px;
                padding: 45px;
                text-align: center;
                box-shadow: 0 0 20px 0 rgba(0, 0, 0, 0.2), 0 5px 5px 0 rgba(0, 0, 0, 0.24);
            }

            .staticrypt-form input[type="password"] {
                outline: 0;
                background: #f2f2f2;
                width: 100%;
                border: 0;
                margin: 0 0 15px;
                padding: 15px;
                box-sizing: border-box;
                font-size: 14px;
            }

            .staticrypt-form .staticrypt-decrypt-button {
                text-transform: uppercase;
                outline: 0;
                background: #4CAF50;
                width: 100%;
                border: 0;
                padding: 15px;
                color: #ffffff;
                font-size: 14px;
                cursor: pointer;
            }

            .staticrypt-form .staticrypt-decrypt-button:hover,
            .staticrypt-form .staticrypt-decrypt-button:active,
            .staticrypt-form .staticrypt-decrypt-button:focus {
                background: #4CAF50;
                filter: brightness(92%);
            }

            .staticrypt-html {
                height: 100%;
            }

            .staticrypt-body {
                height: 100%;
                margin: 0;
            }

            .staticrypt-content {
                height: 100%;
                margin-bottom: 1em;
                font-family: "Arial", sans-serif;
                -webkit-font-smoothing: antialiased;
                -moz-osx-font-smoothing: grayscale;
            }

            .staticrypt-instructions {
                margin-top: -1em;
                margin-bottom: 1em;
            }

            .staticrypt-title {
                font-size: 1.5em;
            }

            label.staticrypt-remember {
                display: flex;
                align-items: center;
                margin-bottom: 1em;
            }

            .staticrypt-remember input[type="checkbox"] {
                transform: scale(1.5);
                margin-right: 1em;
            }

            .hidden {
                display: none !important;
            }

            .staticrypt-spinner-container {
                height: 100%;
                display: flex;
                align-items: center;
                justify-content: center;
            }

            .staticrypt-spinner {
                display: inline-block;
                width: 2rem;
                height: 2rem;
                vertical-align: text-bottom;
                border: 0.25em solid gray;
                border-right-color: transparent;
                border-radius: 50%;
                -webkit-animation: spinner-border 0.75s linear infinite;
                animation: spinner-border 0.75s linear infinite;
                animation-duration: 0.75s;
                animation-timing-function: linear;
                animation-delay: 0s;
                animation-iteration-count: infinite;
                animation-direction: normal;
                animation-fill-mode: none;
                animation-play-state: running;
                animation-name: spinner-border;
            }

            @keyframes spinner-border {
                100% {
                    transform: rotate(360deg);
                }
            }
        </style>
    </head>

    <body class="staticrypt-body">
        <div id="staticrypt_loading" class="staticrypt-spinner-container">
            <div class="staticrypt-spinner"></div>
        </div>

        <div id="staticrypt_content" class="staticrypt-content hidden">
            <div class="staticrypt-page">
                <div class="staticrypt-form">
                    <div class="staticrypt-instructions">
                        <p class="staticrypt-title">Writeup Protegido</p>
                        <p></p>
                    </div>

                    <hr class="staticrypt-hr" />

                    <form id="staticrypt-form" action="#" method="post">
                        <input
                            id="staticrypt-password"
                            type="password"
                            name="password"
                            placeholder="Password"
                            autofocus
                        />

                        <label id="staticrypt-remember-label" class="staticrypt-remember hidden">
                            <input id="staticrypt-remember" type="checkbox" name="remember" />
                            Guardar en caché
                        </label>

                        <input type="submit" class="staticrypt-decrypt-button" value="ENTRAR" />
                    </form>
                </div>
            </div>
        </div>

        <script>
            // these variables will be filled when generating the file - the template format is 'variable_name'
            const staticryptInitiator = ((function(){
  const exports = {};
  const cryptoEngine = ((function(){
  const exports = {};
  const { subtle } = crypto;

const IV_BITS = 16 * 8;
const HEX_BITS = 4;
const ENCRYPTION_ALGO = "AES-CBC";

/**
 * Translates between utf8 encoded hexadecimal strings
 * and Uint8Array bytes.
 */
const HexEncoder = {
    /**
     * hex string -> bytes
     * @param {string} hexString
     * @returns {Uint8Array}
     */
    parse: function (hexString) {
        if (hexString.length % 2 !== 0) throw "Invalid hexString";
        const arrayBuffer = new Uint8Array(hexString.length / 2);

        for (let i = 0; i < hexString.length; i += 2) {
            const byteValue = parseInt(hexString.substring(i, i + 2), 16);
            if (isNaN(byteValue)) {
                throw "Invalid hexString";
            }
            arrayBuffer[i / 2] = byteValue;
        }
        return arrayBuffer;
    },

    /**
     * bytes -> hex string
     * @param {Uint8Array} bytes
     * @returns {string}
     */
    stringify: function (bytes) {
        const hexBytes = [];

        for (let i = 0; i < bytes.length; ++i) {
            let byteString = bytes[i].toString(16);
            if (byteString.length < 2) {
                byteString = "0" + byteString;
            }
            hexBytes.push(byteString);
        }
        return hexBytes.join("");
    },
};

/**
 * Translates between utf8 strings and Uint8Array bytes.
 */
const UTF8Encoder = {
    parse: function (str) {
        return new TextEncoder().encode(str);
    },

    stringify: function (bytes) {
        return new TextDecoder().decode(bytes);
    },
};

/**
 * Salt and encrypt a msg with a password.
 */
async function encrypt(msg, hashedPassword) {
    // Must be 16 bytes, unpredictable, and preferably cryptographically random. However, it need not be secret.
    // https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/encrypt#parameters
    const iv = crypto.getRandomValues(new Uint8Array(IV_BITS / 8));

    const key = await subtle.importKey("raw", HexEncoder.parse(hashedPassword), ENCRYPTION_ALGO, false, ["encrypt"]);

    const encrypted = await subtle.encrypt(
        {
            name: ENCRYPTION_ALGO,
            iv: iv,
        },
        key,
        UTF8Encoder.parse(msg)
    );

    // iv will be 32 hex characters, we prepend it to the ciphertext for use in decryption
    return HexEncoder.stringify(iv) + HexEncoder.stringify(new Uint8Array(encrypted));
}
exports.encrypt = encrypt;

/**
 * Decrypt a salted msg using a password.
 *
 * @param {string} encryptedMsg
 * @param {string} hashedPassword
 * @returns {Promise<string>}
 */
async function decrypt(encryptedMsg, hashedPassword) {
    const ivLength = IV_BITS / HEX_BITS;
    const iv = HexEncoder.parse(encryptedMsg.substring(0, ivLength));
    const encrypted = encryptedMsg.substring(ivLength);

    const key = await subtle.importKey("raw", HexEncoder.parse(hashedPassword), ENCRYPTION_ALGO, false, ["decrypt"]);

    const outBuffer = await subtle.decrypt(
        {
            name: ENCRYPTION_ALGO,
            iv: iv,
        },
        key,
        HexEncoder.parse(encrypted)
    );

    return UTF8Encoder.stringify(new Uint8Array(outBuffer));
}
exports.decrypt = decrypt;

/**
 * Salt and hash the password so it can be stored in localStorage without opening a password reuse vulnerability.
 *
 * @param {string} password
 * @param {string} salt
 * @returns {Promise<string>}
 */
async function hashPassword(password, salt) {
    // we hash the password in multiple steps, each adding more iterations. This is because we used to allow less
    // iterations, so for backward compatibility reasons, we need to support going from that to more iterations.
    let hashedPassword = await hashLegacyRound(password, salt);

    hashedPassword = await hashSecondRound(hashedPassword, salt);

    return hashThirdRound(hashedPassword, salt);
}
exports.hashPassword = hashPassword;

/**
 * This hashes the password with 1k iterations. This is a low number, we need this function to support backwards
 * compatibility.
 *
 * @param {string} password
 * @param {string} salt
 * @returns {Promise<string>}
 */
function hashLegacyRound(password, salt) {
    return pbkdf2(password, salt, 1000, "SHA-1");
}
exports.hashLegacyRound = hashLegacyRound;

/**
 * Add a second round of iterations. This is because we used to use 1k, so for backwards compatibility with
 * remember-me/autodecrypt links, we need to support going from that to more iterations.
 *
 * @param hashedPassword
 * @param salt
 * @returns {Promise<string>}
 */
function hashSecondRound(hashedPassword, salt) {
    return pbkdf2(hashedPassword, salt, 14000, "SHA-256");
}
exports.hashSecondRound = hashSecondRound;

/**
 * Add a third round of iterations to bring total number to 600k. This is because we used to use 1k, then 15k, so for
 * backwards compatibility with remember-me/autodecrypt links, we need to support going from that to more iterations.
 *
 * @param hashedPassword
 * @param salt
 * @returns {Promise<string>}
 */
function hashThirdRound(hashedPassword, salt) {
    return pbkdf2(hashedPassword, salt, 585000, "SHA-256");
}
exports.hashThirdRound = hashThirdRound;

/**
 * Salt and hash the password so it can be stored in localStorage without opening a password reuse vulnerability.
 *
 * @param {string} password
 * @param {string} salt
 * @param {int} iterations
 * @param {string} hashAlgorithm
 * @returns {Promise<string>}
 */
async function pbkdf2(password, salt, iterations, hashAlgorithm) {
    const key = await subtle.importKey("raw", UTF8Encoder.parse(password), "PBKDF2", false, ["deriveBits"]);

    const keyBytes = await subtle.deriveBits(
        {
            name: "PBKDF2",
            hash: hashAlgorithm,
            iterations,
            salt: UTF8Encoder.parse(salt),
        },
        key,
        256
    );

    return HexEncoder.stringify(new Uint8Array(keyBytes));
}

function generateRandomSalt() {
    const bytes = crypto.getRandomValues(new Uint8Array(128 / 8));

    return HexEncoder.stringify(new Uint8Array(bytes));
}
exports.generateRandomSalt = generateRandomSalt;

async function signMessage(hashedPassword, message) {
    const key = await subtle.importKey(
        "raw",
        HexEncoder.parse(hashedPassword),
        {
            name: "HMAC",
            hash: "SHA-256",
        },
        false,
        ["sign"]
    );
    const signature = await subtle.sign("HMAC", key, UTF8Encoder.parse(message));

    return HexEncoder.stringify(new Uint8Array(signature));
}
exports.signMessage = signMessage;

function getRandomAlphanum() {
    const possibleCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    let byteArray;
    let parsedInt;

    // Keep generating new random bytes until we get a value that falls
    // within a range that can be evenly divided by possibleCharacters.length
    do {
        byteArray = crypto.getRandomValues(new Uint8Array(1));
        // extract the lowest byte to get an int from 0 to 255 (probably unnecessary, since we're only generating 1 byte)
        parsedInt = byteArray[0] & 0xff;
    } while (parsedInt >= 256 - (256 % possibleCharacters.length));

    // Take the modulo of the parsed integer to get a random number between 0 and totalLength - 1
    const randomIndex = parsedInt % possibleCharacters.length;

    return possibleCharacters[randomIndex];
}

/**
 * Generate a random string of a given length.
 *
 * @param {int} length
 * @returns {string}
 */
function generateRandomString(length) {
    let randomString = "";

    for (let i = 0; i < length; i++) {
        randomString += getRandomAlphanum();
    }

    return randomString;
}
exports.generateRandomString = generateRandomString;

  return exports;
})());
const codec = ((function(){
  const exports = {};
  /**
 * Initialize the codec with the provided cryptoEngine - this return functions to encode and decode messages.
 *
 * @param cryptoEngine - the engine to use for encryption / decryption
 */
function init(cryptoEngine) {
    const exports = {};

    /**
     * Top-level function for encoding a message.
     * Includes password hashing, encryption, and signing.
     *
     * @param {string} msg
     * @param {string} password
     * @param {string} salt
     *
     * @returns {string} The encoded text
     */
    async function encode(msg, password, salt) {
        const hashedPassword = await cryptoEngine.hashPassword(password, salt);

        const encrypted = await cryptoEngine.encrypt(msg, hashedPassword);

        // we use the hashed password in the HMAC because this is effectively what will be used a password (so we can store
        // it in localStorage safely, we don't use the clear text password)
        const hmac = await cryptoEngine.signMessage(hashedPassword, encrypted);

        return hmac + encrypted;
    }
    exports.encode = encode;

    /**
     * Encode using a password that has already been hashed. This is useful to encode multiple messages in a row, that way
     * we don't need to hash the password multiple times.
     *
     * @param {string} msg
     * @param {string} hashedPassword
     *
     * @returns {string} The encoded text
     */
    async function encodeWithHashedPassword(msg, hashedPassword) {
        const encrypted = await cryptoEngine.encrypt(msg, hashedPassword);

        // we use the hashed password in the HMAC because this is effectively what will be used a password (so we can store
        // it in localStorage safely, we don't use the clear text password)
        const hmac = await cryptoEngine.signMessage(hashedPassword, encrypted);

        return hmac + encrypted;
    }
    exports.encodeWithHashedPassword = encodeWithHashedPassword;

    /**
     * Top-level function for decoding a message.
     * Includes signature check and decryption.
     *
     * @param {string} signedMsg
     * @param {string} hashedPassword
     * @param {string} salt
     * @param {int} backwardCompatibleAttempt
     * @param {string} originalPassword
     *
     * @returns {Object} {success: true, decoded: string} | {success: false, message: string}
     */
    async function decode(signedMsg, hashedPassword, salt, backwardCompatibleAttempt = 0, originalPassword = "") {
        const encryptedHMAC = signedMsg.substring(0, 64);
        const encryptedMsg = signedMsg.substring(64);
        const decryptedHMAC = await cryptoEngine.signMessage(hashedPassword, encryptedMsg);

        if (decryptedHMAC !== encryptedHMAC) {
            // we have been raising the number of iterations in the hashing algorithm multiple times, so to support the old
            // remember-me/autodecrypt links we need to try bringing the old hashes up to speed.
            originalPassword = originalPassword || hashedPassword;
            if (backwardCompatibleAttempt === 0) {
                const updatedHashedPassword = await cryptoEngine.hashThirdRound(originalPassword, salt);

                return decode(signedMsg, updatedHashedPassword, salt, backwardCompatibleAttempt + 1, originalPassword);
            }
            if (backwardCompatibleAttempt === 1) {
                let updatedHashedPassword = await cryptoEngine.hashSecondRound(originalPassword, salt);
                updatedHashedPassword = await cryptoEngine.hashThirdRound(updatedHashedPassword, salt);

                return decode(signedMsg, updatedHashedPassword, salt, backwardCompatibleAttempt + 1, originalPassword);
            }

            return { success: false, message: "Signature mismatch" };
        }

        return {
            success: true,
            decoded: await cryptoEngine.decrypt(encryptedMsg, hashedPassword),
        };
    }
    exports.decode = decode;

    return exports;
}
exports.init = init;

  return exports;
})());
const decode = codec.init(cryptoEngine).decode;

function init(staticryptConfig, templateConfig) {
    const exports = {};

    async function decryptAndReplaceHtml(hashedPassword) {
        const { staticryptEncryptedMsgUniqueVariableName, staticryptSaltUniqueVariableName } = staticryptConfig;
        const { replaceHtmlCallback } = templateConfig;

        const result = await decode(
            staticryptEncryptedMsgUniqueVariableName,
            hashedPassword,
            staticryptSaltUniqueVariableName
        );
        if (!result.success) {
            return false;
        }
        const plainHTML = result.decoded;

        // if the user configured a callback call it, otherwise just replace the whole HTML
        if (typeof replaceHtmlCallback === "function") {
            replaceHtmlCallback(plainHTML);
        } else {
            document.write(plainHTML);
            document.close();
        }

        return true;
    }

    /**
     * Attempt to decrypt the page and replace the whole HTML.
     *
     * @param {string} password
     * @param {boolean} isRememberChecked
     *
     * @returns {Promise<{isSuccessful: boolean, hashedPassword?: string}>} - we return an object, so that if we want to
     *   expose more information in the future we can do it without breaking the password_template
     */
    async function handleDecryptionOfPage(password, isRememberChecked) {
        const { isRememberEnabled, rememberDurationInDays, staticryptSaltUniqueVariableName } = staticryptConfig;
        const { rememberExpirationKey, rememberPassphraseKey } = templateConfig;

        // decrypt and replace the whole page
        const hashedPassword = await cryptoEngine.hashPassword(password, staticryptSaltUniqueVariableName);

        const isDecryptionSuccessful = await decryptAndReplaceHtml(hashedPassword);

        if (!isDecryptionSuccessful) {
            return {
                isSuccessful: false,
                hashedPassword,
            };
        }

        // remember the hashedPassword and set its expiration if necessary
        if (isRememberEnabled && isRememberChecked) {
            window.localStorage.setItem(rememberPassphraseKey, hashedPassword);

            // set the expiration if the duration isn't 0 (meaning no expiration)
            if (rememberDurationInDays > 0) {
                window.localStorage.setItem(
                    rememberExpirationKey,
                    (new Date().getTime() + rememberDurationInDays * 24 * 60 * 60 * 1000).toString()
                );
            }
        }

        return {
            isSuccessful: true,
            hashedPassword,
        };
    }
    exports.handleDecryptionOfPage = handleDecryptionOfPage;

    /**
     * Clear localstorage from staticrypt related values
     */
    function clearLocalStorage() {
        const { clearLocalStorageCallback, rememberExpirationKey, rememberPassphraseKey } = templateConfig;

        if (typeof clearLocalStorageCallback === "function") {
            clearLocalStorageCallback();
        } else {
            localStorage.removeItem(rememberPassphraseKey);
            localStorage.removeItem(rememberExpirationKey);
        }
    }

    async function handleDecryptOnLoad() {
        let isSuccessful = await decryptOnLoadFromUrl();

        if (!isSuccessful) {
            isSuccessful = await decryptOnLoadFromRememberMe();
        }

        return { isSuccessful };
    }
    exports.handleDecryptOnLoad = handleDecryptOnLoad;

    /**
     * Clear storage if we are logging out
     *
     * @returns {boolean} - whether we logged out
     */
    function logoutIfNeeded() {
        const logoutKey = "staticrypt_logout";

        // handle logout through query param
        const queryParams = new URLSearchParams(window.location.search);
        if (queryParams.has(logoutKey)) {
            clearLocalStorage();
            return true;
        }

        // handle logout through URL fragment
        const hash = window.location.hash.substring(1);
        if (hash.includes(logoutKey)) {
            clearLocalStorage();
            return true;
        }

        return false;
    }

    /**
     * To be called on load: check if we want to try to decrypt and replace the HTML with the decrypted content, and
     * try to do it if needed.
     *
     * @returns {Promise<boolean>} true if we derypted and replaced the whole page, false otherwise
     */
    async function decryptOnLoadFromRememberMe() {
        const { rememberDurationInDays } = staticryptConfig;
        const { rememberExpirationKey, rememberPassphraseKey } = templateConfig;

        // if we are login out, terminate
        if (logoutIfNeeded()) {
            return false;
        }

        // if there is expiration configured, check if we're not beyond the expiration
        if (rememberDurationInDays && rememberDurationInDays > 0) {
            const expiration = localStorage.getItem(rememberExpirationKey),
                isExpired = expiration && new Date().getTime() > parseInt(expiration);

            if (isExpired) {
                clearLocalStorage();
                return false;
            }
        }

        const hashedPassword = localStorage.getItem(rememberPassphraseKey);

        if (hashedPassword) {
            // try to decrypt
            const isDecryptionSuccessful = await decryptAndReplaceHtml(hashedPassword);

            // if the decryption is unsuccessful the password might be wrong - silently clear the saved data and let
            // the user fill the password form again
            if (!isDecryptionSuccessful) {
                clearLocalStorage();
                return false;
            }

            return true;
        }

        return false;
    }

    function decryptOnLoadFromUrl() {
        const passwordKey = "staticrypt_pwd";

        // get the password from the query param
        const queryParams = new URLSearchParams(window.location.search);
        const hashedPasswordQuery = queryParams.get(passwordKey);

        // get the password from the url fragment
        const hashRegexMatch = window.location.hash.substring(1).match(new RegExp(passwordKey + "=(.*)"));
        const hashedPasswordFragment = hashRegexMatch ? hashRegexMatch[1] : null;

        const hashedPassword = hashedPasswordFragment || hashedPasswordQuery;

        if (hashedPassword) {
            return decryptAndReplaceHtml(hashedPassword);
        }

        return false;
    }

    return exports;
}
exports.init = init;

  return exports;
})());
            const templateError = "Contraseña erronea",
                isRememberEnabled = true,
                staticryptConfig = {"staticryptEncryptedMsgUniqueVariableName":"6a380afbd61f09c8e59288391c0f454b2ba1a26f9224822cc1ba68ec5ee4d68ccde274cdacdbc735f8d161b20adfdc821998da2ea7e10eb0a1bae7528a41b415ae01c01a8c76e4d99562b390244fa5ad3231d75f3527b1c918a832fcd98a5d59c24cd11dc60798a66d38284d100d46c0951a64778534af8912e38b9721c4dbc3df522e8b56c5d822047f238ba7f24c664795ae57f7e2f5cf191eef97b08ff1842df5a5d97e8a0b049dc0c7ee8fc5d8f5a2c79d68061e3087c22d5c81649f172aed76911a9810deac9f63a6f82f8f4213bcc2f79c518f4256b1685d83e2f8f08eb252e0695aa8a28f5946a424f907253b076e0bb1ee6c8a602599f79660b58052b17efbfced7122c433d519a1dd338b693dd9f92d5ea5bc01fa6b175f9c9581d6bcd8d076ac7aa74fe9d48975f7a2f7340559c9a0f1244f69aa3be272c4fbf8ba050397b11c9598ad40fb2fbee0ab92b0d1cb3374cea76a4b3962f769bd050da326069dff955b852a318316dc4fdbae33beab43ac2592a95c30bc5e9856731c35568e73a686702604bb061f62f9daf8e32e1f50cd89c1752ea64f506cf268670f2d9863b90d115590c1d0161485643d7b5cfc7ff5e12e3720f9fb1b571068dd537dd075d387381082db6c830cdbc83ad6a7280f1494790c4be7761ab4f667cd848c616698b5beba26b86c07e9804ae83af20a75a27fb01ae967b737d57fb5646d4b4075e330edd06b0ec8b5ca565cc25727397395f402727d5b81f9fd119d069cc4d88f79ff69d089826066d9be37b1835671b779f47f09f3fdb6c5a4a7362d80638eea592e75092982de9540bb1673e32555cfdb692e594514202e6176e82aeb4be1e0911c4b4b3c943a278e0ebc355263c62ed482e8587ebc257d1113e6d1e5c0c5be2f2f551a0336a5f98c9e41bb4eb3c5321454aa6fa93989bf5cbd3b4c2a8738c76bebe44ed2f72dfd3d3999a1ea6e39c1ced10eaf4f0cd37e314788f70e3e5e2439cbdc2009b51bbf1090390a59001bee20cda549a6339136a36d6def09e04fab15f2a359ece812a8713ae4fb348e1f84bbf12c0d8034e6fd8dc5eb9f4890beeae410efc64ad25f1c5a41dcc4bb5ace14e51821682f8ace985b6ce97c514669fe5bc1badc752d2e4f200e6de9e92f417c4a8cc83c2f2159678650c98655119c66751f53623831e1b036ecf6c6efaab7d3b0cde13d71e15a64a615e7ee2f9ef79df0dced4e81476d4af158b32ad47b8baa544fd146cce64107a3375249b1198beeb2260e5c396a974f989d34e581bedb131b73812d63424def3cb8de28a4758451aeb4cd7bef3dcfbeb794d3d6c9da4e7978cf6038b04949cfe758029f768b06943eed3b3d40fbb5ffe2a24f57a0f19799b1352c62f83a2324ae605e43379c4704c84e4a9b4c983b24b016f68eb4aeffc7f714e09fd9ebde447f01f44ade3c39d3e0556d7652003aac047d46fae73f5f426ab1255456b8baf3c881a475938f703ad1e41d5339198c1d95cf89fca39aad946b0b9fb81da4cfd54e5442e76ffbff86a22439249e41059f150a6c6c9d4e0ee212ba0bdbd05f4728a8b1ad9abd38f8c6da1340a5605c83773417f0a42a7c8c6fd068f4a243676eca226105cf3b01fb86488646e84fd4db9c68d1e5b58c64cfbf1928645d9b3aeaf58bd4f88bff05a27d909cda0b4365307f81a87f4e9d6580cba1b4b209b8eeb0bf8c564d4293fe173bd8cf52aa8013325d5374f066a11dca18f64721657b42a2f7fc744ae926138b7e75e85d1f71bdcc965e417f9e706e5df578f460990ff4282a3c32707c8e50fc2ac46c786aacbec3dc026a520ebc408050af2f30aedef3e1d015fc513dcbbfacee5c07e6c4c6ba4e553668f6ae0539384c707fa0b69c5b3efb1fb670ee8f540f7a4af136c2e4ddd7e03aba4bf1ed618c042c46cc6c9a29b6c80871340c21578b566f0f9428aea6e4b5bb9c59132c959fd0e14b64184669877ecb3495e2e06eb206642707f1439054be5be07b75d06331ab04b0c9de7ff7afaf8e727bdc02f1e9a7f3aa89bbd23dd9abf610e6c05ad93b18264a94bd0e6b4c5b0bc94cfba7e2553cfebdbff6d88380227fbedfdc3c3de750ffaac4ced3cea3a15cf65a0fa6a3e78546bc959d124950f512f07aac5e5bc7ca32f90b77c5c6674f4892a0eb710d8c8caa5ad8f2e4d6c979b2373330c2362fd9901e92b0a1181fb1f7a309522a052f600b099e2ee90ccff2cb5f402967f6bec631d81b7b95edf5fa5a4ee812c08b580ad8e84d2e16b407cf0830aa98bb8bb4c1419560984e3ce590751667f71a570bd86624d768dd9513ae045d3d9286a34fa6ba7fea7d7e94385a51b6df6770101d9f0f1d3c9c170bf2ca659f9d12df7cc2fdab08fbb42257efc19cd9b7097eaa3f5dc2a457b5cc435fec67592d652de426dbb54db8d0b5264a9250478daeb550da99427d22cdf39898fe8c139858ff3abc3d4b7a91338cbe429c5eaee2e4ba561d0655389c38d78b4acabc94c8f5600b2305043592af3dd87f07ee7878d7e0fb79fbdfe0f9131ad456fae30289192aa7d4089b74d66624f810c8cc9a64484e223871b5926fd001275fd986b926aa4c276c69cdfcbb819d508d4431ad47d60cf80e87bab0640883b6a69c38dd0108f9b507aa528751c9a11ff42ef1bed4ea96d8ab6a14d1288f7af9ed3427341ae266bea36a13cf5319b7330712b36b245a90d7238ef9dabb1da43e4317886941d58f35c2ea637810f18a7ed47f0db32a63798fcc88357c389de8559a9e96778438f26dfe1c5a3bb67d8c9f2679fdfd786465e23eb36f1b3ee6610a224a62a5d8424b5d7b4be2eed8bf82c8eb542d8ea648a0cfc78fa0f13160c9375836b0571e32c2942ad7d8e14bdcfb5df4bce26770ae509f3c7d03e322b91b5ec5bb77e5ae344454c15ef32d49121cf51cc8ef8cf9831b01092406fef5d4c6812f37f2baffd8b86be0c065bd6971a7ac4a4681f2900ce7aa18455bc31b1f526d2251afe83d2c49559bd23240de4f968729aa08349c9ff04085dff1a751d5015d80d9e9c7febe2a840821b9387d60a1b960f16179cd2da2331de0dce1fe441cba14c84ccdba1ae77d66321d8d3a19afb78a29ca78bffe02f58c2eb42726ddc36b100096337a4cd9c0f26e05595d5d337ec4e483e9262f1b198240ed15506befb0bbe3dc74b66f994d5f459015cc8d6e6267266f553471cc0f43824db2b588aa490cf36b2316f680315a7e2b368bcf1e4fe48bc6d4b14080790fd77d515b65648aca73fa039fefa31cbe8230603303d43c4cc085fad3c87de9157edd5bae35b7ef3afe3d74fdedb34dec37e00f5c0d74ad1ed32df252818f15c345e256fdfd60514f9be7cd27edad7655f496a86a286ccead63a2f3033b0c42c783ad6397933501b909b946e261483da3df8735a8e8ba54f85e72967a69caae09f5947ea2b3a56baff5690c650eaf50b0cc02f6edebca54076d12e6e76e50eec7cbf33f2cb8bc7b396455d41a2f60858dbbcc3356687cd174ecc9d98631f5f6902c2c5f7199d18f82c9393d898faed8c0b8a233d23bfdff47d68de11f53d5057f852d420f9bff4380b0a6e088683dcc9712500be4016ec63a1fe09d3fab64af750487c139506ca1f7deb524d4fbc298d47911ad31fbb82a549315fdd14f1b9efa763dce9635c104f0f8325ed1db9f50fff2878d3a9b6eec1a41ae7d225a63901ee3ead5204f60d016f4176fb1d4b7698d439bd8a3e2497f8d8301ec54bad50fbdacb6601f5189ae2f35e10a51b7d9691d96d8e572226e0c1a95107dd6aacf9fbe66bd1dc04f9dff97f97bafecb27cc85ea8030ccfb516b254c22331885041fd6153c996f51aca299549ed65ef53841ab94fcd5cb2ad570d6ab52f1226b4e02e24c59bb72528a20ee601e17266b84e39d939e7672187a5a8afbcc41367db2f599bdb5576b3279cb59f8269caa200d934449e75fe2c1890e2e4722a005bf5f457baeb1492732a55dff845949cea2cfed013209ab9be7f8ab306354ae3080e52433ad6f08ad4973ebb3cd8aca027f94c448885dff9b3042d6640fafa3749a4a7b0fca0797337d78d97b2dc5d3bc6ed205e8f56180c2da9e790687d7e132e5b047b1fa692e40271790b7305b95b61ffcad671686f189114aea7d4bb2e8ac04d4079b81ec535f2e6aaf6dfd27bf884448e1211f138bb7b9fe3caf7878846e5b266314cf0557558cea68dd02dc82b0a33bac59b7d411e3edffdcde9a44aecd82f3d74265accd57224c8cebef6c5aed8fcd21604ddc79402fdc64c14d96802519b16015a34519d2e8bff02032227f1815ea50ee6363e05a6770026b67801d8c8fc6273caa13c68ab55e56d50e59b723f9870bd10e5f1d2a40860ff994a1f14c5df920009661e404ffaba3a685ae0159589df9fd9171cc48f1fbc7e350a81e9f757812ed3c39c703d015864a36faf0caf342e49bdd17773d61a8c36e6ffd8e2aec07e3e2cb8aa06c0f42bffc294887301b4257ef64b00a623d904342617b0bce040f3245a3cdd42a087fab98be89cf95cb1e8851f6cbe06681d85c0e17a283bc9ea11f3468615925a87b86a192c53331ac4a87ab726902c583b1c1475a67ef5b541378d1e492ebd24f6677b4f45ddce53fe250fa010d97830c7b0bde21f19e09ad6c1f00c35e47ef90934cb0a820c2271b8be8500209698cb878be7d2bd33eb1a5ff7fe70afb8bfe704c88b1f71d85cde2a76a9f4053eccd6531c8737e2cc244ef59c32bdb57fda20258101df3cf3b948a1baab0ddab1af515dc3bac4de9884c295dade9c2826d123079f139b04a8ae58d57e3c7a9e14edf00240f5e28d548a6707ddfd46c5d588b903d2f7f01e0a65e32c07df794c26e2145aa29dffbef3fb9a9bd46f1611f040b064f86fa0349efea24d598e98d3b720986121643e13d83d8e3c7a9edc3cec68207873d6f192bc84e7079a4013b04231fb3c9a776084b1784a127e2b86c16a4d6bbb75f807b0e54641b106b5aecf85379d091c13f808674a36948cd3f21bc533bc67bc1abc5dcfee30c8fd893fd7ab2423f018537cb8268007a58d96617e4475822bea295769d8cf3c838f031c961526689bd9733b5626b6b0c990732a4e8cb318d3075cffd747364f8e330d5646ba43a57ea38e69fc90bb40c74dcdfe376157f888736abd92549712596a99173b28b077d2ec25ff7f7c4a9a91242e59ae3a66ad1efd7865f617ba07d73bb994c4159dce215a640d61c0e6f978b422b99e2c37602450bcd295f2a0458c2557ecd41233df5da2a0cb2e2994197d43682bbdbf02ec865182aa58de171dd2677a74a1200812db130e64c11cdd6b8b8716bb4d750e098502d75f7ecd5b091f344ba73669c7f3d717690e8204d5b9312bbf2a06a422257c20c77a17ade663a3521e0a767ff533bfa1bbe3f820e18def8f7e571f71528a7d7f58ce79a27b8a9649274e0249b9a0f173c88609d4dbb698a156f3de0dd05586fccffa512ec088550c7ccb1e5d07d932aac22756b87501c8145ebe1fdf2a4fa86f2a0036622bf1037a5e93ed5c28dc0fef34c01225af4b674173a35dbc48d27e8ef67a0cf1d50df9892c651ab164ac06534c25267aa90678906f3d68e7bbbdbc27c0efae84034786fad16844a3f770df0e93aa5409ca6138ce2a2097d5e2c528a89ddf72db208e9d9cd38061f320731114d684a9a6f222afcdd2c07b079a5d60f0cdc58ff9c6d40b58faa62514f22c6c3bce55e509bfbf1fbabb4401adc9a5024da969dc48aaf0f7cbbf854c922e56c8e86b5c0512a2d25ccddb2bcd5c9ee47cc89786a6331be1d9fcd17be036e69d33d2854f837c5bf1f8eb3afa681b1094450294239d3018b23a3e7a736f9a218284d8090b5dfe0dda46c675f8a129202691bca414548c48569a8e48e913fc56177a87feceb0c7f88c6a4ec4e693f452e39b02c1832a3e2812dfc5fe69ba3f4e4623ddb950fdc8925cfc74c84adeb3a9a806834b368498faa47b92c0a4f5d52b61706a430db71827d103e80783d5f2461e6e490a22e74ab997ad7374bd779d3becee4777b69f40b017dcd7af35c6272337666ca8b4d3242831d7fe0a2404d95cbf3f85408f34539eaedbc212c200f03482aa5483849445f1d972fff39f0219978517d4934f3e5757758da2fad19c9aae0a09f076809ae982f1dd6c49e31d1041b347b0065e8eefd7f5f5245e3a572f76e2b68dabb401c0d0cc98477cdffbf864b63817e56d0d9f8033a4bdc9b0bbf63e8383def2d2105feb5073f2d9061c002b358c41c81484b8acfd1431fb5fedd4c7458d721f77c7b4aa7d028df939ae45b2143b212c60e3b41348af7d33d009a0aeb19d6dd1e90716ce13c37cf18369a3c4ea62c56e496aa4cedd1c6caf63f4647cd785558f55548b54f44ada2278fb0ea77e7932202ec9248935cc67b761a66e3c06c24321da541e545e1339d6a071e7e5924ffe4df003f09d2c53a8ef8a1a5402162e0f72ab282d4799714a329905b67cc847fcc0643b1927e0a5ac4a58d73dc219e7576aa3f8780098bbbc8078da0b2aef483a5086d0290e7b426938ff7805a45732066e44935a7c4c494cfe36234bdb49c5cf676471af7cf536fd6b4aea141b7308bb35617ccfbfc173a082366050c0efc2fe22e4214fd94fd67f81eb57920638fbfbfc21559edf389a66c29d14b83116c79135c408da252c5c7cc2c1b25e5c5c2c9e632252f590e80b75b7acd7af560ad9b8564e50d4d080fc4a948c79d9172eae7bbb9a8f61a2559b2c1f326d78b2fce0ce35c3cd1d9a0bf672ce52d57311ab5f441c978304a7c1b10b0e6f90f601a1301e5cbde18847f55da0bdf913eb3cf7967d00ce94957e0bac65aa8f9ed63a9a2df54193fd732bc49a7a32077f1327fd7ce274db1bec12207cd25cfdb0dbc0dac9e60445806a070276f6f64edc823d6c2f8e0eb314cfb36a2d75c0406e1ee0a93e45e119689aaadaa3c06b4a684bc8df7b9e2ae5d269da6f22ef20e9838a75f0d47385577e9315c4a96ecb7c3f7c4f02a233383bb6771593e3f1b32e3023589d539b13a6df8cda90fee06c21b8755db7503aaabe516e0341004398c4e0f3b7ee1f5c1a31871abe079bf8b666b5fe91748ce14054dd7dbf4196da433469405598d08cc53dace0294186010cc8704948f86186bc3a0896bf01611e2999c2c32682311e46814df5f75ec0fd55dbcd3d678ae24c77493bcf5827ab211e55fe7be5e722d3fcae9fd0fc6b67d5576db564976f2f3d01c0de1a0191d6cf3df8e3ebbd687dd79b8126f22c349ee6c15c42154776e764b3dd9de6f352d91e7c6bc1ee2caebaaeb4e3ef19c603cbe53fbe68c2fc82c4a59b3689cde5d7d7f445cf13abe289e5990e19ca4ec35409af79d83d38bd3a846442e82855e619eddfcfb6d1b970114f842ba63ad7341cb25cd03e992a0fca8fe945bd483967896447190b22c00ec9f2aa1229a9cd1578c0a3e0edb795b406f674a2bdae4b4a14481c0175a10054d8695f3553d6b74a138fad1ac9c39769ede5dbecd4c1d1389e55167362f929f4bafa5b7ae4d7d831ebe85e9bc0f90aa71cab451094f2ee2c5b82b531094c4eef0449f25ae3f3bb90a62f2ee8659d0f19a1e3f8e172039b6e77a3fe54d18a8577fd4e3cb1dc2673ee1d09078fa8e98f9dd9ce2ad13e2d956e4ce694d60cb8947caa6750fd4965e3c2556e279fdfeea8eba3d6bf8cea4dec86693bfd6342424524e5ad9be0b0d1d14aefd1dd5a458fe9f13502e61cc3b46ede808abce9a0086c020e576ba768d585172829ed844ff45d4ffb8cefd2848c2acf4efc9736d640afd134f147b431578c3aa559b24dec009457d2f3f3ae818ca8c2170e9512d555779c872c1cc00a75a298e70963a9607a459b66eaff0fcfa0edece4c72fc5865667763e7d1f8aecae7b010797ffa9667c0f186114d10a9b2102bc1948801d4da0c34e7c3cad8bf56e6d97329c813d86206cfa856561c2a2c4e0c067ab6ca970fb6f9c435ff98975f18dfe64d715d82782542966a6c406e05a1d423c1b7547b7ad2588b8c368a4000b6b669bb3cddb32698279812e1aca54313f7d3cf03e621462cec51a364f69bf0432effc164527b8d3757a44a1fe7cce78b3ab2f1a84fa6257c7af89f92571a8acdda707fe35593302faa392da533f70621db2b0460542c38e07989fbfa76020821f25f8deca0f2b28ca6df28c0f6118be04258c26cb5ec37d76ce9201483ce972aee88385f927c14a5711f4fa20487576202604a2a110a1dd2ccb2a7e6e9701e21345b68ec59ef42abb9a09234fd10cdc2013472dac48419ac917b2b899c568dc4c45b4f6c7fa44e3ccdc78ad7b23a9910d53fd018e3c434def2b6303607382d8be4eceea04d560f269092b5eeaf376ac00d9fe900cd762e018265b9ae7841e79abcdaaa251fcd04bcc8cc338a09e0b5d14c4a692f6192093da866f0bf8acd4bce5740bb9eb83f4576245c19c3e7e0b74377f3d6dfd68a5094e2af86c8ddda46f1601d0d9ce4e4f373d93464d428af5f7e9771b99d120d1223103ca0781b7981fc26577ed6ca623b22cedca88a93a45a4cdb53e79747a46ae5d7daccfdb28d88948adf58589978037b6cd5aad8d1e008dc9ad1c6220db40a5298a2177aa6798d7185cbfa7ad7382a4d136624d62a28e70a801d88a54af0386662bb42b3997e6a9d16bdf368c27ee9db134fced977b1287fac327708652b5f61e63c93423e77a490a3bd9558decd7d1e32e5a9c2c7e2ab0624a6c561fd07de0aa7b591df5dc3261fc41392f5b4a0e4b9cf3054459c424e485a8a897dc1165a5a719d4837715d359305bb1846699688569a40751a1754c05fd9832d731d122b101adc38c220c6a580683e668342f863b97d346a2be4ea07ef523fec2e1bb5ec0b936cc7ac58a7e36ee3b203d4a318baad96fdf4a0b280efa42396d88b463973ef6f696ad9bbd6cb7c8d62d520bdb522fa480289c8b9e22df2705decddb67091ec39aec68da0cf1653d8c2fae49f273b1491ec86e4bd8ee215916d930edd780771613639a1f0e81792b78c25cfa815258f068ce599bb643ddb5547acb391882bd26848a13123bcf14d13f26f2a9fc907752e3462c5a201b48d37f18c8dd263b1dc1fca605a9b9fb800aecad95c8a97eb7a21fd1fab1834c0a48d19eebb10b047cedfb956c4b7f7b0c1200ec45a617007107d5d348742e4029dc580ce217df4eed06ec1298d8f2b968e90a9e417b10d7fbeeb123c3174d46e68fd36dc250b89489e1f36fa99af44a8eff61b63fab14ce41a6642ed5b135454a8fae7c95192c4f9bf8fa56f4b7f7092a0142afed998798cbecb9468e44bdd3cf97baea46d9e8faf1c407979842c0fb2c9f85c9e0b36e1d2878be0baf3687ac7eb79d125d7a583511b4149e02cffc4a1ec0248d07ea850898e41e387cd19778459b51fa9a44e931df2209882cbec6cba0b51117bfaf6b3b7d612ec14a1e8883ae7e0f1acb78764ffa822e4a6218e6f936c76c623dd5a876e4a496a8ddc9dad508ad5f9218cfa3f4df4dd218ff2e320f034b84cfb92527cb4a001caf46c0157ce0b87213970bfceea3be56142279aa0847c0f62c61e59d68f87c35d6cbf93ff07832d7e749117f8f0935e1428bf59964590f84225fd0620f8375c11368594f19222ab665f76354291847d89649bd5e06de2eb69ea1eabbb1bbaef00d28e01d34b2b376accf48b1c3b428a6442b5d68b2b3e80d1b829dbf0ac9e623c28059e59d7046205b4e5bb2eff3f515f8df1d6e86cfbc848cd345bd6ade31df722b11e905a9aec1a19d3ca661c36858207c66f952fb091149ecaf1fb2eeabefc2b1a937db636fe4b503e9e0ff8e8bd249e056ee746431ddbd19c74bebfb699c7cc64f41861699d8acfe41325f0a99fcb00f72934d6a9bb4794557a933580508d18cdd1da8b6192b9c02c11245ac44e177a3ddc34fe0473776193ef38dd97c48603330f2e2c3f0e17ed9a2b5ec4ecd5d291ed8ab78c81a5e51072d0dddbdc20b7e775777d971d2c905a6d84bbe5bdbb64482881c021a0354914c80a9a1c98344895cfb8e87a4a634d104c4e317c5246c5df8d8da528dd18671c510f823a21064718e210d7fb36ce59406fafc587a332fccbfd580722037f4efc4e1c748cb6a998acfbf2678b5956e0110746567e9b61b1481f2425bb0a2bf27eeee26adafdf4f58624c1f4a0dc0bc724a1d877c75d88611ff6303756902b8d4725d826fbb3bf92f1461f8787102a7fa7a76d26356ebd5718eb795fdbc3292cdfd8855ad3e4324813b8162f68d6e1b398c51a738aa8db384afb3492950422c3be50e0627bc8f2420c919099c612d4a7c1729fc2cabf50db385bb58b07cc4ba5ae79f19f5dcba8abaa3f53ccefe2a275fc0ec6fe40d2ea0adb01db2ca5c84f3bc421fcd62ef072160f120c639db0dd4210c0117a57c324504ec1f2bc65fcf80dba3a41fa9d07c5fd8006155302a44dc16ee811761be06ed0fda0dac01e6ac99515bc174cd70608a042c6cab8b47131195115515472d2cfa81320529ce545d101b3c0f024641abb13185a9685104bcf5b01fe2d8d0c2a11605ee81b213e3cc5711874f5936d45b63f23c8f3cd1fcc717f45161ae9193798ad92a1033033db3db8f221df0e6ca7e4de7311e0992ab9e00fcb378acc74ecc257cde3c7e410a4abf6a302fba1af3fa175e2cadecefaefe1caaf938f144e4def1898aee9023e24846e543b69872c2ee7c4261a1968a7bab05cdcc991c40302d48036a490caad43301d6fba323358c7efb8925012727cdca9a3b38726640f19142fd42cd99d31c9cddb0cc717c58eafa3d3ebffd50456cd792e68d5271e9b60264f6424b1484ff90f34ae1bff6e1c7fabfce551eea2c6f449fdd7002c5d8468d6cffb1c2e86af902ebd85a01c69ead4f7da07bc8f6acee7b64522febaf275db8a5f7ecfe39326301265f1024e20c4e721cf5f4a5d2be4fe63ce19dc28162c504d566e8cd434b2241b368adb8107d59f1470633257ff6734b854d00afbfb35aaf5570679d8ce863c97bf762e9a73355bd22e2c4edab484fbfc81b739f199be2d1dad6ea65e0d9ed18e3c7d31592d956da230b35beb9c22851a72a206554cfa5bb33cf665a31cfa12229c340dcac7cd88dd9589a877b0275112bb5f221bbdbaf4df8665a0d7fd4571bda3adea1c2b4d5dbd09673c3fb6d4ff536e9937fd287b9da5a803181359f2894e571567f0cb3581f1665a31738094656be4e65c59bcabea6671b1032cae1361f050b076182269c9ecd85a6f8a06e00e4a1d4442e9830ecbf53c92f8858d1e8a4f94c630c8e98280d4b75d154820bd0a5c1f0a142fa2d15cc2828fd4d0d09e37dab632f07f98ae34be66de27fc1486a82f3f92adf0e4c397f6e629a198a55c4203c54187354d91fd8789fdd3cbcf6026693fdd8b8d7a134519f7f139015f1aa0aeaafadf2261ed7104ae3cf984a7e34e5187167097d3c18be51f894c0de538e68c914237ace97e47c312deefc438252171e0948fe66ca7c9ccfe1ed462169d68315ca6d114ac8f9d0a7a1010d9ba53f9cef2e101af19206081022e13e6df389043a11ac318a1e3914bb9232090018b3c20695088a0d032733154aadce195933b92252236ff336a3c7fab3455d745d0bbc4e09cd75da62c4df4f1f966570651ec5636807ea06d76a360b9e29aba3be0b0d7d50c9a11d1e35ec178ccda3ed54357145041c3338df05efeeaca8267f45a078355c92ab16313d054aee4eecee34949fa90ac979f5550b08b9db82a9946f6b570b5c8868799ead31452c96c0f251cbcd5a4c263ee28c59158602d5b087d41187e52662ed493aaafb75ce6fe2d675ab13565441021f601902f901763aa0bae01d2e53c2ee1123ad4666f1fba3650d9ba39adde5056e9ef9cece0f63bb9accb70dc74265df9ec6c9f2117e608d22d4241d12c6a0d09486309f7bf0087dc260d241f25a6c8e0424693af773999dee4ddb63a100821a822064515b1abc44d734a3013b342b6ef8610e046e602127f8875b15df0c49b48ebaefe2216d8fe4e5156b91d84aa9b153ebbd334da1fe4b992515c45d2d4a78fee8ad8081b4626908fdd0c662cf63a97aaa8346e8cd24f048fbe527d274a12b5c739bc3063e7131dded274c2f57b99e2283ececc3f09ef45e1043040c07e1f5e771bd351d121322ce1da474a3a51f45df160147fda5dfc2a59d0bdac9874d2622e09d65647439b55497b4789a086fb27f1bbdcffb221609391373fd8f52d0ab7b622f1eb5579125cfb260582615163fd2b8eb737da53e29822665ba2422bfd221114fa700dbab64bf7d43cf6a3dc6c355af3681233071352195851500e08b7f44aa68ef12a3199d9b092d441498950ed83464a8104f99157fd6eb2acafd6865c00d8c434355d13e45b2ba9d5b4efcd00116b3257d723c302acba9320d62682b117634914735eed9abdc1a2780ab50d79319377f476941d6a8f49a38de98601d7ec682f2d8315f1c7e98d4d8626825f47b1014bd8562392b3c89178a820d9a5fe4909ff4debc14fdf0fad81d159cd6878869e44709c0b4145ba7ae4f45862c067d2b039c6bcbdc0097cafb20f8d8d7fdf0cbb6ec4262690864857203b1cf6c697306be038052fed9f9ae4bcf60289ba6153e2efdc04c54fe252ba5a74c0fdc999401e3224615469da2d196600a319945793e4034a94c04c1428b39a5197c25d7e690b4dc48679034ff4206d8e0a2f196eb1e12ebdf2aaaa54544d12a2ef230e4480df7ea91cf4a538642b45ba6340018584966a19935215bb7bdc31cc011a92391befa20e498113201a3779f5a77a4c1ec24ea6c92dd34ec51a6aca5d4f3d92c3d54c84522b21c4437d6bc9882ba75097a2ddf05d09d552fd39bf1d84ae1d35fe1ce1440009c574de192a4a4aa0a1c8346fd3ed0338c85907435710f0898429e661a3e5ae745258282cf0465dd2d2aa4fdf27b8be98a7225c0808626c070403eb11ed92c4b883429aabca143c12f8d2df06213242577102551ae04a8a35fea2483d2264e7634fd8905b006e03abcf97ec3be4b3dc6e488ab92813253473df3f697ceb8ebc3b2c9f6da11471143a75e7c6b1ff6f1b4f4ea947818b54647c73b8980ed1007eb5577e8bb87025d6f059d81062eaa4ac1bd3cf173b0f36d8d123f695a7a03005f201d3262113c8cffb95106c01ab6f76358267c98524652e4bcb81ca7cde3638984277fb3b1eb6f64433a144ef8fd94b18b6156e473b0033be12d846d2dbc38c37369350060ff6d0aa92a6b5f936ca7be2bdb2aa84b94400bb5a6d213bd0a6a3da5522d99af1ff496686d65ff6c1957ae88eeb3eb2d106ebe73095ca6b0125c470b05403a783211d71728d3bc6e634d7f0af36f8aa548b14e3a588a855a01983d4503580730cc839e679488b238f6ca54fa0b6f4802a5dff1452e5afaf6bfc4ec2b90acf42906ed494f9987c2f1242c959a73be4d38cafde19bb9f39345ea17c6cfad6b0b98365bd4e7d56cd9f11129b6fc59613750b94dbec1a41e02ca8e53d58c51cd349855da15ab545c843b5fa0ebd1cd211522d3439d9bf63ae23495be54dd41cdd09a22178c4fa3815dadde416ec2003a50d277357722da6bf87f6d1641c21a0d5b78ff1c54f15813222e4fe020e6ebecd53e6056bf0ff9ef77a7e7f5e3f317f8ef91645d6ba96bf2c2408e5481a9c7a5004325728870367bf9064a46a36e1bfe0f1f1d7b9481fd4be75b1d053a052d5d4228debfc836d4c2945b72244f253ebd90fb631d0e84eb1ec4c8763bc0cdbfdbe7878c43fe72f4282ce9386adc67a311b7e127361c8b29d05271b4301c94940a10009595cc62022f941f3665ac20d6bc0522141ec48b1da94be0355045ec11eb7b50edb2d00e873715d7e4c272b8d8637e816c7bbb3472ab0a6893300743f985949f02622b6c77c89c37d1fefd230fb32ac7dc30eb26202675a8ed15c2a3b53b2d13d540698073cfba9076012b0400d09bbb4d196e3d376ded8b0df898c666d9ade9e715bd606af694a4b73660eb083f28bcd9700296659898841c007ae911bc524439270d439f62ec712eefa769f1c915faee57749f7b98eccaf025d9c892d5db0ef63a952bc15e1fa54c192d5f9ee383fbb902bd9865cecb9848834363c4d536e680f0641c23b8a3dd07bbca07acda97cc5d42b876e4c48a0893959387e73f214e22c0ea78e24d7e59abbe375a3a6aac9462d30cfab13665cb1d1b693f52c3c33561d9355f7671a9ba5732d23c7ac3428f34315c48c56af47babfadfd13427167e286ec34bc558dc34435500688157e7a4e493e1351bb033cbaf66053d6ee3b72d0453056ed10167ce38ddf0e3f09bce8be6d30790ad5efc1276ed69547aece46f285c44974369ed14286413413c4b94bca3029e1f88a3927f60433967adeede0bd926b9b7556bf21e235e916c0f26bf9c5249ea33fde1f799b0f78fd452e2269ffe8500114e3188525b4613582961ba7a8cbdd23fde6065a9af50ca6432350210ec1ad9a41ae0dfeef7a4dc4d094aff6a79d6b8357ac251d6ad421a60f360f3026a68f57b7b1938acf8d36a2fa33191584fd643baeedbd6fb1063e62ab948f6c71e2b708689b18b3463da2089ea32268e18219c54f40f631a605a04434197dccaa1843893ce42363569bfe3ca7d347b1b1e80f994f7557c390e305faae2db5552cf682c7fddff86ce2fa55e4112317fea36174b29109b86741216fec60bda88d823fe17957c019155662d6b67bf2dd191636e55f3c67edf6084ff89152476f8bba2f8cd848bc06e284486bdc6f287802ab44bc2fcd7073718dd03907abec5048e8a27bdbd1d4ac7f8fff9e33a3de419606eea3d12d4b589d6807757c805bb4eed4cd1a27bc4651de71918db2fa9936042fa676839bd735a36ec426539507ef3bc2ad45eff4a693072525a24c2a4d1df3f50079ca676d2006970f1631257d7b364c574aa2abcefc63738b311605377bc003142e997200cb71be22c5f78225889d5eaeeb43bbe4052cdb5fbfa88654b5462db95c05ca634d221a420da7c353a041229fe5c7bdbbc74ec172b0848d927ef81ffa32d3fc4378785cdaf0c331308fe30b5e2757e7befbd307631f54f461a0b7665363479762b0a89aa6edb0ded3e5e8836096c85873e611726f7bd55123fae97904fb385dd9f6d41c2e4655e498db6736ce563684fc6e4fed8428c749ca70b52d0478a2b8b080014f147326602fcfac19f08ebc6914d9432f113d8d45e12e0f5d9f458ace1f811f1e0844f137087a78359e8d2da1a4998ffac7405da2c6937b551508a6f8041e0fcd41a92f60c650ef07acde9781eba56029ab49b1357f7bc8993504e78c858c772c78e78f536857d971a7cab1930d5622f6fd4f575bab4dd6e4babfee1f8b82fd61aebf3ba324257f657ebbf0d6c8074d587660e9158a345e37b78b2af1a5e82fee8f22e7c19c863bdcb289a85aa6bea2bb6c501e974ae24f714f295ac89d1f89f153aefa6d45b586053ce54f865dc23999a0d56bcbd1708305ac117a901d284f70d0a87bcbd9c8aacfe9af56e383fa72986bbed3bc5fe74360548f4e0a8978bfef51a879b3579c89f281352cfa82b238bc1270fb5fc90dc7a8d771b2e2956154844cf9cba7cbd02d58e7b07dcbbab4f353d4bbe1a15ed83b967ed2e613fd2da4b5f8973fe9e953c0c9870665e1a5433c8545d3f75e25b529653ca71be92b491aa0d2b566aa896cb63b08454672bd2bd0013e0a2c9df1bdb8a92f078b3683072e12185cbe42f325f2486de3a3a8158741416b0c8d82b29ebc5979509ffb3e3c6f670406206c4ac2161b2937464e12a476442eb42a59b632832edda3f8c46980c54e66267c052245940b2093280d0ce9ee03e61ba28f9d34789c6219e83b5f7953b599662645c3b9b279d0dbab424f0644409c71e40d655e44769b30fc08a9f6e713f210c6dcf76d22a1bac4982be96324b0167d96afa24bfd6a64ebc2a976c29af472e873f148fb4152d693f8ed3dcfe1f7908049c0d2913fde62f668ac44433441115d943d1b8e97c565df948162a7defa7cc9bad356ef13d3e60cb3d99553c353c2ce143f8d8b8236728df43f4daba6715f59db657ca3079d33c77312bd8ffa6a53405786b519c6d7d5133b4284b3599152a916da0a76821306b3af3468b8858f8e60115ca5f300b7dc8311103bbe928b797a74f0cbc04a1442b63820680dae012187529e85fbb759ef6cd49142fea2722550eb5095a210529280e92538bf9c0f184688e2cb2233c2827224f8cf8b1533c2b4aacccc9d92ba179c407afd1301e85dfe88420b30a3a038dbad3ed2170abe7012d710a5f64af56733cf10af6c15571829acfb19e1d04e081ad39bf65ec5477ec8e0bc8cab5caa3da7e084b8261605cdabf0a166e6dc6c9c43325823073a82b13c9df1dd1599988ab7b9640d228af87d62a9b64d88d5d60c861870a7b3c1a95b4b840035839de410929c57df15b14ae686252849bbba112154689ba8d9e348f4ef39aac332e8e89aff08f5be83d906cd788e1ba34613c1e1dfa67dc8137886dd2b42925e6e70f92f3d381a93681c43ebbc53cfca81256d8a39ac865e24a758c8bf8048d494f8193c073be6d5ee966a1e4a169e11e2005710cf733902e5fb0df715d31ca70ce7cd5c83ada3690ed9a6f627bf7e64cc00f07e60643734100ac94e17d28ecff64064ae1269a3d72fde1d75c3530b539ce273d778f9b06f17779674c87516e68b54f5940d8e26aa09ab97c51b96b0ca9db0d1e78527f9eba2c6c8cf45308c26700e199f42f2c2fbc775f98d2b8e888df2833f6142d0fe7bfa93d4acd023017a9a12f3ac4b2ea1f8f3786a48d242bb56d9f2c4cc20e8f898cb4515eca81f2e6c3b0af5d050ec7fce4eec0d64338d807da624d71decff38931eb95ba2b3596f63bbe8e0d3f57280c35a4fffdf6bd36582c0c47939715e50d19fd3f5f503466ce00409df0f2191a17c7505f795d9094e366b6777b7599c466514359aba6d1dd92b90c7843cdbbd5df7160c58da6f7fa4ba181071da16c64e2ae831c64a9fc9a2dd14cac8bf37c61352ff8700ef8983fe9a38d7c8143f490b0a23af941adb2012e24c60f06f78160eda440504a6af628b240322c3c1d6a5b4f17ba7aa6627391414fa202a6308727659ec7743f1ac6f9f0c1b6510b76e2678e83c8ac752394cf9289f2ca4d48384805954ca17ddfa0f294b761742733659b05b78625383f38a76aa59b7127a9801d87005827fa5705de119bfdd9dc0dacbdfbf2fc54b5f233dc6a513be1070db58d7017e583ceff02bd5807410e87eb1498d99b56606bfef5e4f3392f549182835e920599caf9fae5695587d535205faf8a0febb6701f8ab4e002f3e120877b2ae87172233f8af1ef564f5bb826d2dd7e584c52543d65ed1e6a9ab5865d93c2efcdd40e5ef129c6fda8881cff8e8bae143267b1f382cf09808bd0d4ef127e03a80d89b7b839090b8dda8b7d2d717c997d5b9685f9afe9b1289fd578185ec2f0f35194247097cd7869a4c5affed39dec3bbbb0f559b675e0f7fe3b151671f5720176b73ac4ab397202e2be08f5af627de77a45408317ed23c8b39324a1a5404f8580ea67932907dba3526bf90551712589bcf073350057f66fe1e7084a94d90cb72f338e00a6443b66a49ea8e18e3e2003de61acfbafe80c14047e093512342b49b129115c72164e462e05ee328760ad38b432d4bc54c091a37625b59ceedc5a1e67f36d56ebd7b7409e2a108b24b0b15c2f715b1cb6f25b9b570e9ee076ab29cef8087b9f064da99059859a7165fe4e8d68196bff0f81dc6e82d3bca929f7bd3cb792439d12e031636fd66bacd3760bd89f5212e3dab2fc05aa881d2ecf63366d7bb2ab172d8276a6d978dd45dd8505478d34f988b6650fa4b22f88b3de8114bcdb14703ea882e12799e5224ae985ebfef0276c74ee89e8a5b195e2ca2a07055ea89400e81cdec18d71f09b01271bc96816d6e238ba8f871145a24eaefd1d826173d743e66e1b7730d8915df14afe9cc4a1641f68b2943e8c393438dce7507d066df6757e44ae3b0edda470943e3bd447bec7a371aec9b4e6b3ba1e7f547c024ddeb4b5661c59733e2aa5c04609bb9b96294a3d92d03bec784ec5c71b4407c025f0bf9555e9c1cd51e66ac8f373c36555e4d45bfc2ee01eacef4a4da5b36dc4a09614bcdc4b07aa140b015f9b8ff5bb875dbb9f0b796cefe4458824085110f10fbccfbc454796fff40f4d409e037281828eb8a69dfe40f53e3b82f091306d18e0467cac494a4682f6d86600df93f7beea3bdbfd621a5b593c195b74caf84fe4b95a34d6e32fbc6efbf14ac77ddf8ecd8af3dedb87473f83c370a417872cb1802b0e601d87f1586d86fea3e86e8bf1d6a45bd22262376f30d7fea5785940255d91d385461f8d7b4925eee1c35366285ff1004e4b908009d04277de86dc3d1aa7053154ed0b09f4d0ae7ae901ba8466d29cc14f7b835c49b4f78f78915838cca4b8f92d70ded81c9f70528ffd66d3ef4ddfdfa91d473c08f6a99fd74ad76f1ccd51ef16481da3330616ddb3f8d252006dac8c04932704909950e9e68e8e63ea6e86ec15374f1a19fdfb39d677ec013ef994cf9137778200f4fc9005ec80744cbee9310d8298c8b3f47fcf1b73df59c71a52d8a5616397fa8538141389bbabb4334fe5949a17a132195cec2fc91b7340c2de54eddd3ff9631dcd03d2320a43bc3ce8dec79c3e25381498c275c1dcd4925242540eeac47442b3ab913a6a2861947bef2db19bba12c9c84c09cd55e9b5a708d68e18fde6576145a24b6304bc6d419c0131dfc6184929e41521664ef866cbd4c9c86cdebfc97a10e00df3088d7cb33e36ef9f5ac496df107e88fc4987535604487caba80adf86a47139aee282940276ac182ab7cd37a8352767d1a8723813d94d6dce2b601a8d37729bcf3fba13ea68f843391115bd9caf508c06947025fabe35bbab9dead44de2a95fb2ae4633e8b1bf9829f18f2356d41ac1124cd565b0998fcdeda2152c8b5ccd981b1653a09365d2fca79659e156d2f6f917f1d484b09db357156ab9d12136200784aa28b2d111247b203bddd7fa5678cd509fcec63068eb052bd964fd001aeaa35fc225c6ea83818c30346a81df54991e84c91c0a1a32068248e88d45af50dd35651a4553df0454c9c6e8831396605685a0b67ce9c1a5e0cfd2d552dd284f89ccf77b47cd28634dc8a5dc4f1df60eba05d465ed3b7a523bffebe3a267f7f4b6b72337079217a1feeebbf206b13ea4203c0dcf537dcb8a57f0bfbcadaa6b4287ca442cd1a3a7dae25596fc85f8d8630fe78b04df30397fd563432819928240c4d2014ef59f375e629cb8a2657789f31a4e3edb38155a9fcde9320ec7dc93dc2f0cb7ddd9744df279d7c79bb89b28053295630c420bb03e1bac4374e41a21070e9e7565f337a5d846ac22e8fe83d57384819105515fcfdf4f7ede48e84bdbf117dbbefd8269aa668bc93e32c003958d44db0fb1eea25928f624b35a976bc7bbc57b9a972912e7c6d1df00f1ca64646e96e38b8fbb3399adfa1e0dedd461630bf72fe9397b97a88a5bdc9a59da4757a06c06e51452a98b13e8e34fe4229d40598cc9795041803bee16da530c5e7e9c827a4a1d88b43e794bb9360058995278054af2c9aad61210caf59637430cd901a0072394dabecbf6580b4f247e6311a6dc06cacf34c2989698f9a04d359f1187e54c413a7a71c6867e360b594f99e1b5a2747e5dfd1418beae328ee1adbc6870000d4b853e0c3fef14c3101696fec1eb88455089d5bd17a72ee4a902c83c95beda3eb66bf8356c969951b3ce1ea6c374a45692218d8e2105c305bbf9c758d44297790e1cceeb7f39a4b7e82ef4c8305854743b003ea3255699531405e6188bfb69dbb2f891b01cecb29c4b750ec87d32498be2a4572be5cb07e8d4f0ed8a16381751502a62608922035d17933e5cbf84ca9f106ed485078596932227d93c7fc7cbc14c4d1e73c744ce3a860558fab1f854803a0ee0263f6df4d2ab4ee6fe7ab6e7481eb27ecebab563d14bf551f85d1a7be2efc12f0a7fb86b1f8e1c457f3f8e9512e1d1dd903655263dd7a5a4d3a3a9a018d82c70dc64d413c2eb05898381809a2eb0c5107cc50e34b2d2a6a69b73220c882e3d4d3a6248284fc10f212db8b1186760da98bee43c00ad16d445b92b9a96443f675bc2c611d481830be417275259f77cc0e4a405c02942c79bfe3c5410c732470966b188a5188871d7be23bebd246d58ba13c7ae3d24a00bd3301893349d1e74b466ee48be85f0ec027f1a53f2c06e1de526e00e62b1868ee19ea026f76a893e9ba074fe0ba0aa094d7a18276766be9d584a59b5f6177a6c268311e919fed8e4885ff61fb78a01dcdaf52b7d2179224df1b19d37ac1c0caf305db3a55cb513aaac017ab46748e0a2aa8955ccfcefbafa903bb5b2319ce7c48e5ea7bb666aa519d736d6f2684fb687039d72c7c786565123dd1aa919a48a91be8e3c13e9a5d838a363e3a7ec48eb07631591b4abeef27026f309bfcd99f9e869ce24fb4064c14637f9ae8b788a9e036a7549bcfd0f8b5da34544d29cbb914da0e2cd4ecfa1d10f6b01ced174b3aa9bbf3c7c2a17115089f27da0990f1e85c34f8f53a68eb16f8272a1f0420b7934d02231fa19082fd25edeb726fd212729eabb8d00c753b0e7ca57899dab1cd04050f7d8a45777b6722070f71a07515813c59025a890643fe72ed2ab42d41c90e90e62057fc203e99914f0e1903ea88234995426ab891f11ba4288a680e4659d3de6ec1a4577181517b39169690187d9d4354ea1969e173b906a35d78b5972bbe275af311a8def30734c68ef37327ddc30b21a612553f4bce6c0b4e81bd3fe1d4612ce0d8f2f529734ebc0418cab9cc73fdd7053a564c660452a7e277d995c602135870fee147087f343ffba58e6397c555b170f6e14be84cfc3eb1e6259aa613b8e296f7d09e376e955c3d90701b23a568d19c6cec0fff28b142a4540bdbd1768f042e4d037ebb420e49de311bf384ebaab2fa23a6ed4c823e5e3c2eb2b81d1a4b7db494024b56bdd2a3538fcd00a096a9295fe89cde6592999fa9178d81b03719d667b8af3d003e49dbafcd52985e41da354dc0b8b16e562b3d26488712e706105f4ee0cf2e423e32fd62b4907c183b0ea4bca9142e97d1458c22e84efb95983739b0e403f941da08e39c15b85315fdadb91e4c0e3e02146a6a7f5390f8eba1457b558ab2cdec0690ecf91d534daffe663cba4f28214a3da2d0bbc95667094f711c477fbbceaa1ab138d99a5aa9cce760de874724d224fa7654536f562e25e1ea56dd0d15414c1d9fa100f43fa8eac0022b54e9e040edd9883ec08379e3247e409c8dd0e09d2f38bf59faf7802a5f5c3c03c785f43c521c56a117f17119b098caf1825f01bec61b0fc39a205711f2994d29554a778f798a9fe7ba80803bd2542713337a02ce49895201733c35acd91def81254c218665c9f3e894292e9461f7bf5989e32483702532a4c93a6e6e4537e1cd684c5e6db1b9e2ef4e196b95844f9b020b86099120484edfe5daa000b3b20fc198d23e2ca66f349f72d45afefffb1436cdf640cdda3d0622fcb0822859856667f731358cb6cba6fda3019644e3c67528bcd30c102f4bce90acb38aa961f4c0fca7c5a22ac0c7158964da20826da2500973753177649a8f1e7286b5d3b09a2003950d0581f0a09463bf2abd58bf65224fd63f88bc9def2ed8ad9e0e4dabbe958963958ee01b9d0120a26add04f5b2eb0bfa6e28fd24504fbbdd9d54f1b47fca3519ba28029ce6c5c2009b4ec8c84f1fb48c0041718f6071fd3d735c8f90ed0a012a8c5e71702cd1553dd9d99bea3b6fe4a54bd16c6193051c27fec2c34736522af533b181b5e4e4d28a1e09caa3be599344db1ee0b5f7c87197e53b2d7bb0729f643c615cbc3fc317a7fe95fcd1ccbb90a22150a96957bf9d605f4e68ef08003ad6863b8b570741e36c5ef97249358d064be01b90287f281c7cd8550198869baed413a04c6a14c68274bc07ec04a50e57e5d9e5773e89ff3ce8a7c553f597c3288aa3b05e02bac18bc14dc32f58435e3edc1337566acb6946fd35b0e1bd3378e234199156a37b320634359bec4b506259e4bc180210b03f629927ed750a89e479ab298ed402edf7defad4bf3090c1a1371eb964619b88cedb710b4b62c5ed0200adeb81d7bbf9cbb00b2630d95394aea60ab37baf2ee29a20bb515c8961f0ba2ad38822f4935a74c970fc2af1e23923ac11c8a41bc5b0be60dda19d9e23e515cb4b2dd24d5fe3ca25d4172055a8146be4fb2278a87f9370a266ef69796db851192bc490a8f4972a0d498534d99cbffd1afe2d0d4410f220efc5e2508b3bd370e9bf9d64d63a040e6f350b9adaeb08ec8a29ed389a97717c42a0cc093e8cba2a6e23b8cd696a4b924c834fd890a84a05930cfe3455739f399829c1f5ed81f44b46271be781adc5ec353c1d931daae3f991b65a124ad4c0ffbee121547a385a742d8ba409c04ce738a32e780b072293399d6ff38273ec457c8e8bc5bcc4d34e5e33731173ec7a4f83de6bf673436f972c52dc2fec617cab40ff8ac02af8b181b3f07285db6d9df9b927ca5e6bcb9cd59fcd701eca36ee25e614eaf69070a5849cd0c42912dd0f48289f6bf8ae576aa5991c389cb96c20e156f17e986b6344352a0eba25914e3029c9a45c150cd8d22695557f8a2526d884617d70a43141f2fe25dffefcc0a2472aa8fcbc4c680b456468ea2d448556a35ddfa29ef0eea4e1fc307d35155bd4b0289dbe9388466153b83ae401b0f6120cd0dff45b9e2551f63f586cea913ba6ada129feabfa16986fdda25346040e9cd80ca62b57e3168b5c58988c86020c4a4be84fc12777082a83131bc861332ec6c9b310218da83e8ef8d92cc47c88a1287fc46f55ff12bb04275cd6a33cb76e0b1d8f81fea72cfe78f6331fdb23107d6e8bfc05db5ba43ef454233246c0ed5aac85e5f4d053b1a161ff9ff86dd49cd75f5c1dd4929704c9c30cd2bafe9fb5b9acab764dc07d396561bda9f2305f6d881b58ebab09c4c13556eba6754da41995417710b381b7fede31c82655e9d341512dd390786ab48593be12ab9fa94e9492903640f94ca046e272eb18b6e240e1012899a9547c8a42b4ed7c3da219d8bc23f137ddc75fafb83398ddf9eb3b34c3d4bdb715102e041a845585179f35ea2529605822df256dfc3131db2181727e49c0f15b782daa33f72bceb977ba3908e13c918a6ed0ed8affdb22a59969974c840580e429a313ac23707e41c06713746e6b39ba755e9124927bae37d8c29e65a39c22087420b20aede4521a8cbc0f2498b7dee5395ecf08014eac4040d67866ae6f43f2e6d3d78af78a8d8073696cafcc3ce70f08ca6cb308fa1f8e2803e3135ff1652cc1fbf9d839b53ad01466fdb2998af5e739b251e354639584d5bc774d9f6be0e6be7c5dcc31fb3b36b09afeb0b562a70846707307058ecb3b287fb7d0e3887e45558cf00a90777dedcfccafaed1064b97ed10818331c79b33bb5d627fa0f74cce94fa39bf8223451a3ac94078bad39216237b4d4c4ee7e794852ccd9019ce261bf077182030ecc82128bb91deb874b86ca9b002eab9a17032fcaf80f1a0b9c466540a46075dae1ca5ef4a8f63f2fedb00d87a621df2a4f3651dabb65a32ae4c1fc81ddc3702075ed8438688c05cb30c64662d60e1a213f9e2bfc875cdc8a36dbd22fa54fcf422ce7f8b287234bce52b0f2f5ee37f3a6bb2532f503dfd4575a671ef88b8ccd6277ff53c3b252f19104e60bffa0e61cf9c8ce533c2b4721d87b62425c5b560414d17d75f1b4c01291a6b25fd5e0d1ea4f52babad38a9dc837e3e18aa50d667f93398912f8816108e59db4a11fdf47ad67b91b5734b38b9b3e44f6edc8ac828289440c4a4e702498cc4fcabc68bb87210fd776aa1719176791761a1de904331aaededc482f9f051aec014b858c2b8dc2371f74aa741569f92abee121d23c25a0a95b546886d844051f495409177b7c096373c485dc419dd5df148664ace8c960d1e9ed40c91cf66c588f56de08a26640b7baeb8e279f216f4ac2ea3ae97290f739ef5a92064e2025ceed8863aa13c400913f2f69cc4139a4c6615a869a428ace21883392dae35bf187d52426a49a35b09ecaa45fde88ec14157007e01834c95e818c2afdff7d8c8acc8fc1f4797cd01c36db8a19247a4de5a70f2ae383b461239339c52540e895ac232b0af56182c55cba5dded245a0472c6ab5272528d5972b3737fb52feee2050f9b83b49dbac1088598970c40971fcc6ceca06c4e9909694591e1b73228a62c862b9fbe5c6c7892d1a066543e37728c965584e5d599ac23a8b82437a74437207a2ae65d8191d9dac86c444fcfd89a0ac4576c3bf75477c096e859dffcbd15bde4c9b2ec6a5d685140b5f2999e4432a7fa6d8dd68af4de159ced3c859d0190e8516abff74a8a2841cfca4c240bd2ac66aaa78bf4efd1f51eddb86d25e1c081e59ea0b74a17866823e33787e38e7ae0921a3c2d763a7a03aaf9ffcb3158fdfbb118c066caa14f71652843e8becb38c2a7235c3ad3dba845c26297a6388ace11be0b0b3b2e8e011df4d347eb010b6c6523eb2df012f0ef7d6ee20743450e378871e41957d25c016ab012352ca81d8a1d94fc2dfaa6f3f7e64e0891a353b3fa7d04eb344e3029e7b114b8c948f85221bc511bc62b58f4b22e1bbbca683dbeb1798e5da9bf02f34885c91e4940c9521a847c6f28467be57851d100c212becd3692ffd5fc4acf77cfbdc39e9f42aa9a44feadbe1b30e68a2e75659dcb939ed9c997c816357c6f61afc238d13122fb81a08fa79b52b9d10e2e287c8c3545b75c96eec4ed8288b000e80c9984348bdf91f7e531e1ffcca0a215d2cf24bd7fa3d52a77163b054fc4368165210b74fef9a07ea38f66c3674b83296d780889253891c19d65e2883b8daa62c2b73aba3f96f4e9d92b16ad3a9057375ade26d125bd7e71e396753921874651533b0bb46382e268944249e3759faca7d1edd58fc076134af64dedcddcd52886519df287559970e04e80e29a715deff70017c979f3387df4d65a78f05b1aed245ad9345b6c99ec3d3aed13d017ca76b30481ddf7f475e5de8dbfe3ca66a6930ad42fb71b6980d8c54e35ae7e5dada031216fbbd8f70604e9b98de5d63a9f19fdbcfeab1b3d376dec637e3902c162eff48dff5dc3e03cb35eea65b8e155beae07b21d810295de5e6729cce5739f96e727b38608b7328a3e8e52e26b28bcfaa3738075ffd1abe75424ad0e7b914c49b17e4e20bf35a5410cbb2b5f28aea17bfe896fdfca6e64b890996327867a956eefe226c39377d5c12706442fc1ce17336e9db396301882679bbe1dc0bdb6d0c5f69e75029ea21393bc2c597af10dbda86548e21a021d4aeab12f981029bc4e91c667b05605882d499b786ef14085f80a33e282870cb055c19ab8a0dbc0afa6c212fbc23812f71ca382f1a8e5629352a440cd2c717b78222fc1bc762299b12d64066f32d204e91371b3611ef296b9b39d54b5b40afc0c1714fd5c805b83649d06622336cd029b5cb64c7af894b9bd42a9c28977435e1e0d07ba8b501767269763a98a0fd37e348bb072dae196ccf2e71436b639b6487b1d4b829149fb28faf82dfd14e52165471a33bbd781519ce0471764c4fc62ecaea95eeed882348d2f9591f1ee7e53f2150af93a9846d69c40966aa1e4927a12061d25096c3e53a69fcfdbb0d22060f1a256e0f5e49b9e6b10ba1df5b5ae36e9f7baad3a16fd6be95d2914f3d00c19d1f50196d15fc28fbd59fc8c961c6293f59fcdc789075372090d2c88593239ded0d0c3210f98264011251c08337be464330180fe337dd387a8419804b20f0ddb932ac0afb9b9cf8af925dd09fc2b22ccdab00262c3e0be6b16c4469e6ad68619fd6b7afcc4dbf81685e2310e1b6b807a11ed6fba9d9e5769aabe9ce306b74bb8046bda995aad92c648ce51fb1462baa4ff6a11f1dbbe0c9106f3e270a8f3080b9a79f65aa90ae9b9c9b44c7b8c16e3103df03860359a1a09c0da0a9392266f1ef6609ab38d1cc98781070113cee3b54bfe0c14a98ca53157eac23f4de3cb145bd2af14e095d426c421adefaa54f3cb6836ecb42b416ed7385420984884b12cec5f39bd625a243e0d12d7b18e00b6772ca397d17e9aa38adb60addff86c29b61b4573c087434797687f8d4cdd5a91f075f5233478e206ab9f20085cdd155d8f260a811144a58c0ca7b942763af21a4ba6b75b40e5780cc9e17faa77fc9c401adc6b8124980ef21ba5a5af14bff59fd0f45ddd3df9349920090bbfe6e50f39d4bfc1f3be0cc9ce2c99b38dfdd371757b842a4ea04d8b8df63495ff15695c09f595a8bfcab5664df86807b966f79e053462d6d2ff9c4342a4c4d64ba11a332c037ef4ab896b12761c0ecece3ca8be1ecbc98bff030f976c6b0675cb09a21718ca522139afb1f7aab5533c1ca798f86956409adf0bd05a766c9b6394cb328cd67952d78ba4fbabfdfea9440c3f42ec08d3f51c3deaa98c1ccb8b6c1e2d6953951497b300cdecee68c0c6f687ab2af72c86a54d12f256307e3dde9a26d44626615b91d3d11c6b9b1cf1a9c48a5db95cf8f5be7b11e97d16577602a601ab8d829ef7f4774e7b050b4ff30604c832a6ac4698cc883c6fbd3d09893476a42818c4d63f4dfd7fd622069fb3c0fc9be9e1c3c04e13b9a2984b970234d7848cdbadabd53cced30a042229c332b0b08631ba98a6deff1335438d65b71c6c1153ebcfa2d34f434ccf198405ef6690e3af51650775fb6818b94cda0b40e5a1ff2b1642e301e6e30235b5889bac0cffcd7594b1b6b57d96afb8fc057ff8671943e2a0e416d1680920f0d70efa154efd3e5156af383491bf5c1a6dbbe36f4906446423566416b089690fa30efa683170ad0070973d21fc341e0fb568a717115a8b6dcca199ec4be12a5b0a721b1d93a445ed4c42daef764b909962c3e914843bc833aac05e7a673e2391b27703adb157a48676e8c11c1781c6dedd415ccafd52f752985db70b14b5beda24440d0888b2ba1fb8563ffccbb2d33f115cbfd9c33b6e78d174fe5be2bc5222c72d59ebd1f93b993a3916b8170fcaf552ff0181265eedc02cc5bcdef6792827c85abba7409816c7e62848098c5660d722028a07e5419334aea5cd0bc2394e178710dcf1d722431f3fb381bc6a620b1845c7e98feb4715874c6138a15fbd8c1157a58eebd6bdea63d375ec0cd78b63da894d00ae816ac5fbfc651240f616424fa138c28772b9b8ac2d79561dbab1c3c20bb490edb3351f424c4a213ec54989162a5d1f116707168ef1630171512c81549b87e154e53e307c1a01f025b71bc87a814998fe46034f4bb100e4e9a8fb6563c48633f4ca42618529ade071391df191bc3a15902516f37a441051dc4bea27104c750e9ae321f1ecafa67b22f4d2b7cc6dbf1a8c3f020a3916892fd4e97f13648615cc29d62aa2468c360f3c78f5a23359dcdcf2406b4d7944c4cc1355c77d75606608c6af3ceb021e0eee247014b729765c7902154c7701e2360676f0ce0d2d8908aa115d6326b56a2eeb69c6d654facba3459e3557563c8086bfbe9d8709e28705ae64414b9503dccd763e627ecec445d78cabe385a28de05b165fd7f05e1c53a98fc61cba0a972dd21617f7d67083f4f9d60050d5af8c6ed7ecefd6b86f13eab5706f283f67d06b10c8326513fb07955d17cfa9ffe3855920778c35f9a9e333ee89f724064db23c585e693a190e73acf1bd4a9463ed40f8b64a65a9fa02ce7e105b90db7244c5f1932c6cc9317eea6c3c94a46dc3df44b4c4a527886faa3dd01af09e57d09feb0ee2a66a580e08a5e7caa5151cc4c28ec6dce1846316ff3740c08cb041dd5add2e487f8026af273bd8f7a21b1337229c209a2f435e84afea79da41ae4257558e55ef5aa511eb526412aae576cfd78d369508c7223a31816991f419345cd16ff71fd0d744e3e25e06a2d83b745d55576af6274a759533dd74233a4d318d3bc2a1fa7ef2afba133ecdc668223fd708c2ebebb7e528a8c5382b58148579407746000ad7448db016fb92d3da1c819463491193b359cccc85db9527d93cb83b8574f94dc996c1eca053b737ecac36f297033ae0f040bd512ec12e6fe6b08a3ebc4b55126e3950e5469fe572bbbd64ddc326f1c53fd2190400a1362fd60a65879a3d89108cc1dc36f5ce08b6ddb689b928a3249366234bf5ffdbefd948dbcd54c1562be94e3dc48a64f4446035324e264e2d50bb3f63c1dbfe386cd4f1cc4e9ed84977c2231a7bc64f9f02e07dbebd948a3c9748e2b3cd9520829e7cbb665c8cec3e9b36d971a4d66e6591ec71a8a73d3324e2a84f78922ad7414e04b459e52af9ab5e34284641d8c17cfea090675174411994843c0f749ccf563eea956e1464ce7f7e821baef1682ea7bcbe7bb539395c50363e4d5d083f618ffbb49473dbe769f4fda41c42b5c363fefab66ac021638517f5eae8d962c626ae2486ccbeb7a259df307f9e564ff1e61c33961935598aec59f37cc5bc565de8596216640df3b0e1713c8a03d0b5d71832c5a56a012c8f038afa4269dd8c17fcb1be26c1242eed54ac170929262495f8ba50a24b27363a4406c29afacf1e0f528935640469d33ffa757d0f6735aafa04c329f930673fea9cb4e4dfe4fa4e3d6c10f5c5bc3ab6da57e42fc4da4fdd81e622c91b29cfd5b02e97d42cff0c269c4541cf5c51080795d956cfd8314cbe124965563b1f3e4febfcb1170ff26d128c3fb8cf36712acc4ebd2b62a915ca69fccfe764d3c970cf1ecfd4d7870e8825ad94aba5c8512dfeddf88968667abc656878177779ee64626cd67e7c720fc903d16f3230364b350178e02d15342dc8c37e9f08c24d1700c869a7bc7e33e193ffba11bc858ea482189acd7898497c86b49bca595b57b01cfbfce0fab33f383669ab045faf7aa9f8122a1d0b881fce898636a0111195b20fd3328c34616f96e879f7f0c27eb0466556807fa8bca54ad5c55a6b5a699188831e050ff4bb58bec80ea5c664948e2e0a44faa03b9c757e1e8d709d4da43d1e43293d59ed0889fea8333838e368db3a5c1c4efc51d4adf366c0e26d60344870d568d92b206a3eafca8a2c28176a6af9f64b0076a1d26521fd11661ef9f7b943ff901ac12d6249128bea53bd3636941c641fe1eca48e0666ca70a46dc414f6e39365b28528d17915fd6f09ae637abbf1ebc988492e767b60b9cbda79f625db03e4e0542790c3ed3cc1ec4b7966b0d8442a29c2232f10e475e925cdaaed7ba46835146870ffe5fa1e958a9a1103390724a7a753a110840ad9e210fce160741ff6265607b5319786909e08df8ab5ca4520fe19c3a38e3d70fe0bf7562bba44305ae6638e6064b19fafeb31e2b7aacf771e2e3870c0faa52a45c8e3258fce045a65f9db53570bab675ed790ca795983df96ade7350e30b329e4d8422ad96bcfe4d2031eb35b3f0cffbb17794b56aa672dcb89d1cf583309246cf832a4a13ccc1f7434d4b7a3a7d724e2b603c2063f2bd332867a6396891f6a7aba798205e9a72bcdb6ca8c1b37a71eb2f8c0613260bd2d09c72e609a24ee099e96c0ed5516f9212690ca79780a5868f08ad22616083927fe95c2b91abff3d536297aa2bf5d24ce1ffd9b212bc1eba72b9a1d635d8433ee782b7f36ce28d69eb9b357423d8f1bb2950983c70018c023ea49787ac69f9a2c53c65d70a8a7a1eff05a3c2c0e19f3a7e76e349019f6733df1a98eac9bc29522a619cd442f204afb949fcf5985565db1a3da5bbbca1762798ab45950bb0936e2a27274ee5b4428e03a8bf9e0fed69c8cf73f09f80c2fdcb7c6740cc135a6c5a9fc3c97ebfcb0024e4855b8fdfa19c3db2596866622a6ed313354ad4011baca6dcfe37bf52910ec85b520deb743aeb084dc1baa3a6c2719b0a696c8981a2cdce7cee1a2ee1b71c72faab96794472622b0f9d3cec511ec26a49f691dbaec89ec59d8a9fe722aafbcd32b07a9445b65a0bcdf2320c8422db2968e7746cfde741b21e19cdd090c3e0432b072f3b7c47808b6fb2d22fc747a1659121d021a8f5c5f5cbe3e0966706a15a7d1385e6fa6fc775f253baf72db0a4622dc9fb019669e54f239fd686b2c011be48cfb011a23ad0879ac1638aa1c2b06d4acfd02324173c6bf5cf0a7baa892c21bd39a358a81628b8456a9d750331606cd8a84614a21ae2e4c0878ef0cb7ebe795657093fbe7dbe1c182f8396d7d6d3270218172bf589f7b0ab6f875008aa5fd93de5f023117f305828d896d51598cb2ef2ac2add2eead86384fb64dd8428a4dd14b4f952c9bfb3a16c22fe5bc83d65e2deb87d675a8127c492ff1c6489b8243b9d8a131457075792c9fb42de5f8185d9cc58b6f70ecf9259ec28f9979ba9d13f5f9d77e45cd510dca443477c08dc4877b3e69c693e6897228ff24a091c8e9a80f048a3e38e0f5b2daa8b059caf6d801a5410f8ca3a16b57ff709340562fef447d94fccd6eabf76060de4b1ec815d21eba838c15c367bf806c9f2516c013b0cdc7fc9431c5b5b45d5072fa5a6a1f00e8fa5fcde4f8d4bbdc41bfb6ea237c346f87f598aa5548cac9b103e4195ebbe340f6134c877b47d4729d0a6947a912fe5baae582640517ad2b74a9daa906d7cb6f6aa733f39bd38aa49e5a0035d0982d0c4227a654df879d9420dfe4ca75a94a2e565ce0806da3ada32cd8fe76f32948d2eb8099a8aa87b3a9da2a939bd7b41bc896872356ebe68193d536a3d676bf98f13a97925e32c060dc1ca1655c012b8612fe61376c1619963624a305037848d5d77ed13fdd82024586e863d3de0fd7e14b28e3f803a5885b3f0c50947f96a8a045c737650abb839703388ff232f1f40496699adc9c72aff4cc81271f6403ea51decda7dd1338a703bae6dedaa95743d9033da7b14646ccb265176b8e9538995ef542afa6b641470986918df512df24b6b39dc2aa44192005d6d14ad1071d6a1eac42e027cfa9177049bc5b8924882eb59330dace8b4519ba87515bf762b380886da3d48e7808fed778d366a2cd9e8f4d4ae3e798fda9f2eead113c9a5511bce922d4eae27d8e3ffba396a15d38b4ec773b8a99d435d093646cf5e1bae2266a26739f1333ab13d72238f0191c85036858c39ca4a217d85631eab5291bfc8a004f4b0fe2d104bd9e8be324b30a8624bf4d12f8822b0463deb1b9879fd5939185552166100e2d2175da5e21b8cb4e54bc18ee163546400c48deb0ed5d880611bee5dec91d242ddd257d7133f4484bd1d89c0a040344a065afc672b7e9259e3a8eb63d9882718ba30f4baa569b6c50453b5fb3a6ddfcc352f41bc957efdfe3832377a76d4025cfde0d1c2c1de397f5b3b9f61ec1a97166f262e6d099eb68afeb73fc51ba5004dbe18efe7124ddde785462da2560a1ce484dd092fbcdaea370ac2b26b5b6943e5530be444770e10f942f759f6610a07471f763a361088ea595aa4f1e19f571ae364d6fa08b4e99a023d6363b75216be20b62376a6f399f299c84340fea6d43d0bfe5d62d8ffc5e0ac10f8a169555d39914fabfb7a5463081a12bdfb74b3d2cfdfcd1402fc21596ffc39c1db88969a0d429888ca784fb0e9ca04437d8dbc7ab8ed0bf14ba78dfec4df9af1e16a4786a37e1e4578bc55dfb142f354567494f2178f31c34a584ae9a5ca2e734294413dc9badb03cba81ff7631c95aedac0b09239a091081391090e675cbbd98b95717de33d76d5881e45edbc28832f938a88dadc003e1f13b0bf10d90f7dc2a9e03263346f74ec68465be13621ac99569b50622e8e1760455672d7dea1088b0d2cfd6394302fff8babd49c28d975b65221b0f0045be9833bdc2fd10fc43bb5203c409b4e4fcc4157ca3eb0fdf2864274948f5d1569f64c92e495c48d47691d257df8f9298f133943aa1f1191640dad2018f3263be3fbf4e5e4cd021c38ddfb12fbeb8fc412b88d5a08d1e5eb5b37a296b0e3435d69ce20fb22869539cb4990f130a9991d127bfdafc8f0bbee11237a03a49c19d51b3218b19db29e16b0ffa64fec03c6a553822dd413bc9012ab3a3cf647909bd5976de5ee8812358d3745cdbe8042b0f8057408412507f07e95505891054945cb4ade1a046c70385edf4197dfd481d2392e3c57fa2d8ceb1eec2fc6ae09d929f94a1896a34f8f9e2c56b860fb6db70a238f1fb10641ff408e0ddcab19e5cff963ae3aa286b0b71d0a5c8d745371dd62e81f5cb81e0fb7d7a7cf5b67f9f1843dfe8c6e3800d02a0a186d89fb1013c358b872b6f838d290d49de2d44fbc12b87034c20ab31069c0cf6d73893e9725504ab919276f70d464df9dd95bfd16b106a75045eb46b39f627a1853116bb126079e1c4e283d90b1c732627e3c146e24df96c2c0b0b1115fcfb120b0f156e99e1c891658da6c2f4881db485ad2c2314e994c78827e05cd44fcfaa5835777a95a70cc4991fcd9547731fda0231bee3339f5bdd078e2a3a3cdb2f0599ef528ceac211d69950e34ed348f6267b007195acff5859ad42e91bf191f905732b730120af2fcf420094f3ac3b34fcc7097594cba9494206bf99782002e7060928a99073cbe46d4f932769d396e1236ef86f6c2ee48293ce452797c05c4cdbec8a4488c5a02a3eff2666bc7d18b2a2470809a1b9e8b8c9d5e7a976efad4abe02b2db23f11ad7071b27505ffe83069356417e1162d1be254f77b8578a0169078b7e03c1a9c1e48ba0b4de4572cd13c4004f8d9bfd20e42f5c4407eae4c580441d561b8b2c850ad02ae13f043bbf80fe4e76f0347d7fe305660f136361502b9df85698e93512859c32b139b57dfdf36b4ddb29edbe8ddf342b11c848e8193e6589e6cbe0b90cf629fb2195a57393259fcabf0b3bf3078498d9baa649084c4664f7bf695d0718a7d2f1f0e538b1b61294edb5c780c382685801fc54a28b9fed70fdb1d7206677ce00ac074dd48973498ed2a7f218dc42d5be5b3db42b4bb9beb0feac1dad6a3099dc18387fb9cc8ca9894e04c3ba7b09aae22468918174c0752a97a99182b5cfd858040173d85b1f50c5cce285d18638d7b487857d8c81dc14c6bfd7eb116eebdd64856eff317b2fbe678ec027253ba7803fa4507c8c9e00c5e40a95e1e4eeaa86cacb0c9a5e1edb7be79d216088b9e6a0475d395dcfb26718f6e6e701e30463151b6caf7eb78559bdf88a6ccf78bd73cb095afe396d08f32bd2ae35e4076b31af7cd3d4f7778918b86c1fe58d4aa92aa087606a74c15cb5f5c02706fa01071dcbbcc57453c312411046bc5c1ec03a0d5181bc09a7797a2fb0fbd966bdae48f108d996aad45eb5a1624d2ff002e288e7b808b5e24c8bd761fb09419050f34e90351af75ad2005bb13fe6a6fba31db68f4cc84c0b761effcee0b97b7f7534f188fd300d66389a18be44172086341725476f1d6c510b17a987b22916f0c2cc6d20319d37bf00b55b7e4b77cb3e60b79d41c31bfee83d56dcd5c71a690abd6fdfacd1d14e69e98706cc560abca7791ba4692d5dadc76516c61561df6ef2a45c8a4c626f99fe7a975ca99e519efde14a8cba4a0a670965c3bde1fa9fc049ab73b598f412a6f7a25c0fcccff200af35165eb837253e61fd028a376b851385f83ff0221ab282ee87f8eef86815a2731a4344a0209f53632a793f0a5b2b72a9f5e61985d2708a2435b2207afe6d3242a3705916627c960caeeee00df630412e022ff932efacf645cb6c76ce21a7df6db290ddceac9409d34fd7373fd73da4578d3a6282a63af15a5bc2ec37d0a5dc0e303bd730abd21830030428bf88da93bdab03ca8d8403240ad3d5f48d12501c6646024891f43a63748d2b6572a48a5cb09e30bae23f695f4b81a3e678f9526afbd3daecfd33be3fa0e6954767b0165835812485efcdbc0b0da4fe057f20a0c1763a1e6513110608f6ef02f29e2e33cbb80408c09c7383c08244a519a50a093d23f0ad048bd0d69b87895b867a81a99af3dc138a316fdc400d6c35e9ca24c9d61eed2fa9fecca7b54c7684cb59ca9687ce70edefcd1c2ccf5a396ed64e368c6927bf2a8207d9f611f717d3765e6f7dea36e1061182c45f8456bb46edc6a4ac402dc41e831b2db0d78877477000f62977bb6d204264bef86f3dedf1eafd9f6d93075b09006c129818f66be612b1496d04e63f2e87281476547e87c34f8e24219862291924b7d50026c25a432761930c7804be2369840d77bcea878b0423fc3b8ee24c082793324bafadb5a355f05f3ec445e9fc80963941859eeb2eb6e863687f5861d7eb570f638b0c3766dfafa1510af9d7d15ab2c11855bd4562f72a7723a293de4dc946ab1884e9e31e73058ae4b39f065317f91d6a30c99a2aeed46a069be1b8db7ad5f048f486f4ee871d25dc74cffbc243edcc130d535a0668252f11ddcf508c43a46c00f44687006576a22711f16ff023bd4e93b5945a3eb2a0add744dfb26c4e63deb7f40db2f568c5a98fd9fd144f36a9691b480111b300f9726a9095786397c33845f65f8a1cd75219a46c0cb9b7c3efae6853c9f423c2a597f71d58f7de214d0a0d6ab743254c803d7819069b1ed18422661a8e4b889ba54f9382e26cfec113ac80c6280175685d93fa046c6c430ed85ba301584d9d0f3bf242372be2b30fcf826f3ab3f9debcc91273db7fea03e820597a5d0fde852758932f2218de40a17d906bc83ad6b48ee27a795e76376f925a8bd6b9643dfd0a746e07177104ee9347de4606118c0f44e8546dd39f65f70e766a0d02d64916326547a8aba11f6e03a53e7cca0cac38e986286dc37955b50a7892803eb5c4e1795fc6ce79c73fe8bf40f4b84c7a2d1f4e357b2a241150c07a983ee05bbc20aa72653c0082ab4462db780b82516eee741d5af45e7485d05b394223c6b168c29f8fe1bfc5913fa54465629da20e21939e93fb8027e67320d6507faeb263c7aa8e6980dacd95f3705f1b159a5566f4cfcd660525f17ab5158bf5cd15be6c428202774b09ccc20eb3c4c947a5b4e1e0191e30ce01f439d2af0cbb883b4c653804005c621a00b7b5b8ad12fd74ab3030d6011a65bb8a6a512b49fd46701013b4812cf2a101bb86eea945ddce2237865a8eeaed033ed066100c209622094380b701bfc5e6f67a5cee352f38a46a8ebd890cf4d2bb751bc633b8a3df1e9463b8afe121287a1b1e460cb6afd0557b784bd0d64ebdd25cdb2953eccd010a2e55b88da84707bfffbcb88b48af149aa3a74d3dda9594dba9e45a4f76ae205ef846f2717b5bae036fc69f4ad57917df8c773faa0cb9046729882916df9694ae20cb162d834fae435ae1c0b260d9fffc35f1103199fd814695813ebe087d2fa87bd3540f15c322e1498a5c7dda79b62bc2c81d372621b876a2b6ab67d4d5f283841ac18e0723dd2362fea7d7d3d502bb0ff2707756e565b901e3d181c0546cddbd2cc66d48cc63283f197ab0926ffb7e77777c5842559b799e50ea044f792a62eb95cb89fd6791d6b06868cf138a252f07075b8ebac84ddad7e4c70cb63c9d02587704846d18d09ed33306b9b0650a4d408e45718ac5f584b88995c48041c34e7c54c78641d2932b8a4878a1bfa6b62b67fea37493089cab15ad6cedc05681eec1846e6dbf29dee6b8387d06c0187ea46ada44aab9a9926db22d660eaafab63845e15021b2da6035a1f08337f105c466f50f6d3491c6df2f3e3a03f2e91b1a2e2aa95af8b141e33dce31999cc3692e7a163c621b7e4e1b7cb3a07666a13ab98e1f443bdbf0bdc114ecc5377b1f16cd3c5a168c39ce58cb45ccba81f5be815d0ccae46b0df2e1e90666764521d771ebbeb4d4977d2e672aeca2bbe776f9ebfbcc5883297ffa32adeb8606d3d141b6b2d4c13134f6838839862b2b4ef90d8463e6a6274861d5fdcb21b639052b4b0e72aeaf410c7ceb4a78e2e2febfc7eadc160b1912126f56d472c18899b3fa2feb0be26922222158d09d6c30c3c36148527018779dfa264b621fd66612739776ab90fc0d62590ba53699953f955c6149744808c47fa0d52acabe037ef150ab6a8d72263edfe811d1eac36d41d9db270d0d43429cf6190ec83959e873ff9cfd2f68502932734065a0e8446bc07cac3df78c5f8e5cf0d3abf54c6d7b7af6f3e0d3800be2036b9784d0ac4da4de31c16707313c17769d18abf34890c78e46fd545eec244527ab3f7351ef8acead7f9c51341e5dafc84eb63543b779ef25602c738c044c26b78444b50347d30bbfc6a50b2d62ac8ffb4a73515fece4bd85a9aff19d5a837b8377bafd6fe51fb2db7563c13770095774a50fa6da8dcfb4b8610de556049cbd429a9e23246a4ed5ab2d573a19c9cd4555258a2e5101dc9a0275d7379f036467594749e5de107e0eac5cc3aad8640640c6a7c10acf45510ac20ab9ce1407aa3a0ac1ebc570e3cac8f3f144ee7667b5d62bf5451565fda8f80c62f43df23a90114091416d9c057dfa10456991f6b220ab37e95c4b40000f87f4c6b966eff8941aa901b6a0fbbe3025dc7d589ad657844a6d1b6a8bde2be691ea17d62cd47848f9731121e76b29daaa154b19430b1e55f8b5e87fd9936e1d7c7ed00ea54aa59abdd89dad130d2633f9fd98a69962e77a63083a9e077e1c53007c3322a15c64c1629bd8988930b304afb64c109b4a9cd9ce2283cdb5a9cffb9f054f1fbdcba733d4abe6ccc7d840a00b491a265b4523459759f5baed4430e727f27c77022afe37aee03dc66841974aa59f78d801e9786046c18d3b862e372f4f5cd0a90c2061f0a0ab845bf5cef639ffbe7a4fcbd38c90c242d6c4e43308f2c0bdbe5e0901665f17c8a919abb51b86eb8b7f69e6e32923919733d3c02745ca5c78f2f493d1ae40f1dc654ac75f1da7a03c4d43f7f65e4c5e162fa80fececb7c6e44bf924588a020498d6308926b7a4fe44daf065f9cc3699c7616559fddbf50c18c94e9585b11f03e2cae4080c439ec627deca8c99d294bd549f03c390885620b18728d73542101427afee601151b4ebd4ae0f1c3f5f77d10aab2cc548b7b210a8a29959e9382f1943c7de4723671b87eb8eb33f559c58b3cd926553b51ca6c4c454dd9c090d77499bc1c2661303fed30b752f25ae530f1ef332c3f44e36416518d6d58bee79594ddc83e35c9f40fc4cc7506f240439006ba78f41b7db335acb99c05be562b261c1b12c29c91b7dc68a495bcdd8017c618774bc31131bbe3a7d768034e661f2ffb2f8071f26be3db4108ed2ad6eb8eb37c8d48099756339a06b3fe3eb849ab19036fd002dcd2fd624a6bc5d28d347aab1e4554b1fc5ff649fbb30708c564dc207863f242242f4bf066b2f33bb82cdda40c81c1b88083d3af3b72aea701226ebf8ebfcaeb8cc6ced7e9533096c25701a22cda7b3162bab5ca101c437aa1243506eb4c088095f640570b3ca800d1f37a1a4899bccdb1ea77107f12f971ddd6373fc4bad2360b58474e577104b7cfe0ebfb845acbe6e5f350828a6a64fd8680c7308ad4ed124a3dfa139287a9f546ac504f2ecf918a8befd3a0b5e7bb2d1228fb207f2fe743990a98d7fff781fcb2cff0e4fe9ea8a49851c34f6d694a74dddb5e26f14a6e7d15b373b466abe380500cb1e1cdfca58881f6b9a89675c7fb6eb575135635fa930de5a2df30320197db7c66a1eca82ccff3aa043f539454f7dd6beef34db12ff26320fc2da395086f6c58df15b7498947378964b7e58b65f538518b4dde69e9b6fb62c1744f47d9a11c79d151525492ab3f2d0abb5b82b0e1fc75cd54937d24150182390146fc067060a1c3fda4ef3c12225e5a650c0ef45e277c26f7f5b404442c59b856647e99628f86891f868a1eb2585377f4601e7b179c252f050cfd109c73ed638b9600b964b468cac5276e4c640a58685cedb7fcb8745c28fe002d8b148f473db7205de5343b2668a8589e15a9b50a1868a5b07e0686f78048b8637803394ae8c54de8a8dc3a8bc3366fb33d4660aea44e111f7b5458e611edccf6c2fcb1ce7d2b762906cae2f357541a6b32e85ca31a0cf169d451577dd99ae033c69d6547646619bf62ae0a06cc8e6d8964bda8bb5080ddac41dc599e84026b07a22f5ffa0d6a44bf96d474edc4271e9e687cb2ad12e8a3c1f49e406eef05af05f9def4deddd163c90746bfc6cff8c78ea209f70cbd5f11eea10daef583b875b3248577e6fabb005496a000a4154e03c9ee1e47bec6b1733df143d0d6c21e2f3b2c437d009adab83be45e9692bb7524214b7e765ebd1749a64ca95838e7e236230d42f547fe902932b8bbabfdc9b48999b7b756fa828deacd302aeac0c542afca596e694727f78f84e10a6f6b8febd59ddbbb6a5b5fe5aa97bae962eb2e5e28ba02d4f3eb19f742f7279c81b4f90a42b874d7c14a2156f53812e0d2a31d06d75df0c3da2dc5d57e23075c042310b2da599219f5b2938a5c95156802ac02d1f7ead84f885e8bb359a323a3a3a09c213e391bab38f43e4705db5cb344a2e93b4580e54d31b745f61b930c0cba8b4947b1b8b193db5af80a7cd5d3a1aa0b2daeed79c8ee2cccace33598f1ccfde521ceba0f7d81810f38a54b76c7ff91023b9e2881443c61ab6c4ad8e319f166146e710b5bc65a3e969d46c28de7a201d6597ae53cc3a2d83e93bb6deb928a84a461b418dc287ef325c5178601f755412b598a66568ba64c4892c9403a2a3ab92a122e8debc4bf54fb7e905bacd6ed899f61853212cfc39a30269c2cc888735226900d4e06beb4a53de10043f89d4d4e3300853384acd3c3fe6cd3d02d4f1c4913156f3ab1aff16b39cfc63559da400f418f569a8a2fe66acd6dc148f1ea409c572357ca095a63abb773f6108d45138d08743f5b73dec8d7b98f6bc80512f6d49ffb2dfcf9ec6ed34ea6f6a6f26541da3e51a2974fab2b2142e56b94ca8c6ffc0265a47c56c3cb3ea96ab4c45c4e73ba4537219311e276e4ce518bdb63311025f8a1a16acfb195ba62a53f59f868dde935be9479e8cbc9ce1b608dfb5ec6e54bac2ecd5a407c842e805d52c3f3a821d0b32817d0a458e1dbc686a4aa098fc40f65993e8fdb498207f94afe3ec1de685268ec003cc741dba0d9d93c2eb57a6784a29f4466b3c813d7796489c755de9c4b7540dc12034e175fb30278dfe96f496406f5ed885733a4caa80eca4b9765723705b726b573954e8887c18543617104a68beea37622acfc91751a71e5b85389e7a22abe9d86d35ed35154001d2dfa1b65a01c478e03ce1cf86bef7216341de7b860f8c178df633567af1bbc25a00914c2efcea82436066f14cacadcc1325866c9876a81e65d12fcd0b14e1fc9c82ba60ed3ee8dc7486bf6febb3652a1012ef7d0b8966df1441b8124c4da19c57e33efb86a9a38c0dd0ee57b3f0e22faba72567020ada39163d7efccbebd953f72f9bf5761e4a90be6251c4ba36e2958a575bbf03e19241de2cb79d74a6c00552ff7e7a842f608e6b86ccaf81c5e2d0590503a4271be5dfec4bdbac0df8807cb4824d30334ce4f00251719cb0291654cd0f62b7ba358bc9739252991e47926dce7d414a485014c8338c98026c31a520be9ed3e0423471cc8360a218b7974dff42690e8747a7fc9e00b9e1365c5ac67e09b48ab0eabf7b25cec0fbbca1bef4ddfaef5b9736d2e8365b7512802aec90e21915fe9094b5237b8ee2ac0e5614f44bc39df41be2d81ae82d4c8aedc9526b17ef5c44687e962f0615819067b968837e3759b136b901554c9e75be58e70bd2201ecbdb03cf416497c4c4ed063ccd83e51ab5a414ebb1ec957eb341e2af9f38b3f845ec77d34153a2640202aadd0d87470d2f7634db874fdc22fcd2f32dccc6e8049aee6656a4e761d285345964fdb48ada2cfb21ab2e0294337c9b2066879add0cee45ac6fc778c3dda2202e69f6b55466ca2982875403f274d62ca2fea5c8ef0e699cb8606f250b12584e8bd96c1fcb1b0f3678a3d470bce01ee21b9e37406bd22a02520ac9fdfe6825f0cb5b1ab89ba54bd8d3caa665b557b7c410c8f456e6d0b0425d4a874004c878f72897704162f3accbdfdedf56123a058f0c01aa2eac41e5f90f83e9197b5afccd2b289770a0ab5e163231c55a9422cdd787a7484404093f9105d4d35794f47ef1a5eb731bb306865d58725fb75cb9bcb4b33be7c75e6cfa91212ec2ed7f9392d7cd9795cd68ed2f60547029ab4d869eb707ac99870c652d569c5b2f18f83053dc1123a43de8424005080fa35290b708c85e472c6f96d95ca898a16fbafa1e89c3bebc9bad4a7be86db40ca9ffd22bbb94db89bac42881074cc67199f93cdf35eb8c07ad9d832a85542bf8a025e9b214a43514a4fc965537701fe2226b8c2912265058c02027c06058e596c392d323f71a2993d8ead46b1348b390c033a0fa387269de5f464e1f3cdcf5a88301a9f1b51d79fc5d8c748a5149c533a44bd003fe202f57ac1bd699fbcfb0c0dc122c2c713cd66ca0aa640c019a63cd97d314e62fedd0de3db2c55fcfc754eddeade557b2815d61c6751c8fd1c755a9ab7c95fe419eea37c35f3029a880ee177b0a5ccb1a9ce03ab62cb2f6d0401978908b9df9363f199f575f17d25a6f3e1894101076861564115d942968f2bc929b7ff235151b66796079a48b710b6fb24f523ecd460faf57d3d54cbc158bf840615ffec8f98d475cd29a3247fbc4af2f9070b53791ddadff5e7215cbeec296e36ad00b2d1decb8585252ed56599d7ad85dc38217ff4749cdb09ecd4974d428a5373bec6587997d1f8243f95b0fd4fd6556dbfbb3d26f33f0b3ce03c18d484bea57a3d0314d1d4f6859ce8991d689d2cd6083dc7e802410d4b24b478494d9fffce480fbabb81e9393b3838f7c22ac7c2a35b07eb6434a6a32aec0f889a94ae3a92f37967e0b408655b35f94596623106aaa985c66cb5a8e0e7b7aeab0b0a25f1cb0b03917e2b9ffa9761e04cb5529794f0630eb4362ea16a403cbe15b12277c60f67e857d66009107e9662abd8ccceba81bde72830fa5af86e3644b24ddaae7864345e0c7a06fd09e73a4f488b3e8a54d584299356c1a69e21c72d812d0ac38c723e7bb6be24ae80dfb30fc7a91ecafbb478bc27bfd0485c122d9485063f0f8e756f9879d2692cf469af257688a4721ed1690031b385489d355817fce52d8dc7dbb948da13efa6c57787135c22f0e13039a7f04397aa82335b78745cbf1c2ea2cb0e981f418c823d9a7116c992a42545574de95be929f2aeffc8bcf3cad4b2d1fbb0972f4fff658c10bc733f50ff7fd1bdc8f94cecd2bf0f2f87b923aa4d675aab1a3145e9d2e4081494e428aaba66850f3bf9ea2828ba53f8c4ed2a56d9b57b78e22ad3029421bd2636764c3d443c86b2703faba5dd9d068624d8b243e910f3b2bb37b63117744c691454e500c914d650ea4b8fdcde8b194f153add9785e40ce9f2a05ea68b7d27bfec805c50311999658667f254b233017cf9fc13c5fb7e420e9ecdad754d2a5311c562c2386f840d7de40df6a94dfe57baa762850cf17bae19b5db309866b7d2b7ba8e8e3831dac958c23fdb86e620fa3190e17bd0853625676f4cb0ae7dda2eb65aebbdcce4a8baeae8aadf1acb7a4368fcc54571128b4760f43cc26e9d52df754e1975bc8da4dc658b137faee597cd8fa45bddf63d875d5ad12c13c855ff736c45e40f8398032b9d914ec3981a8094dd477dd2c5efc71c9de91bdcbaba6b166b631592c4f5c030e9e3fa7403c5d2bf69a2d59de0dcd81ac62dbb9d3c99d2a8754b483d56366f23be969fe1866f5c5fc179ed8b5ee02da407a822c394985fcc53d8051e685199ee4a289227c9bec9289218ecb7f3c36d3a55641451fa221a3116e6e9b0016fdef57e9bb9b1f25067a5407ee559aabc8ffeb37e4fff5fad175f1313cae69d572e2ad6649c31045f311506d258ccce4135499b3c211f93ee01cfbc2adc4b138b259f6c43a1b8f757caf20872efb0e6240ebdd7d335292c360d074fc3bcbb2effee2cbe56d4bca34150128cf863b2291c581da5f06df63b97ca494997218642e7e65f6f2dd4b0056c98f1b23b8aad99b1312b6373484e41fc46586955ac6b49393727071f86ae9c329da613c1faafe6e34fe0253db3fb52299111c85bdd438729277981fa30a4603801299ad24c3f8e59eae8930c1cec9d51b2ea9859395a963d32d90b6f19cba1b8c2cb9e452c195d789c5db43074b357c4b143b89b6a597816110c8c89533d1a691e6c43d0438e1647ffe7e4b2baaba4a3d42ed605c708b7587b82def7a201f8280dfc3d16e14dbc11ded1534b865b4ddb2da6a0086a0e64a344a387bca51d0b4013f40e49b0b73b5c645a41133a0f72a82209b86d4a5da0a0830dd388b3e880032cf637157464d011c1a1a6e6122574c8258433f4e5dd980684ce60164947b802f7fc1814e82fafe558fefe8573848aa60178e5883882a3b8ff34ed002209c2fc68c9bd942e681ecda62fb0e0b3f765acd1b29551011aff90c252e7cabcd4c61e90e8edcabf5df7e5d80108a58497398539d57775ee949f3a575aae18563d6554aecf7288b01b15f62afefea26fc29b576238ab5441eddb349418f70dad951e250bd39ce7665a01f5e8ac258e28f580b06739f7016b28c07cfb7d3de594a15d831ced31164e53bd0837c5dc55f05a3f87246fffcc89741ed0d4fdc5fb61f41feabd28a8a21992630512c4faf9e947b762cc94721205124fd65a9db2e5f0e8eefab052593ba4f03516dccf9675843896458d132b12dccad3eb5533b76680eb1b4ef0be0f7fd4e8a4673778c168473ca4d0cb6d997067ffbf828b4b74b5c9d135753d80a076a4ed585f9df047d076a5b2bed148fca8a2033be9b05a48f971be022d806f6369fccf5354e3e05adc212a3a25fdc3b4fd9c684c6c7dd28886c20900fe9fdbebe2b1044b633ab054ace96e5ac49f2bb59ca0df506368531f7fc8727134cb3d882b8cd8d37e1b1202133ee0b67c9693f1597dd315b0bb96e6fe3a497754c34ba9951fdfd5e8628e636d87b3be02fd50b7aeb4024abdb694ac1aab83856a40e1b657d38909814eff1dacff17d51d8b892c765b55a1e008d7946d0824f154b0d44fc0eeaa1914eb306f5c9c4f785ffc94053776d8565820534e66da53b189c6d1f70cd81008ba5c95f4d49362268365e8337f01bc9421a5fa1c57d0954e356183e062d191ccae12d14778499b4721473e69538c67afcb06fd3dce71dbfa85fa8aeea0a62872cfcac75dbeda627e1bf61e375ef1f3acb7c33fa2f916dab7732eb272f2403f6b5fee1a761666403fb8aacc80b5ce441a144a5979cd0d6c8866b8ca537a1c977b56a55abcb3532fc789f7a0724d5fe36fe230d24c7b1f7f5ea2fbefe28259bd44f2c5ce6ec93e21be4cfb80ec77533db1d9032b7f9493e4ed0583b0fc22585b6d4643dc1618b7019b91b1270fbecda3f7bb0144b42fd3cea5ba0b29b22edc7e81a220e3bd27599e85fa1c724a83895e98544d4742f155123eeec5725dcbe813596b332511416b7710a50272548b59931e3d0ba3e0d506759ff97be16018c5f4716ab72b38631214b3e2081b4176cc3f3d2e3e2aa9ba60b59649247bc73b22c1497376fad33274a8d7cf9a9141cfd25a9424511bfa02479852069bcf02d4ef61dcdbae4ec60c7fcd7828b86bf8672d9b511e4a35d83c267f0f1019983e5b65ccac2cf9f3e6e7c4f569c7bbb82e5573821f2225c803a76d39eb811368053c67718ca059751107c31d0586a3c6d2c7805bee24718662df989d2ca5cfdecd4d34ee6f3c4aed39819d9b35f00071d58835a5c923cf68c0ac5d45d48b1bafbaef592f2f6831f1abed0040196e8fe8e4ae32836e52a6c6a906619f71b4c1cf3a9f7254557edbe88f3b785d10c6a6bfef79a412904434fdde79db3be4db3d7bc22aaf4519cd7c73f5ae456652e28f610e60555e84b31610498cb42fea4257dadec226eec1b047000ea544a6d88862f2b6961cbc3f6670940187207b25088cf1e3404fe465e7beb0bdb07793e7bfd16cd9ba6d0ff1b287ad74ca7d021f531924e9786fa64172a6c11ee03cae5c6ea7fdf790ba3f4b7ee6d8e9da4ded59b0cf5010f73b6f6ee0e2ab6b2f4ad33177d243a8fcbc6091237b02c7cf7d8dc9f7e7fefce756781521ea633ae48011eaa5b7108d69f26d7ded822a59c2115fd7fb246e50970fe4fd70cb1db3190b42ebed2ac509c8209e270dee2ee61a005c9aa0abae5e2036c6edcb8ff8d286bc543cb074f24ef77a9f2292b0b8b8a126d3f8b5cf4ec0c6816e71063c7101a44e6d0ce67e02761f7f99b641a4dbd21b85262ec7f4ff34c68df3f1b9a2400103427b4c2b166e5d17a090282c6475c128aab54700911a6f28ab16091cd50db0262602991f1b83feb00406346bc314e018f042d120d9157916e525e607044cc2e8e22c3f0dcb3cb58c3f34633a9252565bd7c1d03bcb0a6a9969157c3ecb3d70b71002b3177b43d07f7a4c1e08d66fb11cdd6dfcf33f7ba576f1a0aa04076119326f65bcaf7303d5a2128b901df10d8ea5e95bd58fb3c26a8b0676466508ce84e0c25fa99d888ec8fbb6fdde259a4632009628a0fc9de57923f1ebb9eb8a445501443b2946ef78dc0791e86fc6bb128ff37278c7753f3f4b520282a1220f75e74f24a50d7241b7c3f07293e9760ac1e00771c53f3cc4eab915120270b65bdf3b4c76ac7fec22eecef4eb330e82a0245304a88a01c8340b4b240c7b3aae426f7181e6f3d80e13ee7bb3c544be620e38776ec054883bbb3d6c04c74f9416fcec94d09b9c5df9d209613ee935fe9c689aa57baea612c594bbf9c7a5e1b050b8d37225e6738cda98f53a9e29f70f4a149e0603af956ab64794a45700a27677a53fc1e47ce5f213ab3627f1aebb203799d7fe45275bb7c712e378b807ca8b71ab04b3c65fa0f2e135c640439f9ad0a3bd5a0ab2fbf682d54dd1b284f43d189fef3427f3d9e8a6682ed1765739b2806f54ec62b46031d11692035086dfb59aec53a9a3d6ae36efd3bc09d8bb26ea5d292a94f2503b18acdf5840112d8b14797f7896865c0cf84c0ff417882aabf12f1054899596c57566ac2c7e10502c6ae7db1bd58fef2e2a2f69ea8ace6a8a8191fd0713ed5e10ba1b0f5a415fa00fb84ff0fd89213a54563b735642db8f14156b5f2051e38d328fb15d9a20fa24da025f961fdcaef6ac3d9d3c562c439b99139f8f631a42d07d5b05a3b88e3172595e315b969d94b0b4fc0efe86a5ab648a9b95d98c41764c177ad98286f93e9e7ac8ac893cf9fe54983182c055bb9d762577d374c28a8853c372f3a10c55a718dbc853c2e097f82227bd46fc9f46ef768b50159857bed3e587b8dc8fc18efe2f57570b359eaca0b464367c05e4b3e33bf0838578b381ce8a1db6f573053cdc8cc8f8dfc03581ac8ee352d8fb7263a232838d0c8ea6a03655033e2773941815d51eaf11c9913aa3d83692e4ff98aef5ec27a4f54d965357a283f208ec7b26af66b860241ae1e53afd965587f4fd87a5c1821994c3c39df0bfda32a380c2ebe133fb3db64c4db9e22016e083474c4d6b733f01eef3f524a6b5e4839d3c4a4c7f0ac400dc0bb76250f4a381","isRememberEnabled":true,"rememberDurationInDays":0,"staticryptSaltUniqueVariableName":"2dc30cab31d26476119897b03187621b"};

            // you can edit these values to customize some of the behavior of StatiCrypt
            const templateConfig = {
                rememberExpirationKey: "staticrypt_expiration",
                rememberPassphraseKey: "staticrypt_passphrase",
                replaceHtmlCallback: null,
                clearLocalStorageCallback: null,
            };

            // init the staticrypt engine
            const staticrypt = staticryptInitiator.init(staticryptConfig, templateConfig);

            // try to automatically decrypt on load if there is a saved password
            window.onload = async function () {
                const { isSuccessful } = await staticrypt.handleDecryptOnLoad();

                // if we didn't decrypt anything on load, show the password prompt. Otherwise the content has already been
                // replaced, no need to do anything
                if (!isSuccessful) {
                    // hide loading screen
                    document.getElementById("staticrypt_loading").classList.add("hidden");
                    document.getElementById("staticrypt_content").classList.remove("hidden");
                    document.getElementById("staticrypt-password").focus();

                    // show the remember me checkbox
                    if (isRememberEnabled) {
                        document.getElementById("staticrypt-remember-label").classList.remove("hidden");
                    }
                }
            };

            // handle password form submission
            document.getElementById("staticrypt-form").addEventListener("submit", async function (e) {
                e.preventDefault();

                const password = document.getElementById("staticrypt-password").value,
                    isRememberChecked = document.getElementById("staticrypt-remember").checked;

                const { isSuccessful } = await staticrypt.handleDecryptionOfPage(password, isRememberChecked);

                if (!isSuccessful) {
                    alert(templateError);
                }
            });
        </script>
    </body>
</html>