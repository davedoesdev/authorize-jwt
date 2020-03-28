/**
# authorize-jwt&nbsp;&nbsp;&nbsp;[![Build Status](https://travis-ci.org/davedoesdev/authorize-jwt.png)](https://travis-ci.org/davedoesdev/authorize-jwt) [![Coverage Status](https://coveralls.io/repos/davedoesdev/authorize-jwt/badge.png?branch=master)](https://coveralls.io/r/davedoesdev/authorize-jwt?branch=master) [![NPM version](https://badge.fury.io/js/authorize-jwt.png)](http://badge.fury.io/js/authorize-jwt)

Simple [JSON Web Token](http://self-issued.info/docs/draft-ietf-oauth-json-web-token.html) authorization module for Node.js.

- Uses [`jose`](https://github.com/panva/jose) to perform verification of tokens.
- Uses [`pub-keystore`](https://github.com/davedoesdev/pub-keystore) to retrieve and manage token issuers' public keys.
- Adds extra check for maximum expiry time.
- Extracts tokens from HTTP Authorization (Basic or Bearer) headers or query strings.
- Unit tests with 100% code coverage.
- Support for the [Web Authentication](https://www.w3.org/TR/webauthn/) browser API.
  - [Use case](https://github.com/w3c/webauthn/issues/902#issuecomment-388223929) (thanks to [Emil Lundberg](https://github.com/emlun) for the summary):
    1. Alice logs in and proves she's an admin (e.g. by signing a challenge generated on the server, which is then verified on the server).
    2. Alice uses client side script to generate a JWT.
    3. Client side script uses Alice's public key credential to sign the JWT.
    4. JWT with Alice's admin signature is sent to ordinary user Bob.
    5. Bob sends signed JWT to server, and receives a perk.
  - Uses the excellent [FIDO 2 library](https://github.com/apowers313/fido2-lib) by Adam Powers.
  - See [this test](test/test_webauthn.js) for an example.

The API is described [here](#tableofcontents).

## Example

```javascript
const authorize_jwt = require('authorize-jwt');
const http = require('http');
const assert = require('assert');
const { JWK, JWT } = require('jose');
const priv_key = JWK.generateSync('OKP');
const pub_key = priv_key.toPEM();
const the_uri = 'mailto:example@davedoesdev.com';
const audience = 'urn:authorize-jwt:example';

// create authorization object
authorize_jwt({
    db_type: 'pouchdb',
    db_for_update: true, // we're going to update a public key
    max_token_expiry: 60
}, function (err, authz) {
    assert.ifError(err);

    var the_issuer_id, the_rev, change_rev;

    function doit() {
        assert.equal(the_rev, change_rev);

        // create and sign a JWT
        const the_token = JWT.sign({
            foo: 'bar'
        }, priv_key, {
            algorithm: 'EdDSA',
            issuer: the_issuer_id,
            audience,
            expiresIn: '1m'
        });

        // send and receive the token via HTTP Basic Auth
        const http_server = http.createServer(function (req, res) {
            authz.get_authz_data(req, function (err, info, token) {
                assert.ifError(err);
                assert.equal(info, 'test');
                assert.equal(token, the_token);

                // authorize the token
                authz.authorize(token, ['EdDSA'], function (err, payload, uri, rev) {
                    assert.ifError(err);
                    assert.equal(uri, the_uri);
                    assert.equal(rev, the_rev);
                    assert.equal(payload.foo, 'bar');
                    res.end();
                    http_server.close(cb);
                });
            });
        }).listen(6000, '127.0.0.1', function () {
            http.request({ hostname: '127.0.0.1', port: 6000, auth: 'test:' + the_token }).end();
        });
    }

    // just to demonstrate change events
    authz.keystore.once('change', function (uri, rev) {
        assert.equal(uri, the_uri);
        change_rev = rev;
        if (the_rev) { doit(); }
    });

    // add public key to the store
    authz.keystore.add_pub_key(the_uri, pub_key, function (err, issuer_id, rev) {
        assert.ifError(err);
        the_issuer_id = issuer_id;
        the_rev = rev;
        if (change_rev) { doit(); }
    });
});
```

## Installation

```shell
npm install authorize-jwt
```

## Licence

[MIT](LICENCE)

## Test

```shell
grunt test
```

## Code Coverage

```shell
grunt coverage
```

[Instanbul](http://gotwarlost.github.io/istanbul/) results are available [here](http://rawgit.davedoesdev.com/davedoesdev/authorize-jwt/master/coverage/lcov-report/index.html).

Coveralls page is [here](https://coveralls.io/r/davedoesdev/authorize-jwt).

## Lint

```shell
grunt lint
```

# API
*/
/*jslint node: true, nomen: true */

"use strict";

var util = require('util'),
    url = require('url'),
    { JWK, JWT } = require('jose'),
    basic_auth_parser = require('basic-auth-parser'),
    pub_keystore = require('pub-keystore'),
    Fido2Lib = require('@davedoesdev/fido2-lib').Fido2Lib;

function ab64(s)
{
    const buf = Buffer.from(s, 'base64');
    return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
}

function AuthorizeJWT(config, keystore)
{
    this._config = config;
    this.keystore = keystore;

    if (config.WEBAUTHN_MODE)
    {
        this._fido2lib = new Fido2Lib(config);
    }
}

/**
Creates a JWT authorizer.

@param {Object} config Configures the authorizer. `config` is passed down to [`pub-keystore`](https://github.com/davedoesdev/pub-keystore#moduleexportsconfig-cb), [`jose`](https://github.com/panva/jose/blob/master/docs/README.md#jwtverifytoken-keyorstore-options) and [`fido2-lib`](https://apowers313.github.io/fido2-lib/Fido2Lib.html). The following extra properties are supported:
- `{Integer} [max_token_expiry]` If set then all JSON Web Tokens must expire sooner than `max_token_expiry` seconds in the future (from the time they're presented). Defaults to `undefined`.

- `{Boolean} [WEBAUTHN_MODE]` If truthy then instead of verifying standalone JSON Web Tokens, the authorizer will verify signed [assertions](https://www.w3.org/TR/webauthn/#authenticatorassertionresponse) generated by the [Web Authentication](https://www.w3.org/TR/webauthn/) browser API. The challenge contained in each assertion's client data must be an _unsigned_ JSON Web Token. Defaults to `false`.

- `{Function} [complete_webauthn_token]` This applies only if `WEBAUTHN_MODE` is truthy and is mandatory if you pass strings to [`authorize`](#authorizejwtprototypeauthorizeauthz_token-algorithms-cb). It will receive the following arguments:

  - `{Object} partial_webauthn_token`. This is a partially-complete Web Authentication assertion containing `issuer_id` and `assertion` properties (see [`authorize`](#authorizejwtprototypeauthorizeauthz_token-algorithms-cb) for a description).
  - `{Function} cb` Call this function when you have filled in the remaining properties. It takes the following arguments:

    - `{Object} err` If an error occurred then pass details of the error, otherwise pass `null`.
    - `{Object} webauthn_token` This should have the same properties as `partial_webauthn_token` plus `expected_factor`, `expected_origin`, `prev_counter` and `expected_user_handle` (see [`authorize`](#authorizejwtprototypeauthorizeauthz_token-algorithms-cb)). It's safe to modify `partial_webauthn_token` and then pass it here.

- `{PubKeyStore} [keystore]` If you have a pre-existing [`PubKeyStore`](https://github.com/davedoesdev/pub-keystore#pubkeystore), pass it here. The authorizer will use it to look up the public keys of token issuers. The default is to make a new one by calling [`pub-keystore`](https://github.com/davedoesdev/pub-keystore#moduleexportsconfig-cb).

@param {Function} cb Function called with the result of creating the authorizer. It will receive the following arguments:
- `{Object} err` If an error occurred then details of the error, otherwise `null`.

- `{AuthorizeJWT} authz` The `AuthorizeJWT` object. As well as `AuthorizeJWT`'s prototype methods, it has the following property:

  - `{PubKeyStore} keystore` The [`PubKeyStore`](https://github.com/davedoesdev/pub-keystore#pubkeystore) object that the authorizer is using to look up the public keys of token issuers. For example, you could listen to [PubKeyStore.events.change](https://github.com/davedoesdev/pub-keystore#pubkeystoreeventschangeuri-rev-deleted) events so you know that previously verified tokens are invalid.
*/
module.exports = function (config, cb)
{
    if (config.keystore)
    {
        return cb(null, new AuthorizeJWT(config, config.keystore));
    }

    pub_keystore(config, function (err, ks)
    {
        if (err) { return cb(err); }
        cb(null, new AuthorizeJWT(config, ks));
    });
};

AuthorizeJWT.prototype._validate_token = function (payload, uri, rev, assertion_response, cb)
{
    if (this._config.max_token_expiry)
    {
        var now = new Date().getTime() / 1000;

        if ((payload.exp - now) > this._config.max_token_expiry) 
        {
            return cb(new Error('authorization token expiry too long'));
        }
    }

    cb(null, payload, uri, rev, assertion_response);
};

/**
Extracts JSON Web Tokens from a HTTP request.

@param {http.IncomingMessage} req [HTTP request object](http://nodejs.org/api/http.html#http_http_incomingmessage) which should contain the tokens either in the `Authorization` header (Basic or Bearer auth) or in the `authz_token` query string parameter.

@param {Function} cb Function called with the tokens obtained from `req`. The `Authorization` header is used in preference to the query string. `cb` will receive the following arguments:
- `{Object} err` If an error occurred then details of the error, otherwise `null`.

- `{String} info` Extra information retrieved from `req` along with the tokens. This is either the username extracted from the `Authorization` header or the `authz_info` query string parameter.

- `{String|Array} token` The JSON Web Tokens retrieved from `req`. If only one token is retrieved, it will be passed as a string, otherwise an array of the tokens retrieved will be passed. If no tokens are present in `req` then `info` and `token` will be `undefined`. The tokens are obtained from _either_:

  - The password part of the `Authorization` header, split into multiple tokens using comma as a separator.
  - _Or_ from any `authz_token` query string parameters present. 
*/
AuthorizeJWT.prototype.get_authz_data = function (req, cb)
{
    var parsed_auth, authz_info, authz_token;
    
    if (req.headers.authorization)
    {
        const [ type, bearer_token ] = req.headers.authorization.split(' ');
        if (type === 'Bearer')
        {
            authz_info = '';
            authz_token = bearer_token;
        }
        else
        {
            parsed_auth = basic_auth_parser(req.headers.authorization);
            authz_info = parsed_auth.username;
            authz_token = parsed_auth.password;
        }
        if (authz_token !== undefined)
        {
            authz_token = authz_token.split(',');
            if (authz_token.length === 1)
            {
                authz_token = authz_token[0];
            }
        }
    }
    else
    {
        parsed_auth = url.parse(req.url, true);
        authz_info = parsed_auth.query.authz_info;
        authz_token = parsed_auth.query.authz_token;
    }

    cb(null, authz_info, authz_token);
};

/**
Authorizes (or not) a JSON Web Token.

The token must pass all the tests made by [`jose`](https://github.com/panva/jose/blob/master/docs/README.md#jwtverifytoken-keyorstore-options) and

- If `config.max_token_expiry` was passed to [`module.exports`](#moduleexportsconfig-cb) then the token must expire sooner than `config.max_token_expiry` seconds in the future.

@param {String|Object} authz_token The token to authorize.

- If `config.WEBAUTHN_MODE` was _not_ passed truthy to [`module.exports`](#moduleexportsconfig-cb) then `authz_token` must be a JWT string.

  - The `iss` property in the token's payload is used to retrieve a public key from `AuthorizeJWT`'s key store using [`PubKeyStore.prototype_get_pub_key_by_issuer_id`](https://github.com/davedoesdev/pub-keystore#pubkeystoreprototypeget_pub_key_by_issuer_idissuer_id-cb).
  - If the retrieved value has a `pub_key` property then that is used as the public key otherwise the retrieved value itself is used.
  
- If `config.WEBAUTHN_MODE` _was_ passed truthy to [`module.exports`](#moduleexportsconfig-cb) then `authz_token` must be a [Web Authentication](https://www.w3.org/TR/webauthn/) assertion. It must either be an object with the following properties or a string of the form `issuer_id.id.clientDataJSON.authenticatorData.signature.userHandle` - i.e. some of the properties described below separated by a period. In the latter case, the remaining properties are obtained by calling `config.complete_webauthn_token` (see [`module.exports`](#moduleexportsconfig-cb)).

  - `{String} issuer_id` This is used to retrieve a public key from `AuthorizeJWT`'s key store using [`PubKeyStore.prototype_get_pub_key_by_issuer_id`](https://github.com/davedoesdev/pub-keystore#pubkeystoreprototypeget_pub_key_by_issuer_idissuer_id-cb).
    - If the retrieved value has a `pub_key` property then that is used as the public key otherwise the retrieved value itself is used.
  - `{String} expected_origin` The expected origin that the browser authenticator has signed over.
  - `{String} expected_factor` Which factor is expected for the assertion. Valid values are `first`, `second` or `either`. 
  - `{Integer} prev_counter` The previous value of the signature counter for this authenticator.
  - `{String(base64url)|ArrayBuffer|null} expected_user_handle` The expected [user handle](https://www.w3.org/TR/webauthn/#user-handle) identifying the user for which the assertion was generated. Not all authenticators can store user handles, in which case this may be `null`.
  - `{Object} assertion` The assertion result that was generated by the authenticator in the browser. It must have the following properties:
  
    - `{String(base64url)|ArrayBuffer} id|rawId` The WebAuthn credential identifier returned by the authenticator in the browser. This is not used to retrieve the public key.
    - `{Object} response` The authenticator's response to a request for generation of an authentication assertion, returned by calling [`navigator.credentials.get`](https://developer.mozilla.org/en-US/docs/Web/API/CredentialsContainer/get) in the browser. See [`AuthenticatorAssertionResponse`](https://www.w3.org/TR/webauthn/#authenticatorassertionresponse) in the WebAuthn spec. 
It must have the following properties:

      - `{String(base64url)|ArrayBuffer} clientDataJSON` The [JSON-encoded data](https://www.w3.org/TR/webauthn/#sec-client-data) which was used by the browser to generate the assertion. The `challenge` property of the encoded data must contain an a base64url-encoded _unsigned_ JWT containing the claims being made.
      - `{String(base64url)|ArrayBuffer} authenticatorData` The [bindings](https://www.w3.org/TR/webauthn/#sec-authenticator-data) made by the authenticator in the browser.
      - `{String(base64url)|ArrayBuffer} signature` The [signature](https://www.w3.org/TR/webauthn/#dom-authenticatorassertionresponse-signature) returned by the authenticator, signed using the private key which corresponds to the public key retrieved using `issuer_id`.
      - `{String(base64url)|ArrayBuffer} [userHandle]` The [user handle](https://www.w3.org/TR/webauthn/#dom-authenticatorassertionresponse-userhandle) returned by the authenticator in the browser, if it returned one.

@param {Array} algorithms This is passed to [`jose`](https://github.com/panva/jose/blob/master/docs/README.md#jwtverifytoken-keyorstore-options) and specifies the algorithms expected to be used to sign `authz_token`. If you pass `undefined` then all algorithms available on the public key are allowed. Note this parameter is ignored if `config.WEBAUTHN_MODE` was passed truthy to [`module.exports`](#moduleexportsconfig-cb).

@param {Function} cb Function called with the result of authorizing the token. It will receive the following arguments:
- `{Object} err` If authorization fails for some reason (e.g. the token isn't valid) then details of the failure, otherwise `null`.

- `{Object} payload` The token's payload.

- `{String} uri` The permanent URI of the token's issuer. This is different to the issuer ID in the payload's `iss` property (`PubKeyStore` generates a different issuer ID each time a public key is stored, even for the same issuer).

- `{String} rev` Revision string for the public key used to verify the token. You can use this to identify tokens that become invalid when a [PubKeyStore.events.change](https://github.com/davedoesdev/pub-keystore#pubkeystoreeventschangeuri-rev-deleted) event occurs for the same issuer but with a different revision string.

- `{`[`Fido2AssertionResult`](https://apowers313.github.io/fido2-lib/Fido2AssertionResult.html)`} [assertion_result]` If `config.WEBAUTHN_MODE` was passed truthy to [`module.exports`](#moduleexportsconfig-cb) then this contains the validated assertion.
*/
AuthorizeJWT.prototype.authorize = function (authz_token, algorithms, cb)
{
    if (!authz_token)
    {
        return cb(new Error('no authorization token'));
    }

    var ths = this;

    if (!this._config.WEBAUTHN_MODE)
    {
        let header, payload;

        try
        {
            // Decode the token to get the issuer
            ({ header, payload } = JWT.decode(authz_token, { complete: true }));
        }
        catch (ex)
        {
            return cb(ex);
        }

        // Check the token has an issuer
        if (!(payload && payload.iss))
        {
            return cb(new Error('no issuer found in authorization token'));
        }

        // Check the token has a signing algorithm
        if (!(header && (header.alg !== 'none')))
        {
            return cb(new Error('unsigned token received'));
        }

        // Get the public key for the issuer
        return ths.keystore.get_pub_key_by_issuer_id(payload.iss, function (err, pub_key, uri, rev)
        {
            if (err)
            {
                return cb(err);
            }

            if (!pub_key)
            {
                return cb(new Error('no public key found for issuer ID ' + payload.iss));
            }

            try
            {
                // Import the public key
                pub_key = pub_key.pub_key || pub_key;
                if (!JWK.isKey(pub_key))
                {
                    pub_key = JWK.asKey(pub_key);
                }

                // Verify the token with the public key
                payload = JWT.verify(authz_token, pub_key, Object.assign({}, ths._config, { algorithms }));
            }
            catch (ex)
            {
                return cb(ex);
            }

            // Perform our optional checks
            ths._validate_token(payload, uri, rev, null, cb);
        });
    }

    function webauthn(assertion_obj)
    {
        let challenge;

        try
        {
            // Decode the challenge
            challenge = JSON.parse(Buffer.from(assertion_obj.assertion.response.clientDataJSON, 'base64')).challenge;
        }
        catch (ex)
        {
            return cb(ex);
        }

        // Get the public key for the issuer ID
        ths.keystore.get_pub_key_by_issuer_id(assertion_obj.issuer_id, function (err, pub_key, uri, rev)
        {
            if (err)
            {
                return cb(err);
            }

            if (!pub_key)
            {
                return cb(new Error('no public key found for issuer ID ' + authz_token.issuer_id));
            }

            (async function ()
            {
                let header, payload, assertion_response;

                try
                {
                    // Verify the assertion with the public key
                    assertion_response = await ths._fido2lib.assertionResult(
                        assertion_obj.assertion,
                        {
                            challenge,
                            origin: assertion_obj.expected_origin,
                            factor: assertion_obj.expected_factor,
                            publicKey: pub_key.pub_key || pub_key,
                            prevCounter: assertion_obj.prev_counter,
                            userHandle: assertion_obj.expected_user_handle === undefined ? null : assertion_obj.expected_user_handle
                        });

                    // Decode the token from the verified challenge
                    const jwt = Buffer.from(
                        assertion_response.clientData.get('challenge'),
                        'base64').toString();

                    // Verify the token. We expect it to be unsigned.
                    // We checked the WebAuthn assertion was signed by the
                    // public key above.
                    ({ header, payload } = JWT.verify(jwt, JWK.None, { complete: true }));
                }
                catch (ex)
                {
                    return cb(ex);
                }

                // Check the token doesn't have an issuer
                if (payload && payload.iss)
                {
                    return cb(new Error('issuer found in webauthn mode'));
                }

                // Double-check the token was unsigned, should be caught by
                // JWT.verify above because JWK.None errors for signed tokens.
                /* istanbul ignore if */
                if (header && (header.alg !== 'none'))
                {
                    return cb(new Error('signed token supplied in webauthn mode'));
                }

                // Perform our optional checks
                ths._validate_token(payload, uri, rev, assertion_response, cb);
            })();
        });
    }

    function after_complete(err, assertion_obj)
    {
        if (err)
        {
            return cb(err);
        }

        webauthn(assertion_obj);
    }

    if (authz_token.split)
    {
        if (!this._config.complete_webauthn_token)
        {
            return cb(new Error('no config.complete_webauthn_token'));
        }

        try
        {
            // Get the assertion info from the string
            const [issuer_id,
                   id,
                   clientDataJSON,
                   authenticatorData,
                   signature,
                   userHandle] = authz_token.split('.');

            // Allow the application to complete the assertion info
            return this._config.complete_webauthn_token(
            {
                issuer_id,
                assertion: {
                    id: ab64(id),
                    response: {
                        clientDataJSON: ab64(clientDataJSON),
                        authenticatorData: ab64(authenticatorData),
                        signature: ab64(signature),
                        userHandle: userHandle == undefined ? undefined : ab64(userHandle)
                    }
                }
            }, after_complete);
        }
        catch (ex)
        {
            return cb(ex);
        }
    }

    if (this._config.complete_webauthn_token)
    {
        // Allow the application to complete the assertion info
        return this._config.complete_webauthn_token(
            Object.assign({}, authz_token),
            after_complete);
    }

    webauthn(authz_token);
};

