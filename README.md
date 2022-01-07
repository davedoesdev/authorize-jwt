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
  - Uses [Webauthn4JS](https://github.com/davedoesdev/webauthn4js).
  - See [this test](test/test_webauthn.js) for an example.

The API is described [here](#tableofcontents).

## Example

```javascript
const authorize_jwt = require('..');
const http = require('http');
const assert = require('assert');
const { generateKeyPair, SignJWT, exportJWK } = require('jose');
const the_uri = 'mailto:example@davedoesdev.com';
const audience = 'urn:authorize-jwt:example';

process.on('unhandledRejection', err => { throw err });

// create authorization object
authorize_jwt({
    db_type: 'pouchdb',
    db_for_update: true, // we're going to update a public key
    max_token_expiry: 60
}, async function (err, authz) {
    assert.ifError(err);

    const { privateKey: priv_key, publicKey: pub_key } = await generateKeyPair('EdDSA');

    var the_issuer_id, the_rev, change_rev;

    async function doit() {
        assert.equal(the_rev, change_rev);

        // create and sign a JWT
        const the_token = await new SignJWT({
            foo: 'bar'
        })
        .setProtectedHeader({
            alg: 'EdDSA'
        })
        .setIssuer(the_issuer_id)
        .setAudience(audience)
        .setExpirationTime('1m')
        .sign(priv_key);

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
    authz.keystore.add_pub_key(the_uri, await exportJWK(pub_key), function (err, issuer_id, rev) {
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

[Istanbul](http://gotwarlost.github.io/istanbul/) results are available [here](http://rawgit.davedoesdev.com/davedoesdev/authorize-jwt/master/coverage/lcov-report/index.html).

Coveralls page is [here](https://coveralls.io/r/davedoesdev/authorize-jwt).

## Lint

```shell
grunt lint
```

# API

_Source: [index.js](/index.js)_

<a name="tableofcontents"></a>

- <a name="toc_moduleexportsconfig-cb"></a><a name="toc_module"></a>[module.exports](#moduleexportsconfig-cb)
- <a name="toc_authorizejwtprototypeget_authz_datareq-cb"></a><a name="toc_authorizejwtprototype"></a><a name="toc_authorizejwt"></a>[AuthorizeJWT.prototype.get_authz_data](#authorizejwtprototypeget_authz_datareq-cb)
- <a name="toc_authorizejwtprototypeauthorizeauthz_token-algorithms-cb"></a>[AuthorizeJWT.prototype.authorize](#authorizejwtprototypeauthorizeauthz_token-algorithms-cb)
- <a name="toc_authorizejwtprototypeclosecb"></a>[AuthorizeJWT.prototype.close](#authorizejwtprototypeclosecb)

<a name="module"></a>

## module.exports(config, cb)

> Creates a JWT authorizer.

**Parameters:**

- `{Object} config` Configures the authorizer. `config` is passed down to [`pub-keystore`](https://github.com/davedoesdev/pub-keystore#moduleexportsconfig-cb), [`jose`](https://github.com/panva/jose/blob/master/docs/README.md#jwtverifytoken-keyorstore-options) and [`webauthn4js`](http://rawgit.davedoesdev.com/davedoesdev/webauthn4js/master/docs/modules/webauthn4js.html#exports). The following extra properties are supported:
  - `{Integer} [max_token_expiry]` If set then all JSON Web Tokens must expire sooner than `max_token_expiry` seconds in the future (from the time they're presented). Defaults to `undefined`.

  - `{Boolean} [WEBAUTHN_MODE]` If truthy then instead of verifying standalone JSON Web Tokens, the authorizer will verify signed [assertions](https://www.w3.org/TR/webauthn/#authenticatorassertionresponse) generated by the [Web Authentication](https://www.w3.org/TR/webauthn/) browser API. The challenge contained in each assertion's client data must be an _unsigned_ JSON Web Token. Defaults to `false`.

  - `{Function} [complete_webauthn_token]` This applies only if `WEBAUTHN_MODE` is truthy and is mandatory if you pass strings to [`authorize`](#authorizejwtprototypeauthorizeauthz_token-algorithms-cb). It will receive the following arguments:

    - `{Object} partial_webauthn_token`. This is a partially-complete Web Authentication assertion containing `issuer_id` and `car` properties (see [`authorize`](#authorizejwtprototypeauthorizeauthz_token-algorithms-cb) for a description).
    - `{Function} cb` Call this function when you have filled in the remaining properties. It takes the following arguments:

      - `{Object} err` If an error occurred then pass details of the error, otherwise pass `null`.
      - `{Object} webauthn_token` This should have the same properties as `partial_webauthn_token` plus the `opts` property, if required (see [`authorize`](#authorizejwtprototypeauthorizeauthz_token-algorithms-cb)). It's safe to modify `partial_webauthn_token` and then pass it here.

  - `{PubKeyStore} [keystore]` If you have a pre-existing [`PubKeyStore`](https://github.com/davedoesdev/pub-keystore#pubkeystore) instance, pass it here. The authorizer will use it to look up the public keys of token issuers. The default is to make a new one by calling [`pub-keystore`](https://github.com/davedoesdev/pub-keystore#moduleexportsconfig-cb).

  - `{WebAuthn4JS} [webAuthn]` If you have a pre-existing [`WebAuthn4JS`](http://rawgit.davedoesdev.com/davedoesdev/webauthn4js/master/docs/interfaces/webauthn4js.webauthn4js-1.html) instance, pass it here. The default is to make a new one by calling [`webauthn4js`](http://rawgit.davedoesdev.com/davedoesdev/webauthn4js/master/docs/modules/webauthn4js.html#exports).

- `{Function} cb` Function called with the result of creating the authorizer. It will receive the following arguments:
  - `{Object} err` If an error occurred then details of the error, otherwise `null`.

  - `{AuthorizeJWT} authz` The `AuthorizeJWT` object. As well as `AuthorizeJWT`'s prototype methods, it has the following properties:
    - `{PubKeyStore} keystore` The [`PubKeyStore`](https://github.com/davedoesdev/pub-keystore#pubkeystore) object that the authorizer is using to look up the public keys of token issuers. For example, you could listen to [PubKeyStore.events.change](https://github.com/davedoesdev/pub-keystore#pubkeystoreeventschangeuri-rev-deleted) events so you know that previously verified tokens are invalid.

    - `{WebAuthn4JS} [webAuthn]` The [`WebAuthn4JS`](http://rawgit.davedoesdev.com/davedoesdev/webauthn4js/master/docs/interfaces/webauthn4js.webauthn4js-1.html) object being used to verify assertions, if `WEBAUTHN_MODE` is truthy.

<sub>Go: [TOC](#tableofcontents) | [module](#toc_module)</sub>

<a name="authorizejwtprototype"></a>

<a name="authorizejwt"></a>

## AuthorizeJWT.prototype.get_authz_data(req, cb)

> Extracts JSON Web Tokens from a HTTP request.

**Parameters:**

- `{http.IncomingMessage} req` [HTTP request object](http://nodejs.org/api/http.html#http_http_incomingmessage) which should contain the tokens either in the `Authorization` header (Basic or Bearer auth) or in the `authz_token` query string parameter.
- `{Function} cb` Function called with the tokens obtained from `req`. The `Authorization` header is used in preference to the query string. `cb` will receive the following arguments:
  - `{Object} err` If an error occurred then details of the error, otherwise `null`.

  - `{String} info` Extra information retrieved from `req` along with the tokens. This is either the username extracted from the `Authorization` header or the `authz_info` query string parameter.

  - `{String|Array} token` The JSON Web Tokens retrieved from `req`. If only one token is retrieved, it will be passed as a string, otherwise an array of the tokens retrieved will be passed. If no tokens are present in `req` then `info` and `token` will be `undefined`. The tokens are obtained from _either_:

    - The password part of the `Authorization` header, split into multiple tokens using comma as a separator.
    - _Or_ from any `authz_token` query string parameters present.

<sub>Go: [TOC](#tableofcontents) | [AuthorizeJWT.prototype](#toc_authorizejwtprototype)</sub>

## AuthorizeJWT.prototype.authorize(authz_token, algorithms, cb)

> Authorizes (or not) a JSON Web Token.

The token must pass all the tests made by [`jose`](https://github.com/panva/jose/blob/master/docs/README.md#jwtverifytoken-keyorstore-options) and

- If `config.max_token_expiry` was passed to [`module.exports`](#moduleexportsconfig-cb) then the token must expire sooner than `config.max_token_expiry` seconds in the future.

**Parameters:**

- `{String | Object} authz_token` The token to authorize.


  - If `config.WEBAUTHN_MODE` was _not_ passed truthy to [`module.exports`](#moduleexportsconfig-cb) then `authz_token` must be a JWT string.

    - The `iss` property in the token's payload is used to retrieve a public key from `AuthorizeJWT`'s key store using [`PubKeyStore.prototype_get_pub_key_by_issuer_id`](https://github.com/davedoesdev/pub-keystore#pubkeystoreprototypeget_pub_key_by_issuer_idissuer_id-cb).
    - If the retrieved value has a `pub_key` property then that is used as the public key otherwise the retrieved value itself is used.

  - If `config.WEBAUTHN_MODE` _was_ passed truthy to [`module.exports`](#moduleexportsconfig-cb) then `authz_token` must be a [Web Authentication](https://www.w3.org/TR/webauthn/) assertion. It must either be an object with the following properties or a string of the form `issuer_id.id.clientDataJSON.authenticatorData.signature.userHandle` - i.e. `issuer_id` and the properties of `car.response` (both described below) separated by a period. In the latter case, the remaining `opts` property is obtained by calling `config.complete_webauthn_token` (see [`module.exports`](#moduleexportsconfig-cb)).

    - `{String} issuer_id` This is used to retrieve a [`User`](http://rawgit.davedoesdev.com/davedoesdev/webauthn4js/master/docs/interfaces/webauthn4js.user.html) from `AuthorizeJWT`'s key store using [`PubKeyStore.prototype_get_pub_key_by_issuer_id`](https://github.com/davedoesdev/pub-keystore#pubkeystoreprototypeget_pub_key_by_issuer_idissuer_id-cb).
      - If the retrieved value has a `user` property then that is used as the user otherwise the retrieved value itself is used.
    - `{(`[`PublicKeyCredentialRequestOptions`](http://rawgit.davedoesdev.com/davedoesdev/webauthn4js/master/docs/interfaces/webauthn4js.publickeycredentialrequestoptions.html)` => `[`PublicKeyCredentialRequestOptions`](http://rawgit.davedoesdev.com/davedoesdev/webauthn4js/master/docs/interfaces/webauthn4js.publickeycredentialrequestoptions.html)`)}[]` [opts] Optional list of functions which were used to modify the login requirements when producing `car`.
    - `{`[`CredentialAssertionResponse`](http://rawgit.davedoesdev.com/davedoesdev/webauthn4js/master/docs/interfaces/webauthn4js.credentialassertionresponse.html)`} car` The credential assertion result that was generated by the authenticator in the browser. It must contain an _unsigned_ JWT in its client data.

- `{Array} algorithms` This is passed to [`jose`](https://github.com/panva/jose/blob/master/docs/README.md#jwtverifytoken-keyorstore-options) and specifies the algorithms expected to be used to sign `authz_token`. If you pass `undefined` then all algorithms available on the public key are allowed. Note this parameter is ignored if `config.WEBAUTHN_MODE` was passed truthy to [`module.exports`](#moduleexportsconfig-cb).
- `{Function} cb` Function called with the result of authorizing the token. It will receive the following arguments:
  - `{Object} err` If authorization fails for some reason (e.g. the token isn't valid) then details of the failure, otherwise `null`.

  - `{Object} payload` The JWT's payload.

  - `{String} uri` The permanent URI of the token's issuer. This is different to the issuer ID in the payload's `iss` property (`PubKeyStore` generates a different issuer ID each time a public key is stored, even for the same issuer).

  - `{String} rev` Revision string for the public key used to verify the token. You can use this to identify tokens that become invalid when a [PubKeyStore.events.change](https://github.com/davedoesdev/pub-keystore#pubkeystoreeventschangeuri-rev-deleted) event occurs for the same issuer but with a different revision string.

  - `{`[`Credential`](http://rawgit.davedoesdev.com/davedoesdev/webauthn4js/master/docs/interfaces/webauthn4js.credential.html)`} [credential]` If `config.WEBAUTHN_MODE` was passed truthy to [`module.exports`](#moduleexportsconfig-cb) then this contains the validated credential, plus the issuer ID in the `issuer_id` property and the [`User`](http://rawgit.davedoesdev.com/davedoesdev/webauthn4js/master/docs/interfaces/webauthn4js.user.html) in the `user` property.

<sub>Go: [TOC](#tableofcontents) | [AuthorizeJWT.prototype](#toc_authorizejwtprototype)</sub>

## AuthorizeJWT.prototype.close(cb)

> Closes the JW authorizer.

If you passed your own `keystore` or `webAuthn` to [`module.exports`](#moduleexportsconfig-cb), it will _not_ be closed.

**Parameters:**

- `{Function} cb` Called when everything's closed. It will receive the following argument:
  - `{Object} err` If something failed to close, details of the error.

<sub>Go: [TOC](#tableofcontents) | [AuthorizeJWT.prototype](#toc_authorizejwtprototype)</sub>

_&mdash;generated by [apidox](https://github.com/codeactual/apidox)&mdash;_
