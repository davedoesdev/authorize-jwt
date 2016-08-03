# authorize-jwt&nbsp;&nbsp;&nbsp;[![Build Status](https://travis-ci.org/davedoesdev/authorize-jwt.png)](https://travis-ci.org/davedoesdev/authorize-jwt) [![Coverage Status](https://coveralls.io/repos/davedoesdev/authorize-jwt/badge.png?branch=master)](https://coveralls.io/r/davedoesdev/authorize-jwt?branch=master) [![NPM version](https://badge.fury.io/js/authorize-jwt.png)](http://badge.fury.io/js/authorize-jwt)

Simple [JSON Web Token](http://self-issued.info/docs/draft-ietf-oauth-json-web-token.html) authorization module for Node.js.

- Uses [`node-jsjws`](https://github.com/davedoesdev/node-jsjws) to perform verification of tokens.
- Uses [`pub-keystore`](https://github.com/davedoesdev/pub-keystore) to retrieve and manage token issuers' public keys.
- Adds extra checks for token audience and maximum expiry time.
- Optional 'anonymous' mode where token signatures aren't verified.
- Extracts tokens from HTTP Basic Authorization headers or query strings.
- Unit tests with 100% code coverage.

The API is described [here](#tableofcontents).

## Example

```javascript
var authorize_jwt = require('authorize-jwt'),
    http = require('http'),
    assert = require('assert'),
    jsjws = require('jsjws'),
    priv_key = require('ursa').generatePrivateKey(2048, 65537),
    pub_key = priv_key.toPublicPem('utf8'),
    the_uri = 'mailto:example@davedoesdev.com',
    audience = 'urn:authorize-jwt:example';

// create authorization object
authorize_jwt(
{
    db_type: 'pouchdb',
    db_for_update: true, // we're going to update a public key
    username: 'admin',
    password: 'admin',
    jwt_audience_uri: audience,
    jwt_max_token_expiry: 60
}, function (err, authz)
{
    assert.ifError(err);

    var the_issuer_id, the_rev, change_rev;

    function doit()
    {
        assert.equal(the_rev, change_rev);

        // create and sign a JWT
        var exp = new Date(), the_token, http_server;
        exp.setMinutes(exp.getMinutes() + 1);
        the_token = new jsjws.JWT().generateJWTByKey({ alg: 'PS256' },
        {
            iss: the_issuer_id,
            aud: audience,
            foo: 'bar'
        }, exp, priv_key);

        // send and receive the token via HTTP Basic Auth
        http_server = http.createServer(function (req, res)
        {
            authz.get_authz_data(req, function (err, info, token)
            {
                assert.ifError(err);
                assert.equal(info, 'test');
                assert.equal(token, the_token);

                // authorize the token
                authz.authorize(token, ['PS256'], function (err, payload, uri, rev)
                {
                    assert.ifError(err);
                    assert.equal(uri, the_uri);
                    assert.equal(rev, the_rev);
                    assert.equal(payload.foo, 'bar');
                    res.end();
                    http_server.close();
                    console.log('done')
                });
            });
        }).listen(6000, '127.0.0.1', function ()
        {
            http.request({ hostname: '127.0.0.1', port: 6000, auth: 'test:' + the_token }).end();
        });
    }

    // just to demonstrate change events
    authz.keystore.once('change', function (uri, rev)
    {
        assert.equal(uri, the_uri);
        change_rev = rev;
        if (the_rev) { doit(); }
    });

    // add public key to the store
    authz.keystore.add_pub_key(the_uri, pub_key, function (err, issuer_id, rev)
    {
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

_Source: [index.js](/index.js)_

<a name="tableofcontents"></a>

- <a name="toc_moduleexportsconfig-cb"></a><a name="toc_module"></a>[module.exports](#moduleexportsconfig-cb)
- <a name="toc_authorizejwtprototypeget_authz_datareq-cb"></a><a name="toc_authorizejwtprototype"></a><a name="toc_authorizejwt"></a>[AuthorizeJWT.prototype.get_authz_data](#authorizejwtprototypeget_authz_datareq-cb)
- <a name="toc_authorizejwtprototypeauthorizeauthz_token-allowed_algs-cb"></a>[AuthorizeJWT.prototype.authorize](#authorizejwtprototypeauthorizeauthz_token-allowed_algs-cb)

<a name="module"></a>

## module.exports(config, cb)

> Creates a JWT authorizer.

**Parameters:**

- `{Object} config` Configures the authorizer. `config` is passed down to [`pub-keystore`](https://github.com/davedoesdev/pub-keystore#moduleexportsconfig-cb) and [`node-jsjws`](https://github.com/davedoesdev/node-jsjws#jwtprototypeverifyjwtbykeyjwt-options-key-allowed_algs). The following extra properties are supported: 
  - `{String} [jwt_audience_uri]` If set then all JSON Web Tokens must have an `aud` property in their payload which exactly equals `jwt_audience_uri`. Defaults to `undefined`.

  - `{Integer} [jwt_max_token_expiry]` If set then all JSON Web Tokens must expire sooner than `jwt_max_token_expiry` seconds in the future (from the time they're presented). Defaults to `undefined`.

  - `{Boolean} [ANONYMOUS_MODE]` Whether to authorize all JSON Web Tokens without verifying their signatures. Note that tokens must always pass the [basic checks](https://github.com/davedoesdev/node-jsjws#jwtprototypeverifyjwtbykeyjwt-options-key-allowed_algs) performed by `node-jsjws`. Defaults to `false`.

- `{Function} cb` Function called with the result of creating the authorizer. It will receive the following arguments: 
  - `{Object} err` If an error occurred then details of the error, otherwise `null`.

  - `{AuthorizeJWT} authz` The `AuthorizeJWT` object. As well as `AuthorizeJWT`'s prototype methods, it has the following property:

    - `{PubKeyStore} keystore` The [`PubKeyStore`](https://github.com/davedoesdev/pub-keystore#pubkeystore) object that the authorizer is using to lookup the public keys of token issuers. For example, you could listen to [PubKeyStore.events.change](https://github.com/davedoesdev/pub-keystore#pubkeystoreeventschangeuri-rev-deleted) events so you know that previously verified tokens are invalid. Note: If you pass `config.ANONYMOUS_MODE` as `true` then `keystore` will be `undefined`.

<sub>Go: [TOC](#tableofcontents) | [module](#toc_module)</sub>

<a name="authorizejwtprototype"></a>

<a name="authorizejwt"></a>

## AuthorizeJWT.prototype.get_authz_data(req, cb)

> Extracts JSON Web Tokens from a HTTP request.

**Parameters:**

- `{http.IncomingMessage} req` [HTTP request object](http://nodejs.org/api/http.html#http_http_incomingmessage) which should contain the tokens either in the `Authorization` header (Basic Auth) or in the `authz_token` query string parameter. 
- `{Function} cb` Function called with the tokens obtained from `req`. The `Authorization` header is used in preference to the query string. `cb` will receive the following arguments: 
  - `{Object} err` If an error occurred then details of the error, otherwise `null`.

  - `{String} info` Extra information retrieved from `req` along with the tokens. This is either the username extracted from the `Authorization` header or the `authz_info` query string parameter.

  - `{String|Array} token` The JSON Web Tokens retrieved from `req`. They are obtained from _either_:

    - The password part of the `Authorization` header, split into multiple tokens using comma as a separator.
    - _Or_ from any `authz_token` query string parameters present. 

    If only one token is retrieved, it will be passed as a string, otherwise an array of the tokens retrieved will be passed. If no tokens are present in `req` then `info` and `token` will be `undefined`.

<sub>Go: [TOC](#tableofcontents) | [AuthorizeJWT.prototype](#toc_authorizejwtprototype)</sub>

## AuthorizeJWT.prototype.authorize(authz_token, allowed_algs, cb)

> Authorizes (or not) a JSON Web Token.

The token must pass all the [tests made by node-jsjws](https://github.com/davedoesdev/node-jsjws#jwtprototypeverifyjwtbykeyjwt-options-key-allowed_algs) and

- If `config.jwt_audience_uri` was passed to [`module.exports`](#moduleexportsconfig-cb) then the token's payload must have a matching `aud` property.

- If `config.jwt_max_token_expiry` was passed to `module.exports` then the token must expire sooner than `config.jwt_max_token_expiry` seconds in the future.

**Parameters:**

- `{String | JWT} authz_token` The JWT to authorize. Unless `config.ANONYMOUS_MODE` was passed to `module.exports` then the `iss` property in the token's payload is used to retrieve a public key from `AuthorizeJWT`'s key store using [`PubKeyStore.prototype_get_pub_key_by_issuer_id`](https://github.com/davedoesdev/pub-keystore#pubkeystoreprototypeget_pub_key_by_issuer_idissuer_id-cb). If you don't pass the token as a string then it must be a [`node_jsjws.JWT`](https://github.com/davedoesdev/node-jsjws#jwt) object, pre-processed by calling [`processJWS`](https://github.com/davedoesdev/node-jsjws#jwsprototypeprocessjwsjws). 
- `{Array | Object} allowed_algs` This is passed to [node-jsjws](https://github.com/davedoesdev/node-jsjws#jwtprototypeverifyjwtbykeyjwt-options-key-allowed_algs) and specifies the algorithms expected to be used to sign `authz_token`. If you pass an `Object` then its properties define the set of algorithms expected. 
- `{Function} cb` Function called with the result of authorizing the token. It will receive the following arguments: 
  - `{Object} err` If authorization fails for some reason (e.g. the token isn't valid) then details of the failure, otherwise `null`.

  - `{Object} payload` The token's payload.

  - `{String} uri` The permanent URI of the token's issuer. This is different to the issuer ID in the payload's `iss` property (`PubKeyStore` generates a different issuer ID each time a public key is stored, even for the same issuer).

  - `{String} rev` Revision string for the public key used to verify the token. You can use this to identify tokens that become invalid when a [PubKeyStore.events.change](https://github.com/davedoesdev/pub-keystore#pubkeystoreeventschangeuri-rev-deleted) event occurs for the same issuer but with a different revision string.

<sub>Go: [TOC](#tableofcontents) | [AuthorizeJWT.prototype](#toc_authorizejwtprototype)</sub>

_&mdash;generated by [apidox](https://github.com/codeactual/apidox)&mdash;_
