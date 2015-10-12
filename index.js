/**
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
*/
/*jslint node: true, nomen: true */

"use strict";

var util = require('util'),
    url = require('url'),
    jsjws = require('jsjws'),
    basic_auth_parser = require('basic-auth-parser'),
    pub_keystore = require('pub-keystore');

function AuthorizeJWT(config, keystore)
{
    this._config = config;
    this.keystore = keystore;
}

/**
Creates a JWT authorizer.

@param {Object} config Configures the authorizer. `config` is passed down to [`pub-keystore`](https://github.com/davedoesdev/pub-keystore#moduleexportsconfig-cb) and [`node-jsjws`](https://github.com/davedoesdev/node-jsjws#jwtprototypeverifyjwtbykeyjwt-options-key-allowed_algs). The following extra properties are supported:

  - `{String} [jwt_audience_uri]` If set then all JSON Web Tokens must have an `aud` property in their payload which exactly equals `jwt_audience_uri`. Defaults to `undefined`.

  - `{Integer} [jwt_max_token_expiry]` If set then all JSON Web Tokens must expire sooner than `jwt_max_token_expiry` seconds in the future (from the time they're presented). Defaults to `undefined`.

  - `{Boolean} [ANONYMOUS_MODE]` Whether to authorize all JSON Web Tokens without verifying their signatures. Note that tokens must always pass the [basic checks](https://github.com/davedoesdev/node-jsjws#jwtprototypeverifyjwtbykeyjwt-options-key-allowed_algs) performed by `node-jsjws`. Defaults to `false`.

@param {Function} cb Function called with the result of creating the authorizer. It will receive the following arguments:

  - `{Object} err` If an error occurred then details of the error, otherwise `null`.

  - `{AuthorizeJWT} authz` The `AuthorizeJWT` object. As well as `AuthorizeJWT`'s prototype methods, it has the following property:

    - `{PubKeyStore} keystore` The [`PubKeyStore`](https://github.com/davedoesdev/pub-keystore#pubkeystore) object that the authorizer is using to lookup the public keys of token issuers. For example, you could listen to [PubKeyStore.events.change](https://github.com/davedoesdev/pub-keystore#pubkeystoreeventschangeuri-rev-deleted) events so you know that previously verified tokens are invalid. Note: If you pass `config.ANONYMOUS_MODE` as `true` then `keystore` will be `undefined`.
*/
module.exports = function (config, cb)
{
    if (config.ANONYMOUS_MODE)
    {
        cb(null, new AuthorizeJWT(config));
    }
    else
    {
        pub_keystore(config, function (err, ks)
        {
            if (err) { return cb(err); }
            cb(null, new AuthorizeJWT(config, ks));
        });
    }
};

AuthorizeJWT.prototype._validate_token = function (payload, uri, rev, cb)
{
    if (this._config.jwt_audience_uri &&
        (payload.aud !== this._config.jwt_audience_uri))
    {
        return cb(new Error('unrecognized authorization token audience: ' + payload.aud));
    }

    if (this._config.jwt_max_token_expiry)
    {
        var now = new Date().getTime() / 1000;

        if ((payload.exp - now) > this._config.jwt_max_token_expiry) 
        {
            return cb(new Error('authorization token expiry too long'));
        }
    }

    cb(null, payload, uri, rev);
};

/**
Extracts a JSON Web Token from a HTTP request.

@param {http.IncomingMessage} req [HTTP request object](http://nodejs.org/api/http.html#http_http_incomingmessage) which should contain the token either in the `Authorization` header (Basic Auth) or in the `authz_token` query string parameter.

@param {Function} cb Function called with the token obtained from `req`. The `Authorization` header is used in preference to the query string. `cb` will receive the following arguments:

  - `{Object} err` If an error occurred then details of the error, otherwise `null`.

  - `{String} info` Extra information retrieved from `req` along with the token. This is either the username extracted from the `Authorization` header or the `authz_info` query string parameter.

  - `{String} token` The JSON Web Token retrieved from `req`. This is either the password extracted from the `Authorization` header or the `authz_token` query string parameter.
*/
AuthorizeJWT.prototype.get_authz_data = function (req, cb)
{
    var parsed_auth, authz_info, authz_token;
    
    if (req.headers.authorization)
    {
        parsed_auth = basic_auth_parser(req.headers.authorization);
        authz_info = parsed_auth.username;
        authz_token = parsed_auth.password;
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

The token must pass all the [tests made by node-jsjws](https://github.com/davedoesdev/node-jsjws#jwtprototypeverifyjwtbykeyjwt-options-key-allowed_algs) and

- If `config.jwt_audience_uri` was passed to [`module.exports`](#moduleexportsconfig-cb) then the token's payload must have a matching `aud` property.

- If `config.jwt_max_token_expiry` was passed to `module.exports` then the token must expire sooner than `config.jwt_max_token_expiry` seconds in the future.

@param {String|JWT} authz_token The JWT to authorize. Unless `config.ANONYMOUS_MODE` was passed to `module.exports` then the `iss` property in the token's payload is used to retrieve a public key from `AuthorizeJWT`'s key store using [`PubKeyStore.prototype_get_pub_key_by_issuer_id`](https://github.com/davedoesdev/pub-keystore#pubkeystoreprototypeget_pub_key_by_issuer_idissuer_id-cb). If you don't pass the token as a string then it must be a [`node_jsjws.JWT`](https://github.com/davedoesdev/node-jsjws#jwt) object, pre-processed by calling [`processJWS`](https://github.com/davedoesdev/node-jsjws#jwsprototypeprocessjwsjws).

@param {Array|Object} allowed_algs This is passed to [node-jsjws](https://github.com/davedoesdev/node-jsjws#jwtprototypeverifyjwtbykeyjwt-options-key-allowed_algs) and specifies the algorithms expected to be used to sign `authz_token`. If you pass an `Object` then its properties define the set of algorithms expected.

@param {Function} cb Function called with the result of authorizing the token. It will receive the following arguments:

  - `{Object} err` If authorization fails for some reason (e.g. the token isn't valid) then details of the failure, otherwise `null`.

  - `{Object} payload` The token's payload.

  - `{String} uri` The permanent URI of the token's issuer. This is different to the issuer ID in the payload's `iss` property (`PubKeyStore` generates a different issuer ID each time a public key is stored, even for the same issuer).

  - `{String} rev` Revision string for the public key used to verify the token. You can use this to identify tokens that become invalid when a [PubKeyStore.events.change](https://github.com/davedoesdev/pub-keystore#pubkeystoreeventschangeuri-rev-deleted) event occurs for the same issuer but with a different revision string.
*/
AuthorizeJWT.prototype.authorize = function (authz_token, allowed_algs, cb)
{
    var ths = this, jwt, payload, header, issuer_id, allowed_algs2;

    if (!authz_token)
    {
        return cb(new Error('no authorization token'));
    }

    if (authz_token.parsedJWS)
    {
        jwt = authz_token;
        authz_token = jwt.parsedJWS.si + '.' + jwt.parsedJWS.sivalB64U;
    }
    else
    {
        jwt = new jsjws.JWT();
    }

    try
    {
        // Don't verify signature now - we do it below if not in anonymous mode.
        // We have to allow the 'none' alg because we're passing a null key.
        // But we check for 'none' algs in the header explicitly later.
        if (Array.isArray(allowed_algs))
        {
            allowed_algs2 = allowed_algs.concat('none');
        }
        else
        {
            allowed_algs2 = Object.create(allowed_algs);
            allowed_algs2.none = true;
        }
        jwt.verifyJWTByKey(authz_token, this._config, null, allowed_algs2);
    }
    catch (ex)
    {
        return cb(ex.message);
    }

    payload = jwt.getParsedPayload();

    if (this._config.ANONYMOUS_MODE)
    {
        return this._validate_token(payload, null, null, cb);
    }

    if (!(payload && payload.iss))
    {
        return cb(new Error('no issuer found in authorization token'));
    }

    issuer_id = payload.iss;

    header = jwt.getParsedHeader();

    if (header.alg === 'none')
    {
        return cb(new Error('anonymous token received but not in anonymous mode'));
    }

    this.keystore.get_pub_key_by_issuer_id(issuer_id, function (err, pem, uri, rev)
    {
        if (err)
        {
            return cb(err);
        }

        if (!pem)
        {
            return cb(new Error('no public key found for issuer ID ' + issuer_id));
        }

        var pub_key = jsjws.createPublicKey(pem, 'utf8');

        try
        {
            jwt.verifyJWTByKey(authz_token, ths._config, pub_key, allowed_algs);
        }
        catch (ex)
        {
            return cb(ex.message);
        }

        return ths._validate_token(payload, uri, rev, cb);
    });
};
