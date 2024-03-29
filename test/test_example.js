/*global describe: false,
         it: false */
/*jslint node: true, unparam: true */
"use strict";

describe('example in README', function () {
    it('should pass', function (cb) {
        this.timeout(60000);

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

    });
});
