/*global it: false,
         describe: false,
         before: false,
         after: false */
/*jslint node: true, nomen: true */
"use strict";

var http = require('http'),
    child_process = require('child_process'),
    path = require('path'),
    pub_keystore = require('pub-keystore'),
    { JWK, JWT } = require('jose'),
    expect = require('chai').expect,
    authorize_jwt = require('..'),
    uri1 = 'mailto:dave@davedoesdev.com',
    uri2 = 'http://www.davedoesdev.com',
    audience = 'urn:authorize-jwt:test';

function expr(v) { return v; }

function setup(db_type, kty, alg, crvOrSize)
{
function serialize_key(priv_key) {
    if (db_type === 'in-mem') {
        return priv_key;
    }
    if (priv_key.type === 'secret') {
        return priv_key.toJWK(true);
    }
    return priv_key.toPEM();
}

describe(`authorize-jwt db_type=${db_type} kty=${kty} alg=${alg}`, function ()
{
    var priv_key1,
        priv_key2,
        ks_for_update,
        issuer_id1,
        issuer_id2,
        rev1,
        rev2,
        authz,
        skew_authz,
        no_audience_authz,
        token_no_issuer,
        token_unknown_issuer,
        token_no_audience,
        token_wrong_audience,
        token_beyond_max_expiry,
        token_short_expiry,
        token_wrong_signer,
        token_no_signer,
        token,
        token2,
        allowed_algs = [alg];

    before(function (cb)
    {
        // put public key into keystore

        priv_key1 = JWK.generateSync(kty, crvOrSize, { alg });
        priv_key2 = JWK.generateSync(kty, crvOrSize, { alg });

        var pub_key1 = serialize_key(priv_key1),
            pub_key2 = serialize_key(priv_key2);

        pub_keystore(
        {
            db_type,
            db_for_update: true,
            no_changes: true,
            username: 'admin',
            password: 'admin'
        }, function (err, ks)
        {
            if (err) { return cb(err); }
            expect(ks.db_type).to.equal(db_type);
            ks_for_update = ks;
            ks_for_update.add_pub_key(uri1, pub_key1, function (err, issuer_id, rev)
            {
                if (err) { return cb(err); }
                issuer_id1 = issuer_id;
                rev1 = rev;

                ks_for_update.add_pub_key(uri2, { pub_key: pub_key2 }, function (err, issuer_id, rev)
                {
                    if (err) { return cb(err); }
                    issuer_id2 = issuer_id;
                    rev2 = rev;

                    ks_for_update.deploy(cb);
                });
            });
        });
    });
    
    after(function (cb)
    {
        ks_for_update.close(cb);
    });

    before(function (cb)
    {
        // create JWT authorizer

        authorize_jwt(
        {
            db_type,
            deploy_name: 'test',
            audience,
            max_token_expiry: 60,
            keep_master_open: true,
            username: 'admin',
            password: 'admin',
            share_keys_with: ks_for_update
        }, function (err, the_authz)
        {
            if (err) { return cb(err); }
            expect(the_authz.keystore.db_type).to.equal(db_type);
            authz = the_authz;
            cb();
        });
    });

    after(function (cb)
    {
        authz.keystore.close(function (err)
        {
            //TODOexpr(expect(err).to.exist); // closed in final test
            cb();
        });
    });

    before(function (cb)
    {
        authorize_jwt(
        {
            db_type,
            deploy_name: 'skew',
            audience,
            max_token_expiry: 60,
            keep_master_open: true,
            clockTolerance: '1m',
            username: 'admin',
            password: 'admin',
            share_keys_with: ks_for_update
        }, function (err, the_authz)
        {
            if (err) { return cb(err); }
            expect(the_authz.keystore.db_type).to.equal(db_type);
            skew_authz = the_authz;
            cb();
        });
    });

    after(function (cb)
    {
        skew_authz.keystore.close(cb);
    });

    before(function (cb)
    {
        authorize_jwt(
        {
            db_type,
            deploy_name: 'no_audience',
            max_token_expiry: 60,
            keep_master_open: true,
            username: 'admin',
            password: 'admin',
            share_keys_with: ks_for_update
        }, function (err, the_authz)
        {
            if (err) { return cb(err); }
            expect(the_authz.keystore.db_type).to.equal(db_type);
            no_audience_authz = the_authz;
            cb();
        });
    });

    after(function (cb)
    {
        no_audience_authz.keystore.close(cb);
    });

    before(function ()
    {
        // generate token

        const expiresIn = '1m';

        token_no_issuer = JWT.sign({
            foo: 'wup'
        }, priv_key1, {
            algorithm: alg,
            audience,
            expiresIn
        });
        
        token_unknown_issuer = JWT.sign({}, priv_key1, {
            algorithm: alg,
            audience,
            expiresIn,
            issuer: 'foobar'
        });

        token_no_audience = JWT.sign({}, priv_key1, {
            algorithm: alg,
            expiresIn,
            issuer: issuer_id1
        });

        token_wrong_audience = JWT.sign({}, priv_key1, {
            algorithm: alg,
            audience: 'some audience',
            expiresIn,
            issuer: issuer_id1
        });

        token = JWT.sign({
            foo: 90
        }, priv_key1, {
            algorithm: alg,
            audience,
            expiresIn,
            issuer: issuer_id1
        });
        
        token2 = JWT.sign({
            foo: 90
        }, priv_key2, {
            algorithm: alg,
            audience,
            expiresIn,
            issuer: issuer_id2
        });

        token_wrong_signer = JWT.sign({
            foo: 'bar'
        }, priv_key2, {
            algorithm: alg,
            audience,
            expiresIn,
            issuer: issuer_id1
        });

        token_no_signer = JWT.sign({
            foo: 'bar'
        }, JWK.None, {
            audience,
            expiresIn,
            issuer: issuer_id1
        });

        token_beyond_max_expiry = JWT.sign({}, priv_key1, {
            algorithm: alg,
            audience,
            expiresIn: '2m',
            issuer: issuer_id1
        });

        token_short_expiry = JWT.sign({
            foo: 'bar'
        }, priv_key1, {
            algorithm: alg,
            audience,
            expiresIn: '0s',
            issuer: issuer_id1
        });
    });

    it('should fail to make when passed an unknown keystore type', function (cb)
    {
        authorize_jwt(
        {
            db_type: 'foobar'
        }, function (err)
        {
            expr(expect(err).to.exist);
            cb();
        });
    });

    it('should use keystore config property', function (cb)
    {
        var ks = new Object();
        authorize_jwt(
        {
            keystore: ks
        }, function (err, authz)
        {
            if (err) { return cb(err); }
            expect(authz.keystore).to.equal(ks);
            cb();
        });
    });

    it('should fail to authorize JWT without an issuer', function (cb)
    {
        authz.authorize(token_no_issuer, allowed_algs, function (err)
        {
            expr(expect(err).to.exist);
            cb();
        });
    });

    it('should fail to authorize JWT with an unknown issuer', function (cb)
    {
        authz.authorize(token_unknown_issuer, allowed_algs, function (err)
        {
            expr(expect(err).to.exist);
            cb();
        });
    });

    it('should fail to authorize a JWT without an audience', function (cb)
    {
        authz.authorize(token_no_audience, allowed_algs, function (err)
        {
            expr(expect(err).to.exist);
            cb();
        });
    });

    it('should fail to authorize a JWT with the wrong audience', function (cb)
    {
        authz.authorize(token_wrong_audience, allowed_algs, function (err)
        {
            expr(expect(err).to.exist);
            cb();
        });
    });

    it('should authorize a JWT without an audience when configured without an audience', function (cb)
    {
        no_audience_authz.authorize(token_no_audience, allowed_algs, function (err)
        {
            expr(expect(err).not.to.exist);
            cb();
        });
    });

    it('should authorize a JWT with an audience when configured without an audience', function (cb)
    {
        no_audience_authz.authorize(token, allowed_algs, function (err)
        {
            expr(expect(err).not.to.exist);
            cb();
        });
    });

    it('should fail to authorize a JWT with expiry beyond max expiry', function (cb)
    {
        authz.authorize(token_beyond_max_expiry, allowed_algs, function (err)
        {
            expr(expect(err).to.exist);
            cb();
        });
    });

    it('should fail to authorize a JWT signed with the wrong private key', function (cb)
    {
        authz.authorize(token_wrong_signer, allowed_algs, function (err)
        {
            expr(expect(err).to.exist);
            cb();
        });
    });

    it('should authorize a valid JWT', function (cb)
    {
        authz.authorize(token, allowed_algs, function (err, payload, uri, rev)
        {
            if (err) { return cb(err); }
            expect(uri).to.equal(uri1);
            expect(rev).to.equal(rev1);
            expect(payload.foo).to.equal(90);
            cb();
        });
    });

    it('should authorize a valid JWT (pub key as property)', function (cb)
    {
        authz.authorize(token2, allowed_algs, function (err, payload, uri, rev)
        {
            if (err) { return cb(err); }
            expect(uri).to.equal(uri2);
            expect(rev).to.equal(rev2);
            expect(payload.foo).to.equal(90);
            cb();
        });
    });

    it('should fail to authorize expired token', function (cb)
    {
        authz.authorize(token_short_expiry, allowed_algs, function (err)
        {
            expr(expect(err).to.exist);
            cb();
        });
    });

    it('should fail to authorize malformed token', function (cb)
    {
        authz.authorize('foobar', allowed_algs, function (err)
        {
            expr(expect(err).to.exist);
            cb();
        });
    });

    it('should pass on JWT verify options', function (cb)
    {
        skew_authz.authorize(token_short_expiry, allowed_algs, function (err, payload, uri, rev)
        {
            if (err) { return cb(err); }
            expect(uri).to.equal(uri1);
            expect(rev).to.equal(rev1);
            expect(payload.foo).to.equal('bar');
            cb();
        });
    });

    it('should not allow unsigned tokens', function (cb)
    {
        authz.authorize(token_no_signer, allowed_algs, function (err)
        {
            expr(expect(err).to.exist);
            cb();
        });
    });

    it('should error when given an empty token', function (cb)
    {
        authz.authorize('', allowed_algs, function (err)
        {
            expr(expect(err).to.exist);
            cb();
        });
    });

    it('should extract authorization data from HTTP header (Basic)', function (cb)
    {
        var http_server = http.createServer(function (req, res)
        {
            authz.get_authz_data(req, function (err, req_info, req_token)
            {
                if (err) { return cb(err); }
                expect(req_info).to.equal('test');
                expect(req_token).to.equal(token);
                res.end();
                http_server.close(cb);
            });
        }).listen(6000, '127.0.0.1', function (err)
        {
            if (err) { return cb(err); }
            http.request(
            {
                hostname: '127.0.0.1',
                port: 6000,
                auth: 'test:' + token
            }).end();
        });
    });

    it('should extract multiple authorization tokens from HTTP header (Basic)', function (cb)
    {
        var http_server = http.createServer(function (req, res)
        {
            authz.get_authz_data(req, function (err, req_info, req_token)
            {
                if (err) { return cb(err); }
                expect(req_info).to.equal('test');
                expect(req_token).to.eql([token, token_no_issuer]);
                res.end();
                http_server.close(cb);
            });
        }).listen(6000, '127.0.0.1', function (err)
        {
            if (err) { return cb(err); }
            http.request(
            {
                hostname: '127.0.0.1',
                port: 6000,
                auth: 'test:' + token + ',' + token_no_issuer
            }).end();
        });
    });

    it('should extract authorization data from HTTP header (Bearer)', function (cb)
    {
        var http_server = http.createServer(function (req, res)
        {
            authz.get_authz_data(req, function (err, req_info, req_token)
            {
                if (err) { return cb(err); }
                expect(req_info).to.equal('');
                expect(req_token).to.equal(token);
                res.end();
                http_server.close(cb);
            });
        }).listen(6000, '127.0.0.1', function (err)
        {
            if (err) { return cb(err); }
            http.request(
            {
                hostname: '127.0.0.1',
                port: 6000,
                headers: {
                    Authorization: 'Bearer ' + token
                }
            }).end();
        });
    });

    it('should extract multiple authorization tokens from HTTP header (Bearer)', function (cb)
    {
        var http_server = http.createServer(function (req, res)
        {
            authz.get_authz_data(req, function (err, req_info, req_token)
            {
                if (err) { return cb(err); }
                expect(req_info).to.equal('');
                expect(req_token).to.eql([token, token_no_issuer]);
                res.end();
                http_server.close(cb);
            });
        }).listen(6000, '127.0.0.1', function (err)
        {
            if (err) { return cb(err); }
            http.request(
            {
                hostname: '127.0.0.1',
                port: 6000,
                headers: {
                    Authorization: 'Bearer ' + token + ',' + token_no_issuer
                }
            }).end();
        });
    });

    it('should extract authorization data from URL query', function (cb)
    {
        var http_server = http.createServer(function (req, res)
        {
            authz.get_authz_data(req, function (err, req_info, req_token)
            {
                if (err) { return cb(err); }
                expect(req_info).to.equal('test');
                expect(req_token).to.equal(token);
                res.end();
                http_server.close(cb);
            });
        }).listen(6000, '127.0.0.1', function (err)
        {
            if (err) { return cb(err); }
            http.request(
            {
                hostname: '127.0.0.1',
                port: 6000,
                path: '/?authz_info=test&authz_token=' + token
            }).end();
        });
    });

    it('should extract multiple authorization tokens from URL query', function (cb)
    {
        var http_server = http.createServer(function (req, res)
        {
            authz.get_authz_data(req, function (err, req_info, req_token)
            {
                if (err) { return cb(err); }
                expect(req_info).to.equal('test');
                expect(req_token).to.eql([token, token_no_issuer]);
                res.end();
                http_server.close(cb);
            });
        }).listen(6000, '127.0.0.1', function (err)
        {
            if (err) { return cb(err); }
            http.request(
            {
                hostname: '127.0.0.1',
                port: 6000,
                path: '/?authz_info=test&authz_token=' + token + '&authz_token=' + token_no_issuer
            }).end();
        });
    });

    it('should pass undefineds when no tokens are present in request', function (cb)
    {
        var http_server = http.createServer(function (req, res)
        {
            authz.get_authz_data(req, function (err, req_info, req_token)
            {
                if (err) { return cb(err); }
                expect(req_info).to.equal(undefined);
                expect(req_token).to.equal(undefined);
                res.end();
                http_server.close(cb);
            });
        }).listen(6000, '127.0.0.1', function (err)
        {
            if (err) { return cb(err); }
            http.request(
            {
                hostname: '127.0.0.1',
                port: 6000,
            }).end();
        });
    });

    it('should pass undefineds when authorization header has no scheme', function (cb)
    {
        var http_server = http.createServer(function (req, res)
        {
            authz.get_authz_data(req, function (err, req_info, req_token)
            {
                if (err) { return cb(err); }
                expect(req_info).to.equal(undefined);
                expect(req_token).to.equal(undefined);
                res.end();
                http_server.close(cb);
            });
        }).listen(6000, '127.0.0.1', function (err)
        {
            if (err) { return cb(err); }
            http.request(
            {
                hostname: '127.0.0.1',
                port: 6000,
                headers: {
                    Authorization: 'foo:bar'
                }
            }).end();
        });
    });

    it('should pass empty info when authorization header has no separator', function (cb)
    {
        var http_server = http.createServer(function (req, res)
        {
            authz.get_authz_data(req, function (err, req_info, req_token)
            {
                if (err) { return cb(err); }
                expect(req_info).to.equal('');
                expect(req_token).to.equal('foo;bar');
                res.end();
                http_server.close(cb);
            });
        }).listen(6000, '127.0.0.1', function (err)
        {
            if (err) { return cb(err); }
            http.request(
            {
                hostname: '127.0.0.1',
                port: 6000,
                auth: 'foo;bar'
            }).end();
        });
    });

    it('should pass empty info when authorization header has invalid base 64 characters', function (cb)
    {
        var http_server = http.createServer(function (req, res)
        {
            authz.get_authz_data(req, function (err, req_info, req_token)
            {
                if (err) { return cb(err); }
                expect(req_info).to.equal('');
                expect(req_token).to.equal(Buffer.from('foo;bar', 'base64').toString());
                res.end();
                http_server.close(cb);
            });
        }).listen(6000, '127.0.0.1', function (err)
        {
            if (err) { return cb(err); }
            http.request(
            {
                hostname: '127.0.0.1',
                port: 6000,
                headers: {
                    Authorization: 'Basic foo;bar'
                }
            }).end();
        });
    });

    it('should emit change event when public key is updated', function (cb)
    {
        var change_count = 0, replicated_count = 0, old_rev = rev1;

        function change(uri, rev, deleted)
        {
            change_count += 1;
            expect(change_count).to.be.at.most(2);
            expect(uri).to.equal(uri1);
            expect(rev).not.to.equal(old_rev);
            expr(expect(deleted).to.be.false);

            if ((db_type === 'couchdb') && (change_count === 2))
            {
                cb();
            }
        }

        function replicated()
        {
            replicated_count += 1;
            expect(replicated_count).to.be.at.most(2);
            expect(change_count).to.be.at.least(replicated_count);
            
            if (replicated_count === 2)
            {
                cb();
            }
        }

        authz.keystore.on('change', change);
        skew_authz.keystore.on('change', change);

        authz.keystore.on('replicated', replicated);
        skew_authz.keystore.on('replicated', replicated);

        priv_key1 = JWK.generateSync(kty, crvOrSize, { alg });

        ks_for_update.add_pub_key(uri1, serialize_key(priv_key1), function (err, issuer_id, new_rev)
        {
            if (err) { return cb(err); }
            expect(issuer_id).not.to.equal(issuer_id1);
            expect(new_rev).not.to.equal(rev1);

            issuer_id1 = issuer_id;
            rev1 = new_rev;

            ks_for_update.deploy();
        });
    });

    it('should fail to authorize JWT when public key has been updated', function (cb)
    {
        authz.authorize(token, allowed_algs, function (err)
        {
            expr(expect(err).to.exist);
            cb();
        });
    });

    it('should authorize JWT signed with new private key', function (cb)
    {
        const token2 = JWT.sign({
            foo: 91
        }, priv_key1, {
            algorithm: alg,
            audience,
            expiresIn: '1m',
            issuer: issuer_id1
        });

        authz.authorize(token2, allowed_algs, function (err, payload, uri, rev)
        {
            if (err) { return cb(err); }
            expect(uri).to.equal(uri1);
            expect(rev).to.equal(rev1);
            expect(payload.foo).to.equal(91);
            cb();
        });
    });

    it('should fail to authorize when keystore is closed', function (cb)
    {
        authz.keystore.close(function (err)
        {
            if (err) { return cb(err); }

            authz.authorize(token, allowed_algs, function (err)
            {
                expr(expect(err).to.exist);
                cb();
            });
        });
    });
});

}

var couchdb_process;

// run couchdb with local config so we can add SSL support with a known cert
before(function (cb)
{
    this.timeout(60000);

    couchdb_process = child_process.spawn(
            path.join(__dirname, '..', 'node_modules', 'pub-keystore', 'test', 'fixtures', 'run_couchdb.sh'),
            [],
            { stdio: 'inherit' });

    function check()
    {
        var nv = child_process.spawn('nc',
                ['-zv', '-w', '5', 'localhost', '5984'],
                { stdio: 'inherit' });

        nv.on('exit', function (code)
        {
            if (code === 0)
            {
                return cb();
            }

            setTimeout(check, 1000);
        });
    }

    check();
});

after(function ()
{
    couchdb_process.kill();
});

for (const db_type of ['in-mem', 'pouchdb', 'couchdb']) {
    setup(db_type, 'RSA', 'RS256');
    setup(db_type, 'RSA', 'RS384');
    setup(db_type, 'RSA', 'RS512');

    setup(db_type, 'RSA', 'PS256');
    setup(db_type, 'RSA', 'PS384');
    setup(db_type, 'RSA', 'PS512');

    setup(db_type, 'EC', 'ES256');
    setup(db_type, 'EC', 'ES256K', 'secp256k1');
    setup(db_type, 'EC', 'ES384', 'P-384');
    setup(db_type, 'EC', 'ES512', 'P-521');

    setup(db_type, 'OKP', 'EdDSA');

    setup(db_type, 'oct', 'HS256');
    setup(db_type, 'oct', 'HS384');
    setup(db_type, 'oct', 'HS512');
}
