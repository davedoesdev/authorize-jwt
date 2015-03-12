/*global it: false,
         describe: false,
         before: false,
         after: false */
/*jslint node: true, nomen: true */
"use strict";

var http = require('http'),
    child_process = require('child_process'),
    path = require('path'),
    ursa = require('ursa'),
    pub_keystore = require('pub-keystore'),
    jsjws = require('jsjws'),
    expect = require('chai').expect,
    authorize_jwt = require('..'),
    uri1 = 'mailto:dave@davedoesdev.com',
    uri2 = 'http://www.davedoesdev.com',
    audience = 'urn:authorize-jwt:test';

function expr(v) { return v; }

function setup(db_type)
{

describe('authorize-jwt ' + db_type, function ()
{
    var priv_key1,
        priv_key2,
        ks_for_update,
        issuer_id1,
        rev1,
        authz,
        skew_authz,
        anon_authz,
        no_audience_authz,
        token_no_issuer,
        token_unknown_issuer,
        token_no_audience,
        token_wrong_audience,
        token_beyond_max_expiry,
        token_wrong_signer,
        token_no_signer,
        token,
        alg = 'PS256',
        allowed_algs = [alg],
        allowed_algs2 = {};

    allowed_algs2[alg] = true;

    before(function (cb)
    {
        // put public key into keystore

        priv_key1 = ursa.generatePrivateKey(2048, 65537);
        priv_key2 = ursa.generatePrivateKey(2048, 65537);

        var pub_key1 = priv_key1.toPublicPem('utf8'),
            pub_key2 = priv_key2.toPublicPem('utf8');

        pub_keystore(
        {
            db_type: db_type,
            db_for_update: true,
            no_changes: true,
            username: 'admin',
            password: 'admin'
        }, function (err, ks)
        {
            if (err) { return cb(err); }
            ks_for_update = ks;
            ks_for_update.add_pub_key(uri1, pub_key1, function (err, issuer_id, rev)
            {
                if (err) { return cb(err); }
                issuer_id1 = issuer_id;
                rev1 = rev;

                ks_for_update.add_pub_key(uri2, pub_key2, function (err)
                {
                    if (err) { return cb(err); }
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
            db_type: db_type,
            deploy_name: 'test',
            jwt_audience_uri: audience,
            jwt_max_token_expiry: 60,
            keep_master_open: true
        }, function (err, the_authz)
        {
            if (err) { return cb(err); }
            authz = the_authz;
            cb();
        });
    });

    after(function (cb)
    {
        authz.keystore.close(function (err)
        {
            expr(expect(err).to.exist); // closed in final test
            cb();
        });
    });

    before(function (cb)
    {
        authorize_jwt(
        {
            db_type: db_type,
            deploy_name: 'skew',
            jwt_audience_uri: audience,
            jwt_max_token_expiry: 60,
            keep_master_open: true,
            iat_skew: -10
        }, function (err, the_authz)
        {
            if (err) { return cb(err); }
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
            jwt_audience_uri: audience,
            ANONYMOUS_MODE: true
        }, function (err, the_authz)
        {
            if (err) { return cb(err); }
            anon_authz = the_authz;
            expr(expect(anon_authz.keystore).not.to.exist);
            cb();
        });
    });

    before(function (cb)
    {
        authorize_jwt(
        {
            db_type: db_type,
            deploy_name: 'no_audience',
            jwt_max_token_expiry: 60,
            keep_master_open: true
        }, function (err, the_authz)
        {
            if (err) { return cb(err); }
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

        var token_exp = new Date(),
            header = { alg: alg };

        token_exp.setMinutes(token_exp.getMinutes() + 1);

        token_no_issuer = new jsjws.JWT().generateJWTByKey(header,
        {
            aud: audience,
            foo: 'wup'
        }, token_exp, priv_key1);

        token_unknown_issuer = new jsjws.JWT().generateJWTByKey(header,
        {
            iss: 'foobar'
        }, token_exp, priv_key1);

        token_no_audience = new jsjws.JWT().generateJWTByKey(header,
        {
            iss: issuer_id1
        }, token_exp, priv_key1);

        token_wrong_audience = new jsjws.JWT().generateJWTByKey(header,
        {
            iss: issuer_id1,
            aud: 'some audience'
        }, token_exp, priv_key1);

        token = new jsjws.JWT().generateJWTByKey(header,
        {
            iss: issuer_id1,
            aud: audience,
            foo: 90
        }, token_exp, priv_key1);

        token_wrong_signer = new jsjws.JWT().generateJWTByKey(header,
        {
            iss: issuer_id1,
            aud: audience,
            foo: 'bar'
        }, token_exp, priv_key2);

        token_no_signer = new jsjws.JWT().generateJWTByKey(header,
        {
            iss: issuer_id1,
            aud: audience,
            foo: 'bar'
        }, token_exp);

        token_exp.setMinutes(token_exp.getMinutes() + 1);

        token_beyond_max_expiry = new jsjws.JWT().generateJWTByKey(header,
        {
            iss: issuer_id1,
            aud: audience
        }, token_exp, priv_key1);
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

    it('should authorize pre-processed JWT', function (cb)
    {
        var jwt = new jsjws.JWT();
        jwt.processJWS(token);

        authz.authorize(jwt, allowed_algs, function (err, payload, uri, rev)
        {
            if (err) { return cb(err); }
            expect(uri).to.equal(uri1);
            expect(rev).to.equal(rev1);
            expect(payload.foo).to.equal(90);
            cb();
        });
    });

    it('should pass on JWT verify options', function (cb)
    {
        skew_authz.authorize(token, allowed_algs, function (err)
        {
            expr(expect(err).to.exist);
            cb();
        });
    });

    it('should not allow unsigned tokens when not in anonymous mode', function (cb)
    {
        authz.authorize(token_no_signer, allowed_algs, function (err)
        {
            expr(expect(err).to.exist);
            cb();
        });
    });

    it('should allow unsigned tokens when in anonymous mode', function (cb)
    {
        anon_authz.authorize(token_no_signer, allowed_algs, function (err, payload, uri, rev)
        {
            if (err) { return cb(err); }
            expr(expect(uri).not.to.exist);
            expr(expect(rev).not.to.exist);
            expect(payload.foo).to.equal('bar');
            cb();
        });
    });

    it('should allow signed tokens when in anonymous mode', function (cb)
    {
        anon_authz.authorize(token, allowed_algs, function (err, payload, uri, rev)
        {
            if (err) { return cb(err); }
            expr(expect(uri).not.to.exist);
            expr(expect(rev).not.to.exist);
            expect(payload.foo).to.equal(90);
            cb();
        });
    });

    it('should allow tokens without an issuer when in anonymous mode', function (cb)
    {
        anon_authz.authorize(token_no_issuer, allowed_algs, function (err, payload, uri, rev)
        {
            if (err) { return cb(err); }
            expr(expect(uri).not.to.exist);
            expr(expect(rev).not.to.exist);
            expect(payload.foo).to.equal('wup');
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

    it('should extract authorization data from HTTP header', function (cb)
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

        priv_key1 = ursa.generatePrivateKey(2048, 65537);

        ks_for_update.add_pub_key(uri1, priv_key1.toPublicPem('utf8'), function (err, issuer_id, new_rev)
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
        var token_exp = new Date(),
            header = { alg: alg },
            token2;

        token_exp.setMinutes(token_exp.getMinutes() + 1);

        token2 = new jsjws.JWT().generateJWTByKey(header,
        {
            iss: issuer_id1,
            aud: audience,
            foo: 91
        }, token_exp, priv_key1);

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

            authz.authorize(token, allowed_algs2, function (err)
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
    this.timeout(10000);

    couchdb_process = child_process.spawn(
            path.join(__dirname, '..', 'node_modules', 'pub-keystore', 'couchdb', 'run_couchdb.sh'),
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

setup('pouchdb');
setup('couchdb');
