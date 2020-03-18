const { Fido2Lib } = require('@davedoesdev/fido2-lib');
const { coerceToBase64Url } = require('@davedoesdev/fido2-lib/lib/utils');
const { expect } = require('chai');
const { promisify } = require('util');
const path = require('path');
const fs = require('fs');
const authorize_jwt = promisify(require('..'));
const writeFile = promisify(fs.writeFile);
const origin = 'https://localhost:4567';
const audience = 'urn:authorize-jwt:webauthn-test';
const user_uri = 'tag:localhost,2018-05-22:test';

function BufferToArrayBuffer(buf)
{
    return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
}

let authz;

function complete_webauthn_token(webauthn_token, cb)
{
    webauthn_token.expected_factor = 'either';
    webauthn_token.expected_origin = origin;
    webauthn_token.prev_counter = 0;
    webauthn_token.expected_user_handle = webauthn_token.assertion.response.userHandle;
    cb(null, webauthn_token);
}

before(async function ()
{
    authz = await authorize_jwt({
        db_type: 'pouchdb',
        db_for_update: true,
        WEBAUTHN_MODE: true,
        audience,
        complete_webauthn_token
    });
});

async function executeAsync(f, ...args)
{
    return await browser.executeAsync(function (f, ...args)
    {
        (async function ()
        {
            let done = args[args.length - 1];
            try
            {
                done(await eval(f)(...args.slice(0, -1)));
            }
            catch (ex)
            {
                done({ error: ex.message }); 
            }
        })();
    }, f.toString(), ...args);
}

describe('WebAuthn', function ()
{
    it('should authorize', async function ()
    {
        this.timeout(5 * 60 * 1000);
        browser.setTimeout({ 'script': 5 * 60 * 1000 });

        //await browser.pause(60000);
        await browser.url(origin + '/test_webauthn.html');

        const fido2lib = new Fido2Lib();

        // create challenge (server)

        const options = await fido2lib.attestationOptions();
        expect(options.challenge instanceof ArrayBuffer).to.be.true;
        expect(options.challenge.byteLength).to.equal(64);
        expect(options.timeout).to.equal(60000);

        // check we're getting different ones
        const options2 = await fido2lib.attestationOptions();
        expect(options2.challenge instanceof ArrayBuffer).to.be.true;
        expect(options2.challenge.byteLength).to.equal(64);
        expect(options2.timeout).to.equal(60000);

        let challenge_buf = Buffer.from(options.challenge);
        expect(challenge_buf.equals(Buffer.from(options2.challenge))).to.be.false;

        // allow challenge to be sent to browser
        options.challenge = Array.from(challenge_buf);

        // create credential (browser)
        const cred = await executeAsync(async options =>
        {
            const res = await navigator.credentials.create({ publicKey: {
                rp: { name: 'AuthorizeJWTTest' },
                user: {
                    name: 'test',
                    displayName: 'Test',
                    id: new TextEncoder().encode('test')
                },
                challenge: Uint8Array.from(options.challenge),
                pubKeyCredParams: [{
                    type: 'public-key',
                    alg: -7
                }],
                timeout: options.timeout,
                attestation: 'none' // https://www.w3.org/TR/webauthn/#attestation-conveyance
            }});
            return {
                id: res.id,
                response: {
                    attestationObject: Array.from(new Uint8Array(res.response.attestationObject)),
                    clientDataJSON: new TextDecoder('utf-8').decode(res.response.clientDataJSON)
                }
            };
        }, options);

        if (cred.error) { throw new Error(cred.error); }

        // change types for fido2lib
        cred.id = BufferToArrayBuffer(Buffer.from(cred.id, 'base64'));
        cred.response.attestationObject = BufferToArrayBuffer(Buffer.from(cred.response.attestationObject));
        cred.response.clientDataJSON = BufferToArrayBuffer(Buffer.from(cred.response.clientDataJSON));

        // verify credential (server)
        const cred_response = await fido2lib.attestationResult(cred,
        {
            challenge: challenge_buf,
            origin: origin,
            factor: 'either'
        });
        
        // add public key (server)
        const add_pub_key = promisify(authz.keystore.add_pub_key.bind(authz.keystore));

        let issuer_id = await add_pub_key(
            user_uri,
            {
                pub_key: cred_response.authnrData.get('credentialPublicKeyPem'),
                cred_id: Buffer.from(cred_response.authnrData.get('credId')).toString('base64')
            });

        // check we can retrieve the cred ID (server)
        const get_pub_key_by_uri = promisify(authz.keystore.get_pub_key_by_uri.bind(authz.keystore));

        const cred_id = Array.from(Buffer.from((await get_pub_key_by_uri(user_uri)).cred_id, 'base64'));

        // async function to authorize assertion
        const authorize = promisify((authz, authz_token, allowed_algs, cb) =>
        {
            authz.authorize(authz_token, allowed_algs, (err, payload, uri, rev, assertion_response) =>
            {
                cb(err,
                {
                    payload: payload, 
                    uri: uri,
                    rev: rev,
                    assertion_response: assertion_response
                });
            });
        });

        async function gen_and_verify2(authz, options)
        {
            options = Object.assign(
            {
                audience: audience,
                issuer: undefined,
                expire: true,
                modify_sig: false,
                wrong_issuer: false,
                modify_client_data: false,
                sign_jwt: false,
                allowed_algs: [],
                expire_immediately: false
            }, options);

            // generate JWT and sign it using WebAuthn (browser)

            const assertion = await executeAsync(async (options, cred_id) =>
            {
                function b64url(s)
                {
                    return btoa(s).replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
                }

                async function jwt_encode(header, payload, secret)
                {
                    const unsigned_token = b64url(JSON.stringify(header)) + '.' +
                                           b64url(JSON.stringify(payload));

                    const encoder = new TextEncoder();
                    const signature = secret ?
                        b64url(new Uint8Array(await crypto.subtle.sign(
                            'HMAC',
                            await crypto.subtle.importKey(
                                'raw',
                                encoder.encode(secret),
                                {
                                    name: 'HMAC',
                                    hash: 'SHA-256'
                                },
                                false,
                                ['sign']),
                            encoder.encode(unsigned_token)))
                                .reduce((r, b) => (r.push(String.fromCharCode(b)), r), [])
                                .join('')) :
                        '';

                    return unsigned_token + '.' + signature;
                }

                async function generateJWT(claims, expires)
                {
                    const header = {
                              alg: options.sign_jwt ? 'HS256' : 'none',
                              typ: 'JWT'
                          },
                          new_claims = Object.assign({}, claims),
                          now = new Date(),
                          jti = new Uint8Array(64);

                    window.crypto.getRandomValues(jti);

                    new_claims.jti = Array.from(jti).map(x => String.fromCharCode(x)).join('');
                    new_claims.iat = Math.floor(now.getTime() / 1000);
                    new_claims.nbf = Math.floor(now.getTime() / 1000);

                    if (expires)
                    {
                        new_claims.exp = Math.floor(expires.getTime() / 1000);
                    }

                    return await jwt_encode(header, new_claims, options.sign_jwt ? 'foobar' : null);
                }

                const payload = {
                    aud: options.audience,
                    foo: 90,
                    iss: options.issuer
                };

                let expires;

                if (options.expire)
                {
                    expires = new Date();
                    if (!options.expire_immediately)
                    {
                        expires.setSeconds(expires.getSeconds() + 10);
                    }
                }

                const jwt = options.malformed_token ? 'foobar' :
                    await generateJWT(payload, expires);

                const assertion = await navigator.credentials.get({ publicKey: {
                    challenge: new TextEncoder().encode(jwt),
                    allowCredentials: [{
                        id: Uint8Array.from(cred_id),
                        type: 'public-key'
                    }]
                }});

                return {
                    id: assertion.id,
                    response: {
                        authenticatorData: Array.from(new Uint8Array(assertion.response.authenticatorData)),
                        clientDataJSON: new TextDecoder('utf-8').decode(assertion.response.clientDataJSON),
                        signature: Array.from(new Uint8Array(assertion.response.signature)),
                        userHandle: assertion.response.userHandle ? Array.from(new Uint8Array(assertion.response.userHandle)) : null
                    }
                };
            }, options, cred_id);

            if (assertion.error) { throw new Error(assertion.error); }

            if (options.no_user_handle)
            {
                assertion.response.userHandle = null;
            }

            if (options.empty_user_handle)
            {
                assertion.response.userHandle = [];
            }

            // change types for fido2lib
            const client_jwt = JSON.parse(assertion.response.clientDataJSON).challenge;
            assertion.id = BufferToArrayBuffer(Buffer.from(assertion.id, 'base64'));
            assertion.response.authenticatorData = BufferToArrayBuffer(Buffer.from(assertion.response.authenticatorData));
            assertion.response.clientDataJSON = BufferToArrayBuffer(Buffer.from(assertion.response.clientDataJSON));
            assertion.response.userHandle = assertion.response.userHandle ? BufferToArrayBuffer(Buffer.from(assertion.response.userHandle)) : undefined;

            const sigbuf = Buffer.from(assertion.response.signature);
            assertion.response.signature = BufferToArrayBuffer(sigbuf);

            // check assertion with fido2lib first (server)
            await fido2lib.assertionResult(assertion,
            {
                challenge: client_jwt,
                origin: origin,
                factor: 'either',
                publicKey: cred_response.authnrData.get('credentialPublicKeyPem'),
                prevCounter: 0,
                // not all authenticators can store user handles
                userHandle: assertion.response.userHandle === undefined ? null : assertion.response.userHandle
            });

            if (options.modify_sig)
            {
                for (let i = 0; i < sigbuf.length; ++i)
                {
                    sigbuf[i] ^= 1;
                }
                assertion.response.signature = BufferToArrayBuffer(sigbuf);
            }

            if (options.modify_client_data)
            {
                assertion.response.clientDataJSON = 'a' + assertion.response.clientDataJSON;
            }

            const orig_complete_webauthn_token = authz._config.complete_webauthn_token;
            if (options.no_complete_webauthn_token)
            {
                delete authz._config.complete_webauthn_token;
            }

            if (options.complete_error)
            {
                authz._config.complete_webauthn_token = function (webauthn_token, cb)
                {
                    cb(new Error('error in completion'));
                };
            }

            let info;
            try
            {
                // authorize assertion and token (challenge) inside it (server)
                const issid = options.wrong_issuer ? 'foobar' : issuer_id;
                let token;
                if (options.split_error)
                {
                    token = {
                        split: function ()
                        {
                            throw new Error('error in split');
                        }
                    };
                }
                else if (options.string_token)
                {
                    token = [issid,
                             coerceToBase64Url(assertion.id, 'id'),
                             coerceToBase64Url(assertion.response.clientDataJSON, 'clientDataJSON'),
                             coerceToBase64Url(assertion.response.authenticatorData, 'authenticatorData'),
                             coerceToBase64Url(assertion.response.signature, 'signature')];
                    if (assertion.response.userHandle)
                    {
                        token.push(coerceToBase64Url(assertion.response.userHandle, 'userHandle'));
                    }

                    token = token.join('.');
                }
                else if (options.malformed_assertion_obj)
                {
                    token = 'foobar';
                }
                else
                {
                    token = {
                        assertion: assertion,
                        issuer_id: issid,
                        expected_factor: 'either',
                        expected_origin: origin,
                        prev_counter: 0,
                        // not all authenticators can store user handles
                        expected_user_handle: assertion.response.userHandle
                    };
                }

                info = await authorize(authz, token, options.allowed_algs);
            }
            finally
            {
                authz._config.complete_webauthn_token = orig_complete_webauthn_token;
            }

            expect(info.uri).to.equal(user_uri);
            expect(info.assertion_response.clientData.get('challenge')).to.equal(client_jwt);
            expect(info.payload.foo).to.equal(90);
        }

        async function gen_and_verify(authz, options)
        {
            await gen_and_verify2(authz, options);
            await gen_and_verify2(authz, Object.assign(
            {
                string_token: true
            }, options));
        }

        await gen_and_verify(authz);

        issuer_id = await add_pub_key(
            user_uri,
            cred_response.authnrData.get('credentialPublicKeyPem'));

        await gen_and_verify(authz);

        try
        {
            await gen_and_verify(authz, {audience: 'foobar'});
        }
        catch (ex)
        {
            expect(ex.message).to.equal('unrecognized authorization token audience: foobar');
        }

        try
        {
            await gen_and_verify(authz, {issuer: 'foobar'});
        }
        catch (ex)
        {
            expect(ex.message).to.equal('issuer found in webauthn mode');
        }

        try
        {
            await gen_and_verify(authz, {expire: false});
        }
        catch (ex)
        {
            expect(ex.message).to.equal('no expires claim');
        }

        try
        {
            await gen_and_verify(authz, {modify_sig: true});
        }
        catch (ex)
        {
            expect(ex.message).to.equal('signature validation failed');
        }

        try
        {
            await gen_and_verify(authz, {wrong_issuer: true});
        }
        catch (ex)
        {
            expect(ex.message).to.equal('no public key found for issuer ID foobar');
        }

        try
        {
            await gen_and_verify(authz, {modify_client_data: true});
        }
        catch (ex)
        {
            expect(ex.message).to.be.oneOf([
                'Unexpected token a in JSON at position 0',
                'Unexpected token j in JSON at position 0'
            ]);
        }

        try
        {
            await gen_and_verify(authz, {sign_jwt: true});
        }
        catch (ex)
        {
            expect(ex.message).to.equal('the key does not support HS256 verify algorithm');
        }

        try
        {
            await gen_and_verify(authz, {sign_jwt: true, allowed_algs: ['HS256']});
        }
        catch (ex)
        {
            expect(ex.message).to.equal('the key does not support HS256 verify algorithm');
        }

        try
        {
            await gen_and_verify(authz, {expire_immediately: true});
        }
        catch (ex)
        {
            expect(ex.message).to.equal('"exp" claim timestamp check failed');
        }

        try
        {
            await gen_and_verify(authz, {no_complete_webauthn_token: true});
        }
        catch (ex)
        {
            expect(ex.message).to.equal('no config.complete_webauthn_token');
        }

        try
        {
            await gen_and_verify(authz, {complete_error: true});
        }
        catch (ex)
        {
            expect(ex.message).to.equal('error in completion');
        }

        try
        {
            await gen_and_verify(authz, {split_error: true});
        }
        catch (ex)
        {
            expect(ex.message).to.equal('error in split');
        }

        try
        {
            await gen_and_verify(authz, {malformed_token: true});
        }
        catch (ex)
        {
            expect(ex.message).to.equal('JWTs must have three components');
        }

        try
        {
            await gen_and_verify(authz, {malformed_assertion_obj: true});
        }
        catch (ex)
        {
            expect(ex.message).to.equal('The first argument must be of type string or an instance of Buffer, ArrayBuffer, or Array or an Array-like Object. Received undefined');
        }

        await gen_and_verify(authz, {no_user_handle: true});
        await gen_and_verify(authz, {empty_user_handle: true});

        const close = promisify(cb =>
        {
            authz.keystore.close(cb);
        });

        await close();

        try
        {
            await gen_and_verify(authz);
        }
        catch (ex)
        {
            expect(ex.message).to.equal('not_open');
        }
    });
});
