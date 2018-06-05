const { Fido2Lib } = require('fido2-lib');
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

let authz, authz_anon;

before(async function ()
{
    authz = await authorize_jwt({
        db_type: 'pouchdb',
        db_for_update: true,
        WEBAUTHN_MODE: true,
        jwt_audience_uri: audience
    });

    authz_anon = await authorize_jwt({
        WEBAUTHN_MODE: true,
        ANONYMOUS_MODE: true,
        jwt_audience_uri: audience
    });
});

let io;

if (process.env.CI === 'true')
{
    global.browser = {
        timeouts()
        {
        },

        async url()
        {
        }
    };

    io = JSON.parse(fs.readFileSync(path.join(__dirname, 'io.json')));
}
else
{
    io = [];
}

async function executeAsync(f, ...args)
{
    if (process.env.CI === 'true')
    {
        return JSON.parse(io.shift()).res;
    }

    const r = (await browser.executeAsync(function (f, ...args)
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
    }, f.toString(), ...args)).value;

    io.push(JSON.stringify({ req: args, res: r }));
    return r;
}

describe('WebAuthn', function ()
{
    it('should authorize', async function ()
    {
        this.timeout(5 * 60 * 1000);
        browser.timeouts('script', 5 * 60 * 1000);

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

        if (process.env.CI === 'true')
        {
            challenge_buf = Buffer.from(JSON.parse(io[0]).req[0].challenge);
        }

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
                    id: new TextEncoder('utf-8').encode('test')
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

        const issuer_id = await add_pub_key(
                user_uri,
                cred_response.authnrData.get('credentialPublicKeyPem'));

        const cred_id = Array.from(Buffer.from(cred_response.authnrData.get('credId')));

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

        async function gen_and_verify(authz, options)
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
                function generateJWT(claims, expires)
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

                    return KJUR.jws.JWS.sign(
                        null,
                        header,
                        new_claims,
                        options.sign_jwt ? 'foobar' : undefined);
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

                const jwt = generateJWT(payload, expires);

                const assertion = await navigator.credentials.get({ publicKey: {
                    challenge: new TextEncoder('utf-8').encode(jwt),
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
                        signature: Array.from(new Uint8Array(assertion.response.signature))
                    }
                };
            }, options, cred_id);

            if (assertion.error) { throw new Error(assertion.error); }

            // change types for fido2lib
            const client_jwt = JSON.parse(assertion.response.clientDataJSON).challenge;
            assertion.id = BufferToArrayBuffer(Buffer.from(assertion.id, 'base64'));
            assertion.response.authenticatorData = BufferToArrayBuffer(Buffer.from(assertion.response.authenticatorData));
            assertion.response.clientDataJSON = BufferToArrayBuffer(Buffer.from(assertion.response.clientDataJSON));

            const sigbuf = Buffer.from(assertion.response.signature);
            assertion.response.signature = BufferToArrayBuffer(sigbuf);

            // check assertion with fido2lib first (server)
            await fido2lib.assertionResult(assertion,
            {
                challenge: client_jwt,
                origin: origin,
                factor: 'either',
                publicKey: cred_response.authnrData.get('credentialPublicKeyPem'),
                prevCounter: 0
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

            let orig_getTime = Date.prototype.getTime;

            if (process.env.CI === 'true')
            {
                Date.prototype.getTime = function ()
                {
                    return JSON.parse(Buffer.from(Buffer.from(client_jwt, 'base64').toString().split('.')[1], 'base64')).iat * 1000;
                };
            }

            let info;
            try
            {
                // authorize assertion and token (challenge) in it (server)
                info = await authorize(authz,
                {
                    assertion: assertion,
                    issuer_id: options.wrong_issuer ? 'foobar' : issuer_id,
                    expected_origin: origin,
                    expected_factor: 'either',
                    prev_counter: 0
                }, options.allowed_algs);
            }
            finally
            {
                Date.prototype.getTime = orig_getTime;
            }

            if (authz === authz_anon)
            {
                expect(info.uri).to.equal(null);
                expect(info.assertion_response).to.equal(null);
            }
            else
            {
                expect(info.uri).to.equal(user_uri);
                expect(info.assertion_response.clientData.get('challenge')).to.equal(client_jwt);
            }

            expect(info.payload.foo).to.equal(90);

            return info;
        }

        for (const az of [authz, authz_anon])
        {
            await gen_and_verify(az);

            try
            {
                await gen_and_verify(az, {audience: 'foobar'});
            }
            catch (ex)
            {
                expect(ex.message).to.equal('unrecognized authorization token audience: foobar');
            }

            try
            {
                await gen_and_verify(az, {issuer: 'foobar'});
            }
            catch (ex)
            {
                expect(ex.message).to.equal('issuer found in webauthn mode');
            }

            try
            {
                await gen_and_verify(az, {expire: false});
            }
            catch (ex)
            {
                expect(ex.message).to.equal('no expires claim');
            }

            try
            {
                await gen_and_verify(az, {modify_sig: true});
            }
            catch (ex)
            {
                expect(ex.message).to.equal('signature validation failed');
            }

            try
            {
                await gen_and_verify(az, {wrong_issuer: true});
            }
            catch (ex)
            {
                expect(ex.message).to.equal('no public key found for issuer ID foobar');
            }

            try
            {
                await gen_and_verify(az, {modify_client_data: true});
            }
            catch (ex)
            {
                expect(ex.message).to.equal('Unexpected token a in JSON at position 0');
            }

            try
            {
                await gen_and_verify(az, {sign_jwt: true});
            }
            catch (ex)
            {
                expect(ex.message).to.equal('algorithm not allowed: HS256');
            }

            try
            {
                await gen_and_verify(az, {sign_jwt: true, allowed_algs: ['HS256']});
            }
            catch (ex)
            {
                expect(ex.message).to.equal('signed token supplied in webauthn mode');
            }

            try
            {
                await gen_and_verify(az, {expire_immediately: true});
            }
            catch (ex)
            {
                expect(ex.message).to.equal('expired');
            }
        }

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

        if (process.env.CI !== 'true')
        {
            await writeFile(path.join(__dirname, 'io.json'), JSON.stringify(io));
        }
    });
});
