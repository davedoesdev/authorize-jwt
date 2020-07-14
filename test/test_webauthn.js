const { expect } = require('chai');
const { promisify } = require('util');
const path = require('path');
const fs = require('fs');
const makeWebAuthn = require('webauthn4js');
const authorize_jwt = promisify(require('..'));
const origin = 'https://localhost:4567';
const audience = 'urn:authorize-jwt:webauthn-test';
const user_uri = 'tag:localhost,2018-05-22:test';

function complete_webauthn_token(webauthn_token, cb)
{
    webauthn_token.opts = [cro => {
        cro.userVerification = 'preferred'; // this is the default
    }];
    cb(null, webauthn_token);
}

function b64url(buf) {
    return buf.toString('base64')
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=/g, "");
}

async function executeAsync(f, ...args)
{
    return await browser.executeAsync(function (f, ...args)
    {
        (async function ()
        {
            let done = args[args.length - 1];
            window.bufferDecode = function (value) {
                return Uint8Array.from(atob(value), c => c.charCodeAt(0));
            }
            window.b64url = function (s) {
                return btoa(s)
                    .replace(/\+/g, "-")
                    .replace(/\//g, "_")
                    .replace(/=/g, "");
            }
            window.bufferEncode = function (value) {
                return b64url(String.fromCharCode.apply(null, new Uint8Array(value)));
            }
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

function test(separate)
{
describe(`WebAuthn (separate=${separate})`, function ()
{
    it('should authorize', async function ()
    {
        this.timeout(5 * 60 * 1000);
        browser.setTimeout({ 'script': 5 * 60 * 1000 });

        // make authorize-jwt instance
        const authz_options = {
            db_type: 'pouchdb',
            db_for_update: true,
            WEBAUTHN_MODE: true,
            audience,
            complete_webauthn_token
        };
        const webauthn_options = {
            RPDisplayName: 'AuthorizeJWT',
            RPID: 'localhost',
            RPOrigin: origin
        };
        let authz;
        if (separate) {
            authz = await authorize_jwt({
                ...authz_options,
                webAuthn: await makeWebAuthn(webauthn_options)
            });
        }  else {
            authz = await authorize_jwt({
                ...authz_options,
                ...webauthn_options
            });
        }

        //await browser.pause(60000);
        await browser.url(origin + '/test_webauthn.html');

        // create user (server)
        const user = {
            id: 'test',
            name: 'test',
            displayName: 'Test',
            iconURL: '',
            credentials: []
        };

        // create login options (server)

        const { options, sessionData } = await authz.webAuthn.beginRegistration(user);
        expect(b64url(options.publicKey.challenge)).to.equal(sessionData.challenge);

        // check we're getting different ones (server)
        const { options: options2, sessionData: sessionData2 } = await authz.webAuthn.beginRegistration(user);
        expect(b64url(options2.publicKey.challenge)).to.equal(sessionData2.challenge);
        expect(options2.publicKey.challenge).not.to.equal(options.publicKey.challenge);

        // create credential (browser)
        const ccr = await executeAsync(async options =>
        {
            const { publicKey } = options;
            publicKey.challenge = bufferDecode(publicKey.challenge);
            publicKey.user.id = bufferDecode(publicKey.user.id);
            if (publicKey.excludeCredentials) {
                for (const c of publicKey.excludeCredentials) {
                    c.id = bufferDecode(c.id);
                }
            }
            const credential = await navigator.credentials.create(options);
            const { id, rawId, type, response } = credential;
            const { attestationObject, clientDataJSON } = response;
            return {
                id,
                rawId: bufferEncode(rawId),
                type,
                response: {
                    attestationObject: bufferEncode(attestationObject),
                    clientDataJSON: bufferEncode(clientDataJSON)
                }
            };
        }, options);

        if (ccr.error) { throw new Error(ccr.error); }

        // verify response (server)
        const credential = await authz.webAuthn.finishRegistration(user, sessionData, ccr);
        user.credentials.push(credential);

        // add user (server)
        const add_pub_key = promisify(authz.keystore.add_pub_key.bind(authz.keystore));
        let issuer_id = await add_pub_key(user_uri, user);

        // check we can retrieve the user (server)
        const get_pub_key_by_uri = promisify(authz.keystore.get_pub_key_by_uri.bind(authz.keystore));
        expect(await get_pub_key_by_uri(user_uri)).to.eql(user);

        // async function to authorize assertion
        const authorize = promisify((authz, authz_token, allowed_algs, cb) =>
        {
            authz.authorize(authz_token, allowed_algs, (err, payload, uri, rev, credential) =>
            {
                cb(err, { payload, uri, rev, credential });
            });
        });

        async function gen_and_verify2(authz, options)
        {
            options = Object.assign(
            {
                audience,
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

            const car = await executeAsync(async (options, cred_id) =>
            {
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
                        id: bufferDecode(cred_id),
                        type: 'public-key'
                    }]
                }});
                
                const { id, rawId, type, response } = assertion;
                const { authenticatorData, clientDataJSON, signature, userHandle } = response;

                return {
                    id,
                    rawId: bufferEncode(rawId),
                    type,
                    response: {
                        authenticatorData: bufferEncode(authenticatorData),
                        clientDataJSON: bufferEncode(clientDataJSON),
                        signature: bufferEncode(signature),
                        userHandle: bufferEncode(userHandle)
                    }
                };
            }, options, credential.ID);

            if (car.error) { throw new Error(car.error); }

            if (options.delete_user_handle)
            {
                delete car.response.userHandle;
            }

            if (options.null_user_handle)
            {
                car.response.userHandle = null;
            }

            if (options.empty_user_handle)
            {
                car.response.userHandle = "";
            }

            // check assertion with WebAuthn4JS first (server)
            const { sessionData } = await authz.webAuthn.beginLogin(user);
            sessionData.challenge = JSON.parse(Buffer.from(car.response.clientDataJSON, 'base64')).challenge;
            expect((await authz.webAuthn.finishLogin(user, sessionData, car)).ID).to.equal(credential.ID);

            if (options.modify_sig)
            {
                const sigbuf = Buffer.from(car.response.signature, 'base64');
                for (let i = 0; i < sigbuf.length; ++i)
                {
                    sigbuf[i] ^= 1;
                }
                car.response.signature = b64url(sigbuf);
            }

            if (options.modify_client_data)
            {
                car.response.clientDataJSON = 'YQ' + car.response.clientDataJSON;
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
                             car.id,
                             car.response.clientDataJSON,
                             car.response.authenticatorData,
                             car.response.signature];
                    if (car.response.userHandle !== null)
                    {
                        token.push(car.response.userHandle);
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
                        issuer_id: issid,
                        car
                    };
                }

                info = await authorize(authz, token, options.allowed_algs);
            }
            finally
            {
                authz._config.complete_webauthn_token = orig_complete_webauthn_token;
            }

            expect(info.uri).to.equal(user_uri);
            expect(info.credential.ID).to.equal(credential.ID);
            expect(info.credential.issuer_id).to.equal(issuer_id);
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

        issuer_id = await add_pub_key(user_uri, user);

        await gen_and_verify(authz);

        try
        {
            await gen_and_verify(authz, {audience: 'foobar'});
            throw new Error('should throw');
        }
        catch (ex)
        {
            expect(ex.message).to.equal('unexpected "aud" claim value');
        }

        try
        {
            await gen_and_verify(authz, {issuer: 'foobar'});
            throw new Error('should throw');
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
            throw new Error('should throw');
        }

        try
        {
            await gen_and_verify(authz, {modify_sig: true});
            throw new Error('should throw');
        }
        catch (ex)
        {
            //https://github.com/duo-labs/webauthn/pull/75
            // Message should change once the issue is fixed
            expect(ex.message).to.equal('panic: runtime error: invalid memory address or nil pointer dereference');
        }

        try
        {
            await gen_and_verify(authz, {wrong_issuer: true});
            throw new Error('should throw');
        }
        catch (ex)
        {
            expect(ex.message).to.equal('no user found for issuer ID foobar');
        }

        try
        {
            await gen_and_verify(authz, {modify_client_data: true});
            throw new Error('should throw');
        }
        catch (ex)
        {
            expect(ex.message).to.equal('Unexpected token a in JSON at position 0');
        }

        try
        {
            await gen_and_verify(authz, {sign_jwt: true});
            throw new Error('should throw');
        }
        catch (ex)
        {
            expect(ex.message).to.equal('alg not whitelisted');
        }

        try
        {
            await gen_and_verify(authz, {sign_jwt: true, allowed_algs: ['HS256']});
            throw new Error('should throw');
        }
        catch (ex)
        {
            expect(ex.message).to.equal('alg not whitelisted');
        }

        try
        {
            await gen_and_verify(authz, {expire_immediately: true});
            throw new Error('should throw');
        }
        catch (ex)
        {
            expect(ex.message).to.equal('"exp" claim timestamp check failed');
        }

        try
        {
            await gen_and_verify(authz, {no_complete_webauthn_token: true});
            throw new Error('should throw');
        }
        catch (ex)
        {
            expect(ex.message).to.equal('no config.complete_webauthn_token');
        }

        try
        {
            await gen_and_verify(authz, {complete_error: true});
            throw new Error('should throw');
        }
        catch (ex)
        {
            expect(ex.message).to.equal('error in completion');
        }

        try
        {
            await gen_and_verify(authz, {split_error: true});
            throw new Error('should throw');
        }
        catch (ex)
        {
            expect(ex.message).to.equal('error in split');
        }

        try
        {
            await gen_and_verify(authz, {malformed_token: true});
            throw new Error('should throw');
        }
        catch (ex)
        {
            expect(ex.message).to.equal('JWTs must have three components');
        }

        try
        {
            await gen_and_verify(authz, {malformed_assertion_obj: true});
            throw new Error('should throw');
        }
        catch (ex)
        {
            expect(ex.message).to.equal('The first argument must be of type string or an instance of Buffer, ArrayBuffer, or Array or an Array-like Object. Received undefined');
        }

        await gen_and_verify(authz, {delete_user_handle: true});
        await gen_and_verify(authz, {empty_user_handle: true});

        try
        {
            await gen_and_verify(authz, {null_user_handle: true});
            throw new Error('should throw');
        }
        catch (ex)
        {
            // https://github.com/duo-labs/webauthn/blob/master/protocol/base64.go#L34
            // unmarshals to the string "null"
            expect(ex.message).to.equal('userHandle and User ID do not match');
        }

        await promisify(authz.close.bind(authz))();
        await promisify(authz.close.bind(authz))(); // Check ignores not_open errors

        try
        {
            await gen_and_verify(authz);
            throw new Error('should throw');
        }
        catch (ex)
        {
            expect(ex.message).to.equal(separate ? 'not_open' : 'Go program has already exited');
        }

        if (separate)
        {
            await authz.webAuthn.exit();
        }

        try
        {
            await authorize_jwt(authz_options);
            throw new Error('should throw');
        }
        catch (ex)
        {
            expect(ex.message).to.equal('Configuration error: Missing RPDisplayName');
        }
    });
});
}
test(false);
test(true);
