const { Fido2Lib } = require('fido2-lib');
const { expect } = require('chai');
const { promisify } = require('util');
const authorize_jwt = promisify(require('..'));
const origin = 'https://localhost:4567';
const audience = 'urn:authorize-jwt:webauthn-test';

function BufferToArrayBuffer(buf)
{
    return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
}

let authz;

before(async function ()
{
    authz = await authorize_jwt({
        db_type: 'pouchdb',
        db_for_update: true,
        WEBAUTHN_MODE: true
    });
});

after(function (cb)
{
    authz.keystore.close(cb);
});

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

        const options = await fido2lib.createCredentialChallenge();
        expect(options.challenge instanceof ArrayBuffer).to.be.true;
        expect(options.challenge.byteLength).to.equal(64);
        expect(options.timeout).to.equal(60000);

        // check we're getting different ones
        const options2 = await fido2lib.createCredentialChallenge();
        expect(options2.challenge instanceof ArrayBuffer).to.be.true;
        expect(options2.challenge.byteLength).to.equal(64);
        expect(options2.timeout).to.equal(60000);

        const challenge_buf = Buffer.from(options.challenge);
        expect(challenge_buf.equals(Buffer.from(options2.challenge))).to.be.false;

        // allow challenge to be sent to browser
        options.challenge = challenge_buf.toString('binary');

        // create credential (browser)
        const cred = (await browser.executeAsync(function (options, done)
        { (async function () { try {
            const res = await navigator.credentials.create({ publicKey: {
                rp: { name: 'AuthorizeJWTTest' },
                user: {
                    name: 'test',
                    displayName: 'Test',
                    id: new TextEncoder('utf-8').encode('test')
                },
                challenge: Uint8Array.from(options.challenge, x => x.charCodeAt(0)),
                pubKeyCredParams: [{
                    type: 'public-key',
                    alg: -7
                }],
                timeout: options.timeout,
                attestation: 'direct' // TODO: can we use none?
            }});
            done({
                id: res.id,
                response: {
                    attestationObject: Array.from(new Uint8Array(res.response.attestationObject)),
                    clientDataJSON: new TextDecoder('utf-8').decode(res.response.clientDataJSON)
                }
            });
        } catch (ex) { done({ error: ex.message }); }})(); }, options)).value;

        if (cred.error) { throw new Error(cred.error); }

        // change types for fido2lib
        cred.id = BufferToArrayBuffer(Buffer.from(cred.id, 'base64'));
        cred.response.attestationObject = BufferToArrayBuffer(Buffer.from(cred.response.attestationObject));
        cred.response.clientDataJSON = BufferToArrayBuffer(Buffer.from(cred.response.clientDataJSON));

        // verify credential (server)
        const cred_response = await fido2lib.createCredentialResponse(cred, challenge_buf, origin, 'either');

        // add public key (server)
        const add_pub_key = promisify(authz.keystore.add_pub_key.bind(authz.keystore));

        const issuer_id = await add_pub_key(
                'tag:localhost,2018-05-22:test',
                cred_response.authnrData.get('credentialPublicKeyPem'));

        // generate JWT and sign it using WebAuthn (browser)

        const cred_id = Buffer.from(cred_response.authnrData.get('credId')).toString('binary');

        const assertion = (await browser.executeAsync(function (audience, cred_id, done)
        { (async function () { try {
            function generateJWT(claims, expires)
            {
                const header = { alg: 'none', typ: 'JWT' },
                      new_claims = Object.assign({}, claims),
                      now = new Date();;

                new_claims.iat = Math.floor(now.getTime() / 1000);
                new_claims.nbf = Math.floor(now.getTime() / 1000);

                if (expires)
                {
                    new_claims.exp = Math.floor(expires.getTime() / 1000);
                }

                return KJUR.jws.JWS.sign(null, header, new_claims);
            }

            const random_value = new Uint8Array(64);
            window.crypto.getRandomValues(random_value);

            const payload = {
                aud: audience,
                foo: 90,
                random_value: random_value // TODO: will this stringify? should use jti
                // TODO: test with wrong aud and iss
            };
            // TODO: test with optional claims when verifying

            const expires = new Date();
            expires.setSeconds(expires.getSeconds() + 10);

            const jwt = generateJWT(payload, expires);

            const assertion = await navigator.credentials.get({ publicKey: {
                challenge: new TextEncoder('utf-8').encode(jwt),
                allowCredentials: [{
                    id: Uint8Array.from(cred_id, x => x.charCodeAt(0)),
                    type: 'public-key'
                }]
            }});

            done({
                id: assertion.id,
                response: {
                    authenticatorData: Array.from(new Uint8Array(assertion.response.authenticatorData)),
                    clientDataJSON: new TextDecoder('utf-8').decode(assertion.response.clientDataJSON),
                    signature: Array.from(new Uint8Array(assertion.response.signature))
                }
            });
        } catch (ex) { done({ error: ex.message }); }})(); }, audience, cred_id)).value;

        if (assertion.error) { throw new Error(assertion.error); }

        // change types for fido2lib
        const client_jwt = JSON.parse(assertion.response.clientDataJSON).challenge;
        assertion.id = BufferToArrayBuffer(Buffer.from(assertion.id, 'base64'));
        assertion.response.authenticatorData = BufferToArrayBuffer(Buffer.from(assertion.response.authenticatorData));
        assertion.response.clientDataJSON = BufferToArrayBuffer(Buffer.from(assertion.response.clientDataJSON));
        assertion.response.signature = BufferToArrayBuffer(Buffer.from(assertion.response.signature));

        // check assertion with fido2lib first (server)
        const assertion_response = await fido2lib.getAssertionResponse(assertion, client_jwt, origin, 'either', cred_response.authnrData.get('credentialPublicKeyPem'), 0);

        // authorize assertion
        const authorize = promisify((authz_token, allowed_algs, cb) =>
        {
            authz.authorize(authz_token, allowed_algs, (err, payload, uri, rev, assertion_response) =>
            {
                cb(err,
                {
                    paload: payload, 
                    uri: uri,
                    rev: rev,
                    assertion_response: assertion_response
                });
            });
        });

        const info = await authorize(
        {
            assertion: assertion,
            issuer_id: issuer_id,
            expected_origin: origin,
            expected_factor: 'either',
            prev_counter: 0
        }, []);

        console.log(info);

        // TODO: check info is correct

        // TODO: update docs

    });
});