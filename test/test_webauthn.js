const { Fido2Lib } = require('fido2-lib');
const { expect } = require('chai');

function BufferToArrayBuffer(buf)
{
    return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
}

describe('WebAuthn', function ()
{
    it('should authorize', async function ()
    {
        this.timeout(5 * 60 * 1000);
        browser.timeouts('script', 5 * 60 * 1000);

        await browser.url('http://localhost:4567/test_webauthn.html');

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
        const result = (await browser.executeAsync(function (options, done)
        {
            (async function () { try {
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
                    attestation: 'direct'
                }});
                done({
                    id: res.id,
                    response: {
                        attestationObject: Array.from(new Uint8Array(res.response.attestationObject)),
                        clientDataJSON: new TextDecoder('utf-8').decode(res.response.clientDataJSON)
                    }
                });
            } catch (ex) { done({ error: ex.message }); }})();
        }, options)).value;

        if (result.error) { throw new Error(result.error); }
        result.id = BufferToArrayBuffer(Buffer.from(result.id, 'base64'));
        result.response.attestationObject = BufferToArrayBuffer(Buffer.from(result.response.attestationObject));
        result.response.clientDataJSON = BufferToArrayBuffer(Buffer.from(result.response.clientDataJSON));

        console.log(await fido2lib.createCredentialResponse(result, challenge_buf.toString('base64'), 'https://localhost:4567', 'first'));

    });

    //await browser.pause(5000);
});
