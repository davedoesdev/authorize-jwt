const { Fido2Lib } = require('fido2-lib');
const { expect } = require('chai');

describe('WebAuthn', function ()
{
    it('should create credential challenge', async function ()
    {
        const fido2lib = new Fido2Lib();

        const options = await fido2lib.createCredentialChallenge();
        expect(options.challenge instanceof ArrayBuffer).to.be.true;
        expect(options.challenge.byteLength).to.equal(64);
        expect(options.timeout).to.equal(60000);

        const options2 = await fido2lib.createCredentialChallenge();
        expect(options2.challenge instanceof ArrayBuffer).to.be.true;
        expect(options2.challenge.byteLength).to.equal(64);
        expect(options2.timeout).to.equal(60000);

        expect(Buffer.from(options.challenge).equals(Buffer.from(options2.challenge))).to.be.false;
    });

    it('should create credential', async function ()
    {
        this.timeout(5 * 60 * 1000);
        browser.timeouts('script', 5 * 60 * 1000);

        await browser.url('http://localhost:4567/test_webauthn.html');

        const fido2lib = new Fido2Lib();
        const options = await fido2lib.createCredentialChallenge();

        options.challenge = Buffer.from(options.challenge).toString('binary');

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
                    type: res.type,
                    attenstationObject: Array.from(new Uint8Array(res.response.attestationObject)),
                    clientData: new TextDecoder('utf-8').decode(res.response.clientDataJSON)
                });
            } catch (ex) { done({ error: ex.message }); }})();
        }, options)).value;

        if (result.error) { throw new Error(result.error); }

        console.log("HELLO", result);


    });

    //await browser.pause(5000);
});
