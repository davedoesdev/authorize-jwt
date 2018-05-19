describe('WebAuthn', function ()
{
    it('should create credential challenge', async function ()
    {
        await browser.url('http://localhost:4567/test_webauthn.html');
        await browser.pause(5000);

    });
});
