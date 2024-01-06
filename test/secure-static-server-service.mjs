import { readFileSync } from 'fs';
import { createServer } from 'https';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { launcher as StaticServerLauncher } from '@wdio/static-server-service';

const __dirname = dirname(fileURLToPath(import.meta.url));

class SecureStaticServerLauncher extends StaticServerLauncher {
    constructor(...args) {
        super(...args);
        delete this._server; // remove field
    }

    set _server(v) {
        v.listen = function (port, cb) {
            const key = readFileSync(join(__dirname, 'keys', 'server.key'));
            const cert = readFileSync(join(__dirname, 'keys', 'server.crt'));
            const server = createServer({ key, cert }, this);
            server.listen(port, cb);
        };
        this.__server = v;
    }

    get _server() {
        return this.__server;
    }
}

export const launcher = SecureStaticServerLauncher;
