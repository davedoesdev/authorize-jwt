/*jslint node: true */
"use strict";

const { homedir } = require('os');
const { join } = require('path');

const c8 = "npx c8 -x Gruntfile.js -x 'test/**' -x wdio.conf.js";

module.exports = function (grunt)
{
    grunt.initConfig(
    {
        env: {
            test: {
                TMPDIR: join(homedir(), 'tmp')
            }
        },

        eslint: {
            target: [ '*.js', 'test/**/*.js' ],
        },

        apidox: {
            input: ['index.js'],
            output: 'README.md',
            fullSourceDescription: true,
            extraHeadingLevels: 1
        },

        exec: Object.fromEntries(Object.entries({
            test: 'mocha --bail --timeout 10000 test/test_example.js test/test_spec.js',
            test_webauthn: 'npx wdio',
            cover: `${c8} npx grunt test-webauthn test`,
            cover_report: `${c8} report -r lcov`,
            cover_check: `${c8} check-coverage --statements 100 --branches 100 --functions 100 --lines 100`
        }).map(([k, cmd]) => [k, { cmd, stdio: 'inherit' }]))
    });
    
    grunt.loadNpmTasks('grunt-eslint');
    grunt.loadNpmTasks('grunt-apidox');
    grunt.loadNpmTasks('grunt-exec');
    grunt.loadNpmTasks('grunt-env');

    grunt.registerTask('lint', 'eslint');
    grunt.registerTask('test', 'exec:test');
    grunt.registerTask('test-webauthn', ['env:test', 'exec:test_webauthn']);
    grunt.registerTask('docs', 'apidox');
    grunt.registerTask('coverage', ['exec:cover',
                                    'exec:cover_report',
                                    'exec:cover_check']);
    grunt.registerTask('default', ['lint', 'test']);
};
