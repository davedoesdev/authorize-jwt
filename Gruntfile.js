/*jslint node: true */
"use strict";

module.exports = function (grunt)
{
    grunt.initConfig(
    {
        eslint: {
            target: [ '*.js', 'test/**/*.js', '!test/fixtures/jsrsasign/**' ],
        },

        mochaTest: {
            default: {
                src: ['test/test_example.js', 'test/test_spec.js']
            },
            webauthn: {
                src: ['test/test_webauthn.js']
            },
            options: {
                timeout: 10000,
                bail: true
            }
        },

        apidox: {
            input: ['index.js'],
            output: 'README.md',
            fullSourceDescription: true,
            extraHeadingLevels: 1
        },

        bgShell: {
            cover: {
                cmd: "./node_modules/.bin/nyc -x Gruntfile.js -x 'test/**' -x wdio.conf.js node --napi-modules ./node_modules/.bin/grunt test-webauthn test",
                fail: true,
                execOpts: {
                    maxBuffer: 0
                }
            },

            cover_report: {
                cmd: './node_modules/.bin/nyc report -r lcov',
                fail: true
            },

            cover_check: {
                cmd: './node_modules/.bin/nyc check-coverage --statements 100 --branches 100 --functions 100 --lines 100',
                fail: true
            },

            coveralls: {
                cmd: 'cat coverage/lcov.info | coveralls',
                fail: true
            },

            test_webauthn: {
                cmd: './node_modules/.bin/wdio',
                fail: true
            }
        }
    });
    
    grunt.loadNpmTasks('grunt-eslint');
    grunt.loadNpmTasks('grunt-mocha-test');
    grunt.loadNpmTasks('grunt-apidox');
    grunt.loadNpmTasks('grunt-bg-shell');

    grunt.registerTask('lint', 'eslint');
    grunt.registerTask('test', 'mochaTest:default');
    grunt.registerTask('test-webauthn', process.env.CI === 'true' ?
            'mochaTest:webauthn' : 'bgShell:test_webauthn');
    grunt.registerTask('docs', 'apidox');
    grunt.registerTask('coverage', ['bgShell:cover',
								    'bgShell:cover_report',
                                    'bgShell:cover_check']);
    grunt.registerTask('coveralls', 'bgShell:coveralls');
    grunt.registerTask('default', ['lint', 'test']);
};
