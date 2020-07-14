/*jslint node: true */
"use strict";

module.exports = function (grunt)
{
    grunt.initConfig(
    {
        eslint: {
            target: [ '*.js', 'test/**/*.js' ],
        },

        mochaTest: {
            default: {
                src: ['test/test_example.js', 'test/test_spec.js']
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

        shell: {
            cover: {
                command: "./node_modules/.bin/nyc -x Gruntfile.js -x 'test/**' -x wdio.conf.js ./node_modules/.bin/grunt test-webauthn test",
                options: {
                    execOptions: {
                        stdio: 'inherit'
                    }
                }
            },

            cover_report: {
                command: './node_modules/.bin/nyc report -r lcov',
                options: {
                    execOptions: {
                        stdio: 'inherit'
                    }
                }
            },

            cover_check: {
                command: './node_modules/.bin/nyc check-coverage --statements 100 --branches 100 --functions 100 --lines 100',
                options: {
                    execOptions: {
                        stdio: 'inherit'
                    }
                }
            },

            coveralls: {
                command: 'cat coverage/lcov.info | coveralls',
                options: {
                    execOptions: {
                        stdio: 'inherit'
                    }
                }
            },

            test_webauthn: {
                command: './node_modules/.bin/wdio',
                options: {
                    execOptions: {
                        stdio: 'inherit'
                    }
                }
            }
        }
    });
    
    grunt.loadNpmTasks('grunt-eslint');
    grunt.loadNpmTasks('grunt-mocha-test');
    grunt.loadNpmTasks('grunt-apidox');
    grunt.loadNpmTasks('grunt-shell-spawn');

    grunt.registerTask('lint', 'eslint');
    grunt.registerTask('test', 'mochaTest:default');
    grunt.registerTask('test-webauthn', 'shell:test_webauthn');
    grunt.registerTask('docs', 'apidox');
    grunt.registerTask('coverage', ['shell:cover',
								    'shell:cover_report',
                                    'shell:cover_check']);
    grunt.registerTask('coveralls', 'shell:coveralls');
    grunt.registerTask('default', ['lint', 'test']);
};
