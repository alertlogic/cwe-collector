
const assert = require('assert');
const rewire = require('rewire');
const cweMock = require('./cwe_mock');
var cweRewire = rewire('../index');
var cweStub = require('./cwe_stub');
const { KMS } = require("@aws-sdk/client-kms");
    
describe('CWE Unit Tests', function() {

    describe('getStatisticsFunctions()', () => {
        var rewireGetStatisticsFunctions;
        beforeEach(function() {
            rewireGetStatisticsFunctions = cweRewire.__get__('getStatisticsFunctions');
        });

        it('generates an empty list when passed a GD event', () => {
            const result = rewireGetStatisticsFunctions(cweMock.GD_OTHER_KINESIS_TEST_EVENT);
            assert(result.length === 0);
        });

        it('generates a list of functions when passed a Checkin Event', () => {
            const result = rewireGetStatisticsFunctions(cweMock.CHECKIN_TEST_EVENT);
            assert(result.length !== 0);
        });

        it('generates an empty array when an update event is passed', () => {
            const result = rewireGetStatisticsFunctions(cweMock.UPDATE_TEST_EVENT);
            assert(result.length === 0);
        });
    });

    describe('formatMessages()', function() {
        var rewireFormatMessages;

        beforeEach(function() {
            rewireFormatMessages = cweRewire.__get__('formatMessages');
        });

        afterEach(function() {
        });

        it('Guard Duty events format success', function(done) {
            var context = {
                invokedFunctionArn : 'test:arn'
            };
            rewireFormatMessages(cweMock.GD_ONLY_KINESIS_TEST_EVENT, context, function(formatError, collectedData) {
                var expected = {
                    collected_batch : {
                        source_id : context.invokedFunctionArn,
                        collected_messages : [cweMock.GD_EVENT]
                    }
                };
                 assert.equal(null, formatError);
                 assert.deepEqual(expected,collectedData);
                done();
            });
        });
        
        it('Guard Duty events filtering', function(done) {
            var context = {
                invokedFunctionArn : 'test:arn'
            };
            rewireFormatMessages(cweMock.GD_OTHER_KINESIS_TEST_EVENT, context, function(formatError, collectedData) {
                var expected = {
                    collected_batch : {
                        source_id : context.invokedFunctionArn,
                        collected_messages : [cweMock.GD_EVENT]
                    }
                };
                assert.equal(null, formatError);
                assert.deepEqual(expected, collectedData);
                done();
            });
        });

        it('Non-Guard Duty events filtering', function(done) {
            var context = {
                invokedFunctionArn : 'test:arn'
            };
            rewireFormatMessages(cweMock.NON_GD_OTHER_KINESIS_TEST_EVENT, context, function(formatError, collectedData) {
                assert.equal(formatError, null);
                assert.equal(collectedData, undefined);
                done();
            });
        });
        
        
        it('Zero Guard Duty events filtering', function(done) {
            var context = {
                invokedFunctionArn : 'test:arn'
            };
            rewireFormatMessages(cweMock.NO_GD_KINESIS_TEST_EVENT, context, function(formatError, collectedData) {
                assert.equal(null, formatError);
                assert.equal(undefined, collectedData);
                done();
            });
        });
        
        it('Filter out malformed GD jsons', function(done) {
            var context = {
                invokedFunctionArn : 'test:arn'
            };
            rewireFormatMessages(cweMock.GD_MALFORMED_KINESIS_TEST_EVENT, context, function(formatError, collectedData) {
                assert.equal(null, formatError);
                assert.equal(undefined, collectedData);
                done();
            });
        });
    });


    describe('getDecryptedCredentials()', function() {
        var rewireGetDecryptedCredentials;

        const ACCESS_KEY_ID = 'access_key_id';
        const ENCRYPTED_SECRET_KEY = 'encrypted_secret_key';
        const ENCRYPTED_SECRET_KEY_BASE64 = Buffer.from(ENCRYPTED_SECRET_KEY).toString('base64');
        const DECRYPTED_SECRET_KEY = 'secret_key';

        before(function() {
            cweRewire = rewire('../index');
            rewireGetDecryptedCredentials = cweRewire.__get__('getDecryptedCredentials');
        });

        afterEach(function() {
            cweStub.restore(KMS, 'decrypt');
        });

        it('if AIMS_CREDS are declared already it returns ok', function(done) {
            cweRewire.__set__('AIMS_CREDS', {
                access_key_id : ACCESS_KEY_ID,
                secret_key: DECRYPTED_SECRET_KEY
            });
            cweStub.mock(KMS, 'decrypt', function (data, callback) {
                throw Error('don\'t call me');
            });
            rewireGetDecryptedCredentials(function(err) { if (err === null) done(); });
        });

        it('if AIMS_CREDS are not declared KMS decryption is called', function(done) {
            cweRewire.__set__('AIMS_CREDS', undefined);
            process.env.aims_access_key_id = ACCESS_KEY_ID;
            process.env.aims_secret_key = ENCRYPTED_SECRET_KEY_BASE64;
    
            cweStub.mock(KMS, 'decrypt', function (data, callback) {
                assert.equal(data.CiphertextBlob, ENCRYPTED_SECRET_KEY);
                return callback(null, { Plaintext: Buffer.from(DECRYPTED_SECRET_KEY) });
            });
            rewireGetDecryptedCredentials(function(err) {
                assert.equal(err, null);
                assert.deepEqual(cweRewire.__get__('AIMS_CREDS'), {
                    access_key_id: ACCESS_KEY_ID,
                    secret_key: DECRYPTED_SECRET_KEY
                });
                done();
            });
        });

        it('if some error during decryption, function fails', function(done) {
            cweRewire.__set__('AIMS_CREDS', undefined);
            process.env.aims_access_key_id = ACCESS_KEY_ID;
            process.env.aims_secret_key = Buffer.from('wrong_key').toString('base64');
            cweStub.mock(KMS, 'decrypt', function (data, callback) {
                assert.equal(data.CiphertextBlob, 'wrong_key');
                return callback('error', 'stack');
            });
            rewireGetDecryptedCredentials(function(err) {
                assert.equal(err, 'error');
                done();
            });
        });
    });
});
