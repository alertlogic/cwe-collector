
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

        it('Guard Duty events format success', async function() {
            var context = {
                invokedFunctionArn : 'test:arn'
            };
            const collectedData = await rewireFormatMessages(cweMock.GD_ONLY_KINESIS_TEST_EVENT, context);
            var expected = {
                collected_batch : {
                    source_id : context.invokedFunctionArn,
                    collected_messages : [cweMock.GD_EVENT]
                }
            };
            assert.deepEqual(expected,collectedData);
        });
        
        it('Guard Duty events filtering', async function() {
            var context = {
                invokedFunctionArn : 'test:arn'
            };
            const collectedData = await rewireFormatMessages(cweMock.GD_OTHER_KINESIS_TEST_EVENT, context);
            var expected = {
                collected_batch : {
                    source_id : context.invokedFunctionArn,
                    collected_messages : [cweMock.GD_EVENT]
                }
            };
            assert.deepEqual(expected, collectedData);
        });

        it('Non-Guard Duty events filtering', async function() {
            var context = {
                invokedFunctionArn : 'test:arn'
            };
            const collectedData = await rewireFormatMessages(cweMock.NON_GD_OTHER_KINESIS_TEST_EVENT, context);
            assert.equal(collectedData, undefined);
        });
        
        
        it('Zero Guard Duty events filtering', async function() {
            var context = {
                invokedFunctionArn : 'test:arn'
            };
            const collectedData = await rewireFormatMessages(cweMock.NO_GD_KINESIS_TEST_EVENT, context);
            assert.equal(undefined, collectedData);
        });
        
        it('Filter out malformed GD jsons', async function() {
            var context = {
                invokedFunctionArn : 'test:arn'
            };
            const collectedData = await rewireFormatMessages(cweMock.GD_MALFORMED_KINESIS_TEST_EVENT, context);
            assert.equal(undefined, collectedData);
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

        it('if AIMS_CREDS are declared already it returns ok', async function() {
            cweRewire.__set__('AIMS_CREDS', {
                access_key_id : ACCESS_KEY_ID,
                secret_key: DECRYPTED_SECRET_KEY
            });
            cweStub.mock(KMS, 'decrypt', function () {
                throw Error('don\'t call me');
            });
            const result = await rewireGetDecryptedCredentials();
            assert.equal(result, null);
        });

        it('if AIMS_CREDS are not declared KMS decryption is called', async function() {
            cweRewire.__set__('AIMS_CREDS', undefined);
            process.env.aims_access_key_id = ACCESS_KEY_ID;
            process.env.aims_secret_key = ENCRYPTED_SECRET_KEY_BASE64;
    
            cweStub.mock(KMS, 'decrypt', async function (data) {
                assert.deepEqual(data.CiphertextBlob, Buffer.from(ENCRYPTED_SECRET_KEY_BASE64, 'base64'));
                return { Plaintext: Buffer.from(DECRYPTED_SECRET_KEY) };
            });
            await rewireGetDecryptedCredentials();
            assert.deepEqual(cweRewire.__get__('AIMS_CREDS'), {
                access_key_id: ACCESS_KEY_ID,
                secret_key: DECRYPTED_SECRET_KEY
            });
        });

        it('if some error during decryption, function fails', async function() {
            cweRewire.__set__('AIMS_CREDS', undefined);
            process.env.aims_access_key_id = ACCESS_KEY_ID;
            process.env.aims_secret_key = Buffer.from('wrong_key').toString('base64');
            cweStub.mock(KMS, 'decrypt', async function (data) {
                assert.deepEqual(data.CiphertextBlob, Buffer.from('wrong_key'));
                throw 'error';
            });
            await assert.rejects(
                rewireGetDecryptedCredentials(),
                (err) => err === 'error'
            );
        });
    });
});
