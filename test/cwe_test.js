
const assert = require('assert');
const rewire = require('rewire');
const sinon = require('sinon');
const m_aimsc = require('al-collector-js/al_servicec').AimsC;
const AlAwsCollector = require('al-aws-collector-js/al_aws_collector');
var AWS = require('aws-sdk-mock');
const cweMock = require('./cwe_mock');
const cweMockErrors = require('./cwe_mock_errors');
var cweRewire = rewire('../index');
var servicecRewire = rewire('al-collector-js/al_servicec');
var m_servicec = require('al-collector-js/al_servicec');
var m_response = require('cfn-response');

describe('CWE Unit Tests', function() {

    // FIXME - check lambda update call
    describe('processScheduledEvent()', function() {
        var rewireProcessScheduleEvent;
        var mockCollector = {
            update: (callback) => {
                return callback("update");
            },
            checkin: (callback) => {
                return callback("checkin");
            }
        };

        before(function() {
            rewireProcessScheduleEvent = cweRewire.__get__('processScheduledEvent');
        });

        after(function() {

        });

        it('call function update', function(done) {
            rewireProcessScheduleEvent(cweMock.UPDATE_TEST_EVENT, mockCollector, cweMock.DEFAULT_LAMBDA_CONTEXT, (result) => {
                assert(result === "update");
                done();
            });
        });

        it('call function checkin', function(done) {
            rewireProcessScheduleEvent(cweMock.CHECKIN_TEST_EVENT, mockCollector, cweMock.DEFAULT_LAMBDA_CONTEXT, (result) => {
                assert(result === "checkin");
                done();
            });
        });

        it('fails when an unknown event is passed', function(done) {
            const stub = sinon.stub(cweMock.DEFAULT_LAMBDA_CONTEXT, "fail");
            rewireProcessScheduleEvent({"RequestType": "InvalidType"}, mockCollector, cweMock.DEFAULT_LAMBDA_CONTEXT, null);
            assert(stub.called);
            done();
        });
    });

    describe('formatMessages()', function() {

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
                assert.equal(JSON.stringify(expected), collectedData);
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
                assert.equal(JSON.stringify(expected), collectedData);
                done();
            });
        });

        it('Non-Guard Duty events filtering', function(done) {
            var context = {
                invokedFunctionArn : 'test:arn'
            };
            rewireFormatMessages(cweMock.NON_GD_OTHER_KINESIS_TEST_EVENT, context, function(formatError, collectedData) {
                var expected = '';
                assert.equal(formatError, null);
                assert.equal(collectedData, expected);
                done();
            });
        });
        
        
        it('Zero Guard Duty events filtering', function(done) {
            var context = {
                invokedFunctionArn : 'test:arn'
            };
            rewireFormatMessages(cweMock.NO_GD_KINESIS_TEST_EVENT, context, function(formatError, collectedData) {
                assert.equal(null, formatError);
                assert.equal('', collectedData);
                done();
            });
        });
        
        it('Filter out malformed GD jsons', function(done) {
            var context = {
                invokedFunctionArn : 'test:arn'
            };
            rewireFormatMessages(cweMock.GD_MALFORMED_KINESIS_TEST_EVENT, context, function(formatError, collectedData) {
                assert.equal(null, formatError);
                assert.equal('', collectedData);
                done();
            });
        });
    });


    describe('getDecryptedCredentials()', function() {
        var rewireGetDecryptedCredentials;
        var stub;

        const ACCESS_KEY_ID = 'access_key_id';
        const ENCRYPTED_SECRET_KEY = 'encrypted_secret_key';
        const ENCRYPTED_SECRET_KEY_BASE64 = new Buffer(ENCRYPTED_SECRET_KEY).toString('base64');
        const DECRYPTED_SECRET_KEY = 'secret_key';

        before(function() {
            cweRewire = rewire('../index');
            rewireGetDecryptedCredentials = cweRewire.__get__('getDecryptedCredentials');
        });

        afterEach(function() {
            AWS.restore('KMS', 'decrypt');
        });

        it('if AIMS_CREDS are declared already it returns ok', function(done) {
            cweRewire.__set__('AIMS_CREDS', {
                access_key_id : ACCESS_KEY_ID,
                secret_key: DECRYPTED_SECRET_KEY
            });
            AWS.mock('KMS', 'decrypt', function (data, callback) {
                throw Error('don\'t call me');
            });
            rewireGetDecryptedCredentials(function(err) { if (err === null) done(); });
        });

        it('if AIMS_CREDS are not declared KMS decryption is called', function(done) {
            cweRewire.__set__('AIMS_CREDS', undefined);
            cweRewire.__set__('process', {
                    env : {
                        aims_access_key_id : ACCESS_KEY_ID,
                        aims_secret_key: ENCRYPTED_SECRET_KEY_BASE64
                    }
            });
            AWS.mock('KMS', 'decrypt', function (data, callback) {
                assert.equal(data.CiphertextBlob, ENCRYPTED_SECRET_KEY);
                return callback(null, {Plaintext : DECRYPTED_SECRET_KEY});
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
            cweRewire.__set__('process', {
                    env : {
                        aims_access_key_id : ACCESS_KEY_ID,
                        aims_secret_key: new Buffer('wrong_key').toString('base64')
                    }
            });
            AWS.mock('KMS', 'decrypt', function (data, callback) {
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
