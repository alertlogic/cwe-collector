
const assert = require('assert');
const rewire = require('rewire');
const sinon = require('sinon');
const m_aimsc = require('al-collector-js/al_servicec').AimsC;
var AWS = require('aws-sdk-mock');
const cweMock = require('./cwe_mock');
var cweRewire = rewire('../index');
var m_servicec = require('al-collector-js/al_servicec');
var m_response = require('cfn-response');

describe('CWE Unit Tests', function() {

    describe('processEvent()', function() {
        var rewireFun;

        afterEach(function() {
            rewireFun();
        });

        it('cloudwatch event triggers processKinesisRecords()', function(done) {
            rewireFun = cweRewire.__set__({processKinesisRecords: () => { done();}});
            cweRewire.handler(cweMock.GD_ONLY_KINESIS_TEST_EVENT, null);
        });

        it('scheduled event triggers processScheduledEvent()', function(done) {
            rewireFun = cweRewire.__set__({processScheduledEvent: () => { done(); }});
            cweRewire.handler({RequestType : 'ScheduledEvent'}, null);
        });
    });


    // FIXME - check lambda update call
    describe('processScheduledEvent()', function() {

        before(function() {

        });

        after(function() {

        });

        it('call function update', function(done) {
            done();
        });
    });

    describe('processRegistration()', function() {
        var rewireGetDecryptedCredentials;
        var rewireGetAlAuth;
        var rewireProcessRegistration;
        var responseStub;
        var azcollectStub;

        before(function() {
            azcollectStub = sinon.stub(m_servicec.AlServiceC.prototype, 'post').callsFake(
                function fakeFn(path, extraOptions) {
                    assert.equal(cweMock.REGISTRATION_TEST_URL, path);
                    assert.equal(cweMock.REGISTRATION_STACK_NAME, extraOptions.body.cf_stack_name);
                    assert.equal(cweMock.REGISTRATION_COLLECT_RULE, extraOptions.body.collect_rule);
                    return new Promise(function(resolve, reject) {
                                return [{}];
                           });
                });
            responseStub = sinon.stub(m_response, 'send').callsFake(
                 function fakeFn() {
                 });
        });

        beforeEach(function() {
            rewireProcessRegistration = cweRewire.__get__('processRegistration');
            rewireGetDecryptedCredentials = cweRewire.__set__(
                {getDecryptedCredentials: (callback) => { callback(null); }}
            );
            rewireGetAlAuth = cweRewire.__set__(
                {getAlAuth: (callback) => { callback(null, {}); }}
            );
        });

        afterEach(function() {
            rewireGetDecryptedCredentials();
            rewireGetAlAuth();
        });

        after(function() {
            azcollectStub.restore();
            responseStub.restore();
        });

        it('registration waterfall flow OK - sendRegistration()', function(done) {
            var context = {
                functionName : cweMock.REGISTRATION_TEST_FUNCTION_NAME,
                fail : (reason) => { if (reason === 'test error') done(); },
                done : () => { done(); }
            };
            rewireProcessRegistration(cweMock.REGISTRATION_TEST_EVENT, context, true);
            done();
        });

        it('registration waterfall flow error - getDecryptedCredentials()', function(done) {
            var context = {
                fail : (reason) => { }
            };
            rewireGetDecryptedCredentials = cweRewire.__set__(
                {getDecryptedCredentials: function(callback) { callback('decryption_error'); }}
            );
            rewireProcessRegistration(cweMock.REGISTRATION_TEST_EVENT, context, true);
            done();
        });

        it('registration waterfall flow error - getAlAuth()', function(done) {
            var context = {
                fail : (reason) => { if (reason === 'test error') done(); }
            };
            rewireGetAlAuth = cweRewire.__set__(
                {getAlAuth: function(callback) { callback('test error'); }}
            );
            rewireProcessRegistration(cweMock.REGISTRATION_TEST_EVENT, context, true);
            done();
        });

    });

    describe('processDeregistration()', function() {
        var rewireGetDecryptedCredentials;
        var rewireGetAlAuth;
        var rewireProcessRegistration;
        var responseStub;
        var azcollectStub;

        before(function() {
            azcollectStub = sinon.stub(m_servicec.AlServiceC.prototype, 'deleteRequest').callsFake(
                function fakeFn(path, extraOptions) {
                    assert.equal(cweMock.REGISTRATION_TEST_URL, path);
                    return new Promise(function(resolve, reject) {
                                return [{}];
                           });
                });
            responseStub = sinon.stub(m_response, 'send').callsFake(
                 function fakeFn() {
                 });
        });

        beforeEach(function() {
            rewireProcessRegistration = cweRewire.__get__('processRegistration');
            rewireGetDecryptedCredentials = cweRewire.__set__(
                {getDecryptedCredentials: (callback) => { callback(null); }}
            );
            rewireGetAlAuth = cweRewire.__set__(
                {getAlAuth: (callback) => { callback(null, {}); }}
            );
        });

        afterEach(function() {
            rewireGetDecryptedCredentials();
            rewireGetAlAuth();
        });

        after(function() {
            azcollectStub.restore();
            responseStub.restore();
        });

        it('deregistration waterfall flow OK - sendRegistration()', function(done) {
            var context = {
                functionName : cweMock.REGISTRATION_TEST_FUNCTION_NAME,
                fail : (reason) => { if (reason === 'test error') done(); },
                done : () => { done(); }
            };
            rewireProcessRegistration(cweMock.REGISTRATION_TEST_EVENT, context, false);
            done();
        });

        it('deregistration waterfall flow error - getDecryptedCredentials()', function(done) {
            var context = {
                fail : (reason) => { }
            };
            rewireGetDecryptedCredentials = cweRewire.__set__(
                {getDecryptedCredentials: function(callback) { callback('decryption_error'); }}
            );
            rewireProcessRegistration(cweMock.REGISTRATION_TEST_EVENT, context, false);
            done();
        });

        it('registration waterfall flow error - getAlAuth()', function(done) {
            var context = {
                fail : (reason) => { if (reason === 'test error') done(); }
            };
            rewireGetAlAuth = cweRewire.__set__(
                {getAlAuth: function(callback) { callback('test error'); }}
            );
            rewireProcessRegistration(cweMock.REGISTRATION_TEST_EVENT, context, false);
            done();
        });

    });

    describe('processKinesisRecords()', function() {
        var rewireGetDecryptedCredentials;
        var rewireGetAlAuth;
        var rewireFormatMessages;
        var rewireSendToIngest;
        var rewireProcessKinesisRecords;

        beforeEach(function() {
            rewireProcessKinesisRecords = cweRewire.__get__('processKinesisRecords');
            rewireGetDecryptedCredentials = cweRewire.__set__(
                {getDecryptedCredentials: (callback) => { callback(null); }}
            );
            rewireGetAlAuth = cweRewire.__set__(
                {getAlAuth: (callback) => { callback(null, {}); }}
            );
            rewireFormatMessages = cweRewire.__set__(
                {formatMessages: (event, context, callback) => { callback(null, 'msg'); }}
            );
            rewireSendToIngest = cweRewire.__set__(
                {sendToIngest: (event, context, aimsC, message, callback) => { callback(null, 'resp'); }}
            );
        });

        afterEach(function() {
            rewireGetDecryptedCredentials();
            rewireGetAlAuth();
            rewireFormatMessages();
            rewireSendToIngest();
        });

        it('waterfall flow OK', function(done) {
            var context = {
                succeed : () => { done(); }
            };
            rewireProcessKinesisRecords(cweMock.GD_ONLY_KINESIS_TEST_EVENT, context);
        });

        it('waterfall flow error - getDecryptedCredentials()', function(done) {
            var context = {fail : (reason) => { if (reason === 'decryption_error') done(); } };
            rewireGetDecryptedCredentials = cweRewire.__set__(
                {getDecryptedCredentials: function(callback) { callback('decryption_error'); }}
            );
            rewireProcessKinesisRecords(cweMock.GD_ONLY_KINESIS_TEST_EVENT, context);
        });

        it('waterfall flow error - getAlAuth()', function(done) {
            var context = {
                fail : (reason) => { if (reason === 'test error') done(); } 
            };
            rewireGetAlAuth();
            rewireGetAlAuth = cweRewire.__set__(
                {getAlAuth: function(callback) { callback('test error'); }}
            );
            rewireProcessKinesisRecords(cweMock.GD_ONLY_KINESIS_TEST_EVENT, context);
        });

        it('waterfall flow error - formatMessages()', function(done) {
            var context = {
                fail : (reason) => { if (reason === 'test error') done(); }
            };
            rewireFormatMessages = cweRewire.__set__(
                {formatMessages: (event, fakeContext, callback) => { callback('test error'); }}
            );
            rewireProcessKinesisRecords(cweMock.GD_ONLY_KINESIS_TEST_EVENT, context);
        });

        it('waterfall flow error - sendToIngest()', function(done) {
            var context = {
                fail : (reason) => { if (reason === 'test error') done(); }
            };
            rewireSendToIngest();
            rewireSendToIngest = cweRewire.__set__(
                {sendToIngest: (event, fakeContext, aimsC, message, callback) => { callback('test error'); }}
            );
            rewireProcessKinesisRecords(cweMock.GD_ONLY_KINESIS_TEST_EVENT, context);
        });
    });

    describe('sendToIngest()', function() {
        var rewireGetDecryptedCredentials;
        var rewireGetAlAuth;
        var rewireSendToIngest;
        var aimscStub;
        var responseStub;
        var ingestStub;

        before(function() {
            aimscStub = sinon.stub(m_aimsc.prototype, 'authenticate').
            callsFake(
                function fake(aa,bb) {
                    return new Promise(function(resolve, reject) {
                        resolve();
                    });
                }
            );
            responseStub = sinon.stub(m_response, 'send').callsFake(
                 function fakeFn() {
                 });
        });

        beforeEach(function() {
            rewireSendToIngest = cweRewire.__get__('sendToIngest');
            rewireGetDecryptedCredentials = cweRewire.__set__(
                {getDecryptedCredentials: (callback) => { callback(null); }}
            );
            rewireGetAlAuth = cweRewire.__set__(
                {getAlAuth: (callback) => { callback(null, {}); }}
            );
        });

        afterEach(function() {
            rewireGetDecryptedCredentials();
            rewireGetAlAuth();
            ingestStub.restore();
        });

        after(function() {
            responseStub.restore();
            aimscStub.restore();
        });

        it('waterfall send to ingest OK', function(done) {
            ingestStub = sinon.stub(m_servicec.AlServiceC.prototype, 'post').callsFake(
                function fakeFn(path, extraOptions) {
                    assert.equal(cweMock.INGEST_TEST_URL, path);
                    return new Promise(function(resolve, reject) {
                                resolve();
                           });
                });
            
            var context = {};            
            var collectedBatch = JSON.stringify(cweMock.TEST_COLLECTED_BATCH);
            rewireSendToIngest(cweMock.GD_ONLY_KINESIS_TEST_EVENT, context,
                aimscStub, collectedBatch, 
                function(arg) { 
                    done();
                });            
        });

        it('waterfall send to ingest Error', function(done) {
            ingestStub = sinon.stub(m_servicec.AlServiceC.prototype, 'post').callsFake(
                function fakeFn(path, extraOptions) {
                    assert.equal(cweMock.INGEST_TEST_URL, path);
                    return new Promise(function(resolve, reject) {
                                throw 'exception';
                           });
                });
            
            var context = {};            
            var collectedBatch = JSON.stringify(cweMock.TEST_COLLECTED_BATCH);
            rewireSendToIngest(cweMock.GD_ONLY_KINESIS_TEST_EVENT, context,
                aimscStub, collectedBatch, 
                function(exception) {
                    assert.equal('Unable to send to Ingest exception', exception);                    
                    done();
                });            
        });
        
    });

    describe('getAlAuth()', function() {
        var rewireGetAlAuth;
        var stub;

        before(function() {
            cweRewire = rewire('../index');
            cweRewire.__set__('AIMS_CREDS', {
                access_key_id : 'access_key_id',
                secret_key: 'secret_key_value'
            });
            rewireGetAlAuth = cweRewire.__get__('getAlAuth');
        });

        afterEach(function() {
            stub.restore();
        });

        it('aims returns ok', function(done) {
            stub = sinon.stub(m_aimsc.prototype, 'authenticate').
            callsFake(
                function fake(aa,bb) {
                    return new Promise(function(resolve, reject) {
                        resolve();
                    });
                }
            );

            rewireGetAlAuth(function(err) { if (err === null) done(); });
        });

        it('aims returns error', function(done) {
            stub = sinon.stub(m_aimsc.prototype, 'authenticate').
            callsFake(
                function fake(aa,bb) {
                    return new Promise(function(resolve, reject) {
                        reject('reject');
                    });
                }
            );

            rewireGetAlAuth(function(err) { if (err === 'reject') done(); });
        });

        it('aims throws exception', function(done) {
            stub = sinon.stub(m_aimsc.prototype, 'authenticate').
            callsFake(
                function fake(aa,bb) {
                    return new Promise(function(resolve, reject) {
                        throw 'exception';
                    });
                }
            );

            rewireGetAlAuth(function(err) { if (err === 'exception') done(); });
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
