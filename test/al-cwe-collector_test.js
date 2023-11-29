var CweCollector = require('../al-cwe-collector').cweCollector;
var m_alCollector = require('@alertlogic/al-collector-js');
const m_al_aws = require('@alertlogic/al-aws-collector-js').Util;
const m_response = require('cfn-response');
const cweMock = require('./cwe_mock');
const sinon = require('sinon');
const assert = require('assert');
var AWS = require('aws-sdk-mock');
let alserviceStub = {};
let ingestCStub = {};
let setEnvStub = {};
let responseStub = {};
let decryptStub = {};
let ssmStub = {};

function setAlServiceStub() {
    alserviceStub.get = sinon.stub(m_alCollector.AlServiceC.prototype, 'get').callsFake(
        function fakeFn(path, extraOptions) {
            return new Promise(function (resolve, reject) {
                var ret = null;
                switch (path) {
                    case '/residency/default/services/ingest/endpoint':
                        ret = {
                            ingest: 'new-ingest-endpoint'
                        };
                        break;
                    case '/residency/default/services/azcollect/endpoint':
                        ret = {
                            azcollect: 'new-azcollect-endpoint'
                        };
                        break;
                    case '/residency/default/services/collector_status/endpoint':
                        ret = {
                            collector_status: 'new-collectors-status-endpoint'
                        };
                        break;
                    default:
                        break;
                }
                return resolve(ret);
            });
        });

    ingestCStub.sendSecmsgs = sinon.stub(m_alCollector.IngestC.prototype, 'sendSecmsgs').callsFake(
        function fakeFn(data, callback) {
            return new Promise(function (resolve, reject) {
                resolve(null);
            });
        });
    ingestCStub.logmsgs = sinon.stub(m_alCollector.IngestC.prototype, 'sendLogmsgs').callsFake(
        function fakeFn(data, callback) {
            return new Promise(function (resolve, reject) {
                resolve(null);
            });
        });

    ingestCStub.lmcStats = sinon.stub(m_alCollector.IngestC.prototype, 'sendLmcstats').callsFake(
        function fakeFn(data, callback) {
            return new Promise(function (resolve, reject) {
                resolve(null);
            });
        });
}

function restoreAlServiceStub() {
    alserviceStub.get.restore();
    ingestCStub.sendSecmsgs.restore();
    ingestCStub.logmsgs.restore();
    ingestCStub.lmcStats.restore();
}

function mockSetEnvStub() {
    setEnvStub = sinon.stub(m_al_aws, 'setEnv').callsFake((vars, callback) => {
        const {
            ingest_api,
            azcollect_api,
            collector_status_api
        } = vars;
        process.env.ingest_api = ingest_api ? ingest_api : process.env.ingest_api;
        process.env.azollect_api = azcollect_api ? azcollect_api : process.env.azollect_api;
        process.env.collector_status_api = collector_status_api ? collector_status_api : process.env.collector_status_api;
        const returnBody = {
            Environment: {
                Varaibles: vars
            }
        };
        return callback(null, returnBody);
    });
}

function formatFunction(event, context, callback) {
    let collectedData = {
        collected_batch: {
            source_id: context.invokedFunctionArn,
            collected_messages: [cweMock.GD_EVENT]
        }
    };
    return callback(null, collectedData);
}

describe('CWE collector Tests', function() {
    describe('Process cwe events', function () {
       
        beforeEach(function () {
            decryptStub = sinon.stub().callsFake(function (params, callback) {
                const data = {
                    Plaintext: 'decrypted-sercret-key'
                };
                return callback(null, data);
            });

            AWS.mock('KMS', 'decrypt', decryptStub);

            AWS.mock('KMS', 'encrypt', function (params, callback) {
                const data = {
                    CiphertextBlob: Buffer.from('creds-from-file')
                };
                return callback(null, data);
            });

            ssmStub = sinon.stub().callsFake(function (params, callback) {
                const data = Buffer.from('test-secret');
                return callback(null, { Parameter: { Value: data.toString('base64') } });
            });

            AWS.mock('SSM', 'getParameter', ssmStub);

            responseStub = sinon.stub(m_response, 'send').callsFake(
                function fakeFn(event, mockContext, responseStatus, responseData, physicalResourceId) {
                    mockContext.succeed();
                });

            setAlServiceStub();
            mockSetEnvStub();
        });
    
        afterEach(function () {
           restoreAlServiceStub();
           setEnvStub.restore();
           responseStub.restore();
           AWS.restore('SSM');
           AWS.restore('KMS');
        });
    
        it('Check process method  get called form handleEvent method if we have records', function (done) {
            const collector = new CweCollector(cweMock.DEFAULT_LAMBDA_CONTEXT, cweMock.AIMS_TEST_CREDS);
            const processfakeFun = function (event, callback) { return callback(null, { data: null }); };
            const processFake = sinon.stub(collector, 'process').callsFake(processfakeFun);
    
            collector.handleEvent(cweMock.GD_ONLY_KINESIS_TEST_EVENT, () => {
                sinon.assert.calledOnce(processFake);
                done();
            });
        });
    
    
        it('Called the send and processLog method to send secmsgs and logmsgs ', function (done) {
            var collector = new CweCollector(cweMock.DEFAULT_LAMBDA_CONTEXT, cweMock.AIMS_TEST_CREDS, formatFunction);
    
            collector.handleEvent(cweMock.GD_ONLY_KINESIS_TEST_EVENT, () => {
                sinon.assert.calledOnce( ingestCStub.sendSecmsgs);
                sinon.assert.calledOnce( ingestCStub.logmsgs);
                sinon.assert.calledOnce( ingestCStub.lmcStats);
                done();
            });
        });
    });
    describe('Format Log Tests', function(){
        it('Format success', function(done) {
            const formattedMsg = {
                hostname: 'collector-id',
                messageTs: 0,
                priority: 11,
                progName: 'CWECollector',
                message: JSON.stringify(cweMock.GD_EVENT),
                messageType: 'json/cwe',
                applicationId: 'guardduty',
                messageTypeId: 'UnauthorizedAccess:EC2/MaliciousIPCaller.Custom'
            };
            let collector = new CweCollector(cweMock.DEFAULT_LAMBDA_CONTEXT, cweMock.AIMS_TEST_CREDS);
            let bindFormat = collector.formatLog.bind(collector);
            const returned = bindFormat(cweMock.GD_EVENT);
            assert.deepEqual(returned, formattedMsg);
            done();
        }); 
    });
});


