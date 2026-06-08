var CweCollector = require('../al-cwe-collector').cweCollector;
var m_alCollector = require('@alertlogic/al-collector-js');
const AlAwsCommon = require('@alertlogic/al-aws-collector-js').AlAwsCommon;
const m_response = require('cfn-response');
const cweMock = require('./cwe_mock');
const sinon = require('sinon');
const assert = require('assert');
var cweStub = require('./cwe_stub');
const { KMS } = require("@aws-sdk/client-kms"),
    { SSM } = require("@aws-sdk/client-ssm");
let alserviceStub = {};
let ingestCStub = {};
let setEnvStub = {};
let responseStub = {};
let decryptStub = {};
let ssmStub = {};

function setAlServiceStub() {
    alserviceStub.get = sinon.stub(m_alCollector.AlServiceC.prototype, 'get').callsFake(
        async function fakeFn(path, extraOptions) {
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
            return ret;
        });

    ingestCStub.sendSecmsgs = sinon.stub(m_alCollector.IngestC.prototype, 'sendSecmsgs').callsFake(
        async function fakeFn(data) {
            return null;
        });
    ingestCStub.logmsgs = sinon.stub(m_alCollector.IngestC.prototype, 'sendLogmsgs').callsFake(
        async function fakeFn(data) {
            return null;
        });

    ingestCStub.lmcStats = sinon.stub(m_alCollector.IngestC.prototype, 'sendLmcstats').callsFake(
        async function fakeFn(data) {
            return null;
        });
}

function restoreAlServiceStub() {
    alserviceStub.get.restore();
    ingestCStub.sendSecmsgs.restore();
    ingestCStub.logmsgs.restore();
    ingestCStub.lmcStats.restore();
}

function mockSetEnvStub() {
    setEnvStub = sinon.stub(AlAwsCommon, 'setEnvAsync').callsFake(async (vars) => {
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
        return returnBody;
    });
}

async function formatFunction(event, context) {
    return {
        collected_batch: {
            source_id: context.invokedFunctionArn,
            collected_messages: [cweMock.GD_EVENT]
        }
    };
}

describe('CWE collector Tests', function() {
    describe('Process cwe events', function () {
       
        beforeEach(function () {
            decryptStub = sinon.stub().callsFake(async function () {
                const data = {
                    Plaintext: Buffer.from('decrypted-sercret-key')
                };
                return data;
            });

            cweStub.mock(KMS, 'decrypt', decryptStub);

            cweStub.mock(KMS, 'encrypt', async function () {
                const data = {
                    CiphertextBlob: Buffer.from('creds-from-file').toString('base64')
                };
                return data;
            });

            ssmStub = sinon.stub().callsFake(async function () {
                const data = Buffer.from('test-secret');
                return { Parameter: { Value: data.toString('base64') } };
            });

            cweStub.mock(SSM, 'getParameter', ssmStub);

            responseStub = sinon.stub(m_response, 'send').callsFake(
                function fakeFn(event, mockContext, responseStatus, responseData, physicalResourceId) {
                    return;
                });

            setAlServiceStub();
            mockSetEnvStub();
        });
    
        afterEach(function () {
           restoreAlServiceStub();
           setEnvStub.restore();
           responseStub.restore();
           cweStub.restore(SSM,'getParameter');
           cweStub.restore(KMS, 'decrypt');
           cweStub.restore(KMS, 'encrypt');
        });
    
        it('Check process method  get called form handleEvent method if we have records', async function () {
            const collector = new CweCollector(cweMock.DEFAULT_LAMBDA_CONTEXT, cweMock.AIMS_TEST_CREDS);
            const processfakeFun = async function () { return { data: null }; };
            const processFake = sinon.stub(collector, 'process').callsFake(processfakeFun);
            await collector.handleEvent(cweMock.GD_ONLY_KINESIS_TEST_EVENT);
            sinon.assert.calledOnce(processFake);
        });
    
    
        it('Called the send and processLog method to send secmsgs and logmsgs ', async function () {
            var collector = new CweCollector(cweMock.DEFAULT_LAMBDA_CONTEXT, cweMock.AIMS_TEST_CREDS, formatFunction);
            const sendStub = sinon.stub(collector, 'send').callsFake(async function () {
                return null;
            });
            const processLogStub = sinon.stub(collector, 'processLog').callsFake(async function () {
                return null;
            });
            await collector.handleEvent(cweMock.GD_ONLY_KINESIS_TEST_EVENT);
            sinon.assert.calledOnce(sendStub);
            sinon.assert.calledOnce(processLogStub);
        });
    });
    describe('Format Log Tests', function(){
        it('Format success', async function() {
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
        }); 
    });
});


