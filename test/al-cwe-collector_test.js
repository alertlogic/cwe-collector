var CweCollector = require('../al-cwe-collector').cweCollector;
const alAwsCollector = require('@alertlogic/al-aws-collector-js');
const cweMock = require('./cwe_mock');
const sinon = require('sinon');
const assert = require('assert');

let credentials = {};
let alAwsCollectorStub = {}; 

function setAlAwsCollectorStub() {
    const sendfakeFun = function (formattedData, compress, injestType, callback) { return callback(null, { data: null }); };
    alAwsCollectorStub.send = sinon.stub(alAwsCollector.AlAwsCollector.prototype, 'send').callsFake(sendfakeFun);

    const processLogfakeFun = function (messages, formatFun, hostmetaElems, callback) { return callback(null, { data: null }); };
    alAwsCollectorStub.processLog = sinon.stub(alAwsCollector.AlAwsCollector.prototype, 'processLog').callsFake(processLogfakeFun);
}

function restoreAlAwsCollectorStub() {
   alAwsCollectorStub.processLog.restore();
   alAwsCollectorStub.send.restore();
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
        let ctx = {
            invokedFunctionArn: 'test:arn'
        };
    
        beforeEach(function () {
            setAlAwsCollectorStub();
    
        });
    
        afterEach(function () {
            restoreAlAwsCollectorStub();
        });
    
        it('Check process method  get called form handleEvent method if we have records', function (done) {
            const collector = new CweCollector(ctx, credentials);
            const processfakeFun = function (event, callback) { return callback(null, { data: null }); };
            const processFake = sinon.stub(collector, 'process').callsFake(processfakeFun);
    
            collector.handleEvent(cweMock.GD_ONLY_KINESIS_TEST_EVENT, () => {
                sinon.assert.calledOnce(processFake);
                done();
            });
        });
    
    
        it('Called the send and processLog method to send secmsgs and logmsgs ', function (done) {
            var collector = new CweCollector(ctx, credentials, formatFunction);
    
            collector.handleEvent(cweMock.GD_ONLY_KINESIS_TEST_EVENT, () => {
                sinon.assert.calledOnce(alAwsCollectorStub.send);
                sinon.assert.calledOnce(alAwsCollectorStub.processLog);
                done();
            });
        });
    });
    describe('Format Log Tests', function(){
        it('Format success', function(done) {
            let ctx = {
                invokedFunctionArn : 'test:arn',
                fail : function(error) {
                    assert.fail(error);
                },
                succeed : function() {
                }
            };
            
            const formattedMsg = {
                messageTs: 0,
                priority: 11,
                progName: 'CWECollector',
                message: JSON.stringify(cweMock.GD_EVENT),
                messageType: 'json/cwe',
                applicationId: undefined,
                messageTypeId: 'UnauthorizedAccess:EC2/MaliciousIPCaller.Custom'
            };
            let collector = new CweCollector(ctx, credentials);
            let bindFormat = collector.formatLog.bind(collector);
            const returned = bindFormat(cweMock.GD_EVENT);
            assert.deepEqual(returned, formattedMsg);
            done();
        }); 
    });
});


