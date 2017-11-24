process.env.AWS_REGION = 'us-east-1';
const assert = require('assert');
const rewire = require('rewire');
const sinon = require('sinon');
const m_aimsc = require('../lib/al_servicec').AimsC;
const AWS = require('aws-sdk-mock');
const cweMock = require('./cwe_mock');
const cweMockErrors = require('./cwe_mock_errors');
const cweCheckin = require('../checkin');
const clone = require('clone');
var cweRewire = rewire('../index');
var cweCheckinRewire = rewire('../checkin');
var m_servicec = require('../lib/al_servicec');
var azcollectStub;

function setAzcollectStub() {
    azcollectStub = sinon.stub(m_servicec.AlServiceC.prototype, 'post').callsFake(
        function fakeFn(path, extraOptions) {
            assert.equal(cweMock.CHECKIN_TEST_URL, path);
            assert.equal('ok', extraOptions.body.status);
            assert.deepEqual([], extraOptions.body.details);
            return new Promise(function(resolve, reject) {
                return [{}];
            });
        });
}

describe('CWE Checkin Tests', function() {

    describe('processCheckin() waterfall check', function() {
        var rewireGetDecryptedCredentials;
        var rewireGetAlAuth;
        var rewireProcessCheckin;
        var rewireCheckHealth;
        var checkinStub;

        before(function() {
            setAzcollectStub();
        });

        beforeEach(function() {
            rewireProcessCheckin = cweRewire.__get__('processCheckin');
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
            checkinStub.restore();
        });

        after(function() {
            azcollectStub.restore();
        });

        it('checkin waterfall flow OK - doCheckin()', function(done) {
            var context = {
                invokedFunctionArn : cweMock.FUNCTION_ARN,
                functionName : cweMock.CHECKIN_TEST_FUNCTION_NAME
            };
            checkinStub = sinon.stub(cweCheckin, 'checkHealth').callsFake(
                function fakeFn(event, context, callback) {
                    return callback(null, {status: 'ok', details: []});
                });
            rewireProcessCheckin(cweMock.CHECKIN_TEST_EVENT, context);
            done();
        });

        it('checkin waterfall flow error - getDecryptedCredentials()', function(done) {
            var context = {
                fail : (reason) => { if (reason == 'decryption_error') done(); }
            };
            rewireGetDecryptedCredentials = cweRewire.__set__(
                {getDecryptedCredentials: function(callback) { callback('decryption_error'); }}
            );
            rewireProcessCheckin(cweMock.CHECKIN_TEST_EVENT, context);
        });

        it('checkin waterfall flow error - getAlAuth()', function(done) {
            var context = {
                fail : (reason) => { if (reason == 'test error') done(); }
            };
            rewireGetAlAuth = cweRewire.__set__(
                {getAlAuth: function(callback) { callback('test error'); }}
            );
            rewireProcessCheckin(cweMock.CHECKIN_TEST_EVENT, context);
        });

        it('checkin waterfall flow error - checkHealth()', function(done) {
            var context = {
                fail : (reason) => { if (reason == 'check_health_error') done(); }
            };
            checkinStub = sinon.stub(cweCheckin, 'checkHealth').callsFake(
                function fakeFn(event, context, callback) {
                    return callback('check_health_error', {});
                });
            rewireProcessCheckin(cweMock.CHECKIN_TEST_EVENT, context);
        });

    });


    describe('checkHealth() sunny case check', function() {
        var checkinRewire = rewire('../checkin');
        var rewireCheckHealth;

        before(function() {
            setAzcollectStub();
        });

        beforeEach(function() {
            mock();
            rewireCheckHealth = checkinRewire.__get__('checkHealth');
        });

        afterEach(function() {
            unmock();
        });

        after(function() {
            azcollectStub.restore();
        });

        it('checkHealth', function(done) {
            rewireCheckHealth(cweMock.CHECKIN_TEST_EVENT, cweMock.DEFAULT_LAMBDA_CONTEXT, function(err, healthStatus) {
                assert.equal(null, err);
                var expected = {
                    status: 'ok',
                    details: []
                };
                assert.deepEqual(expected, healthStatus);
                done();
            });
        });
    });


    describe('checkHealth() unexpected error case check', function() {
        var checkinRewire = rewire('../checkin');
        var rewireCheckHealth;

        before(function() {
            setAzcollectStub();
        });

        beforeEach(function() {
            mock();
            rewireCheckHealth = checkinRewire.__get__('checkHealth');
        });

        afterEach(function() {
            unmock();
        });

        after(function() {
            azcollectStub.restore();
        });

        //TODO maybe test case when err message does not contain `code` field
        //TODO test Throttling message
        //TODO test Internal AWS error case
        it('checkHealth unexpected error code', function(done) {
            mockCFDescribeStacks(function(data, callback) {
                return callback(cweMockErrors.UNEXPECTED_ERROR, {});
            });
            check_error(done, rewireCheckHealth, stringify(cweMockErrors.UNEXPECTED_ERROR));
        });
    });

    describe('checkHealth() - checkCloudFormationStatus errors', function() {
        var checkinRewire = rewire('../checkin');
        var rewireCheckHealth;

        before(function() {
            setAzcollectStub();
        });

        beforeEach(function() {
            mock();
            rewireCheckHealth = checkinRewire.__get__('checkHealth');
        });

        afterEach(function() {
            unmock();
        });

        after(function() {
            azcollectStub.restore();
        });

        it('describeStacks - access denied', function(done) {
            mockCFDescribeStacks(function(data, callback) {
                return callback(cweMockErrors.CF_DESCRIBE_STACKS_ACCESS_DENIED, {});
            });
            check_error(done, rewireCheckHealth, stringify(cweMockErrors.CF_DESCRIBE_STACKS_ACCESS_DENIED));
        });

        it('describeStacks - stack not found', function(done) {
            mockCFDescribeStacks(function(data, callback) {
                return callback(cweMockErrors.CF_DESCRIBE_STACKS_NOT_FOUND, {});
            });
            check_error(done, rewireCheckHealth, stringify(cweMockErrors.CF_DESCRIBE_STACKS_NOT_FOUND));
        });

        it('describeStacks - StackStatus is wrong', function(done) {
            mockCFDescribeStacks(function(data, callback) {
                var resp = clone(cweMock.CF_DESCRIBE_STACKS_RESPONSE);
                resp.Stacks[0].StackStatus = 'NOT_CREATE_COMPLETE';
                return callback(null, resp);
            });
            check_error(done, rewireCheckHealth, 'CF stack has wrong status: NOT_CREATE_COMPLETE');
        });
    });


    describe('checkHealth() - checkCloudWatchEventsRule errors', function() {
        var checkinRewire = rewire('../checkin');
        var rewireCheckHealth;

        before(function() {
            setAzcollectStub();
        });

        beforeEach(function() {
            mock();
            rewireCheckHealth = checkinRewire.__get__('checkHealth');
        });

        afterEach(function() {
            unmock();
        });

        after(function() {
            azcollectStub.restore();
        });

        it('describeRule - not found', function(done) {
            mockCWEDescribeRule(function(data, callback) {
                return callback(cweMockErrors.CWE_DESCRIBE_RULE_NOT_FOUND, {});
            });
            check_error(done, rewireCheckHealth, stringify(cweMockErrors.CWE_DESCRIBE_RULE_NOT_FOUND));
        });

        it('describeRule - AccessDenied', function(done) {
            mockCWEDescribeRule(function(data, callback) {
                return callback(cweMockErrors.CWE_DESCRIBE_RULE_ACCESS_DENIED, {});
            });
            check_error(done, rewireCheckHealth, stringify(cweMockErrors.CWE_DESCRIBE_RULE_ACCESS_DENIED));
        });

        it('describeRule - DISABLED state', function(done) {
            expected = clone(cweMock.CWE_DESCRIBE_RULE);
            expected.State = 'DISABLED';
            mockCWEDescribeRule(function(data, callback) {
                return callback(null, expected);
            });
            check_error(done, rewireCheckHealth, 'CWE Rule is incorrectly configured: ' + stringify(expected));
        });

        it('describeRule - wrong event pattern state', function(done) {
            var expected = clone(cweMock.CWE_DESCRIBE_RULE);
            expected.EventPattern = 'something_is_wrong';
            mockCWEDescribeRule(function(data, callback) {
                return callback(null, expected);
            });
            check_error(done, rewireCheckHealth, 'CWE Rule is incorrectly configured: ' + stringify(expected));
        });

        it('listTargetsByRule - access denied', function(done) {
            mockCWEListTargetsByRule(function(data, callback) {
                return callback(cweMockErrors.CWE_LIST_TARGETS_ACCESS_DENIED, {});
            });
            check_error(done, rewireCheckHealth, stringify(cweMockErrors.CWE_LIST_TARGETS_ACCESS_DENIED));
        });

        it('listTargetsByRule - not found', function(done) {
            mockCWEListTargetsByRule(function(data, callback) {
                return callback(cweMockErrors.CWE_LIST_TARGETS_NOT_FOUND, {});
            });
            check_error(done, rewireCheckHealth, stringify(cweMockErrors.CWE_LIST_TARGETS_NOT_FOUND));
        });

        it('listTargetsByRule - [] targets', function(done) {
            mockCWEListTargetsByRule(function(data, callback) {
                var resp = clone(cweMock.CWE_LIST_TARGETS_BY_RULE);
                resp.Targets = [];
                return callback(null, resp);
            });
            check_error(done, rewireCheckHealth, 'CWE rule ' + cweMock.CWE_RULE_NAME + ' has incorrect target set');
        });

        it('listTargetsByRule - > 1 targets', function(done) {
            mockCWEListTargetsByRule(function(data, callback) {
                var resp = clone(cweMock.CWE_LIST_TARGETS_BY_RULE);
                var target = resp.Targets[0];
                resp.Targets = [target, target];
                return callback(null, resp);
            });
            check_error(done, rewireCheckHealth, 'CWE rule ' + cweMock.CWE_RULE_NAME + ' has incorrect target set');
        });

        it('listTargetsByRule -  wrong kinesis arn', function(done) {
            mockCWEListTargetsByRule(function(data, callback) {
                var resp = clone(cweMock.CWE_LIST_TARGETS_BY_RULE);
                resp.Targets[0].Arn = 'wrong_kinesis_arn';
                return callback(null, resp);
            });
            check_error(done, rewireCheckHealth, 'CWE rule ' + cweMock.CWE_RULE_NAME + ' has incorrect target set');
        });
    });
    
    describe('checkHealth() - checkEventSourceMappings errors', function() {
        var checkinRewire = rewire('../checkin');
        var rewireCheckHealth;

        before(function() {
            setAzcollectStub();
        });

        beforeEach(function() {
            mock();
            rewireCheckHealth = checkinRewire.__get__('checkHealth');
        });

        afterEach(function() {
            unmock();
        });

        after(function() {
            azcollectStub.restore();
        });

        it('listEventSourceMappings - empty', function(done) {
            mockLambdaListEventSourceMappings(function(data, callback) {
                return callback(null, cweMockErrors.LAMBDA_LIST_EVENT_SOURCE_MAPPINGS_EMPTY);
            });
            check_error(done, rewireCheckHealth, 
                'Event source mapping doesn\'t exist: ' + 
                stringify(cweMockErrors.LAMBDA_LIST_EVENT_SOURCE_MAPPINGS_EMPTY));
        });
        
        it('listEventSourceMappings - problem', function(done) {
            mockLambdaListEventSourceMappings(function(data, callback) {
                return callback(null, cweMockErrors.LAMBDA_LIST_EVENT_SOURCE_MAPPINGS_PROBLEM);
            });
            var expectedEventSource = {
                'UUID': '5ca7d79a-7ce9-4b47-b717-e13bdd02334c', 
                'StateTransitionReason': 'User action', 
                'LastModified': 1509977760.0, 
                'BatchSize': 100, 
                'State': 'Enabled', 
                'FunctionArn': 'arn:aws:lambda:us-east-1:352283894008:function:test-guardduty-01-CollectLambdaFunction-2CWNLPPW5XO8', 
                'EventSourceArn': 'arn:aws:kinesis:us-east-1:353333894008:stream/test-KinesisStream-11Z7IDV7G2XDV', 
                'LastProcessingResult': 'PROBLEM: internal Lambda error. Please contact Lambda customer support.'
            };
            
            check_error(done, rewireCheckHealth, 
                'Incorrect event source mapping status: ' + stringify(expectedEventSource));
        });
    });
    
    describe('processCheckin() get statistics', function() {
        var rewireGetDecryptedCredentials;
        var rewireGetAlAuth;
        var rewireProcessCheckin;
        var rewireCheckHealth;
        var sendCheckinStub;

        before(function() {
            setAzcollectStub();
        });

        beforeEach(function() {
            rewireProcessCheckin = cweRewire.__get__('processCheckin');
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
            sendCheckinStub.restore();
            checkHealthStub.restore();
            AWS.restore('CloudWatch', 'getMetricStatistics');
        });

        after(function() {
            azcollectStub.restore();
        });

        it('getStatistics() - OK', function(done) {
            var context = {
                invokedFunctionArn : cweMock.FUNCTION_ARN,
                functionName : cweMock.CHECKIN_TEST_FUNCTION_NAME,
                succeed : () => { return; }
            };
            sendCheckinStub = sinon.stub(cweCheckin, 'sendCheckin').callsFake(
                function fakeFn(event, context, aimsC, healthStatus, callback) {
                    return callback(null);
                });
            checkHealthStub = sinon.stub(cweCheckin, 'checkHealth').callsFake(
                function fakeFn(event, context, callback) {
                    return callback(null, {
                        status: 'ok',
                        details: []
                    });
                });
            AWS.mock('CloudWatch', 'getMetricStatistics', function (params, callback) {
                var ret = cweMock.CLOUDWATCH_GET_METRIC_STATS_OK;
                ret.Label = params.MetricName;
                return callback(null, ret);
            });
            rewireProcessCheckin(cweMock.CHECKIN_TEST_EVENT, context);
            
            expectedHealth = {
                'status':'ok',
                'details':[],
                'statistics':[
                    {'Label':'Invocations','Datapoints':[{'Timestamp':'2017-11-21T16:40:00Z','Sum':1,'Unit':'Count'}]},
                    {'Label':'Errors','Datapoints':[{'Timestamp':'2017-11-21T16:40:00Z','Sum':1,'Unit':'Count'}]},
                    {'Label':'IncomingRecords','Datapoints':[{'Timestamp':'2017-11-21T16:40:00Z','Sum':1,'Unit':'Count'}]},
                    {'Label':'IncomingBytes','Datapoints':[{'Timestamp':'2017-11-21T16:40:00Z','Sum':1,'Unit':'Count'}]},
                    {'Label':'ReadProvisionedThroughputExceeded','Datapoints':[{'Timestamp':'2017-11-21T16:40:00Z','Sum':1,'Unit':'Count'}]},
                    {'Label':'WriteProvisionedThroughputExceeded','Datapoints':[{'Timestamp':'2017-11-21T16:40:00Z','Sum':1,'Unit':'Count'}]}
                ]
            };
            sinon.assert.callCount(checkHealthStub, 1);
            sinon.assert.callCount(sendCheckinStub, 1);
            sinon.assert.calledWith(sendCheckinStub, cweMock.CHECKIN_TEST_EVENT, context, {}, expectedHealth);
            done();
        });
        
        it('getStatistics() - CloudWatch connection error', function(done) {
            var context = {
                invokedFunctionArn : cweMock.FUNCTION_ARN,
                functionName : cweMock.CHECKIN_TEST_FUNCTION_NAME,
                succeed : () => { return; }
            };
            
            sendCheckinStub = sinon.stub(cweCheckin, 'sendCheckin').callsFake(
                function fakeFn(event, context, aimsC, healthStatus, callback) {
                    return callback(null);
                });
            checkHealthStub = sinon.stub(cweCheckin, 'checkHealth').callsFake(
                function fakeFn(event, context, callback) {
                    return callback(null, {
                        status: 'ok',
                        details: []
                    });
                });
            AWS.mock('CloudWatch', 'getMetricStatistics', function (params, callback) {
                var err = {
                    code : 1,
                    message : 'Some error.'
                };
                return callback(err);
            });
            rewireProcessCheckin(cweMock.CHECKIN_TEST_EVENT, context);
            
            expectedHealth = {
                'status' : 'ok',
                'details' : [],
                'statistics' : [
                    {'Label':'Invocations','StatisticsError':'{\"code\":1,\"message\":\"Some error.\"}'},
                    {'Label':'Errors','StatisticsError':'{\"code\":1,\"message\":\"Some error.\"}'},
                    {'Label':'IncomingRecords','StatisticsError':'{\"code\":1,\"message\":\"Some error.\"}'},
                    {'Label':'IncomingBytes','StatisticsError':'{\"code\":1,\"message\":\"Some error.\"}'},
                    {'Label':'ReadProvisionedThroughputExceeded','StatisticsError':'{\"code\":1,\"message\":\"Some error.\"}'},
                    {'Label':'WriteProvisionedThroughputExceeded','StatisticsError':'{\"code\":1,\"message\":\"Some error.\"}'}
                ]
            };
            sinon.assert.callCount(checkHealthStub, 1);
            sinon.assert.callCount(sendCheckinStub, 1);
            sinon.assert.calledWith(sendCheckinStub, cweMock.CHECKIN_TEST_EVENT, context, {}, expectedHealth);
            done();
        });
        
    });

});


function mock() {
    AWS.mock('CloudFormation', 'describeStacks', function (data, callback) {
        assert.equal(data.StackName, cweMock.STACK_NAME);
        return callback(null, cweMock.CF_DESCRIBE_STACKS_RESPONSE);
    });
    AWS.mock('CloudWatchEvents', 'describeRule', function (data, callback) {
        assert.equal(data.Name, cweMock.CWE_RULE_NAME);
        return callback(null, cweMock.CWE_DESCRIBE_RULE);
    });
    AWS.mock('CloudWatchEvents', 'listTargetsByRule', function (data, callback) {
        assert.equal(data.Rule, cweMock.CWE_RULE_NAME);
        return callback(null, cweMock.CWE_LIST_TARGETS_BY_RULE);
    });
    AWS.mock('Lambda', 'listEventSourceMappings', function (data, callback) {
        assert.equal(data.FunctionName, cweMock.CHECKIN_TEST_FUNCTION_NAME);
        return callback(null, cweMock.LAMBDA_LIST_EVENTSOURCE_MAPPINGS_OK);
    });
}


function unmock() {
    AWS.restore('CloudFormation', 'describeStacks');
    AWS.restore('CloudWatchEvents', 'describeRule');
    AWS.restore('CloudWatchEvents', 'listTargetsByRule');
    AWS.restore('Lambda', 'listEventSourceMappings');
}


function mockCFDescribeStacks(fun) {
    AWS.restore('CloudFormation', 'describeStacks');
    AWS.mock('CloudFormation', 'describeStacks', function (data, callback) {
        assert.equal(data.StackName, cweMock.STACK_NAME);
        return fun(data, callback);
    });
}


function mockCWEDescribeRule(fun) {
    AWS.restore('CloudWatchEvents', 'describeRule');
    AWS.mock('CloudWatchEvents', 'describeRule', function (data, callback) {
        assert.equal(data.Name, cweMock.CWE_RULE_NAME);
        return fun(data, callback);
    });
}


function mockCWEListTargetsByRule(fun) {
    AWS.restore('CloudWatchEvents', 'listTargetsByRule');
    AWS.mock('CloudWatchEvents', 'listTargetsByRule', function (data, callback) {
        assert.equal(data.Rule, cweMock.CWE_RULE_NAME);
        return fun(data, callback);
    });
}

function mockLambdaListEventSourceMappings(fun) {
    AWS.restore('Lambda', 'listEventSourceMappings');
    AWS.mock('Lambda', 'listEventSourceMappings', function (data, callback) {
        assert.equal(data.FunctionName, cweMock.CHECKIN_TEST_FUNCTION_NAME);
        return fun(data, callback);
    });
}

function check_error(done, rewireCheckHealth, details) {
    rewireCheckHealth(cweMock.CHECKIN_TEST_EVENT, cweMock.DEFAULT_LAMBDA_CONTEXT, function(err, healthStatus) {
        assert.equal(null, err);
        assert.equal('error', healthStatus.status);
        assert.deepEqual([details], healthStatus.details);
        assert.notEqual(undefined, healthStatus.error_code);
        done();
    });
}

function stringify(jsonObj) {
    return JSON.stringify(jsonObj, null, 0);
}
