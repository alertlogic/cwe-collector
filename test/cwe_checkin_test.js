process.env.AWS_REGION = 'us-east-1';
const assert = require('assert');
const rewire = require('rewire');
const sinon = require('sinon');
const cweMock = require('./cwe_mock');
const cweMockErrors = require('./cwe_mock_errors');
const clone = require('clone');
var {AlServiceC} = require('@alertlogic/al-collector-js');
var cweStub = require('./cwe_stub');
const { CloudWatchEvents } = require("@aws-sdk/client-cloudwatch-events"),
      { CloudFormation } = require("@aws-sdk/client-cloudformation"),
      { Lambda } = require("@aws-sdk/client-lambda");
var azcollectStub;

function setAzcollectStub() {
    azcollectStub = sinon.stub(AlServiceC.prototype, 'post').callsFake(
        async function fakeFn(path, extraOptions) {
            assert.equal(cweMock.CHECKIN_TEST_URL, path);
            assert.equal('ok', extraOptions.body.status);
            assert.deepEqual([], extraOptions.body.details);
            return [{}];
        });
}
describe('CWE Checkin Tests', function() {

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

        it('checkHealth', async function() {
            const healthStatus = await rewireCheckHealth(cweMock.CHECKIN_TEST_EVENT, cweMock.DEFAULT_LAMBDA_CONTEXT);
            var expected = null;
            assert.deepEqual(expected, healthStatus);
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

        it('describeRule - not found', async function() {
            mockCWEDescribeRule(async (data) => {
                throw cweMockErrors.CWE_DESCRIBE_RULE_NOT_FOUND;
            });
            await assert.rejects(
                () => rewireCheckHealth(cweMock.CHECKIN_TEST_EVENT, cweMock.DEFAULT_LAMBDA_CONTEXT),
                err => err && err.details === stringify(cweMockErrors.CWE_DESCRIBE_RULE_NOT_FOUND)
            );
        });

        it('describeRule - AccessDenied', async function() {
            mockCWEDescribeRule(async (data) => {
                throw cweMockErrors.CWE_DESCRIBE_RULE_ACCESS_DENIED;
            });
            await assert.rejects(
                () => rewireCheckHealth(cweMock.CHECKIN_TEST_EVENT, cweMock.DEFAULT_LAMBDA_CONTEXT),
                err => err && err.details === stringify(cweMockErrors.CWE_DESCRIBE_RULE_ACCESS_DENIED)
            );
        });

        it('describeRule - DISABLED state', async function() {
            const expected = clone(cweMock.CWE_DESCRIBE_RULE);
            expected.State = 'DISABLED';
            mockCWEDescribeRule(async (data) => expected);
            const errMsg = 'CWE Rule is incorrectly configured: ' + stringify(expected);
            await assert.rejects(
                () => rewireCheckHealth(cweMock.CHECKIN_TEST_EVENT, cweMock.DEFAULT_LAMBDA_CONTEXT),
                err => err && err.details === errMsg
            );
        });

        it('describeRule - wrong event pattern state', async function() {
            var expected = clone(cweMock.CWE_DESCRIBE_RULE);
            expected.EventPattern = 'something_is_wrong';
            mockCWEDescribeRule(async (data) => expected);
            const errMsg = 'CWE Rule is incorrectly configured: ' + stringify(expected);
            await assert.rejects(
                () => rewireCheckHealth(cweMock.CHECKIN_TEST_EVENT, cweMock.DEFAULT_LAMBDA_CONTEXT),
                err => err && err.details === errMsg
            );
        });

        it('listTargetsByRule - access denied', async function() {
            mockCWEListTargetsByRule(async (data) => { throw cweMockErrors.CWE_LIST_TARGETS_ACCESS_DENIED; });
            await assert.rejects(
                () => rewireCheckHealth(cweMock.CHECKIN_TEST_EVENT, cweMock.DEFAULT_LAMBDA_CONTEXT),
                err => err && err.details === stringify(cweMockErrors.CWE_LIST_TARGETS_ACCESS_DENIED)
            );
        });

        it('listTargetsByRule - not found', async function() {
            mockCWEListTargetsByRule(async (data) => { throw cweMockErrors.CWE_LIST_TARGETS_NOT_FOUND; });
            await assert.rejects(
                () => rewireCheckHealth(cweMock.CHECKIN_TEST_EVENT, cweMock.DEFAULT_LAMBDA_CONTEXT),
                err => err && err.details === stringify(cweMockErrors.CWE_LIST_TARGETS_NOT_FOUND)
            );
        });

        it('listTargetsByRule - [] targets', async function() {
            mockCWEListTargetsByRule(async (data) => {
                var resp = clone(cweMock.CWE_LIST_TARGETS_BY_RULE);
                resp.Targets = [];
                return resp;
            });
            const errMsg = 'CWE rule ' + cweMock.CWE_RULE_NAME + ' has incorrect target set';
            await assert.rejects(
                () => rewireCheckHealth(cweMock.CHECKIN_TEST_EVENT, cweMock.DEFAULT_LAMBDA_CONTEXT),
                err => err && err.details === errMsg
            );
        });

        it('listTargetsByRule - > 1 targets', async function() {
            mockCWEListTargetsByRule(async (data) => {
                var resp = clone(cweMock.CWE_LIST_TARGETS_BY_RULE);
                var target = resp.Targets[0];
                resp.Targets = [target, target];
                return resp;
            });
            const errMsg = 'CWE rule ' + cweMock.CWE_RULE_NAME + ' has incorrect target set';
            await assert.rejects(
                () => rewireCheckHealth(cweMock.CHECKIN_TEST_EVENT, cweMock.DEFAULT_LAMBDA_CONTEXT),
                err => err && err.details === errMsg
            );
        });

        it('listTargetsByRule -  wrong kinesis arn', async function() {
            mockCWEListTargetsByRule(async (data) => {
                var resp = clone(cweMock.CWE_LIST_TARGETS_BY_RULE);
                resp.Targets[0].Arn = 'wrong_kinesis_arn';
                return resp;
            });
            const errMsg = 'CWE rule ' + cweMock.CWE_RULE_NAME + ' has incorrect target set';
            await assert.rejects(
                () => rewireCheckHealth(cweMock.CHECKIN_TEST_EVENT, cweMock.DEFAULT_LAMBDA_CONTEXT),
                err => err && err.details === errMsg
            );
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

        it('listEventSourceMappings - empty', async function() {
            mockLambdaListEventSourceMappings(async (data) => cweMockErrors.LAMBDA_LIST_EVENT_SOURCE_MAPPINGS_EMPTY);
            const errMsg = 'Event source mapping doesn\'t exist: ' + stringify(cweMockErrors.LAMBDA_LIST_EVENT_SOURCE_MAPPINGS_EMPTY);
            await assert.rejects(
                () => rewireCheckHealth(cweMock.CHECKIN_TEST_EVENT, cweMock.DEFAULT_LAMBDA_CONTEXT),
                err => err && err.details === errMsg
            );
        });
        
        it('listEventSourceMappings - problem', async function() {
            mockLambdaListEventSourceMappings(async (data) => cweMockErrors.LAMBDA_LIST_EVENT_SOURCE_MAPPINGS_PROBLEM);
            await assert.rejects(
                () => rewireCheckHealth(cweMock.CHECKIN_TEST_EVENT, cweMock.DEFAULT_LAMBDA_CONTEXT),
                err => err && err.code === 'CWE00010' && err.details.includes('CWE00020')
            );
        });
    });
});

function mock() {
    cweStub.mock(CloudFormation, 'describeStacks', async function (data) {
        assert.equal(data.StackName, cweMock.STACK_NAME);
        return cweMock.CF_DESCRIBE_STACKS_RESPONSE;
    });
    cweStub.mock(CloudWatchEvents, 'describeRule', async function (data) {
        assert.equal(data.Name, cweMock.CWE_RULE_NAME);
        return cweMock.CWE_DESCRIBE_RULE;
    });
    cweStub.mock(CloudWatchEvents, 'listTargetsByRule', async function (data) {
        assert.equal(data.Rule, cweMock.CWE_RULE_NAME);
        return cweMock.CWE_LIST_TARGETS_BY_RULE;
    });
    cweStub.mock(Lambda, 'listEventSourceMappings', async function (data) {
        assert.equal(data.FunctionName, cweMock.CHECKIN_TEST_FUNCTION_NAME);
        return cweMock.LAMBDA_LIST_EVENTSOURCE_MAPPINGS_OK;
    });
}


function unmock() {
    cweStub.restore(CloudFormation, 'describeStacks');
    cweStub.restore(CloudWatchEvents, 'describeRule');
    cweStub.restore(CloudWatchEvents, 'listTargetsByRule');
    cweStub.restore(Lambda, 'listEventSourceMappings');
}


function mockCWEDescribeRule(fun) {
    cweStub.restore(CloudWatchEvents, 'describeRule');
    cweStub.mock(CloudWatchEvents, 'describeRule', async function (data) {
        assert.equal(data.Name, cweMock.CWE_RULE_NAME);
        return await fun(data);
    });
}


function mockCWEListTargetsByRule(fun) {
    cweStub.restore(CloudWatchEvents, 'listTargetsByRule');
    cweStub.mock(CloudWatchEvents, 'listTargetsByRule', async function (data) {
        assert.equal(data.Rule, cweMock.CWE_RULE_NAME);
        return await fun(data);
    });
}

function mockLambdaListEventSourceMappings(fun) {
    cweStub.restore(Lambda, 'listEventSourceMappings');
    cweStub.mock(Lambda, 'listEventSourceMappings', async function (data) {
        assert.equal(data.FunctionName, cweMock.CHECKIN_TEST_FUNCTION_NAME);
        return await fun(data);
    });
}

function stringify(jsonObj) {
    return JSON.stringify(jsonObj, null, 0);
}
