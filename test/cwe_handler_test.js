const assert = require('assert');
const rewire = require('rewire');
const sinon = require('sinon');
const cweMock = require('./cwe_mock');

var cweRewire = rewire('../index');

describe('Handler Tests', function() {

    describe('envVarMigration()', function() {
        let rewireEnvVarMigration;
        let alCommonStub;

        beforeEach(function() {
            rewireEnvVarMigration = cweRewire.__get__('envVarMigration');
            const AlAwsCommon = require('@alertlogic/al-aws-collector-js').AlAwsCommon;
            alCommonStub = sinon.stub(AlAwsCommon, 'setEnvAsync').resolves();
        });

        afterEach(function() {
            if (alCommonStub) alCommonStub.restore();
        });

        it('sets aws_lambda_update_config_name when missing', async function() {
            delete process.env.aws_lambda_update_config_name;
            const event = cweMock.CHECKIN_TEST_EVENT;
            
            await rewireEnvVarMigration(event);
            
            assert.equal(process.env.aws_lambda_update_config_name, 'configs/lambda/al-cwe-collector.json',
                'aws_lambda_update_config_name should be set');
        });

        it('sets stack_name and al_application_id when missing', async function() {
            delete process.env.stack_name;
            const event = cweMock.CHECKIN_TEST_EVENT;
            
            await rewireEnvVarMigration(event);
            
            assert(alCommonStub.calledWith(
                sinon.match({ stack_name: event.StackName, al_application_id: 'guardduty' })
            ), 'setEnvAsync should be called with stack_name and al_application_id');
        });

        it('does not call setEnvAsync when all env vars are set', async function() {
            process.env.aws_lambda_update_config_name = 'configs/lambda/al-cwe-collector.json';
            process.env.stack_name = 'test-stack';
            process.env.al_application_id = 'guardduty';
            
            await rewireEnvVarMigration({});
            
            assert(!alCommonStub.called, 'setEnvAsync should not be called when all vars are set');
        });

        it('handles setEnvAsync errors gracefully', async function() {
            alCommonStub.rejects(new Error('Environment set failed'));
            delete process.env.aws_lambda_update_config_name;
            
            // Should not throw
            await assert.doesNotReject(
                () => rewireEnvVarMigration(cweMock.CHECKIN_TEST_EVENT)
            );
        });
    });

    describe('getKinesisData()', function() {
        let rewireGetKinesisData;

        beforeEach(function() {
            rewireGetKinesisData = cweRewire.__get__('getKinesisData');
        });

        it('decodes valid base64 Kinesis records', async function() {
            const event = cweMock.GD_ONLY_KINESIS_TEST_EVENT;
            const result = await rewireGetKinesisData(event);
            
            assert(Array.isArray(result), 'Result should be an array');
            assert(result.length > 0, 'Result should contain decoded records');
            assert.equal(result[0].source, 'aws.guardduty', 'Decoded record should have correct source');
        });

        it('handles malformed JSON in Kinesis records', async function() {
            const event = {
                Records: [{
                    kinesis: {
                        data: Buffer.from('{"invalid": json}').toString('base64')
                    }
                }]
            };
            
            const result = await rewireGetKinesisData(event);
            
            assert(Array.isArray(result), 'Result should be an array');
            assert.deepEqual(result[0], {}, 'Should return empty object for invalid JSON');
        });

        it('handles empty Kinesis records', async function() {
            const event = { Records: [] };
            const result = await rewireGetKinesisData(event);
            
            assert.deepEqual(result, [], 'Should return empty array for empty records');
        });

        it('handles multiple Kinesis records with mixed validity', async function() {
            const event = {
                Records: [
                    {
                        kinesis: {
                            data: Buffer.from(JSON.stringify({ source: 'aws.guardduty', 'detail-type': 'GuardDuty Finding' })).toString('base64')
                        }
                    },
                    {
                        kinesis: {
                            data: Buffer.from('invalid json').toString('base64')
                        }
                    },
                    {
                        kinesis: {
                            data: Buffer.from(JSON.stringify({ source: 'aws.ec2', 'detail-type': 'EC2 Event' })).toString('base64')
                        }
                    }
                ]
            };
            
            const result = await rewireGetKinesisData(event);
            
            assert.equal(result.length, 3, 'Should process all records');
            assert.equal(result[0].source, 'aws.guardduty');
            assert.deepEqual(result[1], {});
            assert.equal(result[2].source, 'aws.ec2');
        });
    });

    describe('filterGDEvents()', function() {
        let rewireFilterGDEvents;

        beforeEach(function() {
            rewireFilterGDEvents = cweRewire.__get__('filterGDEvents');
        });

        it('filters only GuardDuty events with correct detail-type', async function() {
            const events = [
                { source: 'aws.guardduty', 'detail-type': 'GuardDuty Finding' },
                { source: 'aws.ec2', 'detail-type': 'EC2 Instance State-change Notification' },
                { source: 'aws.guardduty', 'detail-type': 'Other Type' }
            ];
            
            const result = await rewireFilterGDEvents(events);
            
            assert.equal(result.length, 1, 'Should filter to only one GuardDuty Finding event');
            assert.equal(result[0].source, 'aws.guardduty');
            assert.equal(result[0]['detail-type'], 'GuardDuty Finding');
        });

        it('handles events with missing source field', async function() {
            const events = [
                { 'detail-type': 'GuardDuty Finding' },
                { source: 'aws.guardduty', 'detail-type': 'GuardDuty Finding' }
            ];
            
            const result = await rewireFilterGDEvents(events);
            
            assert.equal(result.length, 1, 'Should filter out event without source');
            assert.equal(result[0].source, 'aws.guardduty');
        });

        it('handles events with missing detail-type field', async function() {
            const events = [
                { source: 'aws.guardduty' },
                { source: 'aws.guardduty', 'detail-type': 'GuardDuty Finding' }
            ];
            
            const result = await rewireFilterGDEvents(events);
            
            assert.equal(result.length, 1, 'Should filter out event without detail-type');
        });

        it('returns empty array for non-GuardDuty events', async function() {
            const events = [
                { source: 'aws.ec2', 'detail-type': 'EC2 Event' },
                { source: 'aws.s3', 'detail-type': 'S3 Event' }
            ];
            
            const result = await rewireFilterGDEvents(events);
            
            assert.equal(result.length, 0, 'Should return empty array');
        });

        it('handles empty events array', async function() {
            const result = await rewireFilterGDEvents([]);
            assert.deepEqual(result, [], 'Should return empty array');
        });
    });

    describe('formatMessages() - expanded edge cases', function() {
        let rewireFormatMessages;

        beforeEach(function() {
            rewireFormatMessages = cweRewire.__get__('formatMessages');
        });

        it('returns undefined for empty GuardDuty events', async function() {
            const event = {
                Records: [{
                    kinesis: {
                        data: Buffer.from(JSON.stringify([
                            { source: 'aws.ec2', 'detail-type': 'EC2 Event' }
                        ])).toString('base64')
                    }
                }]
            };
            const context = { invokedFunctionArn: 'arn:test' };
            
            const result = await rewireFormatMessages(event, context);
            
            assert.strictEqual(result, undefined, 'Should return undefined when no GuardDuty events');
        });

        it('formats messages correctly with context ARN', async function() {
            const event = cweMock.GD_ONLY_KINESIS_TEST_EVENT;
            const context = { invokedFunctionArn: 'arn:aws:lambda:us-east-1:123456789012:function:test' };
            
            const result = await rewireFormatMessages(event, context);
            
            assert(result, 'Should return result');
            assert.equal(result.collected_batch.source_id, context.invokedFunctionArn);
            assert(Array.isArray(result.collected_batch.collected_messages));
            assert(result.collected_batch.collected_messages.length > 0);
        });

        it('handles multiple Kinesis records with mixed GuardDuty and non-GuardDuty events', async function() {
            const event = cweMock.GD_OTHER_KINESIS_TEST_EVENT;
            const context = { invokedFunctionArn: 'arn:test' };
            
            const result = await rewireFormatMessages(event, context);
            
            assert(result, 'Should return result');
            assert(result.collected_batch.collected_messages.every(
                msg => msg.source === 'aws.guardduty' && msg['detail-type'] === 'GuardDuty Finding'
            ), 'All messages should be GuardDuty Findings');
        });

        it('handles records with only invalid JSON', async function() {
            const event = {
                Records: [{
                    kinesis: {
                        data: Buffer.from('completely invalid json').toString('base64')
                    }
                }]
            };
            const context = { invokedFunctionArn: 'arn:test' };
            
            const result = await rewireFormatMessages(event, context);
            
            assert.strictEqual(result, undefined, 'Should return undefined when all JSON is invalid');
        });
    });

    describe('getStatisticsFunctions()', function() {
        let rewireGetStatisticsFunctions;

        beforeEach(function() {
            rewireGetStatisticsFunctions = cweRewire.__get__('getStatisticsFunctions');
        });

        it('returns array of functions for Checkin event with KinesisArn', function() {
            const result = rewireGetStatisticsFunctions(cweMock.CHECKIN_TEST_EVENT);
            
            assert(Array.isArray(result), 'Result should be an array');
            assert.equal(result.length, 4, 'Should return 4 statistic functions for Checkin event');
            result.forEach(fn => {
                assert.equal(typeof fn, 'function', 'Each item should be a function');
            });
        });

        it('returns empty array for event without KinesisArn', function() {
            const event = { Type: 'Checkin' };
            const result = rewireGetStatisticsFunctions(event);
            
            assert.deepEqual(result, [], 'Should return empty array');
        });

        it('returns empty array for SelfUpdate event', function() {
            const result = rewireGetStatisticsFunctions(cweMock.UPDATE_TEST_EVENT);
            
            assert.deepEqual(result, [], 'Should return empty array for SelfUpdate event');
        });

        it('returns empty array for registration event', function() {
            const event = { RequestType: 'Create' };
            const result = rewireGetStatisticsFunctions(event);
            
            assert.deepEqual(result, [], 'Should return empty array for registration event');
        });

        it('statistic functions return valid promises', async function() {
            const event = cweMock.CHECKIN_TEST_EVENT;
            const statsFunctions = rewireGetStatisticsFunctions(event);
            
            assert.equal(statsFunctions.length, 4);
            statsFunctions.forEach(fn => {
                const result = fn();
                assert(result instanceof Promise, 'Statistic function should return a Promise');
            });
        });
    });

});
