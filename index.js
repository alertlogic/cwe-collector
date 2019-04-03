/* -----------------------------------------------------------------------------
 * @copyright (C) 2017, Alert Logic, Inc
 * @doc
 *
 * Lambda function for collecting Amazon CloudWatch events and ingesting them
 * into Alert Logic backend.
 *
 * @end
 * -----------------------------------------------------------------------------
 */
 
const debug = require('debug') ('index'); 
const https = require('https');
const util = require('util');
const AWS = require('aws-sdk');
const async = require('async');
const zlib = require('zlib');

const m_alServiceC = require('al-collector-js/al_servicec');
const m_alAzCollectC = require('al-collector-js/azcollectc');
const m_alAws = require('al-aws-collector-js/al_aws');
const m_statsTemplate = require('al-aws-collector-js/statistics_templates');
const AlAwsCollector = require('al-aws-collector-js/al_aws_collector');
const m_checkin = require('./checkin');
const m_packageJson = require('./package.json');

const response = require('cfn-response');

let AIMS_CREDS;

const COLLECTOR_TYPE = 'cwe';
const INGEST_ENDPOINT = process.env.ingest_api;
const AL_ENDPOINT = process.env.al_api;
const AZCOLLECT_ENDPOINT = process.env.azollect_api;

function getDecryptedCredentials(callback) {
    if (AIMS_CREDS) {
        return callback(null);
    } else {
        const kms = new AWS.KMS();
        kms.decrypt(
            {CiphertextBlob: new Buffer(process.env.aims_secret_key, 'base64')},
            (err, data) => {
                if (err) {
                    return callback(err);
                } else {
                    AIMS_CREDS = {
                        access_key_id: process.env.aims_access_key_id,
                        secret_key: data.Plaintext.toString('ascii')
                    };
                    return callback(null);
                }
            });
    }
}

function getKinesisData(event, callback) {
    async.map(event.Records, function(record, mapCallback) {
        var cwEvent = new Buffer(record.kinesis.data, 'base64').toString('utf-8');
        try {
            return mapCallback(null, JSON.parse(cwEvent));
        } catch (ex) {
            console.warn('Event parse failed.', ex);
            console.warn('Skipping: ', record.kinesis.data);
            return mapCallback(null, {});
        }
    }, callback);
}

function filterGDEvents(cwEvents, callback) {
    async.filter(cwEvents,
        function(cwEvent, filterCallback){
            var isValid = (typeof(cwEvent.source) !== 'undefined') && 
                 cwEvent.source === 'aws.guardduty' &&
                 cwEvent['detail-type'] === 'GuardDuty Finding';
            if (isValid) {
                debug(`DEBUG0002: filterGDEvents - including event: ` +
                    `${JSON.stringify(cwEvent)} `);
            } else {
                debug(`DEBUG0003: filterGDEvents - filtering out event: ` +
                    `${JSON.stringify(cwEvent)} `); 
            }
            return filterCallback(null, isValid);
        },
        callback
    );
}

function formatMessages(event, context, callback) {
    async.waterfall([
        function(asyncCallback) {
            getKinesisData(event, asyncCallback);
        },
        function(kinesisData, asyncCallback) {
            filterGDEvents(kinesisData, asyncCallback);
        },
        function(collectedData, asyncCallback) {
            if (collectedData.length > 0) {
                return asyncCallback(null, JSON.stringify({ 
                    collected_batch : {
                        source_id : context.invokedFunctionArn,
                        collected_messages : collectedData
                    }
                }));
            } else {
                return asyncCallback(null, '');
            }
        }],
        callback);
}


function processScheduledEvent(event, collector, callback) {
    console.info("Processing scheduled event: ", event);
    switch (event.Type) {
        case 'SelfUpdate':
            console.info("starting framework self update");
            collector.update(callback);
            break;
        case 'Checkin':
            console.info("starting framework checkin");
            collector.checkin(callback);
            break;
        default:
            return context.fail("Unknown scheduled event detail type: " + event.type);
    }
}


function getStatisticsFunctions(event) {
    if(!event.KinesisArn){
        return [];
    }
    const kinesisName = m_alAws.arnToName(event.KinesisArn);
    return [
       function(callback) {
           return m_statsTemplate.getKinesisMetrics(kinesisName,
               'IncomingRecords',
               callback);
       },
       function(callback) {
           return m_statsTemplate.getKinesisMetrics(kinesisName,
               'IncomingBytes',
               callback);
       },
       function(callback) {
           return m_statsTemplate.getKinesisMetrics(kinesisName,
               'ReadProvisionedThroughputExceeded',
               callback);
       },
       function(callback) {
           return m_statsTemplate.getKinesisMetrics(kinesisName,
               'WriteProvisionedThroughputExceeded',
               callback);
       }
    ];
}


exports.handler = function(event, context) {
    async.waterfall([
        getDecryptedCredentials,
        function(asyncCallback){
            //migration code for old collectors
            if(!process.env.aws_lambda_update_config_name){
                process.env.aws_lambda_update_config_name = 'configs/lambda/config.json';
            }

            const collector = new AlAwsCollector(
                context,
                "cwe",
                AlAwsCollector.IngestTypes.SECMSGS,
                m_packageJson.version,
                AIMS_CREDS,
                formatMessages,
                [m_checkin.checkHealth(event, context)],
                getStatisticsFunctions(event)
            );

            debug("DEBUG0001: Received event: ", JSON.stringify(event));
            switch (event.RequestType) {
                case 'ScheduledEvent':
                    processScheduledEvent(event, collector, asyncCallback);
                    break;
                case 'Create':
                    var registrationValues = {
                        stackName : event.ResourceProperties.StackName,
                        custom_fields: {
                            collect_rule : event.ResourceProperties.CollectRule
                        }
                    };

                    collector.register(event, registrationValues);
                    break;
                case 'Delete':
                    collector.deregister(event);
                    break;
                default:
                    if (event.Records) {
                        return collector.process(event, asyncCallback);
                    } else {
                        return context.fail('Unknown event source: ' + event.source);
                    }
            }
        }
    ],
    function(err, result){
        if(err){
            console.log('Invocation failed: ', err);
            context.fail(err);
        } else {
            console.log('Invocation success: ', result);
            context.succeed();
        }
    });
};
