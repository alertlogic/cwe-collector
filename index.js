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
const m_alAws = require('al-aws-collector-js/al_aws');
const m_checkin = require('./checkin');
const m_packageJson = require('./package.json');

const response = require('cfn-response');

let AIMS_CREDS;

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

function getAlAuth(callback) {
    var aimsC = new m_alServiceC.AimsC(AL_ENDPOINT, AIMS_CREDS);
    aimsC.authenticate().then(
        ok => { return callback(null, aimsC); },
        err => { return callback(err); }
    );
}

function getKinesisData(event, callback) {
    async.map(event.Records, function(record, mapCallback) {
        var cwEvent = new Buffer(record.kinesis.data, 'base64').toString('utf-8');
        try {
            return mapCallback(null, JSON.parse(cwEvent));
        } catch (ex) {
            console.warn('Event parse failed.', ex);
            console.warn('Skipping', record.kinesis.data);
            return mapCallback(null, {});
        }
    }, callback);
}

function filterGDEvents(cwEvents, callback) {
    async.filter(cwEvents,
        function(cwEvent, filterCallback){
            if ((cwEvent.source && 
                 cwEvent.source === 'aws.guardduty' &&
                 cwEvent['detail-type'] === 'GuardDuty Finding')) {
                debug(`DEBUG0002: filterGDEvents - including event: ` +
                    `${JSON.stringify(cwEvent)} `);
            } else {
                debug(`DEBUG0003: filterGDEvents - filtering out event: ` +
                    `${JSON.stringify(cwEvent)} `); 
            };
            return filterCallback(null, cwEvent.source && 
                cwEvent.source === 'aws.guardduty');
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


function sendToIngest(event, context, aimsC, collectedBatch, callback) {
    zlib.deflate(collectedBatch, function(compressionErr, compressed) {
        if (compressionErr) {
            return callback(compressionErr);
        } else {
            var ingest = new m_alServiceC.IngestC(INGEST_ENDPOINT, aimsC);
            ingest.sendSecmsgs(compressed)
                .then(resp => {
                    return callback(null, resp);
                })
                .catch(exception =>{
                    return callback(`Unable to send to Ingest ${exception}`);
                });
        }
    });
}


function processResultInContext(context, err, result) {
    if (err) {
        return context.fail(err);
    } else {
        return context.succeed();
    }
}


function processCheckin(event, context) {
    async.waterfall([
        function(callback) {
            return getDecryptedCredentials(callback);
        },
        function(callback) {
            return getAlAuth(callback);
        },
        function(aimsC, callback) {
            return m_checkin.checkHealth(event, context, function(err, healthStatus) {
                return callback(err, aimsC, healthStatus);
            });
        },
        function(aimsC, healthStatus, callback) {
            return getStatistics(context, event, function(err, response) {
                healthStatus.statistics = response;
                return callback(err, aimsC, healthStatus);
            });
        },
        function(aimsC, healthStatus, callback) {
            return m_checkin.sendCheckin(event, context, aimsC, healthStatus, callback);
        }
    ],
    function(err, result) {
        return processResultInContext(context, err, result);
    });
}

function sendRegistration(event, context, aimsC, isRegistration, callback) {
    var registrationValues = {
        collectorType : 'cwe',
        awsAccountId : event.ResourceProperties.AwsAccountId,
        region : process.env.AWS_REGION,
        functionName : context.functionName,
        stackName : event.ResourceProperties.StackName,
        version : m_packageJson.version,
        collectRule : event.ResourceProperties.CollectRule
    };

    var azcollectSvc = new m_alServiceC.AzcollectC(AZCOLLECT_ENDPOINT, aimsC);

    if (isRegistration) {
        azcollectSvc.doRegistration(registrationValues)
            .then(resp => {
                return callback(null);
            })
            .catch(exception => {
                return callback(`Registration failed: ${exception}`);
            });
    } else {
        azcollectSvc.doDeregistration(registrationValues)
            .then(resp => {
                return callback(null);
            })
            .catch(exception => {
                return callback(`De-registration failed: ${exception}`);
            });
    }
}

function processRegistration(event, context, isRegistration) {
      async.waterfall([
          function(callback) {
              getDecryptedCredentials(callback);
          },
          function(callback) {
              getAlAuth(callback);
          },
          function(aimsC, callback) {
              sendRegistration(event, context, aimsC, isRegistration, callback);
          }
      ],
      function(err, result) {
          if (err) {
              return response.send(event, context, response.FAILED, {Error: err});
          } else {
              return response.send(event, context, response.SUCCESS);
          }
      });
}

function processKinesisRecords(event, context) {
    async.waterfall([
        function(callback) {
            getDecryptedCredentials(callback);
        },
        function(callback) {
            getAlAuth(callback);
        },
        function(aimsC, callback) {
            formatMessages(event, context, function(formatError, collectedData) {
                return callback(formatError, aimsC, collectedData);
            });
        },
        function(aimsC, collectedData, callback) {
            if (collectedData !== '') {
                sendToIngest(event, context, aimsC, collectedData, callback);
            } else {
                return callback(null);
            }
        }
    ],
    function(err, result) {
        processResultInContext(context, err, result);
    });
}


function processScheduledEvent(event, context) {
    console.info("Processing scheduled event: ", event);
    switch (event.Type) {
        case 'SelfUpdate':
            m_alAws.selfUpdate(function(err) {
                if (err) {
                    return context.fail(err);
                } else {
                    return context.succeed();
                }
            });
            break;
        case 'Checkin':
            processCheckin(event, context);
            break;
        default:
            return context.fail("Unknown scheduled event detail type: " + event.type);
    }
}


function getStatistics(context, event, finalCallback) {
    const kinesisName = m_alAws.arnToName(event.KinesisArn);
    async.waterfall([
       function(asyncCallback) {
           return m_alAws.getLambdaMetrics(context.functionName,
               'Invocations',
               [],
               asyncCallback);
       },
       function(statistics, asyncCallback) {
           return m_alAws.getLambdaMetrics(context.functionName,
               'Errors',
               statistics,
               asyncCallback);
       },
       function(statistics, asyncCallback) {
           return m_alAws.getKinesisMetrics(kinesisName,
               'IncomingRecords',
               statistics,
               asyncCallback);
       },
       function(statistics, asyncCallback) {
           return m_alAws.getKinesisMetrics(kinesisName,
               'IncomingBytes',
               statistics,
               asyncCallback);
       },
       function(statistics, asyncCallback) {
           return m_alAws.getKinesisMetrics(kinesisName,
               'ReadProvisionedThroughputExceeded',
               statistics,
               asyncCallback);
       },
       function(statistics, asyncCallback) {
           return m_alAws.getKinesisMetrics(kinesisName,
               'WriteProvisionedThroughputExceeded',
               statistics,
               asyncCallback);
       }
    ], finalCallback);
};



exports.handler = function(event, context) {
    debug("DEBUG0001: Received event: ", JSON.stringify(event));
    switch (event.RequestType) {
        case 'ScheduledEvent':
            return processScheduledEvent(event, context);
        case 'Create':
            return processRegistration(event, context, true);
        case 'Delete':
            return processRegistration(event, context, false);
        default:
            if (event.Records) {
                return processKinesisRecords(event, context);
            } else {
                return context.fail('Unknown event source: ' + event.source);
            }
    }
};
