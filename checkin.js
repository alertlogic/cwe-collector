/* -----------------------------------------------------------------------------
 * @copyright (C) 2017, Alert Logic, Inc
 * @doc
 *
 * Lambda collector health check functions.
 *
 * @end
 * -----------------------------------------------------------------------------
 */
 
const AWS = require('aws-sdk');
const async = require('async');
const m_alServiceC = require('./lib/al_servicec');
const m_packageJson = require('./package.json');

const AZCOLLECT_ENDPOINT = process.env.azollect_api;

function checkCloudFormationStatus(event, callback) {
    var stackName = event.StackName;
    var cloudformation = new AWS.CloudFormation();
    cloudformation.describeStacks({StackName: stackName}, function(err, data) {
        if (err) {
            return callback(errorMsg('CWE00001', stringify(err)));
        } else {
            var stackStatus = data.Stacks[0].StackStatus;
            if (stackStatus == 'CREATE_COMPLETE' ||
                stackStatus == 'UPDATE_COMPLETE') {
                return callback(null);
            } else {
                return callback(errorMsg('CWE00002', 'CF stack has wrong status: ' + stackStatus));
            }
        }
    });
}

function checkCloudWatchEventsRule(event, finalCallback) {
    var cwe = new AWS.CloudWatchEvents();
    async.waterfall([
       function(callback) {
            cwe.describeRule({Name: event.CloudWatchEventsRule}, function(err, data) {
                if (err) {
                    return callback(errorMsg('CWE00003', stringify(err)));
                } else {
                    if (data.State == 'ENABLED' &&
                        data.EventPattern == event.CweRulePattern) {
                        return callback(null);
                    } else {
                        return callback(errorMsg('CWE00004', 'CWE Rule is incorrectly configured: ' + stringify(data)));
                    }
                }
            });
        },
        function(callback) {
            cwe.listTargetsByRule({Rule: event.CloudWatchEventsRule}, function(err, data) {
                if (err) {
                    return callback(errorMsg('CWE00005', stringify(err)));
                } else {
                    if (data.Targets.length == 1 &&
                        data.Targets[0].Arn == event.KinesisArn) {
                        return callback(null);
                    } else {
                        return callback(errorMsg('CWE00006', 'CWE rule ' + event.CloudWatchEventsRule + ' has incorrect target set'));
                    }
                }
            });
        }
    ], finalCallback);
}

function checkEventSourceMapping(checkinEvent, context, callback) {
    var lambda = new AWS.Lambda();
    lambda.listEventSourceMappings({FunctionName: context.functionName},
        function(err, data) {
            if (err) {
                return callback(errorMsg('CWE00010', stringify(err)));
            } else {
                var eventSource = data.EventSourceMappings.find(
                            obj => obj.EventSourceArn === checkinEvent.KinesisArn);
                if (eventSource) {
                    return checkEventSourceStatus(checkinEvent, eventSource, callback);
                } else {
                    return callback(errorMsg(
                        'CWE00015',
                        'Event source mapping doesn\'t exist: ' + stringify(data)));
                }
            }
    });
}

function checkEventSourceStatus(checkinEvent, eventSource, callback) {
    var lastProcessingResult = eventSource.LastProcessingResult;
    var state = eventSource.State;
    
    if (state === 'Enabled' &&
        (lastProcessingResult === 'OK' ||
         // At this point the assumption is that all kinesis and events configuration
         // around collect lambda is correct and 'No records processed' 
         // means just no events being generated.
         lastProcessingResult === 'No records processed')) {
        return callback(null);
    } else {
        return callback(errorMsg('CWE00020', 'Incorrect event source mapping status: ' + stringify(eventSource)));
    }
}

function checkHealth(event, context, finalCallback) {
    async.waterfall([
        function(callback) {
            checkCloudFormationStatus(event, callback);
        },
        function(callback) {
            checkCloudWatchEventsRule(event, callback);
        },
        function(callback) {
            checkEventSourceMapping(event, context, callback);
        }
    ],
    function(errMsg) {
        if (errMsg) {
            console.warn('Health check failed with',  errMsg);
            return finalCallback(null, {
                status: errMsg.status,
                error_code: errMsg.code,
                details: [errMsg.details]
            });
        } else {
            return finalCallback(null, {
                status: 'ok',
                details: []
            });
        }
    });
}


function sendCheckin(event, context, aimsC, healthStatus, callback) {
    var checkinValues = {
        collectorType : 'cwe',
        awsAccountId : event.AwsAccountId,
        region : process.env.AWS_REGION,
        functionName : context.functionName,
        status : healthStatus.status,
        details : healthStatus.details,
        error_code: healthStatus.error_code,
        version : m_packageJson.version
    };
    var azcollectSvc = new m_alServiceC.AzcollectC(AZCOLLECT_ENDPOINT, aimsC);
    azcollectSvc.doCheckin(checkinValues)
        .then(resp => {
            return callback(null);
        })
        .catch(function(exception) {
            return callback(`Checkin failed: ${exception}`);
        });
}


function stringify(jsonObj) {
    return JSON.stringify(jsonObj, null, 0);
}

function errorMsg(code, message) {
    return {
        status: 'error',
        code: code,
        details: message
    };
}

module.exports = {
    checkHealth : checkHealth,
    sendCheckin : sendCheckin
};