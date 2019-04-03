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
const m_alServiceC = require('al-collector-js/al_servicec');
const m_alAzCollectC = require('al-collector-js/azcollectc');
const m_packageJson = require('./package.json');

const AZCOLLECT_ENDPOINT = process.env.azollect_api;
const COLLECTOR_TYPE = 'cwe';

function checkCloudWatchEventsRule(event, finalCallback) {
    var cwe = new AWS.CloudWatchEvents();
    async.waterfall([
       function(callback) {
            cwe.describeRule({Name: event.CloudWatchEventsRule}, function(err, data) {
                if (err) {
                    return callback(errorMsg('CWE00003', stringify(err)));
                } else {
                    if (data.State === 'ENABLED' &&
                        data.EventPattern === event.CweRulePattern) {
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
                    if (data.Targets.length === 1 &&
                        data.Targets[0].Arn === event.KinesisArn) {
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
            checkCloudWatchEventsRule(event, callback);
        },
        function(callback) {
            checkEventSourceMapping(event, context, callback);
        }
    ],
    function(errMsg) {
        if (errMsg) {
            console.warn('Health check failed with',  errMsg);
            return finalCallback(errMsg);
        } else {
            return finalCallback(null);
        }
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
    checkHealth : function(event, context){
        //add in the env var for the framework
        if(!process.env.stack_name){
            process.env.stack_name = event.StackName;
        }
        return function(callback){
            checkHealth(event, context, callback);
        };
    }
};
