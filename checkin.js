/* -----------------------------------------------------------------------------
 * @copyright (C) 2017, Alert Logic, Inc
 * @doc
 *
 * Lambda collector health check functions.
 *
 * @end
 * -----------------------------------------------------------------------------
 */



const { CloudWatchEvents } = require("@aws-sdk/client-cloudwatch-events");
const { Lambda } = require("@aws-sdk/client-lambda");
const AlLogger = require('@alertlogic/al-aws-collector-js').Logger;


async function checkCloudWatchEventsRule(event) {
    var cwe = new CloudWatchEvents();
    try {
        const describeRuleData = await cwe.describeRule({ Name: event.CloudWatchEventsRule });
        if (describeRuleData.State !== 'ENABLED' ||
            describeRuleData.EventPattern !== event.CweRulePattern) {
            throw errorMsg('CWE00004', 'CWE Rule is incorrectly configured: ' + stringify(describeRuleData));
        }
    } catch (err) {
        if (err && err.code === 'CWE00004') {
            throw err;
        }
        throw errorMsg('CWE00003', stringify(err));
    }

    try {
        const targetData = await cwe.listTargetsByRule({ Rule: event.CloudWatchEventsRule });
        if (targetData.Targets.length === 1 &&
            targetData.Targets[0].Arn === event.KinesisArn) {
            return null;
        }

        throw errorMsg('CWE00006', 'CWE rule ' + event.CloudWatchEventsRule + ' has incorrect target set');
    } catch (err) {
        if (err && (err.code === 'CWE00006')) {
            throw err;
        }
        throw errorMsg('CWE00005', stringify(err));
    }
}

async function checkEventSourceMapping(checkinEvent, context) {
    var lambda = new Lambda();
    try {
        const data = await lambda.listEventSourceMappings({ FunctionName: context.functionName });
        var eventSource = data.EventSourceMappings.find(
            obj => obj.EventSourceArn === checkinEvent.KinesisArn
        );
        if (eventSource) {
            return checkEventSourceStatus(checkinEvent, eventSource);
        }

        throw errorMsg(
            'CWE00015',
            'Event source mapping doesn\'t exist: ' + stringify(data)
        );
    } catch (err) {
        if (err && err.code === 'CWE00015') {
            throw err;
        }
        throw errorMsg('CWE00010', stringify(err));
    }
}

function checkEventSourceStatus(checkinEvent, eventSource) {
    var lastProcessingResult = eventSource.LastProcessingResult;
    var state = eventSource.State;

    if (state === 'Enabled' &&
        (lastProcessingResult === 'OK' ||
         // At this point the assumption is that all kinesis and events configuration
         // around collect lambda is correct and 'No records processed'
         // means just no events being generated.
         lastProcessingResult === 'No records processed')) {
        return null;
    } else {
        throw errorMsg('CWE00020', 'Incorrect event source mapping status: ' + stringify(eventSource));
    }
}

async function checkHealth(event, context) {
    try {
        await checkCloudWatchEventsRule(event);
        await checkEventSourceMapping(event, context);
        return null;
    } catch (errMsg) {
        AlLogger.warn(`CWE00008: Health check failed with \`${JSON.stringify(errMsg)}\``, errMsg);
        throw errMsg;
    }
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
    checkHealth
};
