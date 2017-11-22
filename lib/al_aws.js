/* -----------------------------------------------------------------------------
 * @copyright (C) 2017, Alert Logic, Inc
 * @doc
 *
 * Helper class for lambda function utility and helper methods.
 *
 * @end
 * -----------------------------------------------------------------------------
 */

const AWS = require('aws-sdk');
const moment = require('moment');
const async = require('async');

const AWS_STATISTICS_PERIOD_MINUTES = 15;

module.exports.selfUpdate = function (callback) {
    var params = {
      FunctionName: process.env.AWS_LAMBDA_FUNCTION_NAME,
      S3Bucket: process.env.aws_lambda_s3_bucket,
      S3Key: process.env.aws_lambda_zipfile_name
    };
    var lambda = new AWS.Lambda();
    console.info('Performing lambda self-update with params: ', JSON.stringify(params));
    lambda.updateFunctionCode(params, function(err, data) {
        if (err) {
            console.info('Lambda self-update error: ', err);
        } else {
            console.info('Lambda self-update successful.  Data: ' + data);
        }
        callback(err);
    });
};

function getMetricStatistics(params, statistics, callback) {
    var cloudwatch = new AWS.CloudWatch({apiVersion: '2010-08-01'});
    cloudwatch.getMetricStatistics(params, function(err, data) {
        if (err) {
            statistics.push({
                "Label": params.MetricName,
                "StatisticsError": stringify(err)
            });
            callback(null, statistics);
        } else {
            statistics.push({
                "Label": data.Label,
                "Datapoints": data.Datapoints
            });
            callback(null, statistics);
        }
    });
}

function getLambdaMetrics(functionName, metricName, statistics, callback) {
    var params = {
        Dimensions: [
              {
                  Name: 'FunctionName',
                  Value: functionName
              }
        ],
        MetricName: metricName,
        Namespace: 'AWS/Lambda',
        Statistics: ['Sum'],
        StartTime: moment().subtract(AWS_STATISTICS_PERIOD_MINUTES, 'minutes').toISOString(),
        EndTime: new Date(),
        Period: 60*AWS_STATISTICS_PERIOD_MINUTES   /* 15 mins as seconds */
    };
    getMetricStatistics(params, statistics, callback);
}

function getKinesisMetrics(streamName, metricName, statistics, callback) {
    var params = {
        Dimensions: [
              {
                  Name: 'StreamName',
                  Value: streamName
              }
        ],
        MetricName: metricName,
        Namespace: 'AWS/Kinesis',
        Statistics: ['Sum'],
        StartTime: moment().subtract(AWS_STATISTICS_PERIOD_MINUTES, 'minutes').toISOString(),
        EndTime: new Date(),
        Period: 60*AWS_STATISTICS_PERIOD_MINUTES   /* 15 mins as seconds */
    };
    getMetricStatistics(params, statistics, callback);
}

module.exports.getStatistics = function(context, event, response, finalCallback) {
    response.statistics = [];
    async.waterfall([
       function(asyncCallback) {
           getLambdaMetrics(context.functionName,
               'Invocations',
               response.statistics,
               asyncCallback);
       },
       function(statistics, asyncCallback) {
           getLambdaMetrics(context.functionName,
               'Errors',
               response.statistics,
               asyncCallback);
       },
       function(statistics, asyncCallback) {
           getKinesisMetrics(event.KinesisArn,
               'IncomingRecords',
               response.statistics,
               asyncCallback);
       },
       function(statistics, asyncCallback) {
           getKinesisMetrics(event.KinesisArn,
               'ReadProvisionedThroughputExceeded',
               response.statistics,
               asyncCallback);
       },
       function(statistics, asyncCallback) {
           getKinesisMetrics(event.KinesisArn,
               'WriteProvisionedThroughputExceeded',
               response.statistics,
               asyncCallback);
       }
    ], finalCallback);

};
