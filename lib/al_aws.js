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
const MAX_ERROR_MSG_LEN = 1024;

var selfUpdate = function (callback) {
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
        return callback(err);
    });
};

var getMetricStatistics = function (params, statistics, callback) {
    var cloudwatch = new AWS.CloudWatch({apiVersion: '2010-08-01'});
    cloudwatch.getMetricStatistics(params, function(err, data) {
        if (err) {
            statistics.push({
                Label: params.MetricName,
                StatisticsError: JSON.stringify(err).slice(0, MAX_ERROR_MSG_LEN)
            });
        } else {
            statistics.push({
                Label: data.Label,
                Datapoints: data.Datapoints
            });
        }
        return callback(null, statistics);
    });
};

var getLambdaMetrics = function (functionName, metricName, statistics, callback) {
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
    return getMetricStatistics(params, statistics, callback);
};

var getKinesisMetrics = function (streamName, metricName, statistics, callback) {
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
    return getMetricStatistics(params, statistics, callback);
};

var arnToName = function (arn) {
    const parsedArn = arn.split(':');
    if (parsedArn.length > 3) {
        const parsedId = parsedArn[parsedArn.length-1].split('/');
        return parsedId[parsedId.length-1];
    } else {
        return undefined;
    }
};

module.exports = {
    getMetricStatistics : getMetricStatistics,
    getLambdaMetrics : getLambdaMetrics,
    getKinesisMetrics : getKinesisMetrics,
    selfUpdate : selfUpdate,
    arnToName : arnToName
};
