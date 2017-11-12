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

module.exports.selfUpdate = function (callback) {
    var params = {
      FunctionName: process.env.AWS_LAMBDA_FUNCTION_NAME,
      S3Bucket: process.env.aws_lambda_s3_bucket,
      S3Key: process.env.aws_lambda_zipfile_name
    };
    var lambda = new AWS.Lambda();
    console.info("Performing lambda self-update with params: ", JSON.stringify(params));
    lambda.updateFunctionCode(params, function(err, data) {
        if (err) {
            console.info("Lambda self-update error: ", err);
        } else {
            console.info("Lambda self-update successful.  Data: " + data);
        }
        callback(err);
    });
};