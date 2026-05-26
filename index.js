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
const { KMS } = require("@aws-sdk/client-kms");
const AlAwsCommon = require('@alertlogic/al-aws-collector-js').AlAwsCommon;
const AlAwsStats = require('@alertlogic/al-aws-collector-js').AlAwsStats;
const AlLogger = require('@alertlogic/al-aws-collector-js').Logger;
const m_checkin = require('./checkin');
const cweCollector = require('./al-cwe-collector').cweCollector

let AIMS_CREDS;

async function getDecryptedCredentials() {
    try {
        if (AIMS_CREDS) {
            return null;
        }
        const kms = new KMS();
        const data = await kms.decrypt(
            { CiphertextBlob: Buffer.from(process.env.aims_secret_key, 'base64') }
        );
        AIMS_CREDS = {
            access_key_id: process.env.aims_access_key_id,
            secret_key: new TextDecoder("utf-8").decode(data.Plaintext)
        };
        return null;
    } catch (err) {
        AlLogger.error(`CWE00027: Failed to decrypt credentials from KMS: \`${err.message}\``, err);
        throw err;
    }
}

async function getKinesisData(event) {
    return Promise.all(event.Records.map(async (record) => {
        var cwEvent = Buffer.from(record.kinesis.data, 'base64').toString('utf-8');
        try {
            return JSON.parse(cwEvent);
        } catch (ex) {
            AlLogger.warn(`Event parse failed. ${JSON.stringify(ex)}`);
            AlLogger.warn(`Skipping: ${JSON.stringify(record.kinesis.data)}`);
            return {};
        }
    }));
}

function filterGDEvents(cwEvents) {
    return cwEvents.filter(cwEvent => {
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
        return isValid;
    });
}

async function formatMessages(event, context) {
    try {
        if (!event || !Array.isArray(event.Records)) {
            AlLogger.warn('Invalid event structure: missing or invalid Records array');
            return undefined;
        }
        
        const kinesisData = await getKinesisData(event);
        const collectedData = filterGDEvents(kinesisData);
        
        if (collectedData.length > 0) {
            return {
                collected_batch: {
                    source_id: context.invokedFunctionArn,
                    collected_messages: collectedData
                }
            };
        }
        return undefined;
    } catch (err) {
        AlLogger.error(`CWE00028: Failed to format messages: \`${err.message}\``, err);
        throw err;
    }
}




function getStatisticsFunctions(event) {
    if(!event.KinesisArn){
        return [];
    }
    const kinesisName = AlAwsCommon.arnToName(event.KinesisArn);
    return [
        async () => AlAwsStats.getKinesisMetrics(kinesisName, 'IncomingRecords'),
        async () => AlAwsStats.getKinesisMetrics(kinesisName, 'IncomingBytes'),
        async () => AlAwsStats.getKinesisMetrics(kinesisName, 'ReadProvisionedThroughputExceeded'),
        async () => AlAwsStats.getKinesisMetrics(kinesisName, 'WriteProvisionedThroughputExceeded')
    ];
}

// Migration code for old collectors.
// This is required because the collector lambda does not have premissions to set its own env vars.
async function envVarMigration(event) {
    try {
        if (!process.env.aws_lambda_update_config_name) {
            process.env.aws_lambda_update_config_name = 'configs/lambda/al-cwe-collector.json';
            await AlAwsCommon.setEnvAsync({ aws_lambda_update_config_name: 'configs/lambda/al-cwe-collector.json' });
        }
        if ((!process.env.stack_name && event.StackName) || !process.env.al_application_id) {
            await AlAwsCommon.setEnvAsync({ stack_name: event.StackName, al_application_id: 'guardduty' });
        }
    } catch (err) {
        AlLogger.error('CWE error while adding environment variable');
    }
}


exports.handler = async function(event, context) {
    try {
        await Promise.all([
            envVarMigration(event),
            getDecryptedCredentials()
        ]);
   
    // Some old collector has KMS permission issue and so we can't add the variable in environment variable
    // The process.env.azollect_api has missing c and so connection with azcollect is break, so start connection with azcollect, assign the value to process.env.azcollect_api.
    // Set the collector_id to NA to not call the register api call in every check in event.
    if (process.env.azollect_api && !process.env.azcollect_api) {
        process.env.collector_id = 'NA';
        process.env.azcollect_api = process.env.azollect_api;
        process.env.collector_status_api = process.env.azcollect_api;
    }
    const collector = new cweCollector(
        context,
        AIMS_CREDS,
        formatMessages,
        [
            async () => m_checkin.checkHealth(event, context),
            async () => AlAwsCommon.checkCloudFormationStatusAsync(event.StackName)
        ],
        getStatisticsFunctions(event)
    );

        debug("DEBUG0001: Received event: ", JSON.stringify(event));
       
        return await collector.handleEvent(event);
    } catch (err) {
        AlLogger.error(`CWE00029: Handler execution failed: \`${err.message}\``, err);
        throw err;
    }
};
