'use strict';
const AlAwsCollectorV2 = require('@alertlogic/al-aws-collector-js').AlAwsCollectorV2;
const AlLogger = require('@alertlogic/al-aws-collector-js').Logger;
const m_packageJson = require('./package.json');
const parse = require('@alertlogic/al-collector-js').Parse

const typeIdPaths = [
    { path: ['detail', 'type'] }
];

const tsPaths = [
    { path: ['time'] }
];

class CweCollector extends AlAwsCollectorV2 {
    constructor(context, aimsCreds, formatMessages, healthChecks = [], statsChecks = []) {
        super(context,
            "cwe",
            AlAwsCollectorV2.IngestTypes.SECMSGS,
            m_packageJson.version,
            aimsCreds,
            formatMessages,
            healthChecks,
            statsChecks);
        this.stack_name = process.env.stack_name;
    }

    getProperties(event) {
        const baseProps = super.getProperties();
        const stack_name = event && event.ResourceProperties.StackName ? event.ResourceProperties.StackName : this.stack_name;
        const collectRule = event && event.ResourceProperties.CollectRule ? event.ResourceProperties.CollectRule : `aws.guardduty`;

        let cweProps = {
            cf_stack_name: stack_name,
            collect_rule: collectRule
        };
        return Object.assign(cweProps, baseProps);
    };

    async register(event, custom) {
        try {
            const cweRegisterProps = this.getProperties(event);
            if (custom && typeof custom === 'object') {
                Object.assign(cweRegisterProps, custom);
            }
            return await super.register(event, cweRegisterProps);
        } catch (err) {
            AlLogger.error(`CWE00021: CWE registration failed: \`${err.message}\``, err);
            throw err;
        }
    }

    async _formatMessagesAsync(event, context) {
        try {
            return await this._formatFun(event, context);
        } catch (err) {
            AlLogger.error(`CWE00022: Failed to format messages: \`${err.message}\``, err);
            throw err;
        }
    }

    async _sendAsync(formattedData, compress = true) {
        try {
            if (arguments.length === 2 && typeof compress === 'function') {
                compress = true;
            }
            await this.send(JSON.stringify(formattedData), compress, this._ingestType);
            return formattedData;
        } catch (err) {
            AlLogger.error(`CWE00023: Failed to send formatted data: \`${err.message}\``, err);
            throw err;
        }
    }

    async _processLogAsync(formattedData) {
        try {
            if (!formattedData || !formattedData.collected_batch) {
                AlLogger.warn('Invalid formattedData structure, skipping log processing');
                return null;
            }
            return await this.processLog(
                formattedData.collected_batch.collected_messages,
                this.formatLog.bind(this),
                null
            );
        } catch (err) {
            AlLogger.error(`CWE00024: Failed to process logs: \`${err.message}\``, err);
            throw err;
        }
    }

    async process(event) {
        try {
            const context = this._invokeContext;
            const formattedData = await this._formatMessagesAsync(event, context);
            
            if (!formattedData) {
                AlLogger.warn('No formatted data to process, returning empty batch');
                return { collected_messages: [] };
            }
            
            await this._sendAsync(formattedData, true);
            return await this._processLogAsync(formattedData);
        } catch (err) {
            AlLogger.error(`CWE00025: CWE process execution failed: \`${err.message}\``, err);
            throw err;
        }
    }

    async handleEvent(event) {
        try {
            if (event.Records) {
                return await this.process(event);
            }
            if (!this.stack_name && event.StackName) {
                this.stack_name = event.StackName;
            }
            return await super.handleEvent(event);
        } catch (err) {
            AlLogger.error(`CWE00026: CWE handleEvent failed: \`${err.message}\``, err);
            throw err;
        }
    };

    /**
     * Format the message to process logmessages
     * @param {*} msg 
     */
    formatLog(msg) {
        let collector = this;
        const ts = parse.getMsgTs(msg, tsPaths);
        const typeId = parse.getMsgTypeId(msg, typeIdPaths);
        let formattedMsg = {
            hostname: collector.collector_id,
            messageTs: ts.sec,
            priority: 11,
            progName: 'CWECollector',
            message: JSON.stringify(msg),
            messageType: 'json/cwe',
            applicationId: collector.application_id
        };

        if (typeId !== null && typeId !== undefined) {
            formattedMsg.messageTypeId = `${typeId}`;
        }
        if (ts.usec) {
            formattedMsg.messageTsUs = ts.usec;
        }
        return formattedMsg;
    }
}

module.exports = {
    cweCollector: CweCollector
};

