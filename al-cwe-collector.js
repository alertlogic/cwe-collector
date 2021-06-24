'use strict';
const AlAwsCollector = require('@alertlogic/al-aws-collector-js').AlAwsCollector;
const m_packageJson = require('./package.json');
const parse = require('@alertlogic/al-collector-js').Parse
const async = require('async');

const typeIdPaths = [
    { path: ['detail', 'type'] }
];

const tsPaths = [
    { path: ['time'] }
];

class CweCollector extends AlAwsCollector {
    constructor(context, aimsCreds, formatMessages, healthChecks = [], statsChecks = []) {
        super(context,
            "cwe",
            AlAwsCollector.IngestTypes.SECMSGS,
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

    register(event, custom, callback) {
        let collector = this;
        let cweRegisterProps = this.getProperties(event);
        AlAwsCollector.prototype.register.call(collector, event, cweRegisterProps, callback);
    }

    process(event, callback) {
        const context = this._invokeContext;
        var collector = this;
        async.waterfall([
            function (asyncCallback) {
                collector._formatFun(event, context, asyncCallback);
            },
            function (formattedData, compress, asyncCallback) {
                if (arguments.length === 2 && typeof compress === 'function') {
                    asyncCallback = compress;
                    compress = true;
                }
                collector.send(JSON.stringify(formattedData), compress, collector._ingestType, (err, res) => {
                    return asyncCallback(err, formattedData);
                });
            },
            function (formattedData, asyncCallback) {
                collector.processLog(formattedData.collected_batch.collected_messages, collector.formatLog.bind(collector), null, asyncCallback);
            }
        ],
            callback);
    }

    handleEvent(event, asyncCallback) {
        let collector = this;
        if (event.Records) {
            return collector.process(event, asyncCallback);

        } else {
            if (!this.stack_name && event.StackName) {
                this.stack_name = event.StackName;
            }
            return super.handleEvent(event);
        }
    };

    /**
     * Format the message to process logmessages
     * @param {*} msg 
     */
    formatLog(msg) {
        const ts = parse.getMsgTs(msg, tsPaths);
        const typeId = parse.getMsgTypeId(msg, typeIdPaths);
        let formattedMsg = {
            messageTs: ts.sec,
            priority: 11,
            progName: 'CWECollector',
            message: JSON.stringify(msg),
            messageType: 'json/cwe',
            applicationId: this.application_id
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

