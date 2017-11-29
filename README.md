# cwe-collector

Alert Logic Amazon Web Services (AWS) CloudWatch Events (CWE) Collector.


# Overview

This repository contains the AWS CWE JavaScript Lambda function and CloudFormation Template (CFT) for deploying
a CW events collector in AWS which will collect and forward CW events to the Alert Logic CloudInsight 
backend services.

# Installation

Refer to [CF template readme](./cfn/README.md) for installation instructions.

# How It Works

## Updater Function

The `Updater` is a timer triggered function that runs a deployment sync operation every 12 hours in order to keep 
the collector lambda function up to date.  The `Updater` syncs from the Alert Logic S3 bucket where you originally
deployed from.

## Collector Function

The `Collector` function is an AWS lambda function which takes CloudWatch events from Kinesis and sends them to 
the AlertLogic `Ingest` service data API for further processing.

1. A CloudWatch rule is used to send CloudWatch events to a AWS Kinesis stream.
1. An AWS Event Source Mapping is used to invoke an Alert Logic `Collector` lambda function to read
CloudWatch events from the Kinesis stream.
1. The Alert Logic `Collector` lambda function reads CloudWatch events from the Kinesis stream and forwards
them to the Alert Logic `Ingest` service data API.


## Checkin Trigger

The `Checkin` Scheduled Event trigger is used to report the health and status of the Alert Logic 
AWS lambda collector to the `Azcollect` back-end service based on an AWS Scheduled Event that 
occurs every 15 minutes.

# Local Development

1. Clone repo `git clone git@github.com:alertlogic/cwe-collector.git`
1. `cd cwe-collector`
1. Run `make compile test package` in order to perform code analysis, unit tests and package the 
lambda function into a zip file.
1. Run `make cfn` to check CloudFromation templates.

Please use the following [code style](https://github.com/airbnb/javascript) as much as possible.

# Known Issues/ Open Questions

- TBD.

# Useful Links

- [Alert Logic AIMs service API](https://console.cloudinsight.alertlogic.com/api/aims/)
- [Alert Logic Sources service API](https://console.cloudinsight.alertlogic.com/api/sources/)
- [How to monitor AWS Lambda functions](http://docs.aws.amazon.com/lambda/latest/dg/monitoring-functions.html)
- [Node.js static code analysis tool](http://jshint.com/install/)
- [Node.js rewire testing tool](https://github.com/jhnns/rewire)
- [Node.js sinon testing tool](http://sinonjs.org/)
