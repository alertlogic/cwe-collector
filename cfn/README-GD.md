# guardduty.template

Alert Logic Amazon Web Services (AWS) CloudWatch Events (CWE) Collector CloudFormation templates.

# Overview

This folder contains the AWS CWE JavaScript lambda function and the CloudFormation template (CFT) that deploys the GuardDuty events collector to AWS. The GuardDuty collector collects and forwards CloudWatch events to the Cloud Insight backend for display as threats on the Incidents page.

Amazon GuardDuty is a continuous security monitoring service that requires no customer-managed hardware or software. 
GuardDuty analyzes and processes VPC Flow Logs and AWS CloudTrail event logs. GuardDuty uses security logic and 
AWS usage statistics techniques to identify unexpected and potentially unauthorized and malicious activity. 
Such activity includes escalations of privileges, uses of exposed credentials, or communication with 
malicious IPs, URLs, or domains. GuardDuty informs you of the status of your AWS infrastructure and applications by producing security `findings`. 

# Installation

To install the GuardDuty events collector:

1. **Enable CloudWatch event collection** - In your AWS account, enable Amazon GuardDuty CloudWatch event collection.
1. **Alert Logic Access key creation** - Create an Alert Logic access key that allows the collector to connect to the Alert Logic Cloud Insight back end.
1. **CloudFormation template deployment** - Deploy a custom AWS CloudFormation template to your AWS account to create lambda functions.
1. **Deployment verification** - Use the Cloud Insight console to verify a successful installation.

## Enable CloudWatch event collection

The Alert Logic CWE collector for GuardDuty collects `findings` from Amazon CloudWatch events.

To enable Amazon GuardDuty events, see [Setting Up Amazon GuardDuty](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_settingup.html).

## Alert Logic Access key creation

**Before you begin:** Be sure you have an Alert Logic Cloud Insight account with administrator permissions. Log into the Cloud Insight console as an administrator [here](https://console.cloudinsight.alertlogic.com/#/login).
In order to verify the user has administrator permissions:

1. Once logged in click on the user name at the top-right corner of Cloud Insight console.
1. In the drop-down menu click `Users`.
1. Select the user in `AIMS User` section. **Note** you can start typing a name in the search box to find an appropriate user.
1. Once found check that `user role` list under the `Edit an AIMS User` section has `Administrator` role selected.

The following procedure assumes a Linux-based local machine using [curl](https://curl.haxx.se/) and 
[jq](https://stedolan.github.io/jq/). For Windows please use command line and windows versions of [curl](https://curl.haxx.se/download.html) and [jq](https://stedolan.github.io/jq/download/).

From the bash command line, type the following commands, where `<email address>` is your Alert Logic Cloud Insight email address you use to log in, and then enter your password when prompted:

```
export AL_USERNAME='<email address>'
auth=$(curl -X POST -s -u $AL_USERNAME https://api.global-services.global.alertlogic.com/aims/v1/authenticate); export AL_ACCOUNT_ID=$(echo $auth | jq -r '.authentication.account.id'); export AL_USER_ID=$(echo $auth | jq -r '.authentication.user.id'); export AL_TOKEN=$(echo $auth | jq -r '.authentication.token'); if [ -z $AL_TOKEN ]; then echo "Authentication failure"; else roles=$(curl -s -X GET -H "x-aims-auth-token: $AL_TOKEN" https://api.global-services.global.alertlogic.com/aims/v1/$AL_ACCOUNT_ID/users/$AL_USER_ID/roles | jq -r '.roles[].name'); if [ "$roles" != "Administrator" ]; then echo "The $AL_USERNAME doesn’t have Administrator role. Assigned role is '$roles'"; else curl -s -X POST -H "x-aims-auth-token: $AL_TOKEN" https://api.global-services.global.alertlogic.com/aims/v1/$AL_ACCOUNT_ID/users/$AL_USER_ID/access_keys | jq .; fi; fi; unset AL_USERNAME;
```
An example of a successful response is:

```
{
  "access_key_id": "712c0b413eef41f6",
  "secret_key": "1234567890b3eea8880d292fb31aa96902242a076d3d0e320cc036eb51bf25ad"
}
```

**Important:** If the command returns no output, verify your Alert Logic account has administrator permissions. Click [here](https://console.cloudinsight.alertlogic.com/api/aims/) for more information about AIMS APIs.

Make a note of the `access_key_id` and `secret_key` values, which you need when you deploy the CloudFormation template to your AWS account. 

**Note:** Each user can create only five access keys. If a "limit exceeded" response appears, you must delete one or more access keys before you can create new keys. 

**Type the following command to list access keys:**
```
curl -s -X GET -H "x-aims-auth-token: $AL_TOKEN" https://api.global-services.global.alertlogic.com/aims/v1/$AL_ACCOUNT_ID/users/$AL_USER_ID/access_keys | jq
```

**Use the selected access_key_id in the following curl command to delete the key:**

```
curl -X DELETE -H "x-aims-auth-token: $AL_TOKEN" https://api.global-services.global.alertlogic.com/aims/v1/$AL_ACCOUNT_ID/users/$AL_USER_ID/access_keys/<ACCESS_KEY_ID_HERE>
```

## CloudFormation template deployment

The Alert Logic CWE collector deploys to a single AWS region. To collect from 
multiple AWS regions, you must either install the collector in each target region, or 
set up GuardDuty collection across regions. For more information, see: [Setting up GuardDuty across
regions and accounts](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_accounts.html).

**Note:** This procedure assumes setup in the AWS `us-east-1` region 
using the Alert Logic Cloud Insight [US console](https://console.cloudinsight.alertlogic.com/#/login). If
your setup is in a European region (e.g. `eu-east-1`), use the 
[UK console](https://console.cloudinsight.alertlogic.co.uk/#/login).

1. Log in to the [AWS Management Console](https://aws.amazon.com/console/) with an AWS account that has AWS administrator privileges. 
1. Select the region in which you want to deploy the CFT.
1. Click `Services`->`CloudFormation`->`Create Stack`.
1. In the `Choose a template` section select `Specify an Amazon S3 template URL`, use the following URL and click `Next`:
`https://s3.amazonaws.com/alertlogic-collectors-us-east-1/cfn/guardduty.template`
1. On the `Specify Details` window, provide the following required parameters:
   - `Stack name` - Any name you have used for creating an AWS stack
   - `AccessKeyId` - `access_key_id` returned from AIMs [above](#alert-logic-access-key-creation)
   - `AlApiEndpoint` - usually `api.global-services.global.alertlogic.com` 
   - `AlDataResidency` - usually `default`
   - `SecretKey` - `secret_key` returned from AIMs [above](#alert-logic-access-key-creation)
1. Click Next. 
1. On the Options panel, click Next.
1. In the Review panel, perform a predeployment check. 
1. Select "I acknowledge that AWS CloudFormation might create IAM resources," and then click Create.
1. On the CloudFormation, Stacks panel, filter based on the stack name you created, and then 
select your stack by name.

**Note:** Only one collector installation is allowed per AWS region. If you try to deploy the template multiple times in the same region, if will fail with the following error:

Status | Type | Logical ID | Status Reason
--|--|--|--
CREATE_FAILED | AWS::Lambda::Function | CollectLambdaFunction | alertlogic-cwe-collector already exists in stack arn:aws:cloudformation:us-east-1:123456789101:stack/test-one/f9536300-d12b-11e7-ac98-50d5cd16c68e


If the deployment was successful, the status appears as: CREATE_COMPLETE. If the deployment was not successful, 
see [Troubleshooting Installation Issues](#troubleshooting-installation-issues) below.

#### Use a Command Line to deploy

Follow these steps to deploy the Alert Logic custom template using the [AWS CLI](https://aws.amazon.com/cli/).

1. Download the Alert Logic custom CFT to your local machine from [the Alert Logic public github repository](https://github.com/alertlogic/cwe-collector/blob/master/cfn/guardduty.template). 
1. In the command line, type the following command, where the required parameters are:
    - `stack-name` - Any name you have used to create an AWS stack
    - `AccessKeyId` - `access_key_id` returned from AIMs [above](#alert-logic-access-key-creation)
    - `SecretKey` - `secret_key` returned from AIMs [above](#alert-logic-access-key-creation)

    ```
    aws cloudformation create-stack --template-url https://s3.amazonaws.com/alertlogic-collectors-us-east-1/cfn/guardduty.template --stack-name <alertlogic-collector-stack-name> --capabilities CAPABILITY_IAM --parameters ParameterKey=AccessKeyId,ParameterValue=<access_key_id> ParameterKey=SecretKey,ParameterValue=<secret_key>
    ```
1. Wait for the stack creation to complete.

## Deployment verification

1. Log into the Alert Logic Cloud Insight console.
**Note:** You must log in with an account that has administrator permissions.
    - Use the [US console](https://console.cloudinsight.alertlogic.com/#/login) for regions in the US and associated geographical regions.
    - Use the [UK console](https://console.cloudinsight.alertlogic.co.uk/#/login) for regions in Europe and other regions not in the US.
1. If you have not already created a Cloud Insight deployment, follow the instructions [here](https://docs.alertlogic.com/gsg/amazon-web-services-cloud-insight-get-started.htm) to do so for the AWS account and region where you installed the CFT.
1. Verify successful deployment by checking the Incident list in Alert Logic Cloud Insight UI. The list should be populated with Incidents that correspond to recent Amazon GuardFindings which are displayed in Amazon GuardDuty console.

## Troubleshooting Installation Issues

If installation through the [AWS Management Console](https://aws.amazon.com/console/) is not successful, you can access 
`CloudFormation`->`Stacks`->`Stack Detail` (by selecting your stack name from the list) to see detailed
error messages in the AWS [CloudWatch Log Stream](https://console.aws.amazon.com/cloudwatch/home). Click `Logs`, 
and then filter by `/aws/lambda/my-new-stack` (where `my-new-stack` is the name you gave your stack). 

If installation through the AWS CLI is not successful, issue the following command for more information:

```
aws cloudformation describe-stack-events --stack-name my-new-stack
```

1. If `GetEndpointsLambdaFunction` fails, an issue could exist with the AIMs access key id or the secret key
 you provided. Be sure the key id is correct, your secret key is valid, and your user account has administrative permissions for the Alert Logic Cloud Insight account.
1. Other issues, TBD.


# Known Issues/ Open Questions

- TBD.

# Useful Links

- [Alert Logic AIMs service API](https://console.cloudinsight.alertlogic.com/api/aims/)
- [How to monitor AWS Lambda functions](http://docs.aws.amazon.com/lambda/latest/dg/monitoring-functions.html)
- [AWS GuardDuty API Reference](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_api_ref.html)

