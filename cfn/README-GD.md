# guardduty.template

Alert Logic Amazon Web Services (AWS) CloudWatch Events (CWE) Collector CloudFormation templates.

# Overview

This folder contains the AWS CWE JavaScript lambda function and the CloudFormation template (CFT) that deploys the GuardDuty events collector to AWS. The GuardDuty collector collects and forwards CloudWatch events to the Cloud Insight backend for display as threats on the Incidents page. 

# Installation

**To install the GuardDuty events collector:

1. In your AWS account, enable GuardDuty CloudWatch event collection.
1. Create an Alert Logic access key that allows the collector to connect to the Alert Logic Cloud Insight back end.
1. Deploy a custom AWS CloudFormation template to your AWS account to create lambda functions
for collecting and managing GuardDuty event data.
1. Use the Cloud Insight console to verify a successful installation.

## Enable Amazon GuardDuty CloudWatch event collection in your AWS account
START 
Amazon GuardDuty is a continuous security monitoring service that requires no customer-managed hardware or software. 
GuardDuty analyzes and processes VPC Flow Logs and AWS CloudTrail event logs. GuardDuty uses security logic and 
AWS usage statistics techniques to identify unexpected and potentially unauthorized and malicious activity. 
Such activity includes escalations of privileges, uses of exposed credentials, or communication with 
malicious IPs, URLs, or domains. GuardDuty informs you of the status of your AWS infrastructure and applications by producing security `findings`. The Alert Logic CWE collector for GuardDuty collects `findings` from Amazon CloudWatch events.

To capture GuardDuty events, see [Setting Up Amazon GuardDuty] (http://docs.aws.amazon.com/AWSGuardDuty/latest/UserGuide/settingup.html).

**Temp Dev and Test Note: The current template is stored here 
https://s3.amazonaws.com/rcs-test-us-east-1/templates/guardduty.template Access to this template is granted to 
Route105 (948063967832), Collect (352283894008) and Ozone (481746159046) AWS accounts only.**

## Create an Alert Logic Access Key

**Before you begin:** Be sure you have an Alert Logic Cloud Insight account with administrator permissions. Log into the Cloud Insight console as an administrator [here](https://console.cloudinsight.alertlogic.com/#/login).

This procedure assumes a Linux-based local machine using [curl](https://curl.haxx.se/) and 
[jq](https://stedolan.github.io/jq/).

From the bash command line, type the following commands, where `<username>` and `<password>` are your Alert Logic Cloud Insight credentials:

**Temp Dev and Test Note: In the curl command below, use the integration url here api.global-integration.product.dev.alertlogic.com instead.**

```
export AL_USERNAME='<username>'
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

## Deploy a custom AWS CloudFormation template to your AWS account

The Alert Logic CWE collector deploys to a single AWS region. To collect from 
multiple AWS regions, you must either install the collector in each target region, or 
set up GuardDuty collection across regions. For more information, see: [Setting up GuardDuty across
regions and accounts](TBD)).  

**Note:** This procedure assumes setup in the AWS `us-east-1` region 
using the Alert Logic Cloud Insight [US console](https://console.cloudinsight.alertlogic.com/#/login). If
your setup is in a European region (e.g. `eu-east-1`), use the 
[UK console](https://console.cloudinsight.alertlogic.co.uk/#/login).

1. Log in to the [AWS Management Console](https://aws.amazon.com/console/) with an AWS account that has AWS administrator privileges. 
1. Select the region in which you want to deploy the CFT.
1. Click `Services`->`CloudFormation`->`Design Template`.
1. On the menu bar, click the file icon, and then click `Open`.
1. In the `Open a template` window, click `Amazon S3 bucket`.
1. In the `Template URL` field, type the following: 
Alert Logic S3 bucket URL: `https://s3.amazonaws.com/alert-logic-cwe-<region>/templates/guardduty.template` 
where `<region>` matches your AWS region. **TODO: This must be altered before GA**
1. On the menu bar, click the `Create stack` icon.
1. On the `Select Template` window, click `Next`.
1. On the `Specify Details` window, provide the following required parameters:
   - `Stack name` - Any name you have used for creating an AWS stack
   - `AccessKeyId` - `access_key_id` returned from AIMs [above](#create_an_alert_logic_access_key)
   - `AlApiEndpoint` - usually `api.global-services.global.alertlogic.com` 
   - `AlDataResidency` - usually `default`
   - `S3Bucket` - Use the dropdown menu to select the bucket that matches your region **TODO: field will be removed before GA.**
   - `S3Zipfile` - **TODO: field will be removed before GA**
   - `SecretKey` - `secret_key` returned from AIMs [above](#create_an_alert_logic_access_key)  
1. Click Next. 
1. On the Options panel, click Next.
1. In the Review panel, perform a predeployment check. 
1. Select "I acknowledge that AWS CloudFormation might create IAM resources," and then click Create.
1. On the CloudFormation, Stacks panel, filter based on the stack name you created, and then 
select your stack by name.

If deployment was successful, the status appears as: CREATE_COMPLETE. If deployment was not successful, 
see [Troubleshooting Installation Issues](#Troubleshooting Installation Issues) below.    

#### Use a Command Line to deploy

Follow these steps to deploy the Alert Logic custom template using the [AWS CLI](https://aws.amazon.com/cli/).

1. Download the Alert Logic custom CFT to your local machine from [the Alert Logic public github repository](). 
1. In the command line, type the following command, where the required parameters are:
    - `stack-name` - Any name you have used to create an AWS stack
    - `AccessKeyId` - `access_key_id` returned from AIMs [above](#create_an_alert_logic_access_key)
    - `SecretKey` - `secret_key` returned from AIMs [above](#create_an_alert_logic_access_key)   

    ```
    aws cloudformation deploy --template /path_to_template/guardduty.template --stack-name my-new-stack --capabilities CAPABILITY_IAM --parameter-overrides AccessKeyId=<access_key_id> SecretKey=<secret_key>
    ```
1. Wait for the stack creation to complete.

## Verify the Installation

1. Log into the Alert Logic Cloud Insight console.
**Note:** You must log in with an account that has administrator permissions.
    - Use the [US console](https://console.cloudinsight.alertlogic.com/#/login) for regions in the US and associated geographical regions.
    - Use the [UK console](https://console.cloudinsight.alertlogic.co.uk/#/login) for regions in Europe and other regions not in the US.
1. If you have not already created a Cloud Insight deployment, follow the instructions [here](https://docs.alertlogic.com/gsg/amazon-web-services-cloud-insight-get-started.htm) to do so for the AWS account and region where you installed the CFT.
1. Verify successful deployment by TBD. **TODO: Complete these steps when the UX definition is clearer.**

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
1.  Other issues, TBD.


# Known Issues/ Open Questions

- TBD.

# Useful Links

- [Alert Logic AIMs service API](https://console.cloudinsight.alertlogic.com/api/aims/)
- [How to monitor AWS Lambda functions](http://docs.aws.amazon.com/lambda/latest/dg/monitoring-functions.html)
- [AWS GuardDuty Development Guide](http://docs.aws.amazon.com/guardduty/latest/dg/welcome.html)

