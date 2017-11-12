# guardduty.template

Alert Logic Amazon Web Services (AWS) CloudWatch Events (CWE) Collector CloudFormation templates.


# Overview

This folder contains CloudFormation templates (CFT) for deploying
a CWE collector in AWS which will collect and forwards GuardDuty findings to the Alert Logic CloudInsight 
backend services.

# Installation

Installation requires the following steps:

1. Enable GuardDuty CloudWatch event collection in your AWS account.
1. Create an Access Key that will allow the collector to connect to the Alert Logic Cloud Insight backend.
1. Deploy a custom AWS CloudFormation template to your AWS account to create lambda functions
for collecting and managing GuardDuty event data.
1. Verify that installation was successful using Alert Logic CloudInsight UI.

## Set up Amazon GuardDuty CloudWatch event collection in your AWS account

Amazon GuardDuty is a continuous security monitoring service that requires no customer-managed hardware or software. 
GuardDuty analyzes and processes VPC Flow Logs and AWS CloudTrail event logs. GuardDuty uses security logic and 
AWS usage statistics techniques to identify unexpected and potentially unauthorized and malicious activity. 
This can include issues like escalations of privileges, uses of exposed credentials, or communication with 
malicious IPs, URLs, or domains.
GuardDuty informs you of the status of your AWS infrastructure and applications by producing security `findings`.
The Alert Logic CWE collector for GuardDuty collects `findings` from Amazon CloudWatch events.
  
In order to capture GuardDuty events, follow the Amazon documentation here: 
[Setting Up Amazon GuardDuty](http://docs.aws.amazon.com/AWSGuardDuty/latest/UserGuide/settingup.html).

**Temp Dev and Test Note: The current template is stored here 
https://s3.amazonaws.com/rcs-test-us-east-1/templates/guardduty.template Access to this template is granted to 
Route105 (948063967832), Collect (352283894008) and Ozone (481746159046) AWS accounts only.**

## Create an Alert Logic Access Key

Make sure you have an Alert Logic CloudInsight (CI) account and you can log into the CI user inteface as
an administrator [here](https://console.cloudinsight.alertlogic.com/#/login).
 
**Note:** The following assumes a Linux-based local machine using [curl](https://curl.haxx.se/) and 
[jq](https://stedolan.github.io/jq/).

From the Bash command line on your local machine, run the following commands, where `<username>` is your 
Alert Logic user and `<password>` is your Alert Logic password:

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

**Note:** if the output is blank please double-check the Alert Logic user permission, you should 
have administrator access. More details about AIMS APIs can be found 
[here](https://console.cloudinsight.alertlogic.com/api/aims/).

Make a note of the `access_key_id` and `secret_key` values for use in the deployment steps below.

**Note:** Only five access keys can be created per user.  If you get a "limit exceeded" response you will need to
delete some keys in order to create new ones.  Use the following command to list access keys:

```
curl -s -X GET -H "x-aims-auth-token: $AL_TOKEN" https://api.global-services.global.alertlogic.com/aims/v1/$AL_ACCOUNT_ID/users/$AL_USER_ID/access_keys | jq
```

Then use the selected access_key_id in the following curl command to delete it:

```
curl -X DELETE -H "x-aims-auth-token: $AL_TOKEN" https://api.global-services.global.alertlogic.com/aims/v1/$AL_ACCOUNT_ID/users/$AL_USER_ID/access_keys/<ACCESS_KEY_ID_HERE>
```

## Deploy a custom AWS CloudFormation template to your AWS account

**Note:** The Alert Logic CWE collector is deployed by AWS region.  To collect from 
multiple AWS regions, you either need to install the collector in each target region or 
you need to set up GuardDuty collection accross regions (See: [Setting up GuardDuty across
regions and accounts](TBD)).  These instructions assume you are setting up in the AWS `us-east-1` region 
using the Alert Logic CloudInsight [US console](https://console.cloudinsight.alertlogic.com/#/login).  If
you are using a European region (e.g. 'eu-east-1`), you would use the 
[UK console](https://console.cloudinsight.alertlogic.co.uk/#/login) 

1. Log in to the [AWS Management Console](https://aws.amazon.com/console/) for your AWS account using 
a user with AWS administrator privileges. 
1. Select the region is which you wish to deploy the CFT.
1. Click `Services`->`CloudFormation`->`Design Template`.
1. Click `Open` from the drop-down selector in the top left corner of the display.
1. In the `Open a template` dialog, select `Amazon S3 bucket` and in the `Template URL` field, enter the appropriate 
Alert Logic S3 bucket URL as follows: `https://s3.amazonaws.com/alert-logic-cwe-<region>/templates/guardduty.template` 
where `<region>` matches your AWS region. **TODO: This must be altered before GA**
1. Click the `Create stack` icon on the menu bar at the top of the template designer.
1. On `Select Template` click `Next`.
1. Fill in the required parameters on the `Specify Details` panel, and click `Next`.  I.e.:
   - `Stack name` - Any name you  have used before for creating an AWS stack
   - `AccessKeyId` - `access_key_id` returned from AIMs [above](#create_an_alert_logic_access_key)
   - `AlApiEndpoint` - usually `api.global-services.global.alertlogic.com` 
   - `AlDataResidency` - usually `default`
   - `S3Bucket` - Use the dropdown to select the bucket that matches your region **TODO: field will be removed before GA.**
   - `S3Zipfile` - **TODO: field will be removed before GA**
   - `SecretKey` - `secret_key` returned from AIMs [above](#create_an_alert_logic_access_key)  
1. On the Options panel click Next.
1. Do a final pre-deployment check on the Review panel and, assuming you agree, check the I acknowledge that 
AWS CloudFormation might create IAM resources. checkbox and click Create.
1. You will be taken to the CloudFormation, Stacks panel. Filter based on the stack name you created and 
select your stack by name.
1. If deployment completes successfully you will see Status: CREATE_COMPLETE. If deployment fails then 
see [Troubleshooting Installation Issues](#Troubleshooting Installation Issues) below.    

#### Deploy via Command Line

If you chose to deploy the Alert Logic custom template using the [AWS CLI](https://aws.amazon.com/cli/), follow
these steps.

1. Download the Alert Logic custom CFT to your local machine from [here](). 
1. Issue the following command from the command line, where the required parameters are:
    - `stack-name` - Any name you  have used before for creating an AWS stack
    - `AccessKeyId` - `access_key_id` returned from AIMs [above](#create_an_alert_logic_access_key)
    - `SecretKey` - `secret_key` returned from AIMs [above](#create_an_alert_logic_access_key)   

    ```
    aws cloudformation deploy --template /path_to_template/guardduty.template --stack-name my-new-stack --capabilities CAPABILITY_IAM --parameter-overrides AccessKeyId=<access_key_id> SecretKey=<secret_key>
    ```
1. Wait for the stack creation to complete.

## Verify the Installation

1. Log into the Alert Logic CloudInsight UI using a user with administrator privileges: 
    - Using the [US console](https://console.cloudinsight.alertlogic.com/#/login) for US and associated geographical regions.
    - Using the [UK console](https://console.cloudinsight.alertlogic.co.uk/#/login) for Europe and other regions.
1. If you have not already created one, follow the instructions for creating a new CloudInsight security environment  
[here](https://docs.alertlogic.com/gsg/amazon-web-services-cloud-insight-get-started.htm) for the AWS account and
region where you installed the CFT.
1. You can verify the deployment was successful by TBD. **TODO: Complete these steps when the UX definition is clearer.**

## Troubleshooting Installation Issues

If installation fails while using the [AWS Management Console](https://aws.amazon.com/console/), go to 
`CloudFormatin`->`Stacks`->`Stack Detail` (by selecting your stack name from the list).  You can see detailed
error messages in the AWS [CloudWatch Log Stream](https://console.aws.amazon.com/cloudwatch/home).  Click on `Logs`
and filter by `/aws/lambda/my-new-stack` (where `my-new-stack` is the name you gave your stack). 

If installation fails while using the AWS CLI, issue the following command for more information:

```
aws cloudformation describe-stack-events --stack-name my-new-stack
```

1. If the `GetEndpointsLambdaFunction` fails, there is probably and issue with the AIMs access key id or secret key
 you provided.  Mak sure the key id is correct, your secret key is valid, and your user has admin authority for the 
 Alert Logic CloudInsight account.
1.  Other issues, TBD.


# Known Issues/ Open Questions

- TBD.

# Useful Links

- [Alert Logic AIMs service API](https://console.cloudinsight.alertlogic.com/api/aims/)
- [How to monitor AWS Lambda functions](http://docs.aws.amazon.com/lambda/latest/dg/monitoring-functions.html)
- [AWS GuardDuty Development Guide](http://docs.aws.amazon.com/guardduty/latest/dg/welcome.html)

