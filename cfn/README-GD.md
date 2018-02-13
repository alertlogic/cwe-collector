# guardduty.template

Alert Logic Amazon Web Services (AWS) CloudWatch Events (CWE) Collector CloudFormation template (CFT).

# Overview

This folder contains the AWS CWE JavaScript lambda function and the AWS CloudFormation template that deploys the GuardDuty events collector to AWS. The GuardDuty collector collects and forwards CloudWatch events to the Cloud Insight Essentials backend for display as threats on the Incidents page.

Amazon GuardDuty is a continuous security monitoring service that requires no customer-managed hardware or software. GuardDuty analyzes and processes VPC Flow Logs and AWS CloudTrail event logs. GuardDuty uses security logic and AWS usage statistics techniques to identify unexpected and potentially unauthorized and malicious activity, like escalations of privileges, uses of exposed credentials, or communication with malicious IPs, URLs, or domains.

# Before you begin

To perform this procedure you must have administrative permissions in your AWS and Alert Logic Cloud Insight Essentials accounts. You must also download the Alert Logic custom CFT to your local machine from [the Alert Logic public github repository](https://github.com/alertlogic/cwe-collector/blob/master/cfn/guardduty.template).

If you use the Windows system, this procedure requires PowerShell 3.0 or later. If you have an earlier version of PowerShell, you can [upgrade it](https://docs.microsoft.com/en-us/powershell/scripting/setup/installing-windows-powershell#upgrading-existing-windows-powershell) to version 3.0 or later.

# Installation

To install the GuardDuty events collector:

1. **[Enable CloudWatch event collection](#enable-cloudwatch-event-collection)** - In your AWS account, enable Amazon GuardDuty CloudWatch event collection.
1. **[Create an Alert Logic access key](#create-an-alert-logic-access-key)** - Create an Alert Logic access key that allows the collector to connect to the Alert Logic Cloud Insight back end.
1. **[Deploy the CloudFormation template](#deploy-the-cloudformation-template)** - Deploy a custom AWS CloudFormation template to your AWS account to create lambda functions.
1. **[Verify deployment](#verify-deployment)** - Use the Cloud Insight console to verify a successful installation.

## Enable CloudWatch event collection

The Alert Logic CWE collector for GuardDuty collects findings from Amazon CloudWatch events.

To enable Amazon GuardDuty events, see [Setting Up Amazon GuardDuty](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_settingup.html).

## Create an Alert Logic access key

### Verify permissions

Log into [Cloud Insight Essentials](https://console.cloudinsight.alertlogic.com/#/login) to verify administrator permissions:

1. In the top right corner, click the user name tile > Users.
1. In the list of users, select your user name. 
   
   **Note:** If your name does not appear first in the list, you can use the search bar to easily find your AIMS entry.

1. In the **Edit User** panel, verify the user role is **Administrator**.

### Key creation

You can create a key through either the Unix (MacOS, Linux) or Windows operating system. 

#### To create a key through the Unix (MacOS, Linux) command line:

**Note:** This procedure assumes use of [curl](https://curl.haxx.se/) and [jq](https://stedolan.github.io/jq/).

1. From the bash command line, type the following commands, where `<email address>` is the user name you use to log into Cloud Insight Essentials. 

```
export AL_USERNAME='<email address>'
auth=$(curl -X POST -s -u $AL_USERNAME https://api.global-services.global.alertlogic.com/aims/v1/authenticate); export AL_ACCOUNT_ID=$(echo $auth | jq -r '.authentication.account.id'); export AL_USER_ID=$(echo $auth | jq -r '.authentication.user.id'); export AL_TOKEN=$(echo $auth | jq -r '.authentication.token'); if [ -z $AL_TOKEN ]; then echo "Authentication failure"; else roles=$(curl -s -X GET -H "x-aims-auth-token: $AL_TOKEN" https://api.global-services.global.alertlogic.com/aims/v1/$AL_ACCOUNT_ID/users/$AL_USER_ID/roles | jq -r '.roles[].name'); if [ "$roles" != "Administrator" ]; then echo "The $AL_USERNAME doesn’t have Administrator role. Assigned role is '$roles'"; else curl -s -X POST -H "x-aims-auth-token: $AL_TOKEN" https://api.global-services.global.alertlogic.com/aims/v1/$AL_ACCOUNT_ID/users/$AL_USER_ID/access_keys | jq .; fi; fi; unset AL_USERNAME;
```

2. Enter your password when prompted.

An example of a successful response is:

```
{
  "access_key_id": "712c0b413eef41f6",
  "secret_key": "1234567890b3eea8880d292fb31aa96902242a076d3d0e320cc036eb51bf25ad"
}
```

Make a note of the `access_key_id` and `secret_key` values, which you need to deploy the CloudFormation template to your AWS account. 

#### To create a key through Windows PowerShell:

1. In the PowerShell console, please type the following commands. 

```
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; $creds = Get-Credential -Message "Please enter your Alert Logic Cloud Insight email address and password"; $unsecureCreds = $creds.GetNetworkCredential(); $base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $unsecureCreds.UserName,$unsecureCreds.Password))); Remove-Variable unsecureCreds; $AUTH = Invoke-RestMethod -Method Post -Headers @{"Authorization"=("Basic {0}" -f $base64AuthInfo)} -Uri https://api.global-services.global.alertlogic.com/aims/v1/authenticate ; Remove-Variable base64AuthInfo; $AL_ACCOUNT_ID = $AUTH.authentication.account.id; $AL_USER_ID = $AUTH.authentication.user.id; $AL_TOKEN = $AUTH.authentication.token; if (!$AL_TOKEN) { Write-Host "Authentication failure"} else { $ROLES_RESP = Invoke-RestMethod -Method Get -Headers @{"x-aims-auth-token"=$AL_TOKEN} -Uri https://api.global-services.global.alertlogic.com/aims/v1/$AL_ACCOUNT_ID/users/$AL_USER_ID/roles ; $ROLES = $ROLES_RESP.roles.name; if ($ROLES -ne "Administrator" ) { Write-Host "Your user doesn’t have Administrator role. Assigned role is '$ROLES'" } else { $ACCESS_KEY = Invoke-RestMethod -Method Post -Headers @{"x-aims-auth-token"=$AL_TOKEN} -Uri https://api.global-services.global.alertlogic.com/aims/v1/$AL_ACCOUNT_ID/users/$AL_USER_ID/access_keys ; Write-Host $ACCESS_KEY } }
```

2. When prompted, enter your Alert Logic Cloud Insight user name and password.

An example of a successful response is:

```
@{access_key_id=712c0b413eef41f6; secret_key=1234567890b3eea8880d292fb31aa96902242a076d3d0e320cc036eb51bf25ad}
```

Make a note of the `access_key_id` and `secret_key` values, which you need to deploy the CloudFormation template to your AWS account.

## Deploy the CloudFormation template 

The Alert Logic CWE collector deploys to a single AWS region. To collect from 
multiple AWS regions, you must either install the collector in each target region or 
set up GuardDuty collection across regions. For more information, see: [Setting up GuardDuty across
regions and accounts](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_accounts.html).

### Use the Amazon console to deploy

**Note:** This procedure assumes setup in the AWS us-east-1 region through the Cloud Insight Essentials [US console](https://console.cloudinsight.alertlogic.com/#/login). If your setup is in an AWS European region, like eu-east-1, use the [UK console](https://console.cloudinsight.alertlogic.co.uk/#/login).

1. Log in to the [AWS Management Console](https://aws.amazon.com/console/) with an AWS account that has AWS administrator privileges. 
1. Select the region in which you want to deploy the CFT.
1. Click **Services** > **CloudFormation** > **Create Stack**.
1. In the **Choose a template** section, select **Specify an Amazon S3 template URL**, and then enter the following URL"
`https://s3.amazonaws.com/alertlogic-collectors-us-east-1/cfn/guardduty.template`
1. Click **Next**.
1. In the **Specify Details** window, provide the following required parameters:
   - `Stack name` - Any name you used to create an AWS stack
   - `AccessKeyId` - `access_key_id` returned from AIMs [above](#alert-logic-access-key-creation)
   - `AlApiEndpoint` - usually `api.global-services.global.alertlogic.com` 
   - `AlDataResidency` - usually `default`
   - `SecretKey` - `secret_key` returned from AIMs [above](#alert-logic-access-key-creation)
1. Click **Next**. 
1. On the **Options** panel, click **Next**.
1. In the **Review** panel, perform a predeployment check. 
1. Select **"I acknowledge that AWS CloudFormation might create IAM resources"**, then click **Create**.
1. On the CloudFormation, **Stacks** panel, filter results based on the stack name you created, and then 
select your stack.

If the deployment was successful, the status appears as: CREATE_COMPLETE. If the deployment was not successful, 
see [Troubleshooting Installation Issues](#troubleshooting-installation-issues) below.

### Use a Command Line to deploy

Follow these steps to use the [AWS CLI](https://aws.amazon.com/cli/) to deploy the Alert Logic CFT.

1. In the command line, type the following command, where the required parameters are:
    - `stack-name` - Any name you have used to create an AWS stack
    - `AccessKeyId` - `access_key_id` returned from AIMs [above](#alert-logic-access-key-creation)
    - `SecretKey` - `secret_key` returned from AIMs [above](#alert-logic-access-key-creation)

    ```
    aws cloudformation create-stack --template-url https://s3.amazonaws.com/alertlogic-collectors-us-east-1/cfn/guardduty.template --stack-name <alertlogic-collector-stack-name> --capabilities CAPABILITY_IAM --parameters ParameterKey=AccessKeyId,ParameterValue=<access_key_id> ParameterKey=SecretKey,ParameterValue=<secret_key>
    ```
1. Wait for the stack creation to complete.

## Deployment verification
You can view a Cloud Insight Essentials or Cloud Insight deployment for the AWS account and region where you installed the CFT. 

1. Log into the Alert Logic Cloud Insight Essentials console with an account that has administrator permissions.    
1. On the Cloud Insight Essentials menu bar, click **Incidents** > **Incident list**. 

Compare the Cloud Insight Essentials Incident List to the Amazon GuardDuty console to verity the Incident List includes recent findings that appear in the GuardDuty console.

## Troubleshooting installation issues

If installation through the [AWS Management Console](https://aws.amazon.com/console/) is not successful, you can access 
`CloudFormation` > `Stacks`->`Stack Detail` (by selecting your stack name from the list) to see detailed
error messages in the AWS [CloudWatch Log Stream](https://console.aws.amazon.com/cloudwatch/home). Click `Logs`, 
and then filter by `/aws/lambda/my-new-stack` (where `my-new-stack` is the name you gave your stack). 

If installation through the AWS CLI is not successful, issue the following command for more information:

```
aws cloudformation describe-stack-events --stack-name my-new-stack
```

1. If `GetEndpointsLambdaFunction` fails, an issue could exist with the `access_key_id` or the `secret_key`
 you provided. Be sure the `access_key_id` is correct, your `secret_key` is valid, and your user account has administrative permissions for the Alert Logic Cloud Insight account.
1. Other issues, TBD.


# Known Issues/ Open Questions

- TBD.

# Useful Links

- [Alert Logic AIMs service API](https://console.cloudinsight.alertlogic.com/api/aims/)
- [How to monitor AWS Lambda functions](http://docs.aws.amazon.com/lambda/latest/dg/monitoring-functions.html)
- [AWS GuardDuty API Reference](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_api_ref.html)

