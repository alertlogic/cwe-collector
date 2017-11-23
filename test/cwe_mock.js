process.env.AWS_REGION = 'us-east-1';

const AIMS_TEST_CREDS = {
    access_key_id: 'test-access-key-id',
    secret_key: 'test-secret-key'
};

const CHECKIN_TEST_FUNCTION_NAME = 'test-CollectLambdaFunction-1JNNKQIPOTEST';
const CHECKIN_TEST_URL = '/aws/cwe/checkin/353333894008/us-east-1/' + encodeURIComponent(CHECKIN_TEST_FUNCTION_NAME);
const FUNCTION_ARN = 'arn:aws:lambda:us-east-1:352283894008:function:test-guardduty-01-CollectLambdaFunction-2CWNLPPW5XO8';
const STACK_NAME = 'test';
const STACK_ID = 'arn:aws:cloudformation:us-east-1:353333894008:stack/test/87b3dc90-bd7e-11e7-9e43-503abe701cfd';
const S3_BUCKET = 'rcs-test-us-east-1';
const ACCESS_KEY_ID = '854gdsn8gstgd34bg';
const CWE_RULE_NAME = 'test-CloudWatchEventsRule-EHIZIHJYHTOD';
const CWE_RULE_ARN = 'arn:aws:events:us-east-1:352283894008:rule/test-CloudWatchEventsRule-EHIZIHJYHTOD';
const KINESIS_ARN = 'arn:aws:kinesis:us-east-1:353333894008:stream/test-KinesisStream-11Z7IDV7G2XDV';

const CHECKIN_TEST_EVENT = {
    'RequestType': 'ScheduledEvent',
    'Type': 'Checkin',
    'AwsAccountId': '353333894008',
    'StackName' : STACK_NAME,
    'CloudWatchEventsRule' : CWE_RULE_NAME,
    'KinesisArn' : KINESIS_ARN,
    'CweRulePattern' : '{\"source\":[\"aws.guardduty\"]}'
};

const DEFAULT_LAMBDA_CONTEXT = {
    invokedFunctionArn : FUNCTION_ARN,
    functionName : CHECKIN_TEST_FUNCTION_NAME
};

const REGISTRATION_TEST_FUNCTION_NAME = 'test-CollectLambdaFunction-1JNNKQIPOTEST';
const REGISTRATION_TEST_URL = '/aws/cwe/353333894008/us-east-1/' + encodeURIComponent(REGISTRATION_TEST_FUNCTION_NAME);
const REGISTRATION_STACK_NAME = 'test-stack-01';
const REGISTRATION_COLLECT_RULE = 'aws.guardduty';

const REGISTRATION_TEST_EVENT = {
    'RequestType': 'Create',
    'ServiceToken': FUNCTION_ARN,
    'ResponseURL': 'https://cloudformation-custom-resource-response-useast1.s3.amazonaws.com/resp',
    'StackId': 'arn:aws:cloudformation:us-east-1:352283894008:stack/test-guardduty-01/92605900',
    'RequestId': '155fe44d-af80-4c42-bf30-6a78aa244aad',
    'LogicalResourceId': 'RegistrationResource',
    'ResourceType': 'Custom::RegistrationResource',
    'ResourceProperties':
    {
        'ServiceToken': FUNCTION_ARN,
        'StackName': REGISTRATION_STACK_NAME,
        'AwsAccountId': '353333894008',
        'CollectRule': REGISTRATION_COLLECT_RULE
    }
};

const GD_ONLY_KINESIS_TEST_EVENT = {
  'Records': [
    {
      'kinesis': {
        'kinesisSchemaVersion': '1.0',
        'partitionKey': '52badd7d-edd6-ac34-b543-393e309cb977_dee8b923-1314-47b0-b820-68030eaf93e3',
        'sequenceNumber': '49577651119794799532435452775356657619317529872846290946',
        'data': 'eyJ2ZXJzaW9uIjoiMCIsImlkIjoiNTJiYWRkN2QtZWRkNi1hYzM0LWI1NDMtMzkzZTMwOWNiOTc3IiwiZGV0YWlsLXR5cGUiOiJHdWFyZER1dHkgRmluZGluZyIsInNvdXJjZSI6ImF3cy5ndWFyZGR1dHkiLCJhY2NvdW50IjoiMzUyMjgzODk0MDA4IiwidGltZSI6IjE5NzAtMDEtMDFUMDA6MDA6MDBaIiwicmVnaW9uIjoidXMtZWFzdC0xIiwicmVzb3VyY2VzIjpbXSwiZGV0YWlsIjp7InNjaGVtYVZlcnNpb24iOiIyLjAiLCJhY2NvdW50SWQiOiIzNTIyODM4OTQwMDgiLCJyZWdpb24iOiJ1cy1lYXN0LTEiLCJwYXJ0aXRpb24iOiJhd3MiLCJpZCI6IjNhYWY4M2RkZDljMzE0MDUyNDZmYTFjNjJlM2UwMzRkIiwiYXJuIjoiYXJuOmF3czpndWFyZGR1dHk6dXMtZWFzdC0xOjM1MjI4Mzg5NDAwODpkZXRlY3Rvci8wNGFmNTFkMTAxYzhjNWJjYWUzYTkyNTYwYzcwMTBjZS9maW5kaW5nLzNhYWY4M2RkZDljMzE0MDUyNDZmYTFjNjJlM2UwMzRkIiwidHlwZSI6IlVuYXV0aG9yaXplZEFjY2VzczpFQzIvTWFsaWNpb3VzSVBDYWxsZXIuQ3VzdG9tIiwicmVzb3VyY2UiOnsicmVzb3VyY2VUeXBlIjoiSW5zdGFuY2UiLCJpbnN0YW5jZURldGFpbHMiOnsiaW1hZ2VJZCI6ImFtaS04YTFhZTJlNyIsImluc3RhbmNlSWQiOiJpLTA5NjFlMGIzYWY4YjNlYzM5IiwiaW5zdGFuY2VUeXBlIjoiYzQubGFyZ2UiLCJsYXVuY2hUaW1lIjoxLjUwNzY1NjA2M0UxMiwicHJvZHVjdENvZGVzIjpbXSwibmV0d29ya0ludGVyZmFjZXMiOlt7ImlwdjZBZGRyZXNzZXMiOltdLCJwcml2YXRlSXBBZGRyZXNzIjoiMTAuNjYuNjYuMzkiLCJwcml2YXRlSXBBZGRyZXNzZXMiOlt7InByaXZhdGVJcEFkZHJlc3MiOiIxMC42Ni42Ni4zOSJ9XSwic3VibmV0SWQiOiJzdWJuZXQtYzM5NmI4Y2YiLCJ2cGNJZCI6InZwYy1iNWE5NmZjZCIsInNlY3VyaXR5R3JvdXBzIjpbeyJncm91cE5hbWUiOiJBbGVydCBMb2dpYyBTZWN1cml0eSBHcm91cCAxMzQyMzI4MjhfMjhENTlCMjctQjU0Ni00QTQ4LUFBMEEtODhGRjEzM0M4MTI2IiwiZ3JvdXBJZCI6InNnLTIxNzE4ZjUzIn1dLCJwdWJsaWNEbnNOYW1lIjoiIiwicHVibGljSXAiOiIzNC4yMDQuMTcyLjE2NiJ9XSwidGFncyI6W3sia2V5IjoiQWxlcnRMb2dpYy1FbnZpcm9ubWVudElEIiwidmFsdWUiOiIyOEQ1OUIyNy1CNTQ2LTRBNDgtQUEwQS04OEZGMTMzQzgxMjYifSx7ImtleSI6Ik5hbWUiLCJ2YWx1ZSI6IkFsZXJ0TG9naWMgU2VjdXJpdHkgQXBwbGlhbmNlIn0seyJrZXkiOiJBbGVydExvZ2ljIiwidmFsdWUiOiJTZWN1cml0eSJ9LHsia2V5IjoiYXdzOmF1dG9zY2FsaW5nOmdyb3VwTmFtZSIsInZhbHVlIjoiQWxlcnQgTG9naWMgU2VjdXJpdHkgQXV0byBTY2FsaW5nIEdyb3VwXzEzNDIzMjgyOF8yOEQ1OUIyNy1CNTQ2LTRBNDgtQUEwQS04OEZGMTMzQzgxMjZfdnBjLWI1YTk2ZmNkIn0seyJrZXkiOiJBbGVydExvZ2ljLUFjY291bnRJRCIsInZhbHVlIjoiMTM0MjMyODI4In1dLCJpbnN0YW5jZVN0YXRlIjoicnVubmluZyIsImF2YWlsYWJpbGl0eVpvbmUiOiJ1cy1lYXN0LTFmIn19LCJzZXJ2aWNlIjp7InNlcnZpY2VOYW1lIjoiZ3VhcmRkdXR5IiwiZGV0ZWN0b3JJZCI6IjA0YWY1MWQxMDFjOGM1YmNhZTNhOTI1NjBjNzAxMGNlIiwiYWN0aW9uIjp7ImFjdGlvblR5cGUiOiJORVRXT1JLX0NPTk5FQ1RJT04iLCJuZXR3b3JrQ29ubmVjdGlvbkFjdGlvbiI6eyJjb25uZWN0aW9uRGlyZWN0aW9uIjoiVU5LTk9XTiIsInJlbW90ZUlwRGV0YWlscyI6eyJpcEFkZHJlc3NWNCI6Ijc3LjcyLjgyLjgwIiwib3JnYW5pemF0aW9uIjp7ImFzbiI6NDMzNTAuMCwiYXNuT3JnIjoiTkZvcmNlIEVudGVydGFpbm1lbnQgQi5WLiIsImlzcCI6Ik5ldFVQIEx0ZC4iLCJvcmciOiJOZXRVUCBMdGQuIn0sImNvdW50cnkiOnsiY291bnRyeUNvZGUiOiJHQiIsImNvdW50cnlOYW1lIjoiVW5pdGVkIEtpbmdkb20ifSwiY2l0eSI6eyJjaXR5TmFtZSI6IlN0b2tlLW9uLVRyZW50In0sImdlb0xvY2F0aW9uIjp7ImxhdCI6NTMuMCwibG9uIjotMi4xODMzfX0sInJlbW90ZVBvcnREZXRhaWxzIjp7InBvcnQiOjQ0NzA1LjAsInBvcnROYW1lIjoiVW5rbm93biJ9LCJsb2NhbFBvcnREZXRhaWxzIjp7InBvcnQiOjQ0ODcuMCwicG9ydE5hbWUiOiJVbmtub3duIn0sInByb3RvY29sIjoiVENQIiwiYmxvY2tlZCI6dHJ1ZX19LCJyZXNvdXJjZVJvbGUiOiJUQVJHRVQiLCJhZGRpdGlvbmFsSW5mbyI6eyJ0aHJlYXROYW1lIjoiQ3VzdG9tZXIgVGhyZWF0IEludGVsIiwidGhyZWF0TGlzdE5hbWUiOiJ0ZG9zb3VkaWwtc2V6bmFtLWN6In0sImV2ZW50Rmlyc3RTZWVuIjoiMjAxNy0xMC0xMFQxOToxODoyMFoiLCJldmVudExhc3RTZWVuIjoiMjAxNy0xMC0xMVQyMzo0OTowOVoiLCJhcmNoaXZlZCI6ZmFsc2UsImNvdW50IjoyMC4wfSwic2V2ZXJpdHkiOjUuMCwiY3JlYXRlZEF0IjoiMjAxNy0xMC0xMFQxOToyMTowMi41OThaIiwidXBkYXRlZEF0IjoiMjAxNy0xMC0xMVQyMzo1MjoxNi45MzVaIiwidGl0bGUiOiJFQzIgSW5zdGFuY2UgaS0wOTYxZTBiM2FmOGIzZWMzOSBjb21tdW5pY2F0aW5nIG91dGJvdW5kIHdpdGggZGlzYWxsb3dlZCBJUCBhZGRyZXNzLiIsImRlc2NyaXB0aW9uIjoiRUMyIEluc3RhbmNlIGktMDk2MWUwYjNhZjhiM2VjMzkgaGFzIGJlZW4gZm91bmQgY29tbXVuaWNhdGluZyBvdXRib3VuZCB3aXRoIGRpc2FsbG93ZWQgSVAgYWRkcmVzcyA3Ny43Mi44Mi44MCBwcmVzZW50IGluIHRoZSBsaXN0IHRkb3NvdWRpbC1zZXpuYW0tY3ouIn19',
        'approximateArrivalTimestamp': 1507769764.013
      },
      'eventSource': 'aws:kinesis',
      'eventVersion': '1.0',
      'eventID': 'shardId-000000000000:49577651119794799532435452775356657619317529872846290946',
      'eventName': 'aws:kinesis:record',
      'invokeIdentityArn': 'arn:aws:iam::352283894008:role/kkuzmin-vpc-flow-role',
      'awsRegion': 'us-east-1',
      'eventSourceARN': 'arn:aws:kinesis:us-east-1:352283894008:stream/kkuzmin-gd-test'
    }
  ]
};

const GD_MALFORMED_KINESIS_TEST_EVENT = {
  'Records': [
    {
      'kinesis': {
        'kinesisSchemaVersion': '1.0',
        'partitionKey': '52badd7d-edd6-ac34-b543-393e309cb977_dee8b923-1314-47b0-b820-68030eaf93e3',
        'sequenceNumber': '49577651119794799532435452775356657619317529872846290946',
        'data': 'yJ2ZXJzaW9uIjoiMCIsImlkIjoiNTJiYWRkN2QtZWRkNi1hYzM0LWI1NDMtMzkzZTMwOWNiOTc3IiwiZGV0YWlsLXR5cGUiOiJHdWFyZER1dHkgRmluZGluZyIsInNvdXJjZSI6ImF3cy5ndWFyZGR1dHkiLCJhY2NvdW50IjoiMzUyMjgzODk0MDA4IiwidGltZSI6IjE5NzAtMDEtMDFUMDA6MDA6MDBaIiwicmVnaW9uIjoidXMtZWFzdC0xIiwicmVzb3VyY2VzIjpbXSwiZGV0YWlsIjp7InNjaGVtYVZlcnNpb24iOiIyLjAiLCJhY2NvdW50SWQiOiIzNTIyODM4OTQwMDgiLCJyZWdpb24iOiJ1cy1lYXN0LTEiLCJwYXJ0aXRpb24iOiJhd3MiLCJpZCI6IjNhYWY4M2RkZDljMzE0MDUyNDZmYTFjNjJlM2UwMzRkIiwiYXJuIjoiYXJuOmF3czpndWFyZGR1dHk6dXMtZWFzdC0xOjM1MjI4Mzg5NDAwODpkZXRlY3Rvci8wNGFmNTFkMTAxYzhjNWJjYWUzYTkyNTYwYzcwMTBjZS9maW5kaW5nLzNhYWY4M2RkZDljMzE0MDUyNDZmYTFjNjJlM2UwMzRkIiwidHlwZSI6IlVuYXV0aG9yaXplZEFjY2VzczpFQzIvTWFsaWNpb3VzSVBDYWxsZXIuQ3VzdG9tIiwicmVzb3VyY2UiOnsicmVzb3VyY2VUeXBlIjoiSW5zdGFuY2UiLCJpbnN0YW5jZURldGFpbHMiOnsiaW1hZ2VJZCI6ImFtaS04YTFhZTJlNyIsImluc3RhbmNlSWQiOiJpLTA5NjFlMGIzYWY4YjNlYzM5IiwiaW5zdGFuY2VUeXBlIjoiYzQubGFyZ2UiLCJsYXVuY2hUaW1lIjoxLjUwNzY1NjA2M0UxMiwicHJvZHVjdENvZGVzIjpbXSwibmV0d29ya0ludGVyZmFjZXMiOlt7ImlwdjZBZGRyZXNzZXMiOltdLCJwcml2YXRlSXBBZGRyZXNzIjoiMTAuNjYuNjYuMzkiLCJwcml2YXRlSXBBZGRyZXNzZXMiOlt7InByaXZhdGVJcEFkZHJlc3MiOiIxMC42Ni42Ni4zOSJ9XSwic3VibmV0SWQiOiJzdWJuZXQtYzM5NmI4Y2YiLCJ2cGNJZCI6InZwYy1iNWE5NmZjZCIsInNlY3VyaXR5R3JvdXBzIjpbeyJncm91cE5hbWUiOiJBbGVydCBMb2dpYyBTZWN1cml0eSBHcm91cCAxMzQyMzI4MjhfMjhENTlCMjctQjU0Ni00QTQ4LUFBMEEtODhGRjEzM0M4MTI2IiwiZ3JvdXBJZCI6InNnLTIxNzE4ZjUzIn1dLCJwdWJsaWNEbnNOYW1lIjoiIiwicHVibGljSXAiOiIzNC4yMDQuMTcyLjE2NiJ9XSwidGFncyI6W3sia2V5IjoiQWxlcnRMb2dpYy1FbnZpcm9ubWVudElEIiwidmFsdWUiOiIyOEQ1OUIyNy1CNTQ2LTRBNDgtQUEwQS04OEZGMTMzQzgxMjYifSx7ImtleSI6Ik5hbWUiLCJ2YWx1ZSI6IkFsZXJ0TG9naWMgU2VjdXJpdHkgQXBwbGlhbmNlIn0seyJrZXkiOiJBbGVydExvZ2ljIiwidmFsdWUiOiJTZWN1cml0eSJ9LHsia2V5IjoiYXdzOmF1dG9zY2FsaW5nOmdyb3VwTmFtZSIsInZhbHVlIjoiQWxlcnQgTG9naWMgU2VjdXJpdHkgQXV0byBTY2FsaW5nIEdyb3VwXzEzNDIzMjgyOF8yOEQ1OUIyNy1CNTQ2LTRBNDgtQUEwQS04OEZGMTMzQzgxMjZfdnBjLWI1YTk2ZmNkIn0seyJrZXkiOiJBbGVydExvZ2ljLUFjY291bnRJRCIsInZhbHVlIjoiMTM0MjMyODI4In1dLCJpbnN0YW5jZVN0YXRlIjoicnVubmluZyIsImF2YWlsYWJpbGl0eVpvbmUiOiJ1cy1lYXN0LTFmIn19LCJzZXJ2aWNlIjp7InNlcnZpY2VOYW1lIjoiZ3VhcmRkdXR5IiwiZGV0ZWN0b3JJZCI6IjA0YWY1MWQxMDFjOGM1YmNhZTNhOTI1NjBjNzAxMGNlIiwiYWN0aW9uIjp7ImFjdGlvblR5cGUiOiJORVRXT1JLX0NPTk5FQ1RJT04iLCJuZXR3b3JrQ29ubmVjdGlvbkFjdGlvbiI6eyJjb25uZWN0aW9uRGlyZWN0aW9uIjoiVU5LTk9XTiIsInJlbW90ZUlwRGV0YWlscyI6eyJpcEFkZHJlc3NWNCI6Ijc3LjcyLjgyLjgwIiwib3JnYW5pemF0aW9uIjp7ImFzbiI6NDMzNTAuMCwiYXNuT3JnIjoiTkZvcmNlIEVudGVydGFpbm1lbnQgQi5WLiIsImlzcCI6Ik5ldFVQIEx0ZC4iLCJvcmciOiJOZXRVUCBMdGQuIn0sImNvdW50cnkiOnsiY291bnRyeUNvZGUiOiJHQiIsImNvdW50cnlOYW1lIjoiVW5pdGVkIEtpbmdkb20ifSwiY2l0eSI6eyJjaXR5TmFtZSI6IlN0b2tlLW9uLVRyZW50In0sImdlb0xvY2F0aW9uIjp7ImxhdCI6NTMuMCwibG9uIjotMi4xODMzfX0sInJlbW90ZVBvcnREZXRhaWxzIjp7InBvcnQiOjQ0NzA1LjAsInBvcnROYW1lIjoiVW5rbm93biJ9LCJsb2NhbFBvcnREZXRhaWxzIjp7InBvcnQiOjQ0ODcuMCwicG9ydE5hbWUiOiJVbmtub3duIn0sInByb3RvY29sIjoiVENQIiwiYmxvY2tlZCI6dHJ1ZX19LCJyZXNvdXJjZVJvbGUiOiJUQVJHRVQiLCJhZGRpdGlvbmFsSW5mbyI6eyJ0aHJlYXROYW1lIjoiQ3VzdG9tZXIgVGhyZWF0IEludGVsIiwidGhyZWF0TGlzdE5hbWUiOiJ0ZG9zb3VkaWwtc2V6bmFtLWN6In0sImV2ZW50Rmlyc3RTZWVuIjoiMjAxNy0xMC0xMFQxOToxODoyMFoiLCJldmVudExhc3RTZWVuIjoiMjAxNy0xMC0xMVQyMzo0OTowOVoiLCJhcmNoaXZlZCI6ZmFsc2UsImNvdW50IjoyMC4wfSwic2V2ZXJpdHkiOjUuMCwiY3JlYXRlZEF0IjoiMjAxNy0xMC0xMFQxOToyMTowMi41OThaIiwidXBkYXRlZEF0IjoiMjAxNy0xMC0xMVQyMzo1MjoxNi45MzVaIiwidGl0bGUiOiJFQzIgSW5zdGFuY2UgaS0wOTYxZTBiM2FmOGIzZWMzOSBjb21tdW5pY2F0aW5nIG91dGJvdW5kIHdpdGggZGlzYWxsb3dlZCBJUCBhZGRyZXNzLiIsImRlc2NyaXB0aW9uIjoiRUMyIEluc3RhbmNlIGktMDk2MWUwYjNhZjhiM2VjMzkgaGFzIGJlZW4gZm91bmQgY29tbXVuaWNhdGluZyBvdXRib3VuZCB3aXRoIGRpc2FsbG93ZWQgSVAgYWRkcmVzcyA3Ny43Mi44Mi44MCBwcmVzZW50IGluIHRoZSBsaXN0IHRkb3NvdWRpbC1zZXpuYW0tY3ouIn19',
        'approximateArrivalTimestamp': 1507769764.013
      },
      'eventSource': 'aws:kinesis',
      'eventVersion': '1.0',
      'eventID': 'shardId-000000000000:49577651119794799532435452775356657619317529872846290946',
      'eventName': 'aws:kinesis:record',
      'invokeIdentityArn': 'arn:aws:iam::352283894008:role/kkuzmin-vpc-flow-role',
      'awsRegion': 'us-east-1',
      'eventSourceARN': 'arn:aws:kinesis:us-east-1:352283894008:stream/kkuzmin-gd-test'
    }
  ]
};

const GD_OTHER_KINESIS_TEST_EVENT = {
  'Records': [
    {
      'kinesis': {
        'kinesisSchemaVersion': '1.0',
        'partitionKey': '52badd7d-edd6-ac34-b543-393e309cb977_dee8b923-1314-47b0-b820-68030eaf93e3',
        'sequenceNumber': '49577651119794799532435452775356657619317529872846290946',
        'data': 'eyJ2ZXJzaW9uIjoiMCIsImlkIjoiNTJiYWRkN2QtZWRkNi1hYzM0LWI1NDMtMzkzZTMwOWNiOTc3IiwiZGV0YWlsLXR5cGUiOiJHdWFyZER1dHkgRmluZGluZyIsInNvdXJjZSI6ImF3cy5ndWFyZGR1dHkiLCJhY2NvdW50IjoiMzUyMjgzODk0MDA4IiwidGltZSI6IjE5NzAtMDEtMDFUMDA6MDA6MDBaIiwicmVnaW9uIjoidXMtZWFzdC0xIiwicmVzb3VyY2VzIjpbXSwiZGV0YWlsIjp7InNjaGVtYVZlcnNpb24iOiIyLjAiLCJhY2NvdW50SWQiOiIzNTIyODM4OTQwMDgiLCJyZWdpb24iOiJ1cy1lYXN0LTEiLCJwYXJ0aXRpb24iOiJhd3MiLCJpZCI6IjNhYWY4M2RkZDljMzE0MDUyNDZmYTFjNjJlM2UwMzRkIiwiYXJuIjoiYXJuOmF3czpndWFyZGR1dHk6dXMtZWFzdC0xOjM1MjI4Mzg5NDAwODpkZXRlY3Rvci8wNGFmNTFkMTAxYzhjNWJjYWUzYTkyNTYwYzcwMTBjZS9maW5kaW5nLzNhYWY4M2RkZDljMzE0MDUyNDZmYTFjNjJlM2UwMzRkIiwidHlwZSI6IlVuYXV0aG9yaXplZEFjY2VzczpFQzIvTWFsaWNpb3VzSVBDYWxsZXIuQ3VzdG9tIiwicmVzb3VyY2UiOnsicmVzb3VyY2VUeXBlIjoiSW5zdGFuY2UiLCJpbnN0YW5jZURldGFpbHMiOnsiaW1hZ2VJZCI6ImFtaS04YTFhZTJlNyIsImluc3RhbmNlSWQiOiJpLTA5NjFlMGIzYWY4YjNlYzM5IiwiaW5zdGFuY2VUeXBlIjoiYzQubGFyZ2UiLCJsYXVuY2hUaW1lIjoxLjUwNzY1NjA2M0UxMiwicHJvZHVjdENvZGVzIjpbXSwibmV0d29ya0ludGVyZmFjZXMiOlt7ImlwdjZBZGRyZXNzZXMiOltdLCJwcml2YXRlSXBBZGRyZXNzIjoiMTAuNjYuNjYuMzkiLCJwcml2YXRlSXBBZGRyZXNzZXMiOlt7InByaXZhdGVJcEFkZHJlc3MiOiIxMC42Ni42Ni4zOSJ9XSwic3VibmV0SWQiOiJzdWJuZXQtYzM5NmI4Y2YiLCJ2cGNJZCI6InZwYy1iNWE5NmZjZCIsInNlY3VyaXR5R3JvdXBzIjpbeyJncm91cE5hbWUiOiJBbGVydCBMb2dpYyBTZWN1cml0eSBHcm91cCAxMzQyMzI4MjhfMjhENTlCMjctQjU0Ni00QTQ4LUFBMEEtODhGRjEzM0M4MTI2IiwiZ3JvdXBJZCI6InNnLTIxNzE4ZjUzIn1dLCJwdWJsaWNEbnNOYW1lIjoiIiwicHVibGljSXAiOiIzNC4yMDQuMTcyLjE2NiJ9XSwidGFncyI6W3sia2V5IjoiQWxlcnRMb2dpYy1FbnZpcm9ubWVudElEIiwidmFsdWUiOiIyOEQ1OUIyNy1CNTQ2LTRBNDgtQUEwQS04OEZGMTMzQzgxMjYifSx7ImtleSI6Ik5hbWUiLCJ2YWx1ZSI6IkFsZXJ0TG9naWMgU2VjdXJpdHkgQXBwbGlhbmNlIn0seyJrZXkiOiJBbGVydExvZ2ljIiwidmFsdWUiOiJTZWN1cml0eSJ9LHsia2V5IjoiYXdzOmF1dG9zY2FsaW5nOmdyb3VwTmFtZSIsInZhbHVlIjoiQWxlcnQgTG9naWMgU2VjdXJpdHkgQXV0byBTY2FsaW5nIEdyb3VwXzEzNDIzMjgyOF8yOEQ1OUIyNy1CNTQ2LTRBNDgtQUEwQS04OEZGMTMzQzgxMjZfdnBjLWI1YTk2ZmNkIn0seyJrZXkiOiJBbGVydExvZ2ljLUFjY291bnRJRCIsInZhbHVlIjoiMTM0MjMyODI4In1dLCJpbnN0YW5jZVN0YXRlIjoicnVubmluZyIsImF2YWlsYWJpbGl0eVpvbmUiOiJ1cy1lYXN0LTFmIn19LCJzZXJ2aWNlIjp7InNlcnZpY2VOYW1lIjoiZ3VhcmRkdXR5IiwiZGV0ZWN0b3JJZCI6IjA0YWY1MWQxMDFjOGM1YmNhZTNhOTI1NjBjNzAxMGNlIiwiYWN0aW9uIjp7ImFjdGlvblR5cGUiOiJORVRXT1JLX0NPTk5FQ1RJT04iLCJuZXR3b3JrQ29ubmVjdGlvbkFjdGlvbiI6eyJjb25uZWN0aW9uRGlyZWN0aW9uIjoiVU5LTk9XTiIsInJlbW90ZUlwRGV0YWlscyI6eyJpcEFkZHJlc3NWNCI6Ijc3LjcyLjgyLjgwIiwib3JnYW5pemF0aW9uIjp7ImFzbiI6NDMzNTAuMCwiYXNuT3JnIjoiTkZvcmNlIEVudGVydGFpbm1lbnQgQi5WLiIsImlzcCI6Ik5ldFVQIEx0ZC4iLCJvcmciOiJOZXRVUCBMdGQuIn0sImNvdW50cnkiOnsiY291bnRyeUNvZGUiOiJHQiIsImNvdW50cnlOYW1lIjoiVW5pdGVkIEtpbmdkb20ifSwiY2l0eSI6eyJjaXR5TmFtZSI6IlN0b2tlLW9uLVRyZW50In0sImdlb0xvY2F0aW9uIjp7ImxhdCI6NTMuMCwibG9uIjotMi4xODMzfX0sInJlbW90ZVBvcnREZXRhaWxzIjp7InBvcnQiOjQ0NzA1LjAsInBvcnROYW1lIjoiVW5rbm93biJ9LCJsb2NhbFBvcnREZXRhaWxzIjp7InBvcnQiOjQ0ODcuMCwicG9ydE5hbWUiOiJVbmtub3duIn0sInByb3RvY29sIjoiVENQIiwiYmxvY2tlZCI6dHJ1ZX19LCJyZXNvdXJjZVJvbGUiOiJUQVJHRVQiLCJhZGRpdGlvbmFsSW5mbyI6eyJ0aHJlYXROYW1lIjoiQ3VzdG9tZXIgVGhyZWF0IEludGVsIiwidGhyZWF0TGlzdE5hbWUiOiJ0ZG9zb3VkaWwtc2V6bmFtLWN6In0sImV2ZW50Rmlyc3RTZWVuIjoiMjAxNy0xMC0xMFQxOToxODoyMFoiLCJldmVudExhc3RTZWVuIjoiMjAxNy0xMC0xMVQyMzo0OTowOVoiLCJhcmNoaXZlZCI6ZmFsc2UsImNvdW50IjoyMC4wfSwic2V2ZXJpdHkiOjUuMCwiY3JlYXRlZEF0IjoiMjAxNy0xMC0xMFQxOToyMTowMi41OThaIiwidXBkYXRlZEF0IjoiMjAxNy0xMC0xMVQyMzo1MjoxNi45MzVaIiwidGl0bGUiOiJFQzIgSW5zdGFuY2UgaS0wOTYxZTBiM2FmOGIzZWMzOSBjb21tdW5pY2F0aW5nIG91dGJvdW5kIHdpdGggZGlzYWxsb3dlZCBJUCBhZGRyZXNzLiIsImRlc2NyaXB0aW9uIjoiRUMyIEluc3RhbmNlIGktMDk2MWUwYjNhZjhiM2VjMzkgaGFzIGJlZW4gZm91bmQgY29tbXVuaWNhdGluZyBvdXRib3VuZCB3aXRoIGRpc2FsbG93ZWQgSVAgYWRkcmVzcyA3Ny43Mi44Mi44MCBwcmVzZW50IGluIHRoZSBsaXN0IHRkb3NvdWRpbC1zZXpuYW0tY3ouIn19',
        'approximateArrivalTimestamp': 1507769764.013
      },
      'eventSource': 'aws:kinesis',
      'eventVersion': '1.0',
      'eventID': 'shardId-000000000000:49577651119794799532435452775356657619317529872846290946',
      'eventName': 'aws:kinesis:record',
      'invokeIdentityArn': 'arn:aws:iam::352283894008:role/kkuzmin-vpc-flow-role',
      'awsRegion': 'us-east-1',
      'eventSourceARN': 'arn:aws:kinesis:us-east-1:352283894008:stream/kkuzmin-gd-test'
    },
    {
      'kinesis': {
        'kinesisSchemaVersion': '1.0',
        'partitionKey': '52badd7d-edd6-ac34-b543-393e309cb977_dee8b923-1314-47b0-b820-68030eaf93e3',
        'sequenceNumber': '49577651119794799532435452775356657619317529872846290946',
        'data': 'eyJ0ZXN0IjoidGVzdCJ9',
        'approximateArrivalTimestamp': 1507769764.013
      },
      'eventSource': 'aws:kinesis',
      'eventVersion': '1.0',
      'eventID': 'shardId-000000000000:49577651119794799532435452775356657619317529872846290946',
      'eventName': 'aws:kinesis:record',
      'invokeIdentityArn': 'arn:aws:iam::352283894008:role/kkuzmin-vpc-flow-role',
      'awsRegion': 'us-east-1',
      'eventSourceARN': 'arn:aws:kinesis:us-east-1:352283894008:stream/kkuzmin-gd-test'
    }
  ]
};

const NO_GD_KINESIS_TEST_EVENT = {
  'Records': [
    {
      'kinesis': {
        'kinesisSchemaVersion': '1.0',
        'partitionKey': '52badd7d-edd6-ac34-b543-393e309cb977_dee8b923-1314-47b0-b820-68030eaf93e3',
        'sequenceNumber': '49577651119794799532435452775356657619317529872846290946',
        'data': 'eyJ0ZXN0IjoidGVzdCJ9',
        'approximateArrivalTimestamp': 1507769764.013
      },
      'eventSource': 'aws:kinesis',
      'eventVersion': '1.0',
      'eventID': 'shardId-000000000000:49577651119794799532435452775356657619317529872846290946',
      'eventName': 'aws:kinesis:record',
      'invokeIdentityArn': 'arn:aws:iam::352283894008:role/kkuzmin-vpc-flow-role',
      'awsRegion': 'us-east-1',
      'eventSourceARN': 'arn:aws:kinesis:us-east-1:352283894008:stream/kkuzmin-gd-test'
    },
    {
      'kinesis': {
        'kinesisSchemaVersion': '1.0',
        'partitionKey': '52badd7d-edd6-ac34-b543-393e309cb977_dee8b923-1314-47b0-b820-68030eaf93e3',
        'sequenceNumber': '49577651119794799532435452775356657619317529872846290946',
        'data': 'eyJ0ZXN0IjoidGVzdCJ9',
        'approximateArrivalTimestamp': 1507769764.013
      },
      'eventSource': 'aws:kinesis',
      'eventVersion': '1.0',
      'eventID': 'shardId-000000000000:49577651119794799532435452775356657619317529872846290946',
      'eventName': 'aws:kinesis:record',
      'invokeIdentityArn': 'arn:aws:iam::352283894008:role/kkuzmin-vpc-flow-role',
      'awsRegion': 'us-east-1',
      'eventSourceARN': 'arn:aws:kinesis:us-east-1:352283894008:stream/kkuzmin-gd-test'
    }
  ]
};

const GD_EVENT = {
    'version': '0',
    'id': '52badd7d-edd6-ac34-b543-393e309cb977',
    'detail-type': 'GuardDuty Finding',
    'source': 'aws.guardduty',
    'account': '352283894008',
    'time': '1970-01-01T00:00:00Z',
    'region': 'us-east-1',
    'resources': [],
    'detail': {
        'schemaVersion': '2.0',
        'accountId': '352283894008',
        'region': 'us-east-1',
        'partition': 'aws',
        'id': '3aaf83ddd9c31405246fa1c62e3e034d',
        'arn': 'arn:aws:guardduty:us-east-1:352283894008:detector/04af51d101c8c5bcae3a92560c7010ce/finding/3aaf83ddd9c31405246fa1c62e3e034d',
        'type': 'UnauthorizedAccess:EC2/MaliciousIPCaller.Custom',
        'resource': {
            'resourceType': 'Instance',
            'instanceDetails': {
                'imageId': 'ami-8a1ae2e7',
                'instanceId': 'i-0961e0b3af8b3ec39',
                'instanceType': 'c4.large',
                'launchTime': 1507656063000,
                'productCodes': [],
                'networkInterfaces': [{
                    'ipv6Addresses': [],
                    'privateIpAddress': '10.66.66.39',
                    'privateIpAddresses': [{
                        'privateIpAddress': '10.66.66.39'
                    }],
                    'subnetId': 'subnet-c396b8cf',
                    'vpcId': 'vpc-b5a96fcd',
                    'securityGroups': [{
                        'groupName': 'Alert Logic Security Group 134232828_28D59B27-B546-4A48-AA0A-88FF133C8126',
                        'groupId': 'sg-21718f53'
                    }],
                    'publicDnsName': '',
                    'publicIp': '34.204.172.166'
                }],
                'tags': [{
                    'key': 'AlertLogic-EnvironmentID',
                    'value': '28D59B27-B546-4A48-AA0A-88FF133C8126'
                }, {
                    'key': 'Name',
                    'value': 'AlertLogic Security Appliance'
                }, {
                    'key': 'AlertLogic',
                    'value': 'Security'
                }, {
                    'key': 'aws:autoscaling:groupName',
                    'value': 'Alert Logic Security Auto Scaling Group_134232828_28D59B27-B546-4A48-AA0A-88FF133C8126_vpc-b5a96fcd'
                }, {
                    'key': 'AlertLogic-AccountID',
                    'value': '134232828'
                }],
                'instanceState': 'running',
                'availabilityZone': 'us-east-1f'
            }
        },
        'service': {
            'serviceName': 'guardduty',
            'detectorId': '04af51d101c8c5bcae3a92560c7010ce',
            'action': {
                'actionType': 'NETWORK_CONNECTION',
                'networkConnectionAction': {
                    'connectionDirection': 'UNKNOWN',
                    'remoteIpDetails': {
                        'ipAddressV4': '77.72.82.80',
                        'organization': {
                            'asn': 43350,
                            'asnOrg': 'NForce Entertainment B.V.',
                            'isp': 'NetUP Ltd.',
                            'org': 'NetUP Ltd.'
                        },
                        'country': {
                            'countryCode': 'GB',
                            'countryName': 'United Kingdom'
                        },
                        'city': {
                            'cityName': 'Stoke-on-Trent'
                        },
                        'geoLocation': {
                            'lat': 53,
                            'lon': -2.1833
                        }
                    },
                    'remotePortDetails': {
                        'port': 44705,
                        'portName': 'Unknown'
                    },
                    'localPortDetails': {
                        'port': 4487,
                        'portName': 'Unknown'
                    },
                    'protocol': 'TCP',
                    'blocked': true
                }
            },
            'resourceRole': 'TARGET',
            'additionalInfo': {
                'threatName': 'Customer Threat Intel',
                'threatListName': 'tdosoudil-seznam-cz'
            },
            'eventFirstSeen': '2017-10-10T19:18:20Z',
            'eventLastSeen': '2017-10-11T23:49:09Z',
            'archived': false,
            'count': 20
        },
        'severity': 5,
        'createdAt': '2017-10-10T19:21:02.598Z',
        'updatedAt': '2017-10-11T23:52:16.935Z',
        'title': 'EC2 Instance i-0961e0b3af8b3ec39 communicating outbound with disallowed IP address.',
        'description': 'EC2 Instance i-0961e0b3af8b3ec39 has been found communicating outbound with disallowed IP address 77.72.82.80 present in the list tdosoudil-seznam-cz.'
    }
};


const CF_DESCRIBE_STACKS_RESPONSE = {
  'ResponseMetadata': {
    'RequestId': 'f9f5e0e7-be24-11e7-9891-49fc9e4a2c65'
  },
  'Stacks': [
    {
      'StackId': STACK_ID,
      'StackName': STACK_NAME,
      'Description': 'Alert Logic template for creating a CloudWatch events collector for Guard Duty events',
      'Parameters': [
        {
          'ParameterKey': 'AlDataResidency',
          'ParameterValue': 'default'
        },
        {
          'ParameterKey': 'SecretKey',
          'ParameterValue': '****'
        },
        {
          'ParameterKey': 'S3Bucket',
          'ParameterValue': S3_BUCKET
        },
        {
          'ParameterKey': 'AccessKeyId',
          'ParameterValue': ACCESS_KEY_ID
        },
        {
          'ParameterKey': 'AlApiEndpoint',
          'ParameterValue': 'api.global-services.global.alertlogic.com'
        },
        {
          'ParameterKey': 'S3Zipfile',
          'ParameterValue': 'packages/lambda/al-cwe-collector.zip'
        }
      ],
      'CreationTime': '2017-10-30T14:27:59.848Z',
      'RollbackConfiguration': {},
      'StackStatus': 'CREATE_COMPLETE',
      'DisableRollback': false,
      'NotificationARNs': [],
      'Capabilities': [
        'CAPABILITY_IAM'
      ],
      'Outputs': [],
      'Tags': [],
      'EnableTerminationProtection': false
    }
  ]
};


const CWE_DESCRIBE_RULE = {
  'Name': CWE_RULE_NAME,
  'Arn': CWE_RULE_ARN,
  'EventPattern': '{\"source\":[\"aws.guardduty\"]}',
  'State': 'ENABLED',
  'Description': 'CloudWatch events rule for Guard Duty events'
};

const CWE_LIST_TARGETS_BY_RULE = {
  'Targets': [
    {
      'Id': '1',
      'Arn': KINESIS_ARN,
      'RoleArn': 'arn:aws:iam::352283894008:role/test-RoleForEventsToInvokeKinesis-GWGPM7IZAOH3'
    }
  ]
};

const LAMBDA_LIST_EVENTSOURCE_MAPPINGS_OK = {
    'EventSourceMappings': [
        {
            'UUID': '5ca7d79a-7ce9-4b47-b717-e13bdd02334c', 
            'StateTransitionReason': 'User action', 
            'LastModified': 1509993240.0, 
            'BatchSize': 100, 
            'State': 'Enabled', 
            'FunctionArn': FUNCTION_ARN, 
            'EventSourceArn': KINESIS_ARN, 
            'LastProcessingResult': 'OK'
        }, 
        {
            'UUID': '36503e36-0266-485f-bf2a-96c695933c06', 
            'StateTransitionReason': 'User action', 
            'LastModified': 1509990300.0, 
            'BatchSize': 100, 
            'State': 'Enabled', 
            'FunctionArn': 'arn:aws:lambda:us-east-1:352283894008:function:kk-test-CollectLambdaFunction-7WSTEZRR2N9R', 
            'EventSourceArn': 'arn:aws:kinesis:us-east-1:352283894008:stream/kk-test', 
            'LastProcessingResult': 'No records processed'
        }
    ]
};

const CLOUDWATCH_GET_METRIC_STATS_OK = {
    'Datapoints': [
        {
            'Timestamp': '2017-11-21T16:40:00Z', 
            'Sum': 1.0, 
            'Unit': 'Count'
        }
    ], 
    'Label': 'Invocations'
};

module.exports = {
    AIMS_TEST_CREDS : AIMS_TEST_CREDS,
    CHECKIN_TEST_FUNCTION_NAME : CHECKIN_TEST_FUNCTION_NAME,
    CHECKIN_TEST_URL : CHECKIN_TEST_URL,
    FUNCTION_ARN : FUNCTION_ARN,
    CHECKIN_TEST_EVENT : CHECKIN_TEST_EVENT,
    STACK_NAME : STACK_NAME,
    REGISTRATION_TEST_FUNCTION_NAME : REGISTRATION_TEST_FUNCTION_NAME,
    REGISTRATION_STACK_NAME : REGISTRATION_STACK_NAME,
    REGISTRATION_COLLECT_RULE : REGISTRATION_COLLECT_RULE,
    REGISTRATION_TEST_URL : REGISTRATION_TEST_URL,
    REGISTRATION_TEST_EVENT : REGISTRATION_TEST_EVENT,
    GD_ONLY_KINESIS_TEST_EVENT : GD_ONLY_KINESIS_TEST_EVENT,
    GD_OTHER_KINESIS_TEST_EVENT : GD_OTHER_KINESIS_TEST_EVENT,
    NO_GD_KINESIS_TEST_EVENT : NO_GD_KINESIS_TEST_EVENT,
    GD_MALFORMED_KINESIS_TEST_EVENT : GD_MALFORMED_KINESIS_TEST_EVENT,
    GD_EVENT : GD_EVENT,
    CF_DESCRIBE_STACKS_RESPONSE : CF_DESCRIBE_STACKS_RESPONSE,
    CWE_DESCRIBE_RULE : CWE_DESCRIBE_RULE,
    CWE_LIST_TARGETS_BY_RULE : CWE_LIST_TARGETS_BY_RULE,
    CWE_RULE_NAME : CWE_RULE_NAME,
    DEFAULT_LAMBDA_CONTEXT : DEFAULT_LAMBDA_CONTEXT,
    LAMBDA_LIST_EVENTSOURCE_MAPPINGS_OK : LAMBDA_LIST_EVENTSOURCE_MAPPINGS_OK,
    CLOUDWATCH_GET_METRIC_STATS_OK : CLOUDWATCH_GET_METRIC_STATS_OK
};