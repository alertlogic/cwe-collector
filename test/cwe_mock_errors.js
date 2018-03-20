const CF_DESCRIBE_STACKS_ACCESS_DENIED = {'message':'User: arn:aws:sts::352283894008:assumed-role/test-CollectLambdaRole-11Z7IDV7G2XDV/test-CollectLambdaFunction-1JNNKQIPOTEST is not authorized to perform: cloudformation:DescribeStacks on resource: arn:aws:cloudformation:us-east-1:352283894008:stack/test-none/*','code':'AccessDenied','time':'2017-10-30T15:18:21.850Z','requestId':'90f56274-bd85-11e7-9cae-317d476fdadc','statusCode':403,'retryable':false,'retryDelay':97.27816804144092};

const CF_DESCRIBE_STACKS_NOT_FOUND = {'message':'Stack with id test-none does not exist','code':'ValidationError','time':'2017-10-31T10:54:20.805Z','requestId':'d9490f74-be29-11e7-abb6-678cd90a910d','statusCode':400,'retryable':false,'retryDelay':98.9884491682175};

const CWE_DESCRIBE_RULE_NOT_FOUND = {'message':'Rule test-CloudWatchEventsRule-tes2t does not exist.','code':'ResourceNotFoundException','time':'2017-10-31T17:20:19.992Z','requestId':'c5508bc6-be5f-11e7-bb99-9bff666f2fca','statusCode':400,'retryable':false,'retryDelay':43.710604355080605};

const CWE_DESCRIBE_RULE_ACCESS_DENIED = {'message':'User: arn:aws:sts::352283894008:assumed-role/test-CollectLambdaRole-11Z7IDV7G2XDV/test-CollectLambdaFunction-1JNNKQIPOTEST is not authorized to perform: events:DescribeRule on resource: arn:aws:events:us-east-1:352283894008:rule/test','code':'AccessDeniedException','time':'2017-10-31T17:56:34.431Z','requestId':'d562abf5-be64-11e7-b2d2-49f153b9770e','statusCode':400,'retryable':false,'retryDelay':7.751107016565584};

const CWE_LIST_TARGETS_ACCESS_DENIED = {'message':'User: arn:aws:sts::352283894008:assumed-role/test-CollectLambdaRole-11Z7IDV7G2XDV/test-CollectLambdaFunction-1JNNKQIPOTEST is not authorized to perform: events:ListTargetsByRule on resource: arn:aws:events:us-east-1:352283894008:rule/test-CloudWatchEventsRule-EHIZIHJYHTOD','code':'AccessDeniedException','time':'2017-10-31T18:02:28.863Z','requestId':'a8a48d56-be65-11e7-b2d2-49f153b9770e','statusCode':400,'retryable':false,'retryDelay':52.54611924068679};

const CWE_LIST_TARGETS_NOT_FOUND = {'message':'Rule test does not exist.','code':'ResourceNotFoundException','time':'2017-10-31T18:08:35.230Z','requestId':'82ff2443-be66-11e7-ab62-c556589c1f4b','statusCode':400,'retryable':false,'retryDelay':57.14009661702399};

const LAMBDA_LIST_EVENT_SOURCE_MAPPINGS_EMPTY = {
    'EventSourceMappings': []
};

const LAMBDA_LIST_EVENT_SOURCE_MAPPINGS_PROBLEM = {
    'EventSourceMappings': [
        {
            'UUID': '5ca7d79a-7ce9-4b47-b717-e13bdd02334c', 
            'StateTransitionReason': 'User action', 
            'LastModified': 1509977760.0, 
            'BatchSize': 100, 
            'State': 'Enabled', 
            'FunctionArn': 'arn:aws:lambda:us-east-1:352283894008:function:test-guardduty-01-CollectLambdaFunction-2CWNLPPW5XO8', 
            'EventSourceArn': 'arn:aws:kinesis:us-east-1:353333894008:stream/test-KinesisStream-11Z7IDV7G2XDV', 
            'LastProcessingResult': 'PROBLEM: internal Lambda error. Please contact Lambda customer support.'
        }, 
        {
            'UUID': '36503e36-0266-485f-bf2a-96c695933c06', 
            'StateTransitionReason': 'User action', 
            'LastModified': 1509990300.0, 
            'BatchSize': 100, 
            'State': 'Enabled', 
            'FunctionArn': 'arn:aws:lambda:us-east-1:352283894008:function:test-guardduty-01-CollectLambdaFunction-2CWNLPPW5XO8', 
            'EventSourceArn': 'arn:aws:kinesis:us-east-1:352283894008:stream/kk-test', 
            'LastProcessingResult': 'No records processed'
        }
    ]
    
};

const UNEXPECTED_ERROR = {'message' : 'unexpected message', 'code' : 'SomeUnexpectedCode', 'statusCode' : 500};

const INGEST_400_RESPONSE = {
    'statusCode': 400,
    'options': {
        'body' : 'compressed unsupported message'
    }
};

const INGEST_400_NO_OPTIONS_RESPONSE = { 'statusCode': 400 };

const INGEST_500_RESPONSE = {'statusCode': 500};

module.exports = {
    CF_DESCRIBE_STACKS_ACCESS_DENIED : CF_DESCRIBE_STACKS_ACCESS_DENIED,
    CF_DESCRIBE_STACKS_NOT_FOUND : CF_DESCRIBE_STACKS_NOT_FOUND,
    CWE_DESCRIBE_RULE_NOT_FOUND : CWE_DESCRIBE_RULE_NOT_FOUND,
    CWE_DESCRIBE_RULE_ACCESS_DENIED : CWE_DESCRIBE_RULE_ACCESS_DENIED,
    CWE_LIST_TARGETS_ACCESS_DENIED : CWE_LIST_TARGETS_ACCESS_DENIED,
    CWE_LIST_TARGETS_NOT_FOUND : CWE_LIST_TARGETS_NOT_FOUND,
    UNEXPECTED_ERROR : UNEXPECTED_ERROR,
    LAMBDA_LIST_EVENT_SOURCE_MAPPINGS_EMPTY : LAMBDA_LIST_EVENT_SOURCE_MAPPINGS_EMPTY,
    LAMBDA_LIST_EVENT_SOURCE_MAPPINGS_PROBLEM : LAMBDA_LIST_EVENT_SOURCE_MAPPINGS_PROBLEM,
    INGEST_400_RESPONSE : INGEST_400_RESPONSE,
    INGEST_500_RESPONSE : INGEST_500_RESPONSE,
    INGEST_400_NO_OPTIONS_RESPONSE : INGEST_400_NO_OPTIONS_RESPONSE
};