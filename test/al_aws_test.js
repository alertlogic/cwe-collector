const assert = require('assert');
const rewire = require('rewire');
const sinon = require('sinon');
const m_alAws = require('../lib/al_aws');
var AWS = require('aws-sdk-mock');

describe('al_aws Tests', function() {

    describe('arnToName() tests', function(done) {
        it('Valid input', function(done) {
            assert.equal(m_alAws.arnToName('arn:aws:iam::123456789101:role/testRole'), 'testRole');
            assert.equal(m_alAws.arnToName('arn:aws:kinesis:us-east-1:123456789101:stream/test-KinesisStream'), 'test-KinesisStream');
            assert.equal(m_alAws.arnToName('arn:aws:sqs:us-east-1:352283894008:testSqs'), 'testSqs');
            assert.equal(m_alAws.arnToName('arn:aws:s3:::teambucket'), 'teambucket');
            done();
        });
        
        it('Invalid input', function(done) {
            assert.ifError(m_alAws.arnToName(''));
            assert.ifError(m_alAws.arnToName('invalid'));
            assert.ifError(m_alAws.arnToName('arn:aws:invalid'));
            done();
        });
    });
});
