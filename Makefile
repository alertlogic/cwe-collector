AWS_LAMBDA_CWE_FUNCTION_NAME ?= alertlogic-cwe-collector
AWS_LAMBDA_CWE_PACKAGE_NAME ?= al-cwe-collector.zip
AWS_TEMPLATES := $(shell find ./cfn -name '*.template') 

.PHONY: test cfn

all: test package package.zip

deps: node_modules

node_modules:
	npm install

compile: deps
	npm run lint

test: compile
	npm run test

cfn: $(AWS_TEMPLATES)
	aws cloudformation validate-template --region us-east-1 --template-body file://$^
	
package: test package.zip

package.zip: node_modules/ *.js package.json
	zip -r $(AWS_LAMBDA_CWE_PACKAGE_NAME) $^

deploy:
	aws lambda update-function-code --function-name $(AWS_LAMBDA_CWE_FUNCTION_NAME) --zip-file fileb://$(AWS_LAMBDA_CWE_PACKAGE_NAME)

clean:
	rm -rf node_modules
	rm -f $(AWS_LAMBDA_CWE_PACKAGE_NAME)
	rm -f package-lock.json
	rm -f test/report.xml
	rm -rf ./coverage/
