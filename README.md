# Log forwarding and filter by log content

Initialize some variables that we will use along the process
```
export REGION=us-east-2
export AWS_ACCOUNT_ID=`aws sts get-caller-identity --query Account --output text`
export AWS_PAGER=""
export WORKING_DIR="/tmp/clf-cloudwatch-vector"
mkdir -p ${WORKING_DIR}
echo "Region: ${REGION}, AWS Account ID: ${AWS_ACCOUNT_ID}"
```
