# Log forwarding and filter by log content using Vector

Initialize some variables that we will use along the process
```
export REGION=us-east-2
export AWS_ACCOUNT_ID=`aws sts get-caller-identity --query Account --output text`
export AWS_PAGER=""
export WORKING_DIR="/tmp/clf-cloudwatch-vector"
mkdir -p ${WORKING_DIR}
echo "Region: ${REGION}, AWS Account ID: ${AWS_ACCOUNT_ID}"
```
Create the policy needed for using cloudwatch
```
POLICY_ARN=$(aws iam list-policies --query "Policies[?PolicyName=='VectorToCloudWatch'].{ARN:Arn}" --output text)
if [[ -z "${POLICY_ARN}" ]]; then
cat << EOF > ${WORKING_DIR}/policy.json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:DescribeLogGroups",
                "logs:DescribeLogStreams",
                "logs:PutLogEvents",
                "logs:PutRetentionPolicy"
            ],
            "Resource": "arn:aws:logs:*:*:*"
        }
    ]
}
EOF
POLICY_ARN=$(aws iam create-policy --policy-name "VectorToCloudWatch" \
--policy-document file:///${WORKING_DIR}/policy.json --query Policy.Arn --output text)
fi
echo ${POLICY_ARN}
```
Create a user, and right after the access key for that user
```
aws iam create-user \
    --user-name vector-to-cloudwatch \
    > $WORKING_DIR/aws-user.json

aws iam create-access-key \
    --user-name vector-to-cloudwatch \
    > $WORKING_DIR/aws-access-key.json
```
Bind the policy with the above user
```
aws iam attach-user-policy \
    --user-name  vector-to-cloudwatch \
    --policy-arn ${POLICY_ARN}
```
Store the id and key in variables to create the secret easily. 
```
AWS_ID=`cat $WORKING_DIR/aws-access-key.json | jq -r '.AccessKey.AccessKeyId'`
AWS_KEY=`cat $WORKING_DIR/aws-access-key.json | jq -r '.AccessKey.SecretAccessKey'`

cat << EOF | oc apply -f -
apiVersion: v1
kind: Secret
metadata:
    name: cloudwatch-credentials
    namespace: openshift-logging
stringData:
    aws_access_key_id: $AWS_ID
    aws_secret_access_key: $AWS_KEY
EOF
```
Create the ClusterLogForwarder instance and define a simple filter for demo purpose

> [!NOTE]
> At the time this doc was written I found some issues: https://github.com/openshift/openshift-docs/pull/75742
```
cat << EOF | oc apply -f -
apiVersion: "logging.openshift.io/v1"
kind: ClusterLogForwarder
metadata:
  name: instance
  namespace: openshift-logging
spec:
  filters:
  - drop:
    - test:
      - field: .message
        notMatches: Special
    name: keep-important
    type: drop
  inputs:
  - application:
      namespaces:
      - logging-tester
    name: test-logging-input
  outputs:
  - cloudwatch:
      groupBy: namespaceName
      groupPrefix: vector2cloudwatch
      region: us-east-2
    name: cw
    secret:
      name: cloudwatch-credentials
    type: cloudwatch
  pipelines:
  - filterRefs:
    - keep-important
    inputRefs:
    - test-logging-input
    name: vector2cloudwatch
    outputRefs:
    - cw
EOF
```

Create the ClusterLogging instance using Vector
```
cat << EOF | oc apply -f -
apiVersion: logging.openshift.io/v1
kind: ClusterLogging
metadata:
  name: instance
  namespace: openshift-logging
spec:
  collection:
    type: vector
    vector: {}
    managementState: Managed
EOF
```
Deploy a busybox and write a few messages that will help to see how the filter works
```
cat << EOF | oc apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: busybox-log-tester
  namespace: logging-tester
spec:
  replicas: 1  
  selector:
    matchLabels:
      app: busybox-log-tester
  template:
    metadata:
      labels:
        app: busybox-log-tester
    spec:
      containers:
      - name: busybox
        image: busybox
        command:
          - /bin/sh
          - -c
          - >
            while true; do
              echo "$(date) Hello, OpenShift logging! This is a general message.";
              echo "$(date) Special Event: Important log entry!" >> /dev/stderr;
              sleep 10;
            done
EOF
```
Check from the command line if the log group has been created in cloudwatch
```
$ aws logs describe-log-groups --log-group-name-prefix vector2cloudwatch
{
    "logGroups": [
        {
            "logGroupName": "vector2cloudwatch.logging-tester",
            "creationTime": 1715339165181,
            "metricFilterCount": 0,
            "arn": "arn:aws:logs:us-east-2:015719942846:log-group:vector2cloudwatch.logging-tester:*",
            "storedBytes": 0
        }
    ]
}
```
If you want to go further without going through Cloudwatch, let's describe a few commands that will help 
first of all, let's get the logStreamName:
```
$ aws logs describe-log-streams --log-group-name "vector2cloudwatch.logging-tester"
{
    "logStreams": [
        {
            "logStreamName": "kubernetes.var.log.pods.logging-tester_busybox-log-tester-756574b88b-dvn5h_e38bf5d3-d298-4741-a0c6-518cbd8d035e.busybox.0.log",
            "creationTime": 1715339165342,
            "firstEventTimestamp": 1715339162973,
            "lastEventTimestamp": 1715339162973,
            "lastIngestionTime": 1715339166072,
            "uploadSequenceToken": "49039859587785285276720670320893078993410934433333211120",
            "arn": "arn:aws:logs:us-east-2:015719942846:log-group:vector2cloudwatch.logging-tester:log-stream:kubernetes.var.log.pods.logging-tester_busybox-log-tester-756574b88b-dvn5h_e38bf5d3-d298-4741-a0c6-518cbd8d035e.busybox.0.log",
            "storedBytes": 0
        }
    ]
}
```
With the logStreamName we can go through to the full log detail
```
$ aws logs get-log-events --log-group-name "vector2cloudwatch.logging-tester" --log-stream-name "**kubernetes.var.log.pods.logging-tester_busybox-log-tester-756574b88b-dvn5h_e38bf5d3-d298-4741-a0c6-518cbd8d035e.busybox.0.log**"
{
    "events": [
        {
            "timestamp": 1715339162973,
            "message": "{\"@timestamp\":\"2024-05-10T11:05:51.525055088Z\",\"group_name\":\"vector2cloudwatch.logging-tester\",\"hostname\":\"wolverine\",\"kubernetes\":{\"annotations\":{\"k8s.ovn.org/pod-networks\":\"{\\\"default\\\":{\\\"ip_addresses\\\":[\\\"10.128.0.250/23\\\"],\\\"mac_address\\\":\\\"0a:58:0a:80:00:fa\\\",\\\"gateway_ips\\\":[\\\"10.128.0.1\\\"],\\\"routes\\\":[{\\\"dest\\\":\\\"10.128.0.0/14\\\",\\\"nextHop\\\":\\\"10.128.0.1\\\"},{\\\"dest\\\":\\\"172.30.0.0/16\\\",\\\"nextHop\\\":\\\"10.128.0.1\\\"},{\\\"dest\\\":\\\"100.64.0.0/16\\\",\\\"nextHop\\\":\\\"10.128.0.1\\\"}],\\\"ip_address\\\":\\\"10.128.0.250/23\\\",\\\"gateway_ip\\\":\\\"10.128.0.1\\\"}}\",\"k8s.v1.cni.cncf.io/network-status\":\"[{\\n    \\\"name\\\": \\\"ovn-kubernetes\\\",\\n    \\\"interface\\\": \\\"eth0\\\",\\n    \\\"ips\\\": [\\n        \\\"10.128.0.250\\\"\\n    ],\\n    \\\"mac\\\": \\\"0a:58:0a:80:00:fa\\\",\\n    \\\"default\\\": true,\\n    \\\"dns\\\": {}\\n}]\",\"openshift.io/scc\":\"restricted-v2\",\"seccomp.security.alpha.kubernetes.io/pod\":\"runtime/default\"},\"container_id\":\"cri-o://446b2256ad8057a6f01fce7ca7730335c64a1e5cb18f389fd7423952f9bfd541\",\"container_image\":\"busybox\",\"container_image_id\":\"docker.io/library/busybox@sha256:50aa4698fa6262977cff89181b2664b99d8a56dbca847bf62f2ef04854597cf8\",\"container_name\":\"busybox\",\"labels\":{\"app\":\"busybox-log-tester\",\"pod-template-hash\":\"756574b88b\"},\"namespace_id\":\"d1ba9cba-6db3-4bf5-9bc3-5343101bdfa0\",\"namespace_labels\":{\"kubernetes_io_metadata_name\":\"logging-tester\",\"pod-security_kubernetes_io_audit\":\"privileged\",\"pod-security_kubernetes_io_audit-version\":\"v1.24\",\"pod-security_kubernetes_io_warn\":\"privileged\",\"pod-security_kubernetes_io_warn-version\":\"v1.24\"},\"namespace_name\":\"logging-tester\",\"pod_id\":\"e38bf5d3-d298-4741-a0c6-518cbd8d035e\",\"pod_ip\":\"10.128.0.250\",\"pod_name\":\"busybox-log-tester-756574b88b-dvn5h\",\"pod_owner\":\"ReplicaSet/busybox-log-tester-756574b88b\"},\"level\":\"default\",\"log_type\":\"application\",\"message\":\"Fri 10 May 13:05:48 CEST 2024 Special Event: Important log entry!\",\"openshift\":{\"cluster_id\":\"6cfb9b2d-20ed-4abc-9312-855e03b25950\",\"sequence\":1715339162972911903},\"stream_name\":\"kubernetes.var.log.pods.logging-tester_busybox-log-tester-756574b88b-dvn5h_e38bf5d3-d298-4741-a0c6-518cbd8d035e.busybox.0.log\"}",
            "ingestionTime": 1715339166072
        },
[...]
```
The output is pretty ugly, so let's tweak it to see if the filter is applied correctly.
```
$ aws logs get-log-events --log-group-name "vector2cloudwatch.logging-tester" --log-stream-name "kubernetes.var.log.pods.logging-tester_busybox-log-tester-756574b88b-dvn5h_e38bf5d3-d298-4741-a0c6-518cbd8d035e.busybox.0.log" | jq -r '.events[] | .message | fromjson | .message'
Fri 10 May 13:05:48 CEST 2024 Special Event: Important log entry!
Fri 10 May 13:05:48 CEST 2024 Special Event: Important log entry!
[...]
```
Additionally you can use 'prune' type filter to remove fields from the message like annotations, group_name, and so on... 


