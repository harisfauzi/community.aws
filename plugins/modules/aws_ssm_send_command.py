#!/usr/bin/python
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}


DOCUMENTATION = '''
---
module: aws_ssm_send_command
short_description: Execute commands through Simple System Manager (SSM) a.k.a. Run Command
description:
  - This module allows you to execute commands through SSM/Run Command.
version_added: '2.10.0'
author: "Joe Wozniak (@woznij)"
requirements:
  - python >= 2.6
  - boto3
notes:
  - Async invocation will always return an empty C(output) key.
  - Synchronous invocation may result in a function timeout, resulting in an
    empty C(output) key.
options:
  document_name:
    description:
      - This should match the name of the SSM document to be invoked.
    type: str
    required: true
  document_hash:
    description:
      - The hash of document created by the system when the document was created.
    required: false
    type: str
  document_hash_type:
    description:
      - The hash type for I(document_hash).
    required: false
    choices: [ Sha256, Sha1 ]
    type: str
  comment:
    description:
      - A comment about this particular invocation.
    required: false
    type: str
  timeout_seconds:
    description:
      - Time out if the command has not already started running, then it will not run.
    required: false
    type: int
  instance_ids:
    description:
      - A list of instance IDs for the instances you wish to run this command
        document against.
    required: true
    type: list
    elements: str
  wait:
    description:
      - Whether to wait for the function results or not. If I(wait) is false,
        the task will not return any results. To wait for the command to
        complete, set C(wait=true) and the result will be available in the
        I(output) key.
    required: false
    type: bool
    default: true
  parameters:
    description:
      - A dictionary to be provided as the parameters for the SSM document
        you're invoking.
    required: false
    type: dict
    default: {}
extends_documentation_fragment:
    - aws
    - ec2
'''

EXAMPLES = '''
- aws_ssm_send_command:
    name: AWS-UpdateSSMAgent
    comment: "SSM agent update check"
    instance_ids:
      - i-123987193812
      - i-289189288278
    parameters:
      version: latest
      allowDowngrade: 'false'
    wait: true
  register: response
'''

RETURN = '''
output:
    description: If wait=true, will return the output of the executed command. Sample truncated for brevity.
    returned: success
    type: str
    sample: "Updating amazon-ssm-agent from 2.3.539.0 to latest\nSuccessfully downloaded https://s3.us-west-2.amazonaws.com/amazon-ssm-us-west-2/ssm-agent..."
status:
    description: Status of the run command.
    returned: success
    type: str
    sample: Success
'''

from ansible_collections.amazon.aws.plugins.module_utils.core import AnsibleAWSModule
from ansible_collections.amazon.aws.plugins.module_utils.ec2 import boto3_conn, get_aws_connection_info, AWSRetry
import traceback
from time import sleep

try:
    import botocore
except ImportError:
    pass  # will be captured by imported HAS_BOTO3


@AWSRetry.backoff(tries=5, delay=5, backoff=2.0)
def ssm_send_command(conn, **kwargs):
    return conn.send_command(**kwargs)


@AWSRetry.backoff(tries=5, delay=5, backoff=2.0)
def ssm_list_command_invocations(conn, **kwargs):
    return conn.list_command_invocations(**kwargs)


def get_targets(module):
    targets = list()
    for key, values in module.params.get('targets', {}).items():
        target = dict()
        target_values = list()
        target['Key'] = key
        for item in values.items():
            target_values.append(item)
        target['Values'] = target_values
        targets.append(target)
    return targets


def get_notification_configs(module):
    params = dict()
    for param, api_name in {
        'notification_arn': 'NotificationArn',
        'notification_events': 'NotificationEvents',
        'notification_type': 'NotificationType'
    }.items():
        if module.params.get('notification_config', {}).get(param):
            params[api_name] = module.params.get('notification_config', {}).get(param)
    return params


def get_cloudwatch_output_configs(module):
    params = dict()
    for param, api_name in {
        'cloudwatch_loggroup_name': 'CloudWatchLogGroupName',
        'cloudwatch_output_enabled': 'CloudWatchOutputEnabled'
    }.items():
        if module.params.get('cloudwatch_output_config', {}).get(param):
            params[api_name] = module.params.get('cloudwatch_output_config', {}).get(param)
    return params


def main():
    target_options = dict(
        key=dict(type='str'),
        values=dict(type='list', elements='str')
    )
    notification_config_options = dict(
        notification_arn=dict(type='str'),
        notification_events=dict(
            type='list',
            elements='str',
            choices=['All', 'InProgress', 'Success', 'TimedOut', 'Cancelled', 'Failed']
        ),
        notification_type=dict(type='str', choices=['Command', 'Invocation'])
    )
    cloudwatch_output_config_options = dict(
        cloudwatch_loggroup_name=dict(type='str'),
        cloudwatch_output_enabled=dict(type='bool')
    )
    argument_spec = dict(
        document_name=dict(required=True, type='str'),
        document_version=dict(default=None, type='str'),
        document_hash=dict(default=None, type='str'),
        document_hash_type=dict(default=None, type='str', choices=['Sha256', 'Sha1']),
        wait=dict(default=True, type='bool'),
        comment=dict(),
        instance_ids=dict(default=None, type='list', elements='str'),
        targets=dict(
            type='list',
            elements='dict',
            options=target_options),
        parameters=dict(default={}, type='dict'),
        timeout_seconds=dict(default=None, type='int'),
        output_s3_bucket_name=dict(default=None, type='str'),
        output_s3_key_prefix=dict(default=None, type='str'),
        max_concurrency=dict(default=None, type='str'),
        max_errors=dict(default=None, type='str'),
        service_role_arn=dict(default=None, type='str'),
        notification_config=dict(default=None, type='dict', options=notification_config_options),
        cloudwatch_output_config=dict(default=None, type='dict', options=cloudwatch_output_config_options)
    )
    module = AnsibleAWSModule(
        argument_spec=argument_spec,
        supports_check_mode=False
    )

    # Needs to be an existing SSM document name
    document_name = module.params.get('document_name')
    document_version = module.params.get('document_version')
    document_hash = module.params.get('document_hash')
    document_hash_type = module.params.get('document_hash_type')
    comment = module.params.get('comment')
    await_return = module.params.get('wait')
    instance_ids = module.params.get('instance_ids')
    targets = module.params.get('targets')
    parameters = module.params.get('parameters')
    timeout_seconds = module.params.get('timeout_seconds')
    output_s3_bucket_name = module.params.get('output_s3_bucket_name')
    output_s3_key_prefix = module.params.get('output_s3_key_prefix')
    max_concurrency = module.params.get('max_concurrency')
    max_errors = module.params.get('max_errors')
    service_role_arn = module.params.get('service_role_arn')
    notification_config = module.params.get('notification_config')
    cloudwatch_output_config = module.params.get('cloudwatch_output_config')

    if not (document_name and instance_ids):
        module.fail_json(
            msg="Must provide SSM document name and at least one instance id.")

    conn = module.client('ssm')

    invoke_params = {}

    if document_name:
        invoke_params['DocumentName'] = document_name
    if document_version:
        invoke_params['DocumentVersion'] = document_version
    if document_hash:
        invoke_params['DocumentHash'] = document_hash
    if document_hash_type:
        invoke_params['DocumentHashType'] = document_hash_type
    if comment:
        invoke_params['Comment'] = comment
    if instance_ids:
        invoke_params['InstanceIds'] = instance_ids
    if parameters:
        invoke_params['Parameters'] = parameters
    if timeout_seconds:
        invoke_params['TimeoutSeconds'] = timeout_seconds
    if output_s3_bucket_name:
        invoke_params['OutputS3BucketName'] = output_s3_bucket_name
    if output_s3_key_prefix:
        invoke_params['OutputS3KeyPrefix'] = output_s3_key_prefix
    if max_concurrency:
        invoke_params['MaxConcurrency'] = max_concurrency
    if max_errors:
        invoke_params['MaxErrors'] = max_errors
    if service_role_arn:
        invoke_params['ServiceRoleArn'] = service_role_arn
    if targets:
        invoke_params['Targets'] = get_targets(module)
    if notification_config:
        invoke_params['NotificationConfig'] = get_notification_configs(module)
    if cloudwatch_output_config:
        invoke_params['CloudWatchOutputConfig'] = get_cloudwatch_output_configs(module)

    try:
        response = ssm_send_command(conn, **invoke_params)
    except botocore.exceptions.ClientError as ce:
        if ce.response['Error']['Code'] == 'ResourceNotFoundException':
            module.fail_json_aws(ce, msg="Could not find the SSM doc to execute. Make sure "
                                 "the document name is correct and your profile has "
                                 "permissions to execute SSM.")
        module.fail_json_aws(
            ce, msg="Client-side error when invoking SSM, check inputs and specific error")
    except botocore.exceptions.ParamValidationError as ve:
        module.fail_json_aws(
            ve, msg="Parameters to `invoke` failed to validate")
    except Exception as e:
        module.fail_json(msg="Unexpected failure while invoking SSM send command.",
                         exception=traceback.format_exc(e))

    if await_return:
        command_id = response.get('Command', {}).get('CommandId')
        list_params = {}
        if command_id:
            list_params['CommandId'] = command_id
            list_params['Details'] = True
            checking = True
            while checking:
                try:
                    invoke_response = ssm_list_command_invocations(
                        conn, **list_params)
                except Exception as e:
                    module.fail_json(msg="Error in checking on execution status",
                                     exception=traceback.format_exc(e))
                if not invoke_response['CommandInvocations'] == []:
                    if invoke_response['CommandInvocations'][0]['Status'] == 'Success':
                        checking = False
                    if invoke_response['CommandInvocations'][0]['Status'] in ['Failed', 'TimedOut', 'Cancelled']:
                        checking = False
                        module.fail_json(msg="SSM Command failed")
                    # Keep looping for Status in ['Pending', 'InProgress', 'Delayed']
                sleep(5)
        else:
            module.fail_json(msg='A valid command invocation ID was not returned.'
                                 'Check the EC2 console command history')
        results = {
            'status': invoke_response['CommandInvocations'][0]['Status'],
            'output': invoke_response['CommandInvocations'][0]['CommandPlugins'][0]['Output'],
        }
    else:
        results = {
            'status': response['Command']['Status'],
            'output': ''
        }

    module.exit_json(changed=True, result=results)


if __name__ == '__main__':
    main()
