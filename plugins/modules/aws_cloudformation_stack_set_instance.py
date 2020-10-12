#!/usr/bin/python
# Copyright: (c) 2018, Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: aws_cloudformation_stack_set_instance
version_added: 2.10.1
short_description: Manage the deployment of  CloudFormation stackset instance(s)
description:
    - Creates/updates/deletes AWS CloudFormation StackSet instances.
notes:
    - To make an individual stack, you want the M(amazon.aws.cloudformation) module.
    - You need to create the CloudFormation Stack-Set before you can create the instance,
      you may want to use M(community.aws.aws_cloudformation_stack_set)
options:
    stack_set_name:
        description:
            - Name of the CloudFormation stack set.
        required: true
        type: str
    parameter_overrides:
        description:
            - A list of parameter overrides.
        type: list
        elements: dict
        suboptions:
            parameter_key:
                description: The key associated with the parameter.
                type: str
            parameter_value:
                description: The input value associated with the parameter.
                type: str
            use_previous_value:
                description:
                    - Use existing value for given parameter_key.
                    - Do not specify parameter_value if I(use_previous_value) is C(true).
                type: bool
            resolved_value:
                description: The value that corresponds to a Systems Manager parameter key.
                type: str
    state:
        description:
            - If I(state=present), stack instance(s) will be created.
            - If I(state=present) and if stack instance(s) exists and parameter_overrides has changed, it will be updated.
            - If I(state=absent), stack instance(s) will be removed.
        default: present
        choices: [ present, absent ]
        type: str
    retain_stacks:
        description:
            - Only applicable when I(state=absent).
            - By default, stack association with the stack set will be removed and instances will be deleted.
            - To keep stack instance and only remove the association to the stackset specify I(retain_stacks=true).
        type: bool
        default: true
    wait:
        description:
            - Whether or not to wait for stack instances operation to complete.
              This includes waiting for stack instances to reach UPDATE_COMPLETE status.
            - If you choose not to wait, this module will not notify when stack instance operations
              fail because it will not wait for them to finish.
        type: bool
        default: false
    wait_timeout:
        description:
            - How long to wait (in seconds) for stack instances to complete create/update/delete operations.
        default: 900
        type: int
    regions:
        description:
            - A list of AWS regions to create instances of a stack in.
            - At least one region must be specified to create a stack set. On updates,
              if fewer regions are specified only the specified regions will have their stack instances updated.
        type: list
        elements: str
    accounts:
        description:
            - A list of AWS accounts in which to create instance of CloudFormation stacksets.
            - At least one region must be specified to create a stack set. On updates,
              if fewer regions are specified only the specified regions will have their stack instances updated.
            - Specify only if the stackset was created without specifying PermissionModel or
              the PermissionModel is set to SELF_MANAGED.
        type: list
        elements: str
    deployment_targets:
        description:
            - The choice of deployment targets, either a set of accounts or organizational units, but not both.
        default: {}
        type: dict
        suboptions:
            accounts:
                description:
                    - A list of AWS accounts in which to create instance of CloudFormation stacksets.
                    - Specify only if the StackSet was created without specifying PermissionModel or
                      the PermissionModel was set to SELF_MANAGED.
                type: list
                elements: str
            organizational_unit_ids:
                description:
                    - A list of AWS organizational unit id(s) whose accounts will be used to create
                      instance of CloudFormation stacksets.
                    - Specify only if the StackSet was created with PermissionModel set to SERVICE_MANAGED.
                type: list
                elements: str
    failure_tolerance:
        description:
            - Settings to change what is considered "failed" when running stack instance updates, and how many to do at a time.
        type: dict
        suboptions:
            fail_count:
                description:
                    - The number of accounts, per region, for which this operation can fail before
                      CloudFormation stops the operation in that region.
                    - You must specify one of I(fail_count) and I(fail_percentage).
                type: int
            fail_percentage:
                type: int
                description:
                    - The percentage of accounts, per region, for which this stack operation can fail
                      before CloudFormation stops the operation in that region.
                    - You must specify one of I(fail_count) and I(fail_percentage).
            parallel_percentage:
                type: int
                description:
                    - The maximum percentage of accounts in which to perform this operation at one time.
                    - You must specify one of I(parallel_count) and I(parallel_percentage).
                    - Note that this setting lets you specify the maximum for operations.
                      For large deployments, under certain circumstances the actual percentage may be lower.
            parallel_count:
                type: int
                description:
                    - The maximum number of accounts in which to perform this operation at one time.
                    - I(parallel_count) may be at most one more than the I(fail_count).
                    - You must specify one of I(parallel_count) and I(parallel_percentage).
                    - Note that this setting lets you specify the maximum for operations.
                      For large deployments, under certain circumstances the actual count may be lower.

author:
    - Haris Fauzi (@harisfauzi)
    - Ryan Scott Brown (@ryansb)
requirements:
    - boto3 >= 1.14.0
    - botocore >= 1.17.7
extends_documentation_fragment:
    - amazon.aws.aws
    - amazon.aws.ec2
'''

EXAMPLES = r'''
- name: Create stack instance(s) with instances in two accounts
  community.aws.cloudformation_stack_set_instance:
    name: my-stack
    description: Test stack instance in two accounts
    state: present
    accounts: [1234567890, 2345678901]
    regions:
    - us-east-1

- name: Create stack instance(s) with instances in accounts using deployment_targets
  community.aws.cloudformation_stack_set_instance:
    name: my-stack
    description: Test stack instance in single account with stackset.permission_model = SELF_MANAGED
    state: present
    parameter_overrides:
      my_param_1: value1
      my_param_2: value2
    deployment_targets:
      accounts:
        - '1234567890'
    regions:
    - us-east-1

- name: Create stack instance(s) with instances in accounts under an OU
  community.aws.cloudformation_stack_set_instance:
    name: my-stack
    description: Test stack instance in accounts under an OU, with stackset.permission_model = SERVICE_MANAGED
    state: present
    deployment_targets:
      organizational_unit_ids:
      - ou-abcd1234
    regions:
    - us-east-1

- name: Remove stack instance(s) with instances in accounts under an OU
  community.aws.cloudformation_stack_set_instance:
    name: my-stack
    description: Delete stack instances in accounts under an OU
    state: absent
    deployment_targets:
      organizational_unit_ids:
      - ou-abcd1234
    regions:
    - us-east-1

- name: Remove stack instance assocation from accounts under an OU
  community.aws.cloudformation_stack_set_instance:
    name: my-stack
    description: Delete stack instances in accounts under an OU
    state: absent
    retain_stacks: Yes
    deployment_targets:
      organizational_unit_ids:
      - ou-abcd1234
    regions:
    - us-east-1

'''

RETURN = r'''
operations:
  description: All operations initiated by this run of the cloudformation_stack_set module
  returned: always
  type: list
  sample:
  - action: CREATE
    administration_role_arn: arn:aws:iam::1234567890:role/AWSCloudFormationStackSetAdministrationRole
    creation_timestamp: '2018-06-18T17:40:46.372000+00:00'
    end_timestamp: '2018-06-18T17:41:24.560000+00:00'
    execution_role_name: AWSCloudFormationStackSetExecutionRole
    operation_id: Ansible-StackInstance-Create-0ff2af5b-251d-4fdb-8b89-1ee444eba8b8
    operation_preferences:
      region_order:
      - us-east-1
      - us-east-2
    stack_set_id: TestStackPrime:19f3f684-aae9-4e67-ba36-e09f92cf5929
    status: SUCCEEDED

operations_log:
  type: list
  description: Most recent events in CloudFormation's event log. This may be from a previous run in some cases.
  returned: always
  sample:
  - action: CREATE
    creation_timestamp: '2018-06-18T17:40:46.372000+00:00'
    end_timestamp: '2018-06-18T17:41:24.560000+00:00'
    operation_id: Ansible-StackInstance-Create-0ff2af5b-251d-4fdb-8b89-1ee444eba8b8
    status: SUCCEEDED

stack_instances:
  description: CloudFormation stack instances that are members of this stack set. This will also include their region and account ID.
  returned: state == present
  type: list
  sample:
    - account: '1234567890'
      drift_status: NOT_CHECKED
      organizational_unit_id: ou-abc-d1234
      region: us-east-1
      stack_set_id: arn:aws:cloudformation:us-east-1:1234567890:stack/StackSet-my-stackset-f1e06cee-c1a7-41d7-a66e-5f09a2cb0b33/03f5d710-dcf6-11ea-9dc1-065724e5a374
      status: CURRENT
stack_set:
  type: dict
  description: Facts about the currently deployed stack set, its parameters, and its tags
  returned: state == present
  sample:
    administration_role_arn: arn:aws:iam::1234567890:role/AWSCloudFormationStackSetAdministrationRole
    capabilities: [ CAPABILITY_NAMED_IAM ]
    description: test stack PRIME
    execution_role_name: AWSCloudFormationStackSetExecutionRole
    parameters: []
    permission_model: SERVICE_MANAGED
    stack_set_arn: arn:aws:cloudformation:us-east-1:1234567890:stackset/my-stackset:19f3f684-aae9-467-ba36-e09f92cf5929
    stack_set_drift_detection_details:
      drift_status: NOT_CHECKED
      drifted_stack_instances_count: 0
      failed_stack_instances_count: 0
      in_progress_stack_instances_count: 0
      in_sync_stack_instances_count: 0
      total_stack_instances_count: 0
    stack_set_id: my-stackset:19f3f684-aae9-4e67-ba36-e09f92cf5929
    stack_set_name: my-stackset
    status: ACTIVE
    tags:
      Some: Thing
      an: other
    template_body: |
      AWSTemplateFormatVersion: "2010-09-09"
      Parameters: {}
      Resources:
        Bukkit:
          Type: "AWS::S3::Bucket"
          Properties: {}
        other:
          Type: "AWS::SNS::Topic"
          Properties: {}

'''  # NOQA

import time
import datetime
import uuid
import itertools

try:
    import boto3
    import botocore.exceptions
    from botocore.exceptions import ClientError, BotoCoreError
except ImportError:
    # handled by AnsibleAWSModule
    pass

from ansible_collections.amazon.aws.plugins.module_utils.ec2 import (
    AWSRetry,
    boto3_tag_list_to_ansible_dict,
    ansible_dict_to_boto3_tag_list,
    camel_dict_to_snake_dict,
)
from ansible_collections.amazon.aws.plugins.module_utils.core import AnsibleAWSModule, is_boto3_error_code
from ansible.module_utils._text import to_native


@AWSRetry.exponential_backoff(retries=5, delay=5)
def list_stack_instances_with_backoff(cfn, **kwargs):
    paginator = cfn.get_paginator('list_stack_instances')
    return paginator.paginate(**kwargs).build_full_result()['Summaries']


def list_stack_instances(module, cfn, stack_set_name):
    try:
        kwargs = {'StackSetName': stack_set_name}
        response = list_stack_instances_with_backoff(cfn, **kwargs)
        retval = []
        for stackset in response:
            retval.append(stackset)
        return retval
    except (botocore.exceptions.BotoCoreError, botocore.exceptions.ClientError) as e:
        module.fail_json_aws(e, msg="Error getting list of stack instances")


def create_stack_set(module, stack_params, cfn):
    try:
        cfn.create_stack_set(aws_retry=True, **stack_params)
        return await_stack_set_exists(cfn, stack_params['StackSetName'])
    except (ClientError, BotoCoreError) as err:
        module.fail_json_aws(err, msg="Failed to create stack set {0}.".format(stack_params.get('StackSetName')))


def update_stack_set(module, stack_params, cfn):
    # if the state is present and the stack already exists, we try to update it.
    # AWS will tell us if the stack template and parameters are the same and
    # don't need to be updated.
    try:
        cfn.update_stack_set(**stack_params)
    except is_boto3_error_code('StackSetNotFound') as err:  # pylint: disable=duplicate-except
        module.fail_json_aws(err, msg="Failed to find stack set. Check the name & region.")
    except is_boto3_error_code('StackInstanceNotFound') as err:  # pylint: disable=duplicate-except
        module.fail_json_aws(err, msg="One or more stack instances were not found for this stack set. Double check "
                             "the `accounts` and `regions` parameters.")
    except is_boto3_error_code('OperationInProgressException') as err:  # pylint: disable=duplicate-except
        module.fail_json_aws(
            err, msg="Another operation is already in progress on this stack set - please try again later. When making "
            "multiple cloudformation_stack_set calls, it's best to enable `wait: yes` to avoid unfinished op errors.")
    except (ClientError, BotoCoreError) as err:  # pylint: disable=duplicate-except
        module.fail_json_aws(err, msg="Could not update stack set.")
    if module.params.get('wait'):
        await_stack_set_operation(
            module, cfn, operation_id=stack_params['OperationId'],
            stack_set_name=stack_params['StackSetName'],
            max_wait=module.params.get('wait_timeout'),
        )

    return True


def get_stack_instances_from_ous(module, cfn, stack_set_name, organizational_unit_ids, regions):
    account_list = []
    all_instance_dict = {}
    try:
        list_stackset_instances = list_stack_instances(module, cfn, stack_set_name)
        # members of list_stackset_instances should have 'OrganizationalUnitId'
        # which we need to find if it matches organizational_unit_ids
        for instance in list_stackset_instances:
            if isinstance(instance, dict) and 'OrganizationalUnitId' in instance.keys():
                instance_region = instance['Region']
                instance_ouid = instance['OrganizationalUnitId']
                if instance_region in regions and instance_ouid in organizational_unit_ids:
                    instances_by_region = all_instance_dict[instance_region] if instance_region in all_instance_dict.keys() else {}
                    instances_by_ou = instances_by_region[instance_ouid] if instance_ouid in instances_by_region.keys() else {}
                    instances_by_ou[instance['Account']] = instance
                    instances_by_region[instance_ouid] = instances_by_ou
                    all_instance_dict[instance_region] = instances_by_region
    except (ClientError, BotoCoreError) as err:  # pylint: disable=duplicate-except
        module.fail_json_aws(err, msg="Could not get the list of stack instances.")
    return all_instance_dict


def get_stack_instances_from_accounts(module, cfn, stack_set_name, accounts, regions):
    all_instance_dict = {}
    try:
        list_stackset_instances = list_stack_instances(module, cfn, stack_set_name)
        # members of list_stackset_instances should have 'OrganizationalUnitId'
        # which we need to find if it matches organizational_unit_ids
        for instance in list_stackset_instances:
            if isinstance(instance, dict) and 'Account' in instance.keys():
                instance_region = instance['Region']
                instance_account = instance['Account']
                if instance_region in regions and instance_account in accounts:
                    instances_by_region = all_instance_dict[instance_region] if instance_region in all_instance_dict.keys() else {}
                    instances_by_region[instance['Account']] = instance
                    all_instance_dict[instance_region] = instances_by_region
    except (ClientError, BotoCoreError) as err:  # pylint: disable=duplicate-except
        module.fail_json_aws(err, msg="Could not get the list of stack instances.")
    return all_instance_dict


@AWSRetry.backoff(tries=3, delay=4)
def stack_set_facts(cfn, stack_set_name):
    try:
        ss = cfn.describe_stack_set(StackSetName=stack_set_name)['StackSet']
        ss['Tags'] = boto3_tag_list_to_ansible_dict(ss['Tags'])
        return ss
    except cfn.exceptions.from_code('StackSetNotFound'):
        # Return None if the stack doesn't exist
        return


def await_stack_set_operation(module, cfn, stack_set_name, operation_id, max_wait):
    wait_start = datetime.datetime.now()
    operation = None
    for i in range(max_wait // 15):
        try:
            operation = cfn.describe_stack_set_operation(StackSetName=stack_set_name, OperationId=operation_id)
            if operation['StackSetOperation']['Status'] not in ('RUNNING', 'STOPPING'):
                # Stack set has completed operation
                break
        except is_boto3_error_code('StackSetNotFound'):  # pylint: disable=duplicate-except
            pass
        except is_boto3_error_code('OperationNotFound'):  # pylint: disable=duplicate-except
            pass
        time.sleep(15)

    if operation and operation['StackSetOperation']['Status'] not in ('FAILED', 'STOPPED'):
        await_stack_instance_completion(
            module, cfn,
            stack_set_name=stack_set_name,
            # subtract however long we waited already
            max_wait=int(max_wait - (datetime.datetime.now() - wait_start).total_seconds()),
        )
    elif operation and operation['StackSetOperation']['Status'] in ('FAILED', 'STOPPED'):
        pass
    else:
        module.warn(
            "Timed out waiting for operation {0} on stack set {1} after {2} seconds. Returning unfinished operation".format(
                operation_id, stack_set_name, max_wait
            )
        )


def await_stack_instance_completion(module, cfn, stack_set_name, max_wait):
    to_await = None
    for i in range(max_wait // 15):
        try:
            stack_instances = cfn.list_stack_instances(StackSetName=stack_set_name)
            to_await = [inst for inst in stack_instances['Summaries']
                        if inst['Status'] != 'CURRENT']
            if not to_await:
                return stack_instances['Summaries']
        except is_boto3_error_code('StackSetNotFound'):  # pylint: disable=duplicate-except
            # this means the deletion beat us, or the stack set is not yet propagated
            pass
        time.sleep(15)

    module.warn(
        "Timed out waiting for stack set {0} instances {1} to complete after {2} seconds. Returning unfinished operation".format(
            stack_set_name, ', '.join(s['StackId'] for s in to_await), max_wait
        )
    )


def await_stack_set_exists(cfn, stack_set_name):
    # AWSRetry will retry on `StackSetNotFound` errors for us
    ss = cfn.describe_stack_set(StackSetName=stack_set_name, aws_retry=True)['StackSet']
    ss['Tags'] = boto3_tag_list_to_ansible_dict(ss['Tags'])
    return camel_dict_to_snake_dict(ss, ignore_list=('Tags',))


def describe_stack_tree(module, stack_set_name, operation_ids=None):
    jittered_backoff_decorator = AWSRetry.jittered_backoff(retries=5, delay=3, max_delay=5, catch_extra_error_codes=['StackSetNotFound'])
    cfn = module.client('cloudformation', retry_decorator=jittered_backoff_decorator)
    result = dict()
    result['stack_set'] = camel_dict_to_snake_dict(
        cfn.describe_stack_set(
            StackSetName=stack_set_name,
            aws_retry=True,
        )['StackSet']
    )
    result['stack_set']['tags'] = boto3_tag_list_to_ansible_dict(result['stack_set']['tags'])
    result['operations_log'] = sorted(
        camel_dict_to_snake_dict(
            cfn.list_stack_set_operations(
                StackSetName=stack_set_name,
                aws_retry=True,
            )
        )['summaries'],
        key=lambda x: x['creation_timestamp']
    )
    result['stack_instances'] = sorted(
        [
            camel_dict_to_snake_dict(i) for i in
            cfn.list_stack_instances(StackSetName=stack_set_name)['Summaries']
        ],
        key=lambda i: i['region'] + i['account']
    )

    if operation_ids:
        result['operations'] = []
        for op_id in operation_ids:
            try:
                result['operations'].append(camel_dict_to_snake_dict(
                    cfn.describe_stack_set_operation(
                        StackSetName=stack_set_name,
                        OperationId=op_id,
                    )['StackSetOperation']
                ))
            except is_boto3_error_code('OperationNotFoundException'):  # pylint: disable=duplicate-except
                pass
    return result


def get_operation_preferences(module):
    params = dict()
    if module.params.get('regions'):
        params['RegionOrder'] = list(module.params['regions'])
    for param, api_name in {
        'fail_count': 'FailureToleranceCount',
        'fail_percentage': 'FailureTolerancePercentage',
        'parallel_percentage': 'MaxConcurrentPercentage',
        'parallel_count': 'MaxConcurrentCount',
    }.items():
        if module.params.get('failure_tolerance', {}).get(param):
            params[api_name] = module.params.get('failure_tolerance', {}).get(param)
    return params


def main():
    argument_spec = dict(
        stack_set_name=dict(required=True),
        wait=dict(type='bool', default=False),
        wait_timeout=dict(type='int', default=900),
        state=dict(default='present', choices=['present', 'absent']),
        parameter_overrides=dict(type='list', elements='dict', options=dict(
            parameter_key=dict(type='str'),
            parameter_value=dict(type='str'),
            use_previous_value=dict(type='bool'),
            resolved_value=dict(type='str')
        )),
        regions=dict(type='list', elements='str'),
        accounts=dict(type='list', elements='str'),
        deployment_targets=dict(
            type='dict',
            default={},
            options=dict(
                accounts=dict(type='list', elements='str'),
                organizational_unit_ids=dict(type='list', elements='str')
            ),
            mutually_exclusive=[
                ['accounts', 'organizational_unit_ids']
            ]
        ),
        failure_tolerance=dict(
            type='dict',
            default={},
            options=dict(
                fail_count=dict(type='int'),
                fail_percentage=dict(type='int'),
                parallel_percentage=dict(type='int'),
                parallel_count=dict(type='int'),
            ),
            mutually_exclusive=[
                ['fail_count', 'fail_percentage'],
                ['parallel_count', 'parallel_percentage'],
            ],
        ),
        retain_stacks=dict(type='bool', default=True)
    )

    module = AnsibleAWSModule(
        argument_spec=argument_spec,
        mutually_exclusive=[['accounts', 'deployment_targets']],
        supports_check_mode=True
    )
    if not (module.boto3_at_least('1.14.0') and module.botocore_at_least('1.17.7')):
        module.fail_json(msg="Boto3 or botocore version is too low. This module requires at least boto3 1.14 and botocore 1.17.7")

    # Wrap the cloudformation client methods that this module uses with
    # automatic backoff / retry for throttling error codes
    jittered_backoff_decorator = AWSRetry.jittered_backoff(retries=10, delay=3, max_delay=30, catch_extra_error_codes=['StackSetNotFound'])
    cfn = module.client('cloudformation', retry_decorator=jittered_backoff_decorator)
    existing_stack_set = stack_set_facts(cfn, module.params['stack_set_name'])

    operation_uuid = to_native(uuid.uuid4())
    operation_ids = []
    # collect the parameters that are passed to boto3. Keeps us from having so many scalars floating around.
    stack_params = {}
    state = module.params['state']
    if state == 'present':
        if not module.params['accounts'] and not module.params['deployment_targets']:
            module.fail_json(
                msg="Can't create stack instance(s) without choosing at least one account or deployment target. "
            )
    else:
        if not module.params['retain_stacks']:
            module.fail_json(
                msg="Can't delete stack instance(s) without specifying retain_stacks. "
            )

    if module.params.get('accounts'):
        module.params['accounts'] = [to_native(a) for a in module.params['accounts']]

    stack_params['StackSetName'] = module.params['stack_set_name']

    stack_params['Regions'] = module.params['regions']

    stack_params['ParameterOverrides'] = []
    if module.params.get('parameter_overrides'):
        for parameter in module.params.get('parameter_overrides', {}):
            if isinstance(parameter, dict) and 'parameter_key' in parameter.keys():
                # set parameter based on a dict to allow additional CFN Parameter Attributes
                param = dict(ParameterKey=parameter['parameter_key'])

                if 'parameter_value' in parameter.keys():
                    param['ParameterValue'] = to_native(parameter['parameter_value'])

                if 'use_previous_value' in parameter.keys() and bool(parameter['use_previous_value']):
                    param['UsePreviousValue'] = True
                    param.pop('ParameterValue', None)

                stack_params['ParameterOverrides'].append(param)

    is_deploying_to_organizational_unit = False
    use_deployment_targets = False
    if module.params['accounts'] and len(module.params['accounts']) > 0:
        stack_params['Accounts'] = module.params['accounts']
    else:
        use_deployment_targets = True
        param_deployment_targets = {}
        deployment_targets = module.params['deployment_targets']
        if 'accounts' in deployment_targets.keys() and deployment_targets['accounts']:
            param_deployment_targets['Accounts'] = [to_native(a) for a in deployment_targets['accounts']]
        elif 'organizational_unit_ids' in deployment_targets.keys() and deployment_targets['organizational_unit_ids']:
            param_deployment_targets['OrganizationalUnitIds'] = [to_native(a) for a in deployment_targets['organizational_unit_ids']]
            is_deploying_to_organizational_unit = True
        stack_params['DeploymentTargets'] = param_deployment_targets

    result = {}

    if module.check_mode:
        if state == 'absent' and existing_stack_set:
            module.exit_json(changed=True, msg='Stack instance(s) would be deleted', meta=[])
        elif state == 'absent' and not existing_stack_set:
            module.exit_json(changed=False, msg='Stack set does not exist', meta=[])
        elif state == 'present' and not existing_stack_set:
            module.exit_json(changed=True, msg='Stack set does not exist', meta=[])
        elif state == 'present' and existing_stack_set:
            module.exit_json(changed=True, msg='New stack instance(s) would be created', meta=[])
        else:
            module.exit_json(changed=False, msg='No changes detected', meta=[])

    changed = False
    if state == 'present':
        if not existing_stack_set:
            module.exit_json(changed=False, msg='Stack set does not exist', meta=[])
        instances = cfn.list_stack_instances(
            StackSetName=module.params['stack_set_name'],
        )

        if use_deployment_targets:  # This must use SERVICE_MANAGED permission model
            if is_deploying_to_organizational_unit:
                instances = get_stack_instances_from_ous(
                    module,
                    cfn,
                    stack_params['StackSetName'],
                    stack_params['DeploymentTargets']['OrganizationalUnitIds'],
                    stack_params['Regions']
                )
            else:
                instances = get_stack_instances_from_accounts(
                    module,
                    cfn,
                    stack_params['StackSetName'],
                    stack_params['DeploymentTargets']['Accounts'],
                    stack_params['Regions']
                )
        else:
            instances = get_stack_instances_from_accounts(
                module,
                cfn,
                stack_params['StackSetName'],
                stack_params['Accounts'],
                stack_params['Regions']
            )
        # if new_stack_instances:
        if len(instances) == 0:
            operation_ids.append('Ansible-StackInstance-Create-{0}'.format(operation_uuid))
            changed = True
            # if use_deployment_targets we will supply DeploymentTargets
            # else we will supply Accounts
            if use_deployment_targets:
                cfn.create_stack_instances(
                    StackSetName=module.params['stack_set_name'],
                    DeploymentTargets=stack_params['DeploymentTargets'],
                    Regions=module.params['regions'],
                    OperationPreferences=get_operation_preferences(module),
                    OperationId=operation_ids[-1],
                )
            else:
                cfn.create_stack_instances(
                    StackSetName=module.params['stack_set_name'],
                    Accounts=stack_params['Accounts'],
                    Regions=module.params['regions'],
                    OperationPreferences=get_operation_preferences(module),
                    OperationId=operation_ids[-1],
                )
        else:
            operation_ids.append('Ansible-StackInstance-Update-{0}'.format(operation_uuid))
            # if use_deployment_targets we will supply DeploymentTargets
            # else we will supply Accounts.
            # Note from https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_DeploymentTargets.html
            # Can't use DeploymentTargets.Accounts for update operations.
            if use_deployment_targets and is_deploying_to_organizational_unit:
                cfn.update_stack_instances(
                    StackSetName=module.params['stack_set_name'],
                    DeploymentTargets=stack_params['DeploymentTargets'],
                    Regions=module.params['regions'],
                    OperationPreferences=get_operation_preferences(module),
                    OperationId=operation_ids[-1],
                )
            else:
                cfn.update_stack_instances(
                    StackSetName=module.params['stack_set_name'],
                    Accounts=stack_params['Accounts'],
                    Regions=module.params['regions'],
                    OperationPreferences=get_operation_preferences(module),
                    OperationId=operation_ids[-1],
                )
        for op in operation_ids:
            await_stack_set_operation(
                module, cfn, operation_id=op,
                stack_set_name=module.params['stack_set_name'],
                max_wait=module.params.get('wait_timeout'),
            )

    elif state == 'absent':
        if not existing_stack_set:
            module.exit_json(msg='Stack set {0} does not exist'.format(module.params['stack_set_name']))
        try:
            # if use_deployment_targets we will supply DeploymentTargets
            # else we will supply Accounts
            delete_instances_op = 'Ansible-StackInstance-Delete-{0}'.format(operation_uuid)
            if use_deployment_targets:
                cfn.delete_stack_instances(
                    StackSetName=module.params['stack_set_name'],
                    DeploymentTargets=stack_params['DeploymentTargets'],
                    Regions=module.params['regions'],
                    OperationPreferences=get_operation_preferences(module),
                    RetainStacks=module.params.get('retain_stacks'),
                    OperationId=delete_instances_op
                )
            else:
                cfn.delete_stack_instances(
                    StackSetName=module.params['stack_set_name'],
                    Accounts=stack_params['Accounts'],
                    Regions=module.params['regions'],
                    OperationPreferences=get_operation_preferences(module),
                    RetainStacks=module.params.get('retain_stacks'),
                    OperationId=delete_instances_op
                )
            await_stack_set_operation(
                module, cfn, operation_id=delete_instances_op,
                stack_set_name=stack_params['StackSetName'],
                max_wait=module.params.get('wait_timeout'),
            )
            module.exit_json(msg='Instances for stack set {0} deleted'.format(module.params['stack_set_name']))
        except is_boto3_error_code('OperationInProgressException') as e:  # pylint: disable=duplicate-except
            module.fail_json_aws(e, msg='Cannot delete instances for stack {0} while there is an operation in progress'.format(module.params['stack_set_name']))
        except (ClientError, BotoCoreError) as err:
            instances = cfn.list_stack_instances(
                StackSetName=module.params['stack_set_name'],
            )
            stack_states = ', '.join('(account={Account}, region={Region}, state={Status})'.format(**i) for i in instances['Summaries'])
            module.fail_json_aws(err, msg='Could not purge all stacks, or not all accounts/regions were chosen for deletion: ' + stack_states)

    result.update(**describe_stack_tree(module, stack_params['StackSetName'], operation_ids=operation_ids))
    if any(o['status'] == 'FAILED' for o in result['operations']):
        module.fail_json(msg="One or more operations failed to execute", **result)
    module.exit_json(changed=changed, **result)


if __name__ == '__main__':
    main()
