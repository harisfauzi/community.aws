#!/usr/bin/python
# Copyright: (c) 2018, Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: aws_cloudformation_stack_set
version_added: 2.10.1
short_description: Manage CloudFormation stack sets
description:
     - Launches/updates/deletes AWS CloudFormation StackSets.
notes:
     - To make an individual stack, you want the M(amazon.aws.cloudformation) module.
options:
    stack_set_name:
        description:
            - Name of the CloudFormation stack set.
        required: true
        type: str
    description:
        description:
            - A description of what this stack set creates.
        type: str
    parameters:
        description:
            - A list of hashes of all the template variables for the stack. The value can be a string or a dict.
            - Dict can be used to set additional template parameter attributes like UsePreviousValue (see example).
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
            - If I(state=present), stack will be created.
            - If I(state=present) and if stack exists and template has changed, it will be updated.
            - If I(state=absent), stack will be removed.
        default: present
        choices: [ present, absent ]
        type: str
    template:
        description:
            - The local path of the CloudFormation template.
            - This must be the full path to the file, relative to the working directory. If using roles this may look
              like C(roles/cloudformation/files/cloudformation-example.json).
            - If I(state=present) and the stack does not exist yet, either I(template), I(template_body) or I(template_url)
              must be specified (but only one of them).
            - If I(state=present), the stack does exist, and neither I(template), I(template_body) nor I(template_url)
              are specified, the previous template will be reused.
        type: path
    template_body:
        description:
            - Template body. Use this to pass in the actual body of
              the CloudFormation template.
            - If I(state=present) and the stack does not exist yet, either
              I(template), I(template_body) or I(template_url)
              must be specified (but only one of them).
            - If I(state=present), the stack does exist, and neither
              I(template), I(template_body) nor I(template_url)
              are specified, the previous template will be reused.
        type: str
    template_url:
        description:
            - Location of file containing the template body.
            - The URL must point to a template (max size 307,200 bytes) located
              in an S3 bucket in the same region as the stack.
            - If I(state=present) and the stack does not exist yet, either
              I(template), I(template_body) or I(template_url) must be
              specified (but only one of them).
            - If I(state=present), the stack does exist, and neither
              I(template), I(template_body) nor I(template_url) are specified,
              the previous template will be reused.
        type: str
    wait:
        description:
            - Whether or not to wait for stack operation to complete.
              This includes waiting for stack instances to reach UPDATE_COMPLETE
              status.
            - If you choose not to wait, this module will not notify when stack
              operations fail because it will not wait for them to finish.
        type: bool
        default: false
    wait_timeout:
        description:
            - How long to wait (in seconds) for stacks to complete
              create/update/delete operations.
        default: 900
        type: int
    capabilities:
        description:
            - Capabilities allow stacks to create and modify IAM resources,
              which may include adding users or roles.
            - Currently the only available values are 'CAPABILITY_IAM' and
              'CAPABILITY_NAMED_IAM'. Either or both may be provided.
            - >
                The following resources require that one or both of these
                parameters is specified: AWS::IAM::AccessKey,
                AWS::IAM::Group, AWS::IAM::InstanceProfile, AWS::IAM::Policy,
                AWS::IAM::Role, AWS::IAM::User, AWS::IAM::UserToGroupAddition.
        type: list
        elements: str
        choices:
            - 'CAPABILITY_IAM'
            - 'CAPABILITY_NAMED_IAM'
    administration_role_arn:
        description:
            - ARN of the administration role, meaning the role that
              CloudFormation StackSets use to assume the roles in your
              child accounts.
            - >
                This defaults to C(arn:aws:iam::{{ account ID }}:role/AWSCloudFormationStackSetAdministrationRole)
                where C({{ account ID }}) is replaced with the account
                number of the current IAM role/user/STS credentials.
        aliases:
            - admin_role_arn
            - admin_role
            - administration_role
        type: str
    execution_role_name:
        description:
            - ARN of the execution role, meaning the role that CloudFormation
              StackSets assumes in your child accounts.
            - This MUST NOT be an ARN, and the roles must exist in each child
              account specified.
            - The default name for the execution role is
              C(AWSCloudFormationStackSetExecutionRole).
        aliases:
            - exec_role_name
            - exec_role
            - execution_role
        type: str
    auto_deployment:
        description:
            - A structure to specify whether to automatically deploy the
              StackSets to the target organizational unit(s).
            - Specify only if permission_model is SERVICE_MANAGED.
        type: dict
        suboptions:
            enabled:
                description:
                    - Whether to enable the auto deployment to account(s)
                      under the specified Organizational Unit(s).
                type: bool
            retain_stacks_on_account_removal:
                description:
                    - Whether to retain stack resources when an account is
                      removed from target Organizational Unit(s).
                    - If set to false stack resources will be deleted.
                    - Only specify if enabled is set to true.
                type: bool
    permission_model:
        description:
            - Permission model for the required IAM roles when the stack set
              operations.
            - Currently the only available values are 'SELF_MANAGED' and
              'SERVICE_MANAGED'. Either one may be provided.
            - To have the stack instances deployed against Organizational
              Units, specify SERVICE_MANAGED.
        type: str
        choices:
            - 'SELF_MANAGED'
            - 'SERVICE_MANAGED'
        default: SELF_MANAGED
    tags:
        description:
            - Dictionary of tags to associate with stack and its resources
              during stack creation.
            - Can be updated later, updating tags removes previous entries.
        type: dict

author:
    - Haris Fauzi (@harisfauzi)
    - Ryan Scott Brown (@ryansb)
requirements:
  - boto3>=1.14.0
  - botocore>=1.17.7
extends_documentation_fragment:
    - amazon.aws.aws
    - amazon.aws.ec2
'''

EXAMPLES = r'''
- name: Create a stack set
  community.aws.aws_cloudformation_stack_set:
    name: my-stack
    description: Test stack in two accounts
    state: present
    template_url: https://s3.amazonaws.com/my-bucket/cloudformation.template
    regions:
    - us-east-1

- name: on subsequent calls, templates are optional but parameters and tags can be altered
  community.aws.aws_cloudformation_stack_set:
    name: my-stack
    state: present
    parameters:
      InstanceName: my_stacked_instance
    permission_model: SERVICE_MANAGED
    auto_deployment:
      enabled: Yes
      retain_stacks_on_account_removal: False
    tags:
      foo: bar
      test: stack
    regions:
    - us-east-1

- name: The same type of update, but wait for the update to complete in all stacks
  community.aws.aws_cloudformation_stack_set:
    name: my-stack
    state: present
    wait: true
    parameters:
      InstanceName: my_restacked_instance
    tags:
      foo: bar
      test: stack
    regions:
    - us-east-1

- name: Delete stack set
  community.aws.aws_cloudformation_stack_set:
    name: my-stack
    state: absent
'''

RETURN = r'''
operations_log:
  type: list
  description: Most recent events in CloudFormation's event log. This may be from a previous run in some cases.
  returned: always
  sample:
  - action: CREATE
    creation_timestamp: '2018-06-18T17:40:46.372000+00:00'
    end_timestamp: '2018-06-18T17:41:24.560000+00:00'
    operation_id: Ansible-StackInstance-Create-0ff2af5b-251d-4fdb-8b89-1ee444eba8b8
    status: FAILED
    stack_instances:
    - account: '1234567890'
      region: us-east-1
      stack_set_id: TestStackPrime:19f3f684-aae9-4e67-ba36-e09f92cf5929
      status: OUTDATED
      status_reason: Account 1234567890 should have 'AWSCloudFormationStackSetAdministrationRole' role with trust relationship to CloudFormation service.

operations:
  description: All operations initiated by this run of the aws_cloudformation_stack_set module
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
    status: FAILED
stack_set:
  type: dict
  description: Facts about the currently deployed stack set, its parameters, its tags, and the template_body
  returned: state == present
  sample:
    administration_role_arn: arn:aws:iam::1234567890:role/AWSCloudFormationStackSetAdministrationRole
    capabilities: []
    description: test stack PRIME
    execution_role_name: AWSCloudFormationStackSetExecutionRole
    parameters: []
    stack_set_arn: arn:aws:cloudformation:us-east-1:1234567890:stackset/TestStackPrime:19f3f684-aae9-467-ba36-e09f92cf5929
    stack_set_id: TestStackPrime:19f3f684-aae9-4e67-ba36-e09f92cf5929
    stack_set_name: TestStackPrime
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
import uuid

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
            "multiple aws_cloudformation_stack_set calls, it's best to enable `wait: yes` to avoid unfinished op errors.")
    except (ClientError, BotoCoreError) as err:  # pylint: disable=duplicate-except
        module.fail_json_aws(err, msg="Could not update stack set.")
    if module.params.get('wait'):
        await_stack_set_operation(
            module, cfn, operation_id=stack_params['OperationId'],
            stack_set_name=stack_params['StackSetName'],
            max_wait=module.params.get('wait_timeout'),
        )

    return True


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
        pass
    elif operation and operation['StackSetOperation']['Status'] in ('FAILED', 'STOPPED'):
        pass
    else:
        module.warn(
            "Timed out waiting for operation {0} on stack set {1} after {2} seconds. Returning unfinished operation".format(
                operation_id, stack_set_name, max_wait
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


def main():
    argument_spec = dict(
        stack_set_name=dict(required=True),
        description=dict(type='str', default=None),
        wait=dict(type='bool', default=False),
        wait_timeout=dict(type='int', default=900),
        state=dict(default='present', choices=['present', 'absent']),
        parameters=dict(type='list', elements='dict', options=dict(
            parameter_key=dict(type='str'),
            parameter_value=dict(type='str'),
            use_previous_value=dict(type='bool'),
            resolved_value=dict(type='str')
        )),
        permission_model=dict(type='str', choices=['SERVICE_MANAGED', 'SELF_MANAGED'], default='SELF_MANAGED'),
        auto_deployment=dict(
            type='dict',
            default=None,
            options=dict(
                enabled=dict(type='bool'),
                retain_stacks_on_account_removal=dict(type='bool')
            )
        ),
        template=dict(type='path'),
        template_url=dict(type='str'),
        template_body=dict(type='str'),
        capabilities=dict(type='list', elements='str', choices=['CAPABILITY_IAM', 'CAPABILITY_NAMED_IAM']),
        administration_role_arn=dict(aliases=['admin_role_arn', 'administration_role', 'admin_role']),
        execution_role_name=dict(aliases=['execution_role', 'exec_role', 'exec_role_name']),
        tags=dict(type='dict')
    )

    module = AnsibleAWSModule(
        argument_spec=argument_spec,
        mutually_exclusive=[['template_url', 'template', 'template_body']],
        supports_check_mode=True
    )
    if not (module.boto3_at_least('1.14.0') and module.botocore_at_least('1.17.7')):
        module.fail_json(msg="Boto3 or botocore version is too low. This module requires at least boto3 1.6 and botocore 1.10.26")

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
    stack_params['StackSetName'] = module.params['stack_set_name']
    if module.params.get('description'):
        stack_params['Description'] = module.params['description']

    if module.params.get('capabilities'):
        stack_params['Capabilities'] = module.params['capabilities']

    if module.params['template'] is not None:
        with open(module.params['template'], 'r') as tpl:
            stack_params['TemplateBody'] = tpl.read()
    elif module.params['template_body'] is not None:
        stack_params['TemplateBody'] = module.params['template_body']
    elif module.params['template_url'] is not None:
        stack_params['TemplateURL'] = module.params['template_url']
    else:
        # no template is provided, but if the stack set exists already, we can use the existing one.
        if existing_stack_set:
            stack_params['UsePreviousTemplate'] = True
        else:
            module.fail_json(
                msg="The Stack Set {0} does not exist, and no template was provided. Provide one of `template`, "
                    "`template_body`, or `template_url`".format(module.params['stack_set_name'])
            )

    stack_params['Parameters'] = []
    if module.params.get('parameters'):
        for k, v in module.params.get('parameters', {}).items():
            if isinstance(v, dict):
                # set parameter based on a dict to allow additional CFN Parameter Attributes
                param = dict(ParameterKey=k)

                if 'value' in v:
                    param['ParameterValue'] = to_native(v['value'])

                if 'use_previous_value' in v and bool(v['use_previous_value']):
                    param['UsePreviousValue'] = True
                    param.pop('ParameterValue', None)

                stack_params['Parameters'].append(param)
            else:
                # allow default k/v configuration to set a template parameter
                stack_params['Parameters'].append({'ParameterKey': k, 'ParameterValue': str(v)})

    if module.params.get('tags') and isinstance(module.params.get('tags'), dict):
        stack_params['Tags'] = ansible_dict_to_boto3_tag_list(module.params['tags'])

    if module.params.get('administration_role_arn'):
        # TODO loosen the semantics here to autodetect the account ID and build the ARN
        stack_params['AdministrationRoleARN'] = module.params['administration_role_arn']
    if module.params.get('execution_role_name'):
        stack_params['ExecutionRoleName'] = module.params['execution_role_name']
    if module.params.get('permission_model'):
        stack_params['PermissionModel'] = module.params.get('permission_model')
    if module.params.get('auto_deployment'):
        # Sanity check, auto_deployment is only defined if PermissionModel == 'SERVICE_MANAGED'
        if module.params.get('permission_model') != 'SERVICE_MANAGED':
            module.fail_json(msg="Only specify auto_deployment if permission_model is SERVICE_MANAGED.")
        param_auto_deployment = {}
        if module.params.get('auto_deployment', {}).get('enabled') is not None:
            param_auto_deployment['Enabled'] = module.params.get('auto_deployment', {}).get('enabled')
        if module.params.get('auto_deployment', {}).get('retain_stacks_on_account_removal') is not None:
            param_auto_deployment['RetainStacksOnAccountRemoval'] = module.params.get('auto_deployment', {}).get('retain_stacks_on_account_removal')
        if param_auto_deployment:
            stack_params['AutoDeployment'] = param_auto_deployment

    result = {}

    if module.check_mode:
        if state == 'absent' and existing_stack_set:
            module.exit_json(changed=True, msg='Stack set would be deleted', meta=[])
        elif state == 'absent' and not existing_stack_set:
            module.exit_json(changed=False, msg='Stack set doesn\'t exist', meta=[])
        elif state == 'present' and not existing_stack_set:
            module.exit_json(changed=True, msg='New stack set would be created', meta=[])
        elif state == 'present' and existing_stack_set:
            module.exit_json(changed=True, msg='Existing stack set would be updated', meta=[])
        else:
            # TODO: need to check the template and other settings for correct check mode
            module.exit_json(changed=False, msg='No changes detected', meta=[])

    changed = False
    if state == 'present':
        if not existing_stack_set:
            # on create this parameter has a different name, and cannot be referenced later in the job log
            stack_params['ClientRequestToken'] = 'Ansible-StackSet-Create-{0}'.format(operation_uuid)
            changed = True
            create_stack_set(module, stack_params, cfn)
        else:
            stack_params['OperationId'] = 'Ansible-StackSet-Update-{0}'.format(operation_uuid)
            operation_ids.append(stack_params['OperationId'])
            changed |= update_stack_set(module, stack_params, cfn)

    elif state == 'absent':
        if not existing_stack_set:
            module.exit_json(msg='Stack set {0} does not exist'.format(module.params['stack_set_name']))
        try:
            cfn.delete_stack_set(
                StackSetName=module.params['stack_set_name'],
            )
            module.exit_json(msg='Stack set {0} deleted'.format(module.params['stack_set_name']))
        except is_boto3_error_code('OperationInProgressException') as e:  # pylint: disable=duplicate-except
            module.fail_json_aws(e, msg='Cannot delete stack {0} while there is an operation in progress'.format(module.params['stack_set_name']))
        except is_boto3_error_code('StackSetNotEmptyException'):  # pylint: disable=duplicate-except
            try:
                cfn.delete_stack_set(
                    StackSetName=module.params['stack_set_name'],
                )
            except is_boto3_error_code('StackSetNotEmptyException') as exc:  # pylint: disable=duplicate-except
                module.fail_json_aws(exc, msg='Could not purge stacks, or not all accounts/regions were chosen for deletion')
            module.exit_json(changed=True, msg='Stack set {0} deleted'.format(module.params['stack_set_name']))

    result.update(**describe_stack_tree(module, stack_params['StackSetName'], operation_ids=operation_ids))
    if 'operations' in result.keys():
        if any(o['status'] == 'FAILED' for o in result['operations']):
            module.fail_json(msg="One or more operations failed to execute", **result)
    module.exit_json(changed=changed, **result)


if __name__ == '__main__':
    main()
