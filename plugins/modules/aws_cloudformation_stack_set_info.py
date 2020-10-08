#!/usr/bin/python
# Copyright: Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: aws_cloudformation_stack_set_info
version_added: 1.0.0
short_description: Obtain information about an AWS CloudFormation stackset
description:
  - Gets information about an AWS CloudFormation stackset.
requirements:
  - boto3 >= 1.14.0
  - python >= 2.7
author:
    - Haris Fauzi (@harisfauzi)
options:
    stack_set_name:
        description:
          - The name of the CloudFormation stackset. Gathers information on all stacks by default.
        type: str
    stack_instances:
        description:
            - Get the list of deployed stack instances for the stackset.
        type: bool
        default: false

extends_documentation_fragment:
    - aws
    - ec2
'''

EXAMPLES = r'''
# Note: These examples do not set authentication details, see the AWS Guide for details.

- name: Get summary information about a stack
  community.aws.aws_cloudformation_stack_set_info:
    stack_set_name: my-cloudformation-stack
  register: output

- debug:
    msg: "{{ output['cloudformation']['my-cloudformation-stack'] }}"

# Get stack instances information about a stack
- amazon.aws.aws_cloudformation_stack_set_info:
    stack_set_name: my-cloudformation-stack
    stack_instances: true

'''

RETURN = '''
stack_description:
    description: Summary facts about the stackset
    returned: if the stackset exists
    type: dict
stack_instances:
    description: Describes stack instances for the stackset
    returned: only if stack_instances is true and the stackset exists
    type: list
'''

import json
import traceback
from functools import partial

try:
    import botocore
except ImportError:
    pass  # Handled by AnsibleAWSModule

from ansible.module_utils._text import to_native
from ansible.module_utils.common.dict_transformations import camel_dict_to_snake_dict

from ansible_collections.amazon.aws.plugins.module_utils.core import AnsibleAWSModule
from ansible_collections.amazon.aws.plugins.module_utils.ec2 import AWSRetry
from ansible_collections.amazon.aws.plugins.module_utils.ec2 import boto3_tag_list_to_ansible_dict


class CloudFormationStacksetServiceManager:
    """Handles CloudFormation StackSet Services"""

    def __init__(self, module):
        self.module = module
        self.client = module.client('cloudformation')

    @AWSRetry.exponential_backoff(retries=5, delay=5)
    def describe_stack_sets_with_backoff(self, **kwargs):
        paginator = self.client.get_paginator('list_stack_sets')
        return paginator.paginate(**kwargs).build_full_result()['Summaries']

    def describe_stack_sets(self, stack_set_name=None, stack_status='ACTIVE'):
        try:
            kwargs = {'Status': stack_status}
            response = self.describe_stack_sets_with_backoff(**kwargs)
            if response is not None:
                if stack_set_name:
                    filtered_response = []
                    for stack_set in response:
                        if stack_set['StackSetName'] == stack_set_name:
                            filtered_response.append(stack_set)
                    return filtered_response
                return response
            self.module.fail_json(msg="Error describing stackset(s) - an empty response was returned")
        except (botocore.exceptions.BotoCoreError, botocore.exceptions.ClientError) as e:
            self.module.fail_json_aws(e, msg="Error describing stackset")

    @AWSRetry.exponential_backoff(retries=5, delay=5)
    def list_stack_instances_with_backoff(self, **kwargs):
        paginator = self.client.get_paginator('list_stack_instances')
        return paginator.paginate(**kwargs).build_full_result()['Summaries']

    def list_stack_instances(self, stack_set_name):
        try:
            kwargs = {'StackSetName': stack_set_name}
            return self.list_stack_instances_with_backoff(**kwargs)
        except (botocore.exceptions.BotoCoreError, botocore.exceptions.ClientError) as err:
            self.module.fail_json_aws(
                err,
                msg="Error listing stack instances for stackset {0}".format(stack_set_name)
            )


def to_dict(items, key, value):
    ''' Transforms a list of items to a Key/Value dictionary '''
    if items:
        return dict(zip([i.get(key) for i in items], [i.get(value) for i in items]))
    else:
        return dict()


def main():
    argument_spec = dict(
        stack_set_name=dict(type='str'),
        all_facts=dict(required=False, default=False, type='bool'),
        stack_instances=dict(required=False, default=False, type='bool')
    )
    module = AnsibleAWSModule(argument_spec=argument_spec, supports_check_mode=True)

    service_mgr = CloudFormationStacksetServiceManager(module)

    result = {'cloudformation': {}}

    for stack_description in service_mgr.describe_stack_sets(module.params.get('stack_set_name')):
        facts = {'stack_description': stack_description}
        stack_set_name = stack_description.get('StackSetName')

        # Create optional stack outputs
        all_facts = module.params.get('all_facts')
        if all_facts or module.params.get('stack_instances'):
            facts['stack_instances'] = service_mgr.list_stack_instances(stack_set_name)

        result['cloudformation'][stack_set_name] = camel_dict_to_snake_dict(
            facts,
            ignore_list=(
                'stack_outputs',
                'stack_parameters',
                'stack_policy',
                'stack_resources',
                'stack_tags',
                'stack_template')
        )

    module.exit_json(changed=False, **result)


if __name__ == '__main__':
    main()
