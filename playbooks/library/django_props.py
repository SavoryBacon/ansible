
# -*- coding: utf-8 -*-

DOCUMENTATION = '''
---
module: django_props
short_description: Loads django properties to ansible variable
description:
     - The M(django_props) module loads data from the provided YAML file, links missing credentials in PasswordSafe,
       and returns all django properties in a JSON-like datastructure.
options:
  properties_file:
    description:
      - The location of the properties file to load.
    required: true
  credentials_file:
    description:
      - The location of the PasswordSafe file (must be in the file format ".psafe3").
    required: false
  credentials_key:
    description:
      - Password used to decrypt the PasswordSafe file.
    required: true if C(credentials_file) is used
  application_name:
    description:
      - The name of the application (as it appears in PasswordSafe).
    required: true if C(credentials_file) is used
  virtualenv:
    description:
      - If selected, module will generate a script and use specified virtualenv to run it.
    required: false
  tmp_dir:
    description:
      - The directory location of the temporary script that may be generated.
    required: false
    default: /tmp
'''

EXAMPLES = '''
# Load properties, and use a PasswordSafe file to fill in protected credentials.
- django_props:
    properties_file: "{{app_properties_file}}"
    credentials_file: "{{password_file}}"
    credentials_key: "{{master_password}}"
    application_name: "{{project}}"
  delegate_to: 127.0.0.1
  run_once: true
  register: app_props

'''

SCRIPT_FILE_CONTENTS='''
from tds_passwordsafe.tds_passwordsafe import PasswordSafeV3
import click
import os
import sys

# Click needs this set in python3 because reasons
# http://click.pocoo.org/5/python3/#python-3-surrogate-handling
os.environ['LC_ALL'] = 'en_US.utf-8'
os.environ['LANG'] = 'en_US.utf-8'

@click.command()
@click.argument('pws_filename', type=click.Path(exists=True))
@click.argument('master_password')
@click.option('--non-database', '-n', 'non_database', is_flag=True)
@click.option('--db-user', '-u', 'user')
@click.option('--db-name', '-d', 'database_name')
@click.option('--app', '-a', 'app_name')
@click.option('--level', '-l', 'variable_level', default='app')
@click.option('--pws-title', '-t', 'pws_title')
@click.option('--pws-attr', '-k', 'pws_attr', type=click.Choice(['user', 'password']))
def main(pws_filename, master_password, non_database, user,
         database_name, app_name, variable_level, pws_title, pws_attr):
    """Ansible expects a single line of output: The password."""
    group_path = ['NA_Systems', 'Network', 'Ansible', 'Automation',]
    if not non_database:
        check_argument(user, "'--db-user' or '-u' is a required parameter.")
        check_argument(database_name, "'--db-name' or '-d' is a required parameter.")
        output = get_database_record(pws_filename, master_password, group_path, user, database_name)
    else:
        check_argument(app_name, "'--app' or '-a' is a required parameter.")
        check_argument(variable_level, "'--level' or '-l' is a required parameter.")
        check_argument(pws_title, "'--pws-title' or '-t' is a required parameter.")
        check_argument(pws_attr, "'--pws-attr' or '-k' is a required parameter.")
        output = get_non_database_record(pws_filename, master_password, group_path, app_name, variable_level, pws_title, pws_attr)
    click.echo(output)

def get_database_record(pws_filename, master_password, group_path, user, database_name):
    group_path.extend(['Datasources', database_name.upper()])
    na_pws = PasswordSafeV3(pws_filename, master_password)
    record = na_pws.get_record_by_username(user, group_path=group_path)
    return record.passwd

def get_non_database_record(pws_filename, master_password, group_path, app_name, variable_level, pws_title, pws_attr):
    group_path.append('Protected_Variables')
    if variable_level == 'app':
        group_path.append(app_name.lower())
    else:
        group_path.append('common')
    na_pws = PasswordSafeV3(pws_filename, master_password)
    record = na_pws.get_record_by_title(pws_title, group_path=group_path)
    if pws_attr == 'user':
        result = record.user
    elif pws_attr == 'password':
        result = record.passwd
    return result

def check_argument(arg, message):
    """Verifies argument is present and exits otherwise."""
    if arg is None:
        click.echo(message, err=True)
        sys.exit(1)

if __name__ == '__main__':
    main()
'''

DATABASE_COMMAND='''{} {} {} {} -u {} -d {}'''
PROTECTED_CREDENTIALS_COMMAND='''{} {} {} {} -n -a {} -l {} -t '{}' -k {}'''

YAML_FILE_SCHEMA = {
    'type': 'object',
    'properties': {
        'remote_app_port': {
            'type': 'string',
        },
        'db_creds': {
            'type': 'array',
            'items': {
                'type': 'object',
                'properties': {
                    'env_var': {
                        'type': 'string'
                    },
                    'database': {
                        'type': 'string'
                    },
                    'user': {
                        'type': 'string'
                    },
                    'db_type': {
                        'type': 'string',
                        'enum': ['oracle'],
                    },
                    'hosts': {
                        'type': 'array',
                        'items': {
                            'type': 'string'
                        },
                    },
                },
                'required': ['env_var', 'database', 'user', 'db_type',],
            }
        },
        'non_db_creds': {
            'type': 'array',
            'items': {
                'type': 'object',
                'properties': {
                    'env_var': {
                        'type': 'string'
                    },
                    'title': {
                        'type': 'string'
                    },
                    'attr': {
                        'type': 'string'
                    },
                    'variable_level': {
                        'type': 'string',
                        'enum': ['common', 'app'],
                    },
                    'hosts': {
                        'type': 'array',
                        'items': {
                            'type': 'string'
                        },
                    },
                },
                'required': ['env_var', 'title', 'attr', 'variable_level',],
            }
        },
        'other_envs': {
            'type': 'array',
            'items': {
                'type': 'object',
                'properties': {
                    'env_var': {
                        'type': 'string'
                    },
                    'value': {
                        'type': 'string'
                    },
                    'hosts': {
                        'type': 'array',
                        'items': {
                            'type': 'string'
                        },
                    },
                },
                'required': ['env_var', 'value',],
            },
        },
    },
    'required': ['remote_app_port',],
}

import os
import yaml
import uuid
import datetime
import jsonschema
from ansible.module_utils.basic import AnsibleModule

def test(module, something):
    command = 'echo {}'.format(something)
    return command, module.run_command(command)

def load_yaml_file(module, yaml_file):
    if not os.path.exists(yaml_file):
        module.fail_json(
            msg="File '{}' does not exist.".format(yaml_file)
        )
    with open(yaml_file, 'r') as f:
        data = yaml.load(f)
    validator = jsonschema.Draft4Validator(YAML_FILE_SCHEMA)
    errors = [str(e) for e in sorted(validator.iter_errors(data), key=str)]
    if len(errors) > 0:
        message = ("The following configuration errors were "
                   "found while loading the App Config:\n{}"
                   ).format("\n\n".join(errors))
        module.fail_json(msg=message)
    return data

def find_passwords_from_script(module, python_executable, credentials_file,
                               credentials_key, application_name, databases,
                               other_protected_items, tmp_dir, current_host):
    new_filename = 'parse_passwordsafe-{}.py'.format(uuid.uuid1())
    new_filepath = os.path.join(tmp_dir, new_filename)
    new_databases = []
    new_other_protected_items = []
    try:
        with open(new_filepath, 'w') as f:
                f.write(SCRIPT_FILE_CONTENTS)
        for index in range(len(databases)):
            configured_hosts = databases[index].get('hosts', [])
            if not len(configured_hosts) or current_host in configured_hosts:
                new_database = databases[index]
                command = DATABASE_COMMAND.format(
                    python_executable,
                    new_filepath,
                    credentials_file,
                    credentials_key,
                    databases[index]['user'],
                    databases[index]['database'],
                )
                rc, out, err = module.run_command(command)
                if rc != 0 or err:
                    module.fail_json(msg='Database script call failed: cmd: {}, code: {}, stderr; {}'.format(command, rc, err))
                new_database['password'] = out.strip()
                new_databases.append(new_database)
        for index in range(len(other_protected_items)):
            configured_hosts = other_protected_items[index].get('hosts', [])
            if not len(configured_hosts) or current_host in configured_hosts:
                new_other_protected_item = other_protected_items[index]
                command = PROTECTED_CREDENTIALS_COMMAND.format(
                    python_executable,
                    new_filepath,
                    credentials_file,
                    credentials_key,
                    application_name,
                    other_protected_items[index]['variable_level'],
                    other_protected_items[index]['title'],
                    other_protected_items[index]['attr'],
                )
                rc, out, err = module.run_command(command)
                if rc != 0 or err:
                    module.fail_json(msg='Non-database script call failed: cmd: {}, code: {}, stderr: {}'.format(command, rc, err))
                new_other_protected_item['value'] = out.strip()
                new_other_protected_items.append(new_other_protected_item)
    finally:
        try:
            os.remove(new_filepath)
        except OSError:
            raise
    return new_databases, new_other_protected_items

def load_and_format_data(module, data, tmp_dir, application_name, current_host,
                         credentials_file=None, credentials_key=None, python_executable=None):
    result_data = {
        'environment': {'other_envs': [], 'databases': [], 'other_protected_items': []},
        'deployment': {},
    }
    if 'other_envs' in data:
        for environment_variable in data['other_envs']:
            configured_hosts = environment_variable.get('hosts', [])
            if not len(configured_hosts) or current_host in configured_hosts:
                result_data['environment']['other_envs'].append(environment_variable)
    if 'db_creds' in data or 'non_db_creds' in data:
        if credentials_file is None or credentials_key is None:
            module.fail_json(
                msg="credentials_file and credentials_key must be specified when db_creds or non_db_creds are present."
            )
        if python_executable:
            databases, other_protected_items = find_passwords_from_script(
                module,
                python_executable,
                credentials_file,
                credentials_key,
                application_name,
                databases=data.get('db_creds', []),
                other_protected_items=data.get('non_db_creds', []),
                tmp_dir=tmp_dir,
                current_host=current_host,
            )
            result_data['environment']['databases'] = databases
            result_data['environment']['other_protected_items'] = other_protected_items
        else:
            module.fail_json(msg="Native password parsing is not available in Python 2.x. Try using python_executable.")
    result_data['deployment'].update(
        {key: value for key, value in data.items() if key not in ['db_creds', 'non_db_creds', 'other_envs']}
    )
    return result_data

def main():
    changed = False

    module = AnsibleModule(
        argument_spec=dict(
            properties_file=dict(required=True, type='path'),
            credentials_file=dict(type='path'),
            credentials_key=dict(type='str'),
            python_executable=dict(required=False, type='path'),
            tmp_dir=dict(required=False, type='path', default='/tmp'),
            application_name=dict(required=True, type='str'),
            current_host=dict(required=True, type='str'),
        ),
        required_together=[
            ['credentials_file', 'credentials_key', 'application_name'],
        ],
    )
    startd = datetime.datetime.now()
    # (command, (rc, out, err)) = test(module, module.params['echo'])
    base_yaml_data = load_yaml_file(module, module.params['properties_file'])
    yaml_data = load_and_format_data(
        module=module,
        data=base_yaml_data,
        tmp_dir=module.params['tmp_dir'],
        application_name=module.params['application_name'],
        current_host=module.params.get('current_host'),
        credentials_file=module.params.get('credentials_file'),
        credentials_key=module.params.get('credentials_key'),
        python_executable=module.params.get('python_executable'),
    )
    endd = datetime.datetime.now()
    delta = endd - startd

    module.exit_json(
        properties_file=module.params['properties_file'],
        credentials_file=module.params.get('credentials_file', ""),
        credentials_key='**********' if module.params.get('credentials_key') else "",
        python_executable=module.params.get('python_executable',""),
        tmp_dir=module.params['tmp_dir'],
        application_name=module.params['application_name'],
        current_host=module.params['current_host'],
        data=yaml_data,
        start=str(startd),
        end=str(endd),
        delta=str(delta),
        changed=changed,
    )

if __name__ == '__main__':
    main()