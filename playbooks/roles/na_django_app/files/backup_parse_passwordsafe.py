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