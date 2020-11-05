import os
import unittest
import coverage
from pybadges import badge
from flask_migrate import Migrate, MigrateCommand
from flask_script import Manager

from app import create_app, db
from app.models import AuthTokenBlacklist, GlobalSettings, User, Role, Permission, DataType, EventStatus, AgentRole, CaseStatus, Organization, CloseReason

app = create_app()
app.app_context().push()
manager = Manager(app)
migrate = Migrate(app, db)
manager.add_command('db', MigrateCommand)
COV = coverage.coverage(
    branch=True, include='app/*',
    omit=['*/__init__.py','__pycache__'],
    data_file='.coverage',
    config_file='.coveragerc'
)

@manager.command
def run():
    app.run(port=80)

@manager.command
def test():
    """Runs the unit tests."""
    tests = unittest.TestLoader().discover('tests', pattern='test*.py')
    result = unittest.TextTestRunner(verbosity=2).run(tests)
    if result.wasSuccessful():
        return 0
    return 1

@manager.command
def coverage(test='*', verbosity=1):
    COV.start()
    suite = unittest.TestLoader().discover('tests', pattern='{}.py'.format(test))
    result = unittest.TextTestRunner(verbosity=int(verbosity)).run(suite)
    COV.stop()
    COV.save()
    print('Coverage Summary:')
    COV.report()
    basedir = os.path.abspath(os.path.dirname(__file__))
    covdir = os.path.join(basedir, 'tmp/coverage')
    COV.html_report(directory=covdir)
    print('HTML Version: file://%s/index.html' % covdir)
    if result.wasSuccessful():
        os.system('coverage-badge -f -o coverage.svg')
        return 0
        
    return 1

@manager.command
def security():
    pipenv_check_results = os.popen('pipenv check').read()
    if 'Passed!' in pipenv_check_results:
        s = badge(left_text='PEP 508', right_text='Passing', right_color='green')
    else:
        s = badge(left_text='PEP 508', right_text='Failing', right_color='red')

    with open('pep508.svg', 'w') as f:
        f.write(s)
        f.close()

    if 'All good!' in pipenv_check_results:
        s = badge(left_text='Vulnerable', right_text='Passing', right_color='green')
    else:
        s = badge(left_text='Vulnerable', right_text='Failing', right_color='red')

    with open('vulnerable.svg', 'w') as f:
        f.write(s)
        f.close()  

@manager.command
def blacklist_token(token):

    blacklist = AuthTokenBlacklist(auth_token = token)
    blacklist.create()


def create_org(name, description):
    print("Creating new organization %s" % name)
    organization = Organization(name=name, description=description)
    organization.create()
    return organization

def create_default_settings(org):
    base_settings = {
        'base_url': 'http://localhost'
    }
    print("Creating default settings for %s" % org.name)
    settings = GlobalSettings(**base_settings)
    settings.organization = org
    settings.create()

def create_super_admin(org):
    print("Creating super user for %s" % org.name)
    perms = { 
        'add_user': True,
        'update_user': True,
        'delete_user': True,
        'add_user_to_role': True,
        'remove_user_from_role': True,
        'reset_user_password': True,
        'unlock_user': True,
        'view_users': True,
        'add_role': True,
        'update_role': True,
        'delete_role': True,
        'set_role_permissions': True,
        'view_roles': True,
        "add_tag": True,
        "update_tag": True,
        "delete_tag": True,
        "view_tags": True,
        "add_credential": True,
        "update_credential": True,
        "decrypt_credential": True,
        "delete_credential": True,
        "view_credentials": True ,
        "add_playbook": True,
        "update_playbook": True,
        "delete_playbook": True,
        "view_playbooks": True,
        "add_tag_to_playbook": True,
        "remove_tag_from_playbook": True,
        "add_event": True,
        "view_events": True,
        "update_event": True,
        "delete_event": True,
        "add_tag_to_event": True,
        "remove_tag_from_event": True,
        "add_observable": True,
        "update_observable": True,
        "delete_observable": True,
        "add_tag_to_observable": True,
        "remove_tag_from_observable": True,
        "view_agents": True,
        "update_agent": True,
        "delete_agent": True,
        "pair_agent": True,
        "add_input": True,
        "view_inputs": True,
        "update_input": True,
        "delete_input": True,
        "create_case": True,
        "view_cases": True,
        "update_case": True,
        "delete_case": True,
        "create_case_comment": True,
        "view_case_comments": True,
        "update_case_comment": True,
        "delete_case_comment": True,
        "view_plugins": True,
        "create_plugin": True,
        "delete_plugin": True,
        "update_plugin": True,
        "create_agent_group": True,
        "view_agent_groups": True,
        "update_agent_group": True,
        "delete_agent_group": True,
        "create_user_group": True,
        "view_user_groups": True,
        "update_user_groups": True,
        "delete_user_group": True,
        "create_case_template": True,
        "view_case_templates": True,
        "update_case_template": True,
        "delete_case_template": True,
        "create_case_task": True,
        "view_case_tasks": True,
        "update_case_task": True,
        "delete_case_task": True,
        "create_case_template_task": True,
        "view_case_template_tasks": True,
        "update_case_template_task": True,
        "delete_case_template_task": True,
        "create_case_status": True,
        "update_case_status": True,
        "delete_case_status": True,
        'update_settings': True,
        'view_settings': True,
        "add_organization": True,
        "view_organizatons": True,
        "update_organization": True,
        "delete_organization": True,
        "use_api": True,
        "add_list": True,
        "update_list": True,
        "view_lists": True,
        "delete_list": True,
        "create_data_type": True,
        "update_data_type": True,
        "create_persistent_pairing_token": True,
        "create_event_rule": True,
        "update_event_rule": True,
        "delete_event_rule": True,
        "view_event_rules": True,
        'upload_case_files': True,
        'view_case_files': True,
        'delete_case_files': True
    }
    permissions = Permission(**perms)
    permissions.organization = org
    permissions.create()

    # Create the administrator role
    details =  {
        'name': 'Super Admin',
        'description': 'Power overwhelming'
    }
    role = Role(**details)
    role.create()

    role.permissions = permissions
    role.organization = org
    role.save()

    # Create the default administrator account
    print("Creating default super admin credentials")
    default_admin = {
        'email': 'admin@reflexsoar.com',
        'username': 'reflex',
        'password': 'reflex',
        'first_name': 'Super',
        'last_name': 'Admin'
    }
    user = User(**default_admin)
    user.create()
    print("Username: reflex")
    print("Password: reflex")

    user.role = role
    user.organization = org
    user.save()

def create_admin(org, email, username):
    # Create the Permissions for an administrator
    perms = { 
        'add_user': True,
        'update_user': True,
        'delete_user': True,
        'add_user_to_role': True,
        'remove_user_from_role': True,
        'reset_user_password': True,
        'unlock_user': True,
        'view_users': True,
        'add_role': True,
        'update_role': True,
        'delete_role': True,
        'set_role_permissions': True,
        'view_roles': True,
        "add_tag": True,
        "update_tag": True,
        "delete_tag": True,
        "view_tags": True,
        "add_credential": True,
        "update_credential": True,
        "decrypt_credential": True,
        "delete_credential": True,
        "view_credentials": True ,
        "add_playbook": True,
        "update_playbook": True,
        "delete_playbook": True,
        "view_playbooks": True,
        "add_tag_to_playbook": True,
        "remove_tag_from_playbook": True,
        "add_event": True,
        "view_events": True,
        "update_event": True,
        "delete_event": True,
        "add_tag_to_event": True,
        "remove_tag_from_event": True,
        "add_observable": True,
        "update_observable": True,
        "delete_observable": True,
        "add_tag_to_observable": True,
        "remove_tag_from_observable": True,
        "view_agents": True,
        "update_agent": True,
        "delete_agent": True,
        "pair_agent": True,
        "add_input": True,
        "view_inputs": True,
        "update_input": True,
        "delete_input": True,
        "create_case": True,
        "view_cases": True,
        "update_case": True,
        "delete_case": True,
        "create_case_comment": True,
        "view_case_comments": True,
        "update_case_comment": True,
        "delete_case_comment": True,
        "view_plugins": True,
        "create_plugin": True,
        "delete_plugin": True,
        "update_plugin": True,
        "create_agent_group": True,
        "view_agent_groups": True,
        "update_agent_group": True,
        "delete_agent_group": True,
        "create_user_group": True,
        "view_user_groups": True,
        "update_user_groups": True,
        "delete_user_group": True,
        "create_case_template": True,
        "view_case_templates": True,
        "update_case_template": True,
        "delete_case_template": True,
        "create_case_task": True,
        "view_case_tasks": True,
        "update_case_task": True,
        "delete_case_task": True,
        "create_case_template_task": True,
        "view_case_template_tasks": True,
        "update_case_template_task": True,
        "delete_case_template_task": True,
        "create_case_status": True,
        "update_case_status": True,
        "delete_case_status": True,
        'update_settings': True,
        'view_settings': True,
        "use_api": True,
        "add_list": True,
        "update_list": True,
        "view_lists": True,
        "delete_list": True,
        "create_data_type": True,
        "update_data_type": True,
        "create_persistent_pairing_token": True,
        "create_event_rule": True,
        "update_event_rule": True,
        "delete_event_rule": True,
        "view_event_rules": True,
        'upload_case_files': True,
        'view_case_files': True,
        'delete_case_files': True
    }
    permissions = Permission(**perms)
    permissions.organization = org
    permissions.create()

    print("Creating the default administrator role...")

    # Create the administrator role
    details =  {
        'name': 'Admin',
        'description': 'Power overwhelming'
    }
    role = Role(**details)
    db.session.add(role)
    db.session.commit()

    role.permissions = permissions
    role.organization = org
    role.save()

    print("Creating the administrator account...")

    # Create the default administrator account
    default_admin = {
        'email': email,
        'username': username,
        'password': 'admin',
        'first_name': 'Super',
        'last_name': 'Admin'
    }
    user = User(**default_admin)
    db.session.add(user)
    db.session.commit()
    print("Username: admin")
    print("Password: admin")

    user.role = role
    user.organization = org
    user.save()
    
def create_analyst(org):
    print("Creating the default user permissions for %s" % org.name)
    perms = { 
        'view_users': True,
        'view_roles': True,
        "add_tag": True,
        "update_tag": True,
        "delete_tag": True,
        "view_tags": True,
        "add_credential": True,
        "update_credential": True,
        "decrypt_credential": True,
        "delete_credential": True,
        "view_credentials": True ,
        "add_playbook": True,
        "view_playbooks": True,
        "add_tag_to_playbook": True,
        "remove_tag_from_playbook": True,
        "add_event": True,
        "view_events": True,
        "update_event": True,
        "add_tag_to_event": True,
        "remove_tag_from_event": True,
        "add_observable": True,
        "update_observable": True,
        "delete_observable": True,
        "add_tag_to_observable": True,
        "remove_tag_from_observable": True,
        "view_agents": True,
        "view_inputs": True,
        "create_case": True,
        "view_cases": True,
        "update_case": True,
        "create_case_comment": True,
        "view_case_comments": True,
        "update_case_comment": True,
        "view_plugins": True,
        "view_agent_groups": True,
        "view_user_groups": True,
        "create_case_template": True,
        "view_case_templates": True,
        "update_case_template": True,
        "delete_case_template": True,
        "create_case_task": True,
        "view_case_tasks": True,
        "update_case_task": True,
        "delete_case_task": True,
        'view_settings': True,
        'upload_case_files': True,
        'view_case_files': True,
        'delete_case_files': True,
        "create_event_rule": True,
        "update_event_rule": True,
        "delete_event_rule": True,
    }

    permissions = Permission(**perms)
    permissions.create()
    permissions.organization = org
    permissions.save()

    print("Creating default user role...")

    # Create the administrator role
    details =  {
        'name': 'Analyst',
        'description': 'The default Analyst role'
    }
    role = Role(**details)
    db.session.add(role)
    db.session.commit()

    role.permissions = permissions
    role.organization = org
    role.save()

def create_agent_role(org):
    print("Creating the agent role for %s" % org.name)
    # Create the Permissions for an administrator
    perms = { 
        "decrypt_credential": True,
        "view_credentials": True ,
        "view_playbooks": True,
        "add_event": True,
        "update_event": True,
        "add_tag_to_event": True,
        "remove_tag_from_event": True,
        "add_observable": True,
        "update_observable": True,
        "delete_observable": True,
        "add_tag_to_observable": True,
        "remove_tag_from_observable": True,
        "view_agents": True,
        "view_plugins": True,
        "add_event": True,
        'view_settings': True
    }
    permissions = Permission(**perms)
    permissions.create()
    permissions.organization = org
    permissions.save()

    # Create the administrator role
    details =  {
        'name': 'Agent',
        'description': 'Reserved for agents'
    }
    role = Role(**details)
    role.create()
    role.permissions = permissions
    role.organization = org
    role.save()

def create_default_observable_types(org):
    print("Creating default Observable Types for %s" % org.name)
    dataTypes = [
        {'name': 'ip', 'description': 'IP Address', 'regex': r'/^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/'},
        {'name': 'domain', 'description': 'A domain name'},
        {'name': 'fqdn', 'description': 'A fully qualified domain name of a host'},
        {'name': 'host', 'description': 'A host name'},
        {'name': 'email', 'description': 'An e-mail address', 'regex': r'/^[a-zA-Z0-9.!#$%&\'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/'},
        {'name': 'email_subject', 'description': 'An e-mail subject'},
        {'name': 'md5hash', 'description': 'A MD5 hash', 'regex': r'/[a-f0-9A-F]{32}/'},
        {'name': 'sha1hash', 'description': 'A SHA1 hash', 'regex': r'/[a-f0-9A-F]{40}/'},
        {'name': 'sha256hash', 'description': 'A SHA256 hash', 'regex': r'/[a-f0-9A-F]{64}/'},
        {'name': 'user', 'description': 'A username'},
        {'name': 'command', 'description': 'A command that was executed'},
        {'name': 'url', 'description': 'An address to a universal resource', 'regex': r'/(http|https)\:\/\/[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,3}(\/\S*)?/'},
        {'name': 'imphash', 'description': 'A hash of a binaries import table'},
        {'name': 'process', 'description': 'A process that was launched on a machine', r'regex':'^([A-Z]?[:\\\/]).*(\.\w{3,})?$'}
    ]
    for d in dataTypes:
        dt = DataType(**d)
        dt.organization = org
        dt.create()

def create_default_closure_reasons(org):
    print("Creating default closure reason for %s" % org.name)
    reasons = [
        {'title': 'False positive', 'description': 'False positive'},
        {'title': 'No action required', 'description': 'No action required'},
        {'title': 'True positive', 'description': 'True positive'},
        {'title': 'Other', 'description': 'Other'}
    ]
    for r in reasons:
        reason = CloseReason(**r)
        reason.organization = org
        reason.create()

def create_default_event_statuses(org):
    print("Creating default event statuses for %s" % org.name)
    statuses = {
        'New': 'A new event.',
        'Closed': 'An event that has been closed.',
        'Open': 'An event is open and being worked in a case.',
        'Dismissed': 'An event that has been ignored from some reason.'
    }
    for k in statuses:
        status = EventStatus(name=k, description=statuses[k])
        status.organization = org
        status.create()
        if k == 'Closed':
            status.closed = True
            status.save()

def create_default_case_statuses(org):
    print("Creating default case statuses for %s" % org.name)
    statuses = {
        'New': 'A new case.',
        'Closed': 'A cased that has been closed.',
        'Hold': 'A case that has been worked on but is currently not being worked.',
        'In Progress': 'A case that is currently being worked on.'
    }
    for k in statuses:
        status = CaseStatus(name=k, description=statuses[k])
        status.organization = org
        status.create()
        if k == 'Closed':
            status.closed = True
            status.save()

def create_default_agent_types(org):
    print("Creating default agent types for %s" % org.name)
    agent_types = {
        'poller': 'Runs input jobs to push data to Reflex',
        'runner': 'Runs playbook actions'
    }
    for k in agent_types:
        agent_type = AgentRole(name=k, description=agent_types[k])
        agent_type.organization = org

        agent_type.create()

@manager.command
def new_org(name, description, admin_email, admin_username):
    org = create_org(name, description)
    create_default_settings(org)
    create_admin(org, admin_email, admin_username)  
    create_analyst(org)
    create_agent_role(org)
    create_default_closure_reasons(org)
    create_default_observable_types(org)
    create_default_event_statuses(org)
    create_default_case_statuses(org)
    create_default_agent_types(org)

@manager.command
def setup():

    org = create_org('Reflex', 'The default Reflex organization')
    create_default_settings(org)
    create_super_admin(org)  
    create_analyst(org)
    create_agent_role(org)
    create_default_closure_reasons(org)
    create_default_observable_types(org)
    create_default_event_statuses(org)
    create_default_case_statuses(org)
    create_default_agent_types(org)

    

    return 0

if __name__ == '__main__':
    manager.run()