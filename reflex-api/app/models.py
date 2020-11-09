import datetime
import uuid
import hashlib
import jwt
import secrets
import base64
import os
from flask import current_app, request
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func, select
from sqlalchemy.sql import func, text
from sqlalchemy.orm import validates, column_property
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.hybrid import hybrid_method
from sqlalchemy.dialects.mysql import LONGTEXT
from sqlalchemy_filters import apply_loads, apply_filters
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import InvalidToken
from app import FLASK_BCRYPT, db


def generate_uuid():
    ''' Returns a UUID for objects when they are created '''

    return str(uuid.uuid4())


# Relationships

org_tag_association = db.Table('tag_organization', db.metadata,
    db.Column('organization_uuid', db.String(255), db.ForeignKey('organization.uuid')),
    db.Column('tag_id', db.String(255), db.ForeignKey('tag.uuid'))
)

playbook_tag_association = db.Table('tag_playbook', db.metadata,
                                    db.Column('playbook_uuid', db.String(255),
                                              db.ForeignKey('playbook.uuid')),
                                    db.Column('tag_id', db.String(255),
                                              db.ForeignKey('tag.uuid'))
                                    )

event_tag_association = db.Table('tag_event', db.metadata,
                                 db.Column('event_uuid', db.String(255),
                                           db.ForeignKey('event.uuid')),
                                 db.Column('tag_id', db.String(255),
                                           db.ForeignKey('tag.uuid'))
                                 )

observable_tag_association = db.Table('tag_observable', db.metadata,
                                      db.Column('observable_uuid', db.String(255), db.ForeignKey(
                                          'observable.uuid')),
                                      db.Column('tag_id', db.String(255),
                                                db.ForeignKey('tag.uuid'))
                                      )

observable_event_association = db.Table('observable_event', db.metadata,
                                        db.Column('observable_uuid', db.String(255), db.ForeignKey(
                                            'observable.uuid')),
                                        db.Column('event_uuid', db.String(255),
                                                  db.ForeignKey('event.uuid'))
                                        )

observable_event_rule_association = db.Table('observable_event_rule', db.metadata,
                                        db.Column('observable_uuid', db.String(255), db.ForeignKey(
                                            'observable.uuid')),
                                        db.Column('event_rule_uuid', db.String(255),
                                                  db.ForeignKey('event_rule.uuid'))
                                        )

input_tag_association = db.Table('tag_input', db.metadata,
                                 db.Column('input_uuid', db.String(255),
                                           db.ForeignKey('input.uuid')),
                                 db.Column('tag_id', db.String(255),
                                           db.ForeignKey('tag.uuid'))
                                 )

agent_role_agent_association = db.Table('agent_role_agent', db.metadata,
                                        db.Column('agent_uuid', db.String(255),
                                                  db.ForeignKey('agent.uuid')),
                                        db.Column('agent_role_uuid', db.String(255), db.ForeignKey(
                                            'agent_role.uuid'))
                                        )

agent_group_agent_association = db.Table('agent_group_agent', db.metadata,
                                         db.Column(
                                             'agent_uuid', db.String(255), db.ForeignKey('agent.uuid')),
                                         db.Column('agent_group_uuid', db.String(255), db.ForeignKey(
                                             'agent_group.uuid'))
                                         )

agent_input_association = db.Table('agent_input', db.metadata,
                                   db.Column('agent_uuid', db.String(255),
                                             db.ForeignKey('agent.uuid')),
                                   db.Column('input_uuid', db.String(255),
                                             db.ForeignKey('input.uuid'))
                                   )

observable_case_association = db.Table('observable_case', db.metadata,
                                       db.Column('observable_uuid', db.String(255), db.ForeignKey(
                                           'observable.uuid')),
                                       db.Column('case_uuid', db.String(255),
                                                 db.ForeignKey('case.uuid'))
                                       )

event_case_association = db.Table('event_case', db.metadata,
                                  db.Column('event_uuid', db.String(255),
                                            db.ForeignKey('event.uuid')),
                                  db.Column('case_uuid', db.String(255),
                                            db.ForeignKey('case.uuid'))
                                  )

case_tag_association = db.Table('tag_case', db.metadata,
                                db.Column('case_uuid', db.String(255),
                                          db.ForeignKey('case.uuid')),
                                db.Column('tag_id', db.String(255),
                                          db.ForeignKey('tag.uuid'))
                                )

case_template_tag_association = db.Table('tag_case_template', db.metadata,
                                         db.Column('case_template_uuid', db.String(255), db.ForeignKey(
                                             'case_template.uuid')),
                                         db.Column('tag_id', db.String(255),
                                                   db.ForeignKey('tag.uuid'))
                                         )

user_case_association = db.Table('user_case', db.metadata,
                                 db.Column('user_uuid', db.String(255),
                                           db.ForeignKey('user.uuid')),
                                 db.Column('case_uuid', db.String(255),
                                           db.ForeignKey('case.uuid'))
                                 )

plugin_config_association = db.Table('plugin_plugin_config', db.metadata,
                                     db.Column('plugin_uuid', db.String(255),
                                               db.ForeignKey('plugin.uuid')),
                                     db.Column('plugin_config.uuid', db.String(255),
                                               db.ForeignKey('plugin_config.uuid'))
                                     )

user_group_association = db.Table('user_group_assignment', db.metadata,
                                  db.Column('user_uuid', db.String(255),
                                            db.ForeignKey('user.uuid')),
                                  db.Column('user_group_uuid', db.String(255),
                                            db.ForeignKey('user_group.uuid'))
                                  )

case_to_case = db.Table('case_to_case', db.metadata,
                         db.Column('parent_case_uuid',  db.String(255), db.ForeignKey('case.uuid')),
                         db.Column('child_case_uuid', db.String(255), db.ForeignKey('case.uuid')))

# End relationships


def _current_user_id_or_none():
    try:
        auth_header = request.headers.get('Authorization')
        current_user = None
        if auth_header:
            access_token = auth_header.split(' ')[1]
            token = jwt.decode(access_token, current_app.config['SECRET_KEY'])
            if 'type' in token and token['type'] == 'agent':
                current_user = None
            elif 'type' in token and token['type'] == 'pairing':
                current_user = "PAIRING"
            else:
                current_user = User.query.filter_by(uuid=token['uuid']).first()
        return current_user.uuid
    except:
        return None


class Base(db.Model):

    __abstract__ = True

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    uuid = db.Column(db.String(255), unique=True, default=generate_uuid)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow, nullable=False)
    modified_at = db.Column(db.DateTime, default=datetime.datetime.utcnow,
                            onupdate=datetime.datetime.utcnow, nullable=False)
    # TODO : Extend created_by
    # TODO : Extend updated_by

    def update(self, data):
        for k in data:
            if hasattr(self, k):
                setattr(self, k, data[k])
        db.session.commit()

    def create(self):
        # Catch on duplicate insertion and return False to indicate the creation failed
        try:
            db.session.add(self)
            db.session.commit()
            return 0
        except IntegrityError:
            return 1
        except Exception:
            return 2

    @classmethod
    def get(self, uuid):
        return self.query.filter_by(uuid=uuid).first()

    @classmethod
    def get_by(self, **kwargs):
        return self.query.filter_by(**kwargs).first()

    @classmethod
    def get_or_404(self, uuid):
        return_value = self.get(uuid)
        if return_value is None:
            abort(404)
        return return_value

    def save(self):
        db.session.commit()

    def delete(self):
        db.session.delete(self)
        db.session.commit()

    def __repr__(self):
        return ("<{} {}>".format(self.__class__.__name__, self.id))


class Permission(Base):
    ''' Permissions for a Role '''

    # Organization Mapping
    organization = db.relationship('Organization', back_populates='permissions')
    organization_uuid = db.Column(db.String(255), db.ForeignKey('organization.uuid'))

    # User Permissions
    add_user = db.Column(db.Boolean, default=False)
    update_user = db.Column(db.Boolean, default=False)
    delete_user = db.Column(db.Boolean, default=False)
    add_user_to_role = db.Column(db.Boolean, default=False)
    remove_user_from_role = db.Column(db.Boolean, default=False)
    reset_user_password = db.Column(db.Boolean, default=False)
    unlock_user = db.Column(db.Boolean, default=False)
    view_users = db.Column(db.Boolean, default=False)

    # Role Permissions
    add_role = db.Column(db.Boolean, default=False)
    update_role = db.Column(db.Boolean, default=False)
    delete_role = db.Column(db.Boolean, default=False)
    set_role_permissions = db.Column(db.Boolean, default=False)
    view_roles = db.Column(db.Boolean, default=False)

    # User Group Permissions
    create_user_group = db.Column(db.Boolean, default=False)
    view_user_groups = db.Column(db.Boolean, default=False)
    update_user_groups = db.Column(db.Boolean, default=False)
    delete_user_group = db.Column(db.Boolean, default=False)

    # Event Permissions
    add_event = db.Column(db.Boolean, default=False)
    view_events = db.Column(db.Boolean, default=False)
    update_event = db.Column(db.Boolean, default=False)
    delete_event = db.Column(db.Boolean, default=False)
    add_tag_to_event = db.Column(db.Boolean, default=False)
    remove_tag_from_event = db.Column(db.Boolean, default=False)

    # Event Rule Permissions
    create_event_rule = db.Column(db.Boolean, default=False)
    view_event_rules = db.Column(db.Boolean, default=False)
    update_event_rule = db.Column(db.Boolean, default=False)
    delete_event_rule = db.Column(db.Boolean, default=False)

    # Observable Permissions
    add_observable = db.Column(db.Boolean, default=False)
    update_observable = db.Column(db.Boolean, default=False)
    delete_observable = db.Column(db.Boolean, default=False)
    add_tag_to_observable = db.Column(db.Boolean, default=False)
    remove_tag_from_observable = db.Column(db.Boolean, default=False)

    # Playbook Permission
    add_playbook = db.Column(db.Boolean, default=False)
    update_playbook = db.Column(db.Boolean, default=False)
    delete_playbook = db.Column(db.Boolean, default=False)
    view_playbooks = db.Column(db.Boolean, default=False)
    add_tag_to_playbook = db.Column(db.Boolean, default=False)
    remove_tag_from_playbook = db.Column(db.Boolean, default=False)

    # Agent Permissions
    view_agents = db.Column(db.Boolean, default=False)
    update_agent = db.Column(db.Boolean, default=False)
    delete_agent = db.Column(db.Boolean, default=False)
    pair_agent = db.Column(db.Boolean, default=False)

    # Agent Group Permissions
    create_agent_group = db.Column(db.Boolean, default=False)
    view_agent_groups = db.Column(db.Boolean, default=False)
    update_agent_group = db.Column(db.Boolean, default=False)
    delete_agent_group = db.Column(db.Boolean, default=False)

    # Input Permissions
    add_input = db.Column(db.Boolean, default=False)
    view_inputs = db.Column(db.Boolean, default=False)
    update_input = db.Column(db.Boolean, default=False)
    delete_input = db.Column(db.Boolean, default=False)

    # Tag Permissions
    add_tag = db.Column(db.Boolean, default=False)
    update_tag = db.Column(db.Boolean, default=False)
    delete_tag = db.Column(db.Boolean, default=False)
    view_tags = db.Column(db.Boolean, default=False)

    # Case Permissions
    create_case = db.Column(db.Boolean, default=False)
    view_cases = db.Column(db.Boolean, default=False)
    update_case = db.Column(db.Boolean, default=False)
    delete_case = db.Column(db.Boolean, default=False)

    # Case File Permissions
    upload_case_files = db.Column(db.Boolean, default=False)
    view_case_files = db.Column(db.Boolean, default=False)
    delete_case_files = db.Column(db.Boolean, default=False)

    # Case Template Task Permissions
    create_case_task = db.Column(db.Boolean, default=False)
    view_case_tasks = db.Column(db.Boolean, default=False)
    update_case_task = db.Column(db.Boolean, default=False)
    delete_case_task = db.Column(db.Boolean, default=False)

    # Case Template Permissions
    create_case_template = db.Column(db.Boolean, default=False)
    view_case_templates = db.Column(db.Boolean, default=False)
    update_case_template = db.Column(db.Boolean, default=False)
    delete_case_template = db.Column(db.Boolean, default=False)

    # Case Template Task Permissions
    create_case_template_task = db.Column(db.Boolean, default=False)
    view_case_template_tasks = db.Column(db.Boolean, default=False)
    update_case_template_task = db.Column(db.Boolean, default=False)
    delete_case_template_task = db.Column(db.Boolean, default=False)

    # Case Comment Permissions
    create_case_comment = db.Column(db.Boolean, default=False)
    view_case_comments = db.Column(db.Boolean, default=False)
    update_case_comment = db.Column(db.Boolean, default=False)
    delete_case_comment = db.Column(db.Boolean, default=False)

    # Case Status Permissions
    create_case_status = db.Column(db.Boolean, default=False)
    update_case_status = db.Column(db.Boolean, default=False)
    delete_case_status = db.Column(db.Boolean, default=False)

    # Plugin Permissions
    view_plugins = db.Column(db.Boolean, default=False)
    create_plugin = db.Column(db.Boolean, default=False)
    delete_plugin = db.Column(db.Boolean, default=False)
    update_plugin = db.Column(db.Boolean, default=False)

    # Credential Permissions
    add_credential = db.Column(db.Boolean, default=False)
    update_credential = db.Column(db.Boolean, default=False)
    decrypt_credential = db.Column(db.Boolean, default=False)
    delete_credential = db.Column(db.Boolean, default=False)
    view_credentials = db.Column(db.Boolean, default=False)

    # Organization Administration
    add_organization = db.Column(db.Boolean, default=False)
    view_organizatons = db.Column(db.Boolean, default=False)
    update_organization = db.Column(db.Boolean, default=False)
    delete_organization = db.Column(db.Boolean, default=False)

    # List Permissions
    add_list = db.Column(db.Boolean, default=False)
    update_list = db.Column(db.Boolean, default=False)
    view_lists = db.Column(db.Boolean, default=False)
    delete_list = db.Column(db.Boolean, default=False)

    # Data Type Permissions
    create_data_type = db.Column(db.Boolean, default=False)
    update_data_type = db.Column(db.Boolean, default=False)

    # Update Settings
    update_settings = db.Column(db.Boolean, default=False)
    view_settings = db.Column(db.Boolean, default=False)
    create_persistent_pairing_token = db.Column(db.Boolean, default=False)

    # API Permissions
    use_api = db.Column(db.Boolean, default=False)

    # Role relationship
    roles = db.relationship('Role', back_populates='permissions')


class Organization(Base):
    ''' 
    The Organization for which all objects fall under

    New organizations can only be added by a platform super admin
    
    '''
    name = db.Column(db.String(200), nullable=False)
    url = db.Column(db.String(200))
    description = db.Column(db.Text)
    enabled = db.Column(db.Integer, default=1)
    users = db.relationship('User', back_populates='organization')
    groups = db.relationship('UserGroup', back_populates='organization')
    permissions = db.relationship('Permission', back_populates='organization')
    roles = db.relationship('Role', back_populates='organization')
    agents = db.relationship('Agent',  back_populates='organization')
    agent_groups = db.relationship('AgentGroup',  back_populates='organization')
    agent_roles = db.relationship('AgentRole',  back_populates='organization')
    playbooks = db.relationship('Playbook',  back_populates='organization')
    plugins = db.relationship('Plugin',  back_populates='organization')
    plugin_configs = db.relationship('PluginConfig',  back_populates='organization')
    events = db.relationship('Event', back_populates='organization')
    event_rules = db.relationship('EventRule', back_populates='organization')
    event_statuses = db.relationship('EventStatus',  back_populates='organization')
    data_types = db.relationship('DataType',  back_populates='organization')
    case_statuses = db.relationship('CaseStatus',  back_populates='organization')
    observables = db.relationship('Observable',  back_populates='organization')
    cases = db.relationship('Case', back_populates='organization')
    case_tasks = db.relationship('CaseTask',  back_populates='organization')
    case_task_notes = db.relationship('TaskNote', back_populates='organization')
    case_templates = db.relationship('CaseTemplate', back_populates='organization')
    case_template_tasks = db.relationship('CaseTemplateTask',  back_populates='organization')
    case_comments = db.relationship('CaseComment',  back_populates='organization')
    closure_reasons = db.relationship('CloseReason',  back_populates='organization')
    case_history = db.relationship('CaseHistory',  back_populates='organization')
    lists = db.relationship('List', back_populates='organization')
    inputs = db.relationship('Input', back_populates='organization')    
    credentials = db.relationship('Credential', back_populates='organization')
    settings = db.relationship('GlobalSettings', back_populates='organization')
    user_settings = db.relationship('UserSettings', back_populates='organization')
    tags = db.relationship('Tag', back_populates='organization')
    files = db.relationship('CaseFile', back_populates='organization')


class Role(Base):
    ''' A Users role in the system '''
    name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.String(255))
    users = db.relationship('User', back_populates='role')
    agents = db.relationship('Agent', back_populates='role')
    permissions = db.relationship('Permission', back_populates='roles', lazy="joined")
    permissions_uuid = db.Column(db.String(255), db.ForeignKey('permission.uuid'))
    organization = db.relationship('Organization', back_populates='roles')
    organization_uuid = db.Column(db.String(255), db.ForeignKey('organization.uuid'))


class User(Base):
    ''' User model for storing user related stuff '''
    email = db.Column(db.String(255), unique=True, nullable=False)
    username = db.Column(db.String(255), nullable=False)
    first_name = db.Column(db.String(255), unique=False, nullable=True)
    last_name = db.Column(db.String(255), unique=False, nullable=True)
    last_logon = db.Column(db.DateTime)
    password_hash = db.Column(db.String(100))
    locked = db.Column(db.Boolean, default=False)
    failed_logons = db.Column(db.Integer, default=0)
    deleted = db.Column(db.Boolean, default=False)
    role = db.relationship('Role', back_populates='users')
    role_uuid = db.Column(db.String(255), db.ForeignKey('role.uuid'))
    settings_uuid = db.Column(db.String(255), db.ForeignKey('user_settings.uuid'))
    settings = db.relationship('UserSettings', foreign_keys=[settings_uuid])
    organization = db.relationship('Organization', back_populates='users', lazy="joined")
    organization_uuid = db.Column(db.String(255), db.ForeignKey('organization.uuid'))
    notifications = db.relationship('Notification')
    groups = db.relationship(
        'UserGroup', secondary=user_group_association, back_populates='members')
    api_key = db.Column(db.String(255))

    # AUDIT COLUMNS
    # TODO: Figure out how to move this to a mixin, it just doesn't want to work
    created_by_uuid = db.Column(db.String(255), db.ForeignKey(
        'user.uuid'), default=_current_user_id_or_none)
    updated_by_uuid = db.Column(db.String(255), db.ForeignKey(
        'user.uuid'), default=_current_user_id_or_none, onupdate=_current_user_id_or_none)
    created_by = db.relationship('User', foreign_keys=[created_by_uuid])
    updated_by = db.relationship('User', foreign_keys=[updated_by_uuid])

    @property
    def password(self):
        raise AttributeError('password: write-only field')

    @password.setter
    def password(self, password):
        self.password_hash = FLASK_BCRYPT.generate_password_hash(
            password).decode('utf-8')

    def generate_api_key(self):
        '''
        Generates a long living API key, which the user can use to make
        API calls without having to authenticate using username/password

        The API Key should only be presented once and will be added to the 
        expired token table 
        '''

        _api_key = jwt.encode({
            'uuid': self.uuid,
            'organization': self.organization_uuid,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(
                    days = GlobalSettings.query.filter_by(
                        organization_uuid = self.organization_uuid).first().api_key_valid_days),
            'iat': datetime.datetime.utcnow(),
            'type': 'api'
        }, current_app.config['SECRET_KEY']).decode('utf-8')

        if self.api_key != None:
            blacklist = AuthTokenBlacklist(auth_token = self.api_key)
            blacklist.create()
            self.api_key = _api_key
        else:
            self.api_key = _api_key
        self.save()
        return {'api_key': self.api_key}


    def create_access_token(self):
        _access_token = jwt.encode({
            'uuid': self.uuid,
            'organization': self.organization_uuid,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=360),
            'iat': datetime.datetime.utcnow(),
            'type': 'user'
        }, current_app.config['SECRET_KEY']).decode('utf-8')

        return _access_token

    @property
    def permissions(self):
        return [
            k for k in self.role.permissions.__dict__ 
            if k not in ['_sa_instance_state', 'created_at', 'modified_at', 'created_by', 'modified_by', 'uuid', 'id'] 
            and self.role.permissions.__dict__[k] == True
        ]

    def create_password_reset_token(self):
        _token = jwt.encode({
            'uuid': self.uuid,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30),
            'iat': datetime.datetime.utcnow(),
            'type': 'password_reset'
        }, current_app.config['SECRET_KEY']).decode('utf-8')

        return _token

    def create_refresh_token(self, user_agent_string):
        _refresh_token = jwt.encode({
            'uuid': self.uuid,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(days=30),
            'iat': datetime.datetime.utcnow(),
            'type': 'refresh'
        }, current_app.config['SECRET_KEY']).decode('utf-8')

        user_agent_hash = hashlib.md5(user_agent_string).hexdigest()

        refresh_token = RefreshToken.query.filter_by(
            user_agent_hash=user_agent_hash).first()

        if not refresh_token:
            refresh_token = RefreshToken(
                user_uuid=self.uuid, refresh_token=_refresh_token, user_agent_hash=user_agent_hash)
            refresh_token.create()
            _refresh_token = refresh_token.refresh_token
        else:
            refresh_token.refresh_token = _refresh_token
            db.session.commit()

        return _refresh_token

    def check_password(self, password):
        '''
        Tries to validate the users password against the 
        local authentication database
        '''

        return FLASK_BCRYPT.check_password_hash(self.password_hash, password)

    def ldap_login(self, password):
        ''' 
        If configured in the organizations settings
        will attempt to log the user in via LDAP
        '''
        
        raise NotImplementedError

    def has_right(self, permission):

        if getattr(self.role.permissions,permission):
            return True
        else:
            return False


class UserSettings(Base):

    notify_on_case_assign = db.Column(db.Boolean, default=False)
    notify_on_task_assign = db.Column(db.Boolean, default=False)
    user_uuid = db.Column(db.String(255), db.ForeignKey('user.uuid'))
    organization = db.relationship('Organization', back_populates='user_settings')
    organization_uuid = db.Column(db.String(255), db.ForeignKey('organization.uuid'))

    # AUDIT COLUMNS
    # TODO: Figure out how to move this to a mixin, it just doesn't want to work
    created_by_uuid = db.Column(db.String(255), db.ForeignKey(
        'user.uuid'), default=_current_user_id_or_none)
    updated_by_uuid = db.Column(db.String(255), db.ForeignKey(
        'user.uuid'), default=_current_user_id_or_none, onupdate=_current_user_id_or_none)
    created_by = db.relationship('User', foreign_keys=[created_by_uuid])
    updated_by = db.relationship('User', foreign_keys=[updated_by_uuid])


class Notification(Base):

    message = db.Column(db.Text)
    recipient = db.relationship('User', back_populates='notifications')
    recipient_uuid = db.Column(db.String(255), db.ForeignKey('user.uuid'))
    is_read = db.Column(db.Boolean, default=False)


class UserGroup(Base):

    name = db.Column(db.String(255))
    description = db.Column(db.Text)
    members = db.relationship(
        'User', secondary=user_group_association, back_populates='groups')
    organization = db.relationship('Organization', back_populates='groups')
    organization_uuid = db.Column(db.String(255), db.ForeignKey('organization.uuid'))


class RefreshToken(Base):

    user_uuid = db.Column(db.String(100))
    organization_uuid = db.Column(db.String(100))
    refresh_token = db.Column(db.String(255))
    user_agent_hash = db.Column(db.String(255))


class AuthTokenBlacklist(Base):

    auth_token = db.Column(db.Text)


class Case(Base):

    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    comments = db.relationship('CaseComment', cascade='delete')
    severity = db.Column(db.Integer, default=2)
    owner_uuid = db.Column(db.String(255), db.ForeignKey('user.uuid'))
    owner = db.relationship('User', foreign_keys=[owner_uuid])
    tlp = db.Column(db.Integer, default=2)
    observables = db.relationship(
        'Observable', secondary=observable_case_association, cascade='delete, save-update')
    events = db.relationship('Event', back_populates='case', lazy="joined")
    tags = db.relationship('Tag', secondary=case_tag_association)
    status_uuid = db.Column(db.String(255), db.ForeignKey('case_status.uuid'))
    status = db.relationship("CaseStatus")
    tasks = db.relationship("CaseTask", back_populates='case', cascade='delete, save-update')
    history = db.relationship("CaseHistory", back_populates='case', cascade='delete, save-update')
    related_cases = db.relationship(
                'Case',
                secondary=case_to_case,
                primaryjoin=('case_to_case.c.parent_case_uuid == Case.uuid'),
                secondaryjoin=('case_to_case.c.child_case_uuid == Case.uuid'),
                backref=db.backref('parent_cases'))
    _closed = db.Column(db.Boolean, default=False)
    closed_at = db.Column(db.DateTime)
    close_comment = db.Column(db.Text)
    close_reason = db.relationship("CloseReason")
    close_reason_uuid = db.Column(db.String(255), db.ForeignKey('close_reason.uuid'))
    case_template = db.relationship('CaseTemplate')
    case_template_uuid = db.Column(db.String(255), db.ForeignKey('case_template.uuid'))
    files = db.relationship('CaseFile')

    # AUDIT COLUMNS
    # TODO: Figure out how to move this to a mixin, it just doesn't want to work
    created_by_uuid = db.Column(db.String(255), db.ForeignKey(
        'user.uuid'), default=_current_user_id_or_none)
    updated_by_uuid = db.Column(db.String(255), db.ForeignKey(
        'user.uuid'), default=_current_user_id_or_none, onupdate=_current_user_id_or_none)
    created_by = db.relationship('User', foreign_keys=[created_by_uuid])
    updated_by = db.relationship('User', foreign_keys=[updated_by_uuid])
    organization = db.relationship('Organization', back_populates='cases')
    organization_uuid = db.Column(db.String(255), db.ForeignKey('organization.uuid'))

    def add_history(self, message):
        history_item = CaseHistory(message=message)
        history_item.organization_uuid = self.organization_uuid
        history_item.create()
        self.history.append(history_item)
        self.save()
    
    @property
    def closed(self):
        return self._closed

    @closed.setter
    def closed(self, value):
        self._closed = value
        if self._closed:
            self.closed_at = datetime.datetime.utcnow()
            self.save()
        if not self._closed:
            self.closed_at = None


class CaseFile(Base):
    """
    A reference to a file that resides on disk that has been uploaded by a user
    in relation to an active case
    """

    filename = db.Column(db.String(255), nullable=False)
    hash_md5 = db.Column(db.String(255))
    hash_sha1 = db.Column(db.String(255))
    hash_sha256 = db.Column(db.String(255))
    extension = db.Column(db.String(10))
    mime_type = db.Column(db.String(100))
    case_uuid = db.Column(db.String(256), db.ForeignKey('case.uuid'))
    case = db.relationship('Case', back_populates='files')

    # AUDIT COLUMNS
    # TODO: Figure out how to move this to a mixin, it just doesn't want to work
    created_by_uuid = db.Column(db.String(255), db.ForeignKey(
        'user.uuid'), default=_current_user_id_or_none)
    updated_by_uuid = db.Column(db.String(255), db.ForeignKey(
        'user.uuid'), default=_current_user_id_or_none, onupdate=_current_user_id_or_none)
    created_by = db.relationship('User', foreign_keys=[created_by_uuid])
    updated_by = db.relationship('User', foreign_keys=[updated_by_uuid])
    organization = db.relationship('Organization', back_populates='files')
    organization_uuid = db.Column(db.String(255), db.ForeignKey('organization.uuid'))
    

    @property
    def on_disk_name(self):
        """
        Returns the name of the file as it is stored on disk
        sha1_hash + organization_uuid + .extension
        """

        return self.organization_uuid+"-"+self.hash_sha1+"."+self.extension

    @property
    def filepath(self):
        return os.path.join(current_app.config['CASE_FILES_DIRECTORY'], self.on_disk_name)

    def save_to_disk(self):
        """
        Saves a file to the uploads/case_files directory
        """

        with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), self.filepath), 'wb') as f:
            f.write(self.data)
            f.close()
    
    def load_file(self):
        """
        Loads the file from disk so it can be returned to the user
        in an API response
        """
        
        self.data = open(self.filepath,'rb').read()

    def compute_hashes(self, data):
        """
        Computes all the hashes of the file
        """

        self.data = data
        self.compute_md5()
        self.compute_sha1()
        self.compute_sha256()
        self.save()
    
    def compute_md5(self):
        """
        Computes the MD5 value of the files binary data
        """

        hasher = hashlib.md5()
        hasher.update(self.data)
        self.hash_md5 = hasher.hexdigest()

    def compute_sha1(self):
        """
        Computes the SHA1 value of the files binary data
        """

        hasher = hashlib.sha1()
        hasher.update(self.data)
        self.hash_sha1 = hasher.hexdigest()

    def compute_sha256(self):
        """
        Computes the SHA256 value of the files binary data
        """

        hasher = hashlib.sha256()
        hasher.update(self.data)
        self.hash_sha256 = hasher.hexdigest()


class CloseReason(Base):
    '''
    A closure reason for a case, is useful for adding additional
    information to a case when closing it.  Example: this case was close as a false positive
    '''

    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.String(255))

    # AUDIT COLUMNS
    # TODO: Figure out how to move this to a mixin, it just doesn't want to work
    created_by_uuid = db.Column(db.String(255), db.ForeignKey(
        'user.uuid'), default=_current_user_id_or_none)
    created_by = db.relationship('User', foreign_keys=[created_by_uuid])
    organization = db.relationship('Organization', back_populates='closure_reasons')
    organization_uuid = db.Column(db.String(255), db.ForeignKey('organization.uuid'))


class CaseHistory(Base):
    ''' 
    A case history entry that shows what changed on the case
    the message should be stored in markdown format
    so that it can be processed by the UI
    '''

    message = db.Column(db.String(255), nullable=False)
    case = db.relationship('Case', back_populates='history')
    case_uuid = db.Column(db.String(255), db.ForeignKey('case.uuid'))

    # AUDIT COLUMNS
    # TODO: Figure out how to move this to a mixin, it just doesn't want to work
    created_by_uuid = db.Column(db.String(255), db.ForeignKey(
        'user.uuid'), default=_current_user_id_or_none)
    created_by = db.relationship('User', foreign_keys=[created_by_uuid])
    organization = db.relationship('Organization', back_populates='case_history')
    organization_uuid = db.Column(db.String(255), db.ForeignKey('organization.uuid'))


class CaseTask(Base):

    title = db.Column(db.String(255), nullable=False)
    order = db.Column(db.Integer, default=0)
    description = db.Column(db.Text)
    group_uuid = db.Column(db.String(255), db.ForeignKey('user_group.uuid'))
    group = db.relationship('UserGroup')
    owner_uuid = db.Column(db.String(255), db.ForeignKey('user.uuid'))
    owner = db.relationship('User', foreign_keys=[owner_uuid])
    notes = db.relationship('TaskNote')
    case_uuid = db.Column(db.String(255), db.ForeignKey('case.uuid'))
    case = db.relationship('Case', back_populates='tasks')
    from_template = db.Column(db.Boolean, default=False)
    status = db.Column(db.Integer, default=0) # 0 = Open, 1 = Started, 2 = Complete
    start_date = db.Column(db.DateTime)
    finish_date = db.Column(db.DateTime)

    # AUDIT COLUMNS
    # TODO: Figure out how to move this to a mixin, it just doesn't want to work
    created_by_uuid = db.Column(db.String(255), db.ForeignKey(
        'user.uuid'), default=_current_user_id_or_none)
    updated_by_uuid = db.Column(db.String(255), db.ForeignKey(
        'user.uuid'), default=_current_user_id_or_none, onupdate=_current_user_id_or_none)
    created_by = db.relationship('User', foreign_keys=[created_by_uuid])
    updated_by = db.relationship('User', foreign_keys=[updated_by_uuid])
    organization = db.relationship('Organization', back_populates='case_tasks')
    organization_uuid = db.Column(db.String(255), db.ForeignKey('organization.uuid'))


class TaskNote(Base):

    note = db.Column(db.Text, nullable=False)
    task_uuid = db.Column(db.String(255), db.ForeignKey('case_task.uuid'))
    task = db.relationship('CaseTask', back_populates='notes')
    after_complete = db.Column(db.Boolean, default=False)

    # AUDIT COLUMNS
    # TODO: Figure out how to move this to a mixin, it just doesn't want to work
    created_by_uuid = db.Column(db.String(255), db.ForeignKey(
        'user.uuid'), default=_current_user_id_or_none)
    updated_by_uuid = db.Column(db.String(255), db.ForeignKey(
        'user.uuid'), default=_current_user_id_or_none, onupdate=_current_user_id_or_none)
    created_by = db.relationship('User', foreign_keys=[created_by_uuid])
    updated_by = db.relationship('User', foreign_keys=[updated_by_uuid])
    organization = db.relationship('Organization', back_populates='case_task_notes')
    organization_uuid = db.Column(db.String(255), db.ForeignKey('organization.uuid'))


class CaseComment(Base):

    message = db.Column(db.Text)
    case_uuid = db.Column(db.String(255), db.ForeignKey('case.uuid'))
    is_closure_comment = db.Column(db.Text)
    closure_reason_uuid = db.Column(db.String(255), db.ForeignKey('close_reason.uuid'))
    closure_reason = db.relationship('CloseReason')
    edited = db.Column(db.Boolean, default=False)

    # AUDIT COLUMNS
    # TODO: Figure out how to move this to a mixin, it just doesn't want to work
    created_by_uuid = db.Column(db.String(255), db.ForeignKey(
        'user.uuid'), default=_current_user_id_or_none)
    updated_by_uuid = db.Column(db.String(255), db.ForeignKey(
        'user.uuid'), default=_current_user_id_or_none, onupdate=_current_user_id_or_none)
    created_by = db.relationship('User', foreign_keys=[created_by_uuid])
    updated_by = db.relationship('User', foreign_keys=[updated_by_uuid])
    organization = db.relationship('Organization', back_populates='case_comments')
    organization_uuid = db.Column(db.String(255), db.ForeignKey('organization.uuid'))


class CaseTemplate(Base):

    title = db.Column(db.String(255), unique=True)
    description = db.Column(db.Text)
    severity = db.Column(db.Integer, default=2)
    owner_uuid = db.Column(db.String(255), db.ForeignKey('user.uuid'))
    owner = db.relationship('User', foreign_keys=[owner_uuid])
    tlp = db.Column(db.Integer, default=2)
    tags = db.relationship('Tag', secondary=case_template_tag_association)
    tasks = db.relationship('CaseTemplateTask', back_populates='case_template')

    # AUDIT COLUMNS
    # TODO: Figure out how to move this to a mixin, it just doesn't want to work
    created_by_uuid = db.Column(db.String(255), db.ForeignKey(
        'user.uuid'), default=_current_user_id_or_none)
    updated_by_uuid = db.Column(db.String(255), db.ForeignKey(
        'user.uuid'), default=_current_user_id_or_none, onupdate=_current_user_id_or_none)
    created_by = db.relationship('User', foreign_keys=[created_by_uuid])
    updated_by = db.relationship('User', foreign_keys=[updated_by_uuid])
    organization = db.relationship('Organization', back_populates='case_templates')
    organization_uuid = db.Column(db.String(255), db.ForeignKey('organization.uuid'))


class CaseTemplateTask(Base):

    title = db.Column(db.String(255))
    order = db.Column(db.Integer, default=0)
    description = db.Column(db.Text)
    group_uuid = db.Column(db.String(255), db.ForeignKey('user_group.uuid'))
    group = db.relationship('UserGroup')
    owner_uuid = db.Column(db.String(255), db.ForeignKey('user.uuid'))
    owner = db.relationship('User', foreign_keys=[owner_uuid])
    case_template_uuid = db.Column(
        db.String(255), db.ForeignKey('case_template.uuid'))
    case_template = db.relationship('CaseTemplate', back_populates='tasks')
    status = db.Column(db.Integer, default=0)

    # AUDIT COLUMNS
    # TODO: Figure out how to move this to a mixin, it just doesn't want to work
    created_by_uuid = db.Column(db.String(255), db.ForeignKey(
        'user.uuid'), default=_current_user_id_or_none)
    updated_by_uuid = db.Column(db.String(255), db.ForeignKey(
        'user.uuid'), default=_current_user_id_or_none, onupdate=_current_user_id_or_none)
    created_by = db.relationship('User', foreign_keys=[created_by_uuid])
    updated_by = db.relationship('User', foreign_keys=[updated_by_uuid])
    organization = db.relationship('Organization', back_populates='case_template_tasks')
    organization_uuid = db.Column(db.String(255), db.ForeignKey('organization.uuid'))


class EventRule(Base):
    '''
    An Event Rule is created so that when new events come in they can
    be automatically handled based on how the analyst sees fit without the
    analyst actually having to do anything.
    '''

    name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    event_signature = db.Column(db.String(255)) # The title of the event that this was created from
    rule_signature = db.Column(db.String(255)) # A hash of the title + user customized observable values
    target_case_uuid = db.Column(db.String(255)) # The target case to merge this into if merge into case is selected
    observables = db.relationship('Observable', secondary=observable_event_rule_association)
    merge_into_case = db.Column(db.Boolean)
    dismiss = db.Column(db.Boolean)
    expire = db.Column(db.Boolean, default=True) # If not set the rule will never expire
    expire_at = db.Column(db.DateTime) # Computed from the created_at date of the event + a timedelta in days
    active = db.Column(db.Boolean, default=True) # Users can override the alarm and disable it out-right

    # AUDIT COLUMNS
    # TODO: Figure out how to move this to a mixin, it just doesn't want to work
    created_by_uuid = db.Column(db.String(255), db.ForeignKey(
        'user.uuid'), default=_current_user_id_or_none)
    updated_by_uuid = db.Column(db.String(255), db.ForeignKey(
        'user.uuid'), default=_current_user_id_or_none, onupdate=_current_user_id_or_none)
    created_by = db.relationship('User', foreign_keys=[created_by_uuid])
    updated_by = db.relationship('User', foreign_keys=[updated_by_uuid])
    organization = db.relationship('Organization', back_populates='event_rules')
    organization_uuid = db.Column(db.String(255), db.ForeignKey('organization.uuid'))

    def hash_observables(self):
        hasher = hashlib.md5()
        obs = []
        for observable in self.observables:
            obs.append({'dataType': observable.dataType.name.lower(), 'value': observable.value.lower()})
        obs = [dict(t) for t in {tuple(d.items()) for d in obs}] # Deduplicate the observables
        obs = sorted(sorted(obs, key = lambda i: i['dataType']), key = lambda i: i['value'])        
        hasher.update(str(obs).encode())
        self.rule_signature = hasher.hexdigest()
        self.save()
        return

    def hash_target_observables(self, target_observables):
        hasher = hashlib.md5()
        obs = []
        expected_observables = [{'dataType':obs.dataType.name.lower(), 'value':obs.value.lower()} for obs in self.observables]
        for observable in target_observables:
            obs_dict = {'dataType': observable.dataType.name.lower(), 'value': observable.value.lower()}
            if obs_dict in expected_observables:
                obs.append(obs_dict)
        obs = [dict(t) for t in {tuple(d.items()) for d in obs}] # Deduplicate the observables
        obs = sorted(sorted(obs, key = lambda i: i['dataType']), key = lambda i: i['value'])             
        hasher.update(str(obs).encode())
        return hasher.hexdigest()


class Event(Base):

    title = db.Column(db.String(255), nullable=False)
    reference = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=False)
    tlp = db.Column(db.Integer, default=2)
    severity = db.Column(db.Integer, default=2)
    status_id = db.Column(db.String(255), db.ForeignKey('event_status.uuid'))
    status = db.relationship("EventStatus")
    observables = db.relationship(
        'Observable', secondary=observable_event_association)
    tags = db.relationship('Tag', secondary=event_tag_association)
    case_uuid = db.Column(db.String(255), db.ForeignKey('case.uuid'))
    case = db.relationship('Case', back_populates='events')
    raw_log = db.Column(db.JSON)
    signature = db.Column(db.String(255))
    source = db.Column(db.String(255))
    dismiss_reason_uuid = db.Column(db.String(255), db.ForeignKey('close_reason.uuid'))
    dismiss_reason = db.relationship('CloseReason')
    dismiss_comment = db.Column(db.Text)
    organization = db.relationship('Organization', back_populates='events')
    organization_uuid = db.Column(db.String(255), db.ForeignKey('organization.uuid'))
    created_by_uuid = db.Column(db.String(255), db.ForeignKey(
        'user.uuid'), default=_current_user_id_or_none)
    updated_by_uuid = db.Column(db.String(255), db.ForeignKey(
        'user.uuid'), default=_current_user_id_or_none, onupdate=_current_user_id_or_none)
    created_by = db.relationship('User', foreign_keys=[created_by_uuid])
    updated_by = db.relationship('User', foreign_keys=[updated_by_uuid])
    
    def hash_event(self, data_types=['host','user']):
        hasher = hashlib.md5()
        hasher.update(self.title.encode())
        obs = []
        for observable in self.observables:
            if observable.dataType.name in sorted(data_types):
                obs.append({'dataType': observable.dataType.name.lower(), 'value': observable.value.lower()})
        obs = [dict(t) for t in {tuple(d.items()) for d in obs}] # Deduplicate the observables
        obs = sorted(sorted(obs, key = lambda i: i['dataType']), key = lambda i: i['value'])
        hasher.update(str(obs).encode())
        self.signature = hasher.hexdigest()
        self.save()
        return

    
        

class EventStatus(Base):

    name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.String(255), nullable=False)
    closed = db.Column(db.Boolean, default=False)

    # AUDIT COLUMNS
    # TODO: Figure out how to move this to a mixin, it just doesn't want to work
    created_by_uuid = db.Column(db.String(255), db.ForeignKey(
        'user.uuid'), default=_current_user_id_or_none)
    updated_by_uuid = db.Column(db.String(255), db.ForeignKey(
        'user.uuid'), default=_current_user_id_or_none, onupdate=_current_user_id_or_none)
    created_by = db.relationship('User', foreign_keys=[created_by_uuid])
    updated_by = db.relationship('User', foreign_keys=[updated_by_uuid])
    organization = db.relationship('Organization', back_populates='event_statuses')
    organization_uuid = db.Column(db.String(255), db.ForeignKey('organization.uuid'))


class CaseStatus(Base):

    name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.String(255), nullable=False)
    closed = db.Column(db.Boolean, default=False)

    # AUDIT COLUMNS
    # TODO: Figure out how to move this to a mixin, it just doesn't want to work
    created_by_uuid = db.Column(db.String(255), db.ForeignKey(
        'user.uuid'), default=_current_user_id_or_none)
    updated_by_uuid = db.Column(db.String(255), db.ForeignKey(
        'user.uuid'), default=_current_user_id_or_none, onupdate=_current_user_id_or_none)
    created_by = db.relationship('User', foreign_keys=[created_by_uuid])
    updated_by = db.relationship('User', foreign_keys=[updated_by_uuid])
    organization = db.relationship('Organization', back_populates='case_statuses')
    organization_uuid = db.Column(db.String(255), db.ForeignKey('organization.uuid'))


class Observable(Base):

    value = db.Column(db.Text)
    dataType_id = db.Column(db.String(255), db.ForeignKey('data_type.uuid'))
    dataType = db.relationship("DataType", lazy="joined")
    tlp = db.Column(db.Integer)
    tags = db.relationship('Tag', secondary=observable_tag_association)
    ioc = db.Column(db.Boolean, default=False)
    spotted = db.Column(db.Boolean, default=False)
    safe = db.Column(db.Boolean, default=False)

    # AUDIT COLUMNS
    # TODO: Figure out how to move this to a mixin, it just doesn't want to work
    created_by_uuid = db.Column(db.String(255), db.ForeignKey(
        'user.uuid'), default=_current_user_id_or_none)
    updated_by_uuid = db.Column(db.String(255), db.ForeignKey(
        'user.uuid'), default=_current_user_id_or_none, onupdate=_current_user_id_or_none)
    created_by = db.relationship('User', foreign_keys=[created_by_uuid])
    updated_by = db.relationship('User', foreign_keys=[updated_by_uuid])
    organization = db.relationship('Organization', back_populates='observables')
    organization_uuid = db.Column(db.String(255), db.ForeignKey('organization.uuid'))


class Agent(Base):

    name = db.Column(db.String(255))
    inputs = db.relationship('Input', secondary=agent_input_association)
    roles = db.relationship(
        'AgentRole', secondary=agent_role_agent_association)
    groups = db.relationship(
        'AgentGroup', secondary=agent_group_agent_association)
    active = db.Column(db.Boolean, default=True)
    ip_address = db.Column(db.String(255))
    last_heartbeat = db.Column(db.DateTime)
    role = db.relationship('Role', back_populates='agents')
    role_uuid = db.Column(db.String(255), db.ForeignKey('role.uuid'))
    organization = db.relationship('Organization', back_populates='agents')
    organization_uuid = db.Column(db.String(255), db.ForeignKey('organization.uuid'))

    def has_right(self, permission):

        if getattr(self.role.permissions,permission):
            return True
        else:
            return False


class AgentRole(Base):

    name = db.Column(db.String(255))
    description = db.Column(db.Text)
    organization = db.relationship('Organization', back_populates='agent_roles')
    organization_uuid = db.Column(db.String(255), db.ForeignKey('organization.uuid'))


class AgentGroup(Base):

    name = db.Column(db.String(255))
    description = db.Column(db.Text)

    # AUDIT COLUMNS
    # TODO: Figure out how to move this to a mixin, it just doesn't want to work
    created_by_uuid = db.Column(db.String(255), db.ForeignKey(
        'user.uuid'), default=_current_user_id_or_none)
    updated_by_uuid = db.Column(db.String(255), db.ForeignKey(
        'user.uuid'), default=_current_user_id_or_none, onupdate=_current_user_id_or_none)
    created_by = db.relationship('User', foreign_keys=[created_by_uuid])
    updated_by = db.relationship('User', foreign_keys=[updated_by_uuid])
    organization = db.relationship('Organization', back_populates='agent_groups')
    organization_uuid = db.Column(db.String(255), db.ForeignKey('organization.uuid'))


class DataType(Base):

    name = db.Column(db.String(255))
    description = db.Column(db.Text)
    regex = db.Column(db.Text)

    # AUDIT COLUMNS
    # TODO: Figure out how to move this to a mixin, it just doesn't want to work
    created_by_uuid = db.Column(db.String(255), db.ForeignKey(
        'user.uuid'), default=_current_user_id_or_none)
    updated_by_uuid = db.Column(db.String(255), db.ForeignKey(
        'user.uuid'), default=_current_user_id_or_none, onupdate=_current_user_id_or_none)
    created_by = db.relationship('User', foreign_keys=[created_by_uuid])
    updated_by = db.relationship('User', foreign_keys=[updated_by_uuid])
    organization = db.relationship('Organization', back_populates='data_types')
    organization_uuid = db.Column(db.String(255), db.ForeignKey('organization.uuid'))


class Playbook(Base):

    name = db.Column(db.String(255), unique=True, nullable=False)
    description = db.Column(db.String(255))
    enabled = db.Column(db.Boolean(), default=True)
    tags = db.relationship('Tag', secondary=playbook_tag_association)

    # AUDIT COLUMNS
    # TODO: Figure out how to move this to a mixin, it just doesn't want to work
    created_by_uuid = db.Column(db.String(255), db.ForeignKey(
        'user.uuid'), default=_current_user_id_or_none)
    updated_by_uuid = db.Column(db.String(255), db.ForeignKey(
        'user.uuid'), default=_current_user_id_or_none, onupdate=_current_user_id_or_none)
    created_by = db.relationship('User', foreign_keys=[created_by_uuid])
    updated_by = db.relationship('User', foreign_keys=[updated_by_uuid])
    organization = db.relationship('Organization', back_populates='playbooks')
    organization_uuid = db.Column(db.String(255), db.ForeignKey('organization.uuid'))


class Plugin(Base):
    name = db.Column(db.String(255), unique=True, nullable=False)
    description = db.Column(db.String(255), nullable=False)
    logo = db.Column(LONGTEXT)
    manifest = db.Column(db.JSON, nullable=False)
    config_template = db.Column(db.JSON)
    enabled = db.Column(db.Boolean, default=False)
    filename = db.Column(db.String(255), nullable=False)
    file_hash = db.Column(db.String(255))
    configs = db.relationship('PluginConfig', back_populates='plugin')

    # AUDIT COLUMNS
    # TODO: Figure out how to move this to a mixin, it just doesn't want to work
    created_by_uuid = db.Column(db.String(255), db.ForeignKey(
        'user.uuid'), default=_current_user_id_or_none)
    updated_by_uuid = db.Column(db.String(255), db.ForeignKey(
        'user.uuid'), default=_current_user_id_or_none, onupdate=_current_user_id_or_none)
    created_by = db.relationship('User', foreign_keys=[created_by_uuid])
    updated_by = db.relationship('User', foreign_keys=[updated_by_uuid])
    organization = db.relationship('Organization', back_populates='plugins')
    organization_uuid = db.Column(db.String(255), db.ForeignKey('organization.uuid'))


class PluginConfig(Base):
    name = db.Column(db.String(255), unique=True, nullable=False)
    description = db.Column(db.String(255), nullable=False)
    config = db.Column(db.JSON, nullable=False)
    plugin_uuid = db.Column(db.String(255), db.ForeignKey('plugin.uuid'))
    plugin = db.relationship('Plugin', back_populates='configs')

    # AUDIT COLUMNS
    # TODO: Figure out how to move this to a mixin, it just doesn't want to work
    created_by_uuid = db.Column(db.String(255), db.ForeignKey(
        'user.uuid'), default=_current_user_id_or_none)
    updated_by_uuid = db.Column(db.String(255), db.ForeignKey(
        'user.uuid'), default=_current_user_id_or_none, onupdate=_current_user_id_or_none)
    created_by = db.relationship('User', foreign_keys=[created_by_uuid])
    updated_by = db.relationship('User', foreign_keys=[updated_by_uuid])
    organization = db.relationship('Organization', back_populates='plugin_configs')
    organization_uuid = db.Column(db.String(255), db.ForeignKey('organization.uuid'))


class List(Base):
    '''
    A list of values, strings or regular expressions

    List Types: value,pattern
    '''

    name = db.Column(db.String(255), unique=True, nullable=False)
    list_type = db.Column(db.String(255))
    data_type_uuid = db.Column(db.String(255), db.ForeignKey('data_type.uuid'))
    data_type = db.relationship('DataType')
    tag_on_match = db.Column(db.Boolean, default=False)
    values = db.relationship('ListValue', back_populates='parent_list')
    organization = db.relationship('Organization', back_populates='lists')
    organization_uuid = db.Column(db.String(255), db.ForeignKey('organization.uuid'))

    # AUDIT COLUMNS
    # TODO: Figure out how to move this to a mixin, it just doesn't want to work
    created_by_uuid = db.Column(db.String(255), db.ForeignKey(
        'user.uuid'), default=_current_user_id_or_none)
    updated_by_uuid = db.Column(db.String(255), db.ForeignKey(
        'user.uuid'), default=_current_user_id_or_none, onupdate=_current_user_id_or_none)
    created_by = db.relationship('User', foreign_keys=[created_by_uuid])
    updated_by = db.relationship('User', foreign_keys=[updated_by_uuid])


class ListValue(Base):
    ''' 
    A value in a List, it can be a String or a Regular Expression
    '''

    value = db.Column(db.Text)
    parent_list_uuid = db.Column(db.String(255), db.ForeignKey('list.uuid'))
    parent_list = db.relationship('List', back_populates='values')
    organization_uuid = db.Column(db.String(255))

    # AUDIT COLUMNS
    # TODO: Figure out how to move this to a mixin, it just doesn't want to work
    created_by_uuid = db.Column(db.String(255), db.ForeignKey(
        'user.uuid'), default=_current_user_id_or_none)
    updated_by_uuid = db.Column(db.String(255), db.ForeignKey(
        'user.uuid'), default=_current_user_id_or_none, onupdate=_current_user_id_or_none)
    created_by = db.relationship('User', foreign_keys=[created_by_uuid])
    updated_by = db.relationship('User', foreign_keys=[updated_by_uuid])


class Input(Base):

    name = db.Column(db.String(255), unique=True, nullable=False)
    description = db.Column(db.String(255), nullable=False)
    plugin = db.Column(db.String(255), nullable=False)
    enabled = db.Column(db.Boolean, default=True)
    config = db.Column(db.JSON, nullable=False)
    credential_id = db.Column(db.String(255), db.ForeignKey('credential.uuid'))
    credential = db.relationship('Credential')
    tags = db.relationship('Tag', secondary=input_tag_association)
    field_mapping = db.Column(db.JSON, nullable=False)

    # AUDIT COLUMNS
    # TODO: Figure out how to move this to a mixin, it just doesn't want to work
    created_by_uuid = db.Column(db.String(255), db.ForeignKey(
        'user.uuid'), default=_current_user_id_or_none)
    updated_by_uuid = db.Column(db.String(255), db.ForeignKey(
        'user.uuid'), default=_current_user_id_or_none, onupdate=_current_user_id_or_none)
    created_by = db.relationship('User', foreign_keys=[created_by_uuid])
    updated_by = db.relationship('User', foreign_keys=[updated_by_uuid])
    organization = db.relationship('Organization', back_populates='inputs')
    organization_uuid = db.Column(db.String(255), db.ForeignKey('organization.uuid'))


class Credential(Base):
    ''' Stores a credential that can be used by worker processes '''

    name = db.Column(db.String(255), unique=True, nullable=False)
    description = db.Column(db.String(255))
    username = db.Column(db.String(255))
    secret = db.Column(db.String(2048))
    organization = db.relationship('Organization', back_populates='credentials')
    organization_uuid = db.Column(db.String(255), db.ForeignKey('organization.uuid'))

    # AUDIT COLUMNS
    # TODO: Figure out how to move this to a mixin, it just doesn't want to work
    created_by_uuid = db.Column(db.String(255), db.ForeignKey(
        'user.uuid'), default=_current_user_id_or_none)
    updated_by_uuid = db.Column(db.String(255), db.ForeignKey(
        'user.uuid'), default=_current_user_id_or_none, onupdate=_current_user_id_or_none)
    created_by = db.relationship('User', foreign_keys=[created_by_uuid])
    updated_by = db.relationship('User', foreign_keys=[updated_by_uuid])

    def _derive_key(self, secret: bytes, salt: bytes, iterations: int = 100_000) -> bytes:

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations,
            backend=default_backend()
        )
        return base64.urlsafe_b64encode(kdf.derive(secret))

    def encrypt(self, message: bytes, secret: str, iterations: int = 100_000) -> bytes:
        iterations = 100_000
        salt = secrets.token_bytes(16)
        key = self._derive_key(secret.encode(), salt, iterations)
        self.secret = base64.urlsafe_b64encode(b'%b%b%b' % (salt, iterations.to_bytes(4, 'big'),
                                                            base64.urlsafe_b64encode(Fernet(key).encrypt(message)))).decode()

    def decrypt(self, secret: str) -> bytes:
        decoded = base64.urlsafe_b64decode(self.secret)
        salt, iter, token = decoded[:16], decoded[16:20], base64.urlsafe_b64decode(
            decoded[20:])
        iterations = int.from_bytes(iter, 'big')
        key = self._derive_key(secret.encode(), salt, iterations)
        try:
            return Fernet(key).decrypt(token).decode()
        except InvalidToken:
            return None


class Tag(Base):

    name = db.Column(db.String(200))
    color = db.Column(db.String(7))

    # AUDIT COLUMNS
    # TODO: Figure out how to move this to a mixin, it just doesn't want to work
    created_by_uuid = db.Column(db.String(255), db.ForeignKey(
        'user.uuid'), default=_current_user_id_or_none)
    updated_by_uuid = db.Column(db.String(255), db.ForeignKey(
        'user.uuid'), default=_current_user_id_or_none, onupdate=_current_user_id_or_none)
    created_by = db.relationship('User', foreign_keys=[created_by_uuid])
    updated_by = db.relationship('User', foreign_keys=[updated_by_uuid])
    organization = db.relationship('Organization', back_populates='tags')
    organization_uuid = db.Column(db.String(255), db.ForeignKey('organization.uuid'))

    @validates('name')
    def convert_lower(self, key, value):
        return value.lower()


class GlobalSettings(Base):

    base_url = db.Column(db.String(2048))
    require_case_templates = db.Column(db.Boolean, default=True)
    email_from = db.Column(db.String(255))
    email_server = db.Column(db.String(255))
    email_secret_uuid = db.Column(db.String(255), db.ForeignKey("credential.uuid"))
    email_secret = db.relationship('Credential')
    allow_comment_deletion = db.Column(db.Boolean, default=False)
    playbook_action_timeout = db.Column(db.Integer, default=300)
    playbook_timeout = db.Column(db.Integer, default=3600)
    logon_password_attempts = db.Column(db.Integer, default=5)
    organization = db.relationship('Organization', back_populates='settings')
    organization_uuid = db.Column(db.String(255), db.ForeignKey('organization.uuid'))
    api_key_valid_days = db.Column(db.Integer, default=366)
    agent_pairing_token_valid_minutes = db.Column(db.Integer, default=15)
    peristent_pairing_token = db.Column(db.String(255))
    require_event_dismiss_comment = db.Column(db.Boolean, default=False)
    allow_event_deletion = db.Column(db.Boolean, default=False)
    require_case_close_comment = db.Column(db.Boolean, default=False)
    assign_case_on_create = db.Column(db.Boolean, default=True)
    assign_task_on_start = db.Column(db.Boolean, default=True)
    allow_comment_editing = db.Column(db.Boolean, default=False)
    events_page_refresh = db.Column(db.Integer, default=60)
    events_per_page = db.Column(db.Integer, default=10)

    def generate_persistent_pairing_token(self):
        '''
        Generates a long living pairing token which can be used in
        automated deployment of agents
        '''

        _api_key = jwt.encode({
            'organization': self.organization_uuid,
            'iat': datetime.datetime.utcnow(),
            'type': 'pairing'
        }, current_app.config['SECRET_KEY']).decode('utf-8')

        if self.peristent_pairing_token != None:
            blacklist = AuthTokenBlacklist(auth_token = self.peristent_pairing_token)
            blacklist.create()
            self.peristent_pairing_token = _api_key
        else:
            self.peristent_pairing_token = _api_key
        self.save()
        return {'token': self.peristent_pairing_token}
