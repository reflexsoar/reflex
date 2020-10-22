from flask_restx import Model, fields


class ValueCount(fields.Raw):
    def format(self, value):
        return len(value)

class ObservableCount(fields.Raw):
    ''' Returns the number of observables '''

    def format(self, value):
        return len(value)

class OpenTaskCount(fields.Raw):
    ''' Returns a count of open tasks '''

    def format(self, value):
        return len([a for a in value if a.status != 2])

class IOCCount(fields.Raw):
    ''' Returns the number of observables that are IOC '''

    def format(self, value):
        iocs = [o for o in value if o.ioc == True]
        return len(iocs)

class AsNewLineDelimited(fields.Raw):
    ''' Returns an array as a string delimited by new line characters '''
    def format(self, value):
        return '\n'.join([v.value for v in value])

class AsDefaultType(fields.Raw):
    ''' Returns the value in its default type '''
    def format(self, value):
        return value

class JSONField(fields.Raw):
    def format(self, value):
        return value

class ISO8601(fields.Raw):
    ''' Returns a Python DateTime object in ISO8601 format with the Zulu time indicator '''
    def format(self, value):
        return value.isoformat()+"Z"

# Models
mod_user_list = Model('UserList', {
    'username': fields.String,
    'uuid': fields.String
})

mod_user_role = Model('UserRole', {
    'uuid': fields.String,
    'name': fields.String
})

mod_organization_basic = Model('OrganizationBasic', {
    'uuid': fields.String,
    'name': fields.String
})

mod_user_full = Model('UserFull', {
    'uuid': fields.String,
    'username': fields.String,
    'email': fields.String,
    'first_name': fields.String,
    'last_name': fields.String,
    'last_logon': ISO8601(attribute='last_logon'),
    'locked': fields.Boolean,
    'role': fields.Nested(mod_user_role)
})

mod_user_create_success = Model('UserCreateSuccess', {
    'message': fields.String,
    'user': fields.Nested(mod_user_full)
})

mod_user_create = Model('UserCreate', {
    'username': fields.String,
    'email': fields.String,
    'password': fields.String,
    'first_name': fields.String,
    'last_name': fields.String,
    'locked': fields.Boolean
})

mod_user_self = Model('UserSelf', {
    'uuid': fields.String,
    'username': fields.String,
    'first_name': fields.String,
    'last_name': fields.String,
    'email': fields.String,
    'permissions': fields.List(fields.String),
    'organization': fields.Nested(mod_organization_basic)
})

mod_user_group_create = Model('UserGroupCreate', {
    'name': fields.String,
    'description': fields.String
})

mod_user_group_list = Model('UserGroupList', {
    'uuid': fields.String,
    'name': fields.String,
    'description': fields.String,
    'created_at': ISO8601(attribute='created_at'),
    'modified_at': ISO8601(attribute='modified_at'),
    'members': fields.List(fields.Nested(mod_user_list))
})

mod_add_user_to_group = Model('UsersToGroup', {
    'members': fields.List(fields.String)
})

mod_auth = Model('AuthModel', {
    'username': fields.String(default='reflex'),
    'password': fields.String(default='reflex')
})

mod_auth_success_token = Model('AuthSuccessToken', {
    'access_token': fields.String
})

mod_refresh_token = Model('RefreshToken', {
    'refresh_token': fields.String
})

mod_role_create = Model('RoleCreate', {
    'name': fields.String,
    'description': fields.String
})

mod_role_uuid = Model('RoleUUID', {
    'uuid': fields.String
})

permission_fields = {
    'add_user': fields.Boolean,
    'update_user': fields.Boolean,
    'delete_user': fields.Boolean,
    'add_user_to_role': fields.Boolean,
    'remove_user_from_role': fields.Boolean,
    'reset_user_password': fields.Boolean,
    'unlock_user': fields.Boolean,
    'view_users': fields.Boolean,
    'add_event': fields.Boolean,
    'view_events': fields.Boolean,
    'update_event': fields.Boolean,
    'delete_event': fields.Boolean,
    'add_tag_to_event': fields.Boolean,
    'remove_tag_from_event': fields.Boolean,
    'add_observable': fields.Boolean,
    'update_observable': fields.Boolean,
    'delete_observable': fields.Boolean,
    'add_tag_to_observable': fields.Boolean,
    'remove_tag_from_observable': fields.Boolean,
    'add_playbook': fields.Boolean,
    'update_playbook': fields.Boolean,
    'delete_playbook': fields.Boolean,
    'view_playbooks': fields.Boolean,
    'add_tag_to_playbook': fields.Boolean,
    'remove_tag_from_playbook': fields.Boolean,
    'add_role': fields.Boolean,
    'update_role': fields.Boolean,
    'delete_role': fields.Boolean,
    'set_role_permissions': fields.Boolean,
    'view_roles': fields.Boolean,
    "add_tag": fields.Boolean,
    "update_tag": fields.Boolean,
    "delete_tag": fields.Boolean,
    "view_tags": fields.Boolean,
    "add_credential": fields.Boolean,
    "update_credential": fields.Boolean,
    "decrypt_credential": fields.Boolean,
    "delete_credential": fields.Boolean,
    "view_credentials": fields.Boolean,
    "view_agents": fields.Boolean,
    "update_agent": fields.Boolean,
    "delete_agent": fields.Boolean,
    "pair_agent": fields.Boolean,
    'add_input': fields.Boolean,
    "view_inputs": fields.Boolean,
    "update_input": fields.Boolean,
    "delete_input": fields.Boolean,
    "create_case": fields.Boolean,
    "view_cases": fields.Boolean,
    "update_case": fields.Boolean,
    "delete_case": fields.Boolean,
    "create_case_comment": fields.Boolean,
    "view_case_comments": fields.Boolean,
    "update_case_comment": fields.Boolean,
    "delete_case_comment": fields.Boolean,
    "view_plugins": fields.Boolean,
    "create_plugin": fields.Boolean,
    "delete_plugin": fields.Boolean,
    "update_plugin": fields.Boolean,
    "create_agent_group": fields.Boolean,
    "view_agent_groups": fields.Boolean,
    "update_agent_group": fields.Boolean,
    "delete_agent_group": fields.Boolean,
    "create_user_group": fields.Boolean,
    "view_user_groups": fields.Boolean,
    "update_user_groups": fields.Boolean,
    "delete_user_group": fields.Boolean,
    "create_case_template": fields.Boolean,
    "view_case_templates": fields.Boolean,
    "update_case_template": fields.Boolean,
    "delete_case_template": fields.Boolean,
    "create_case_task": fields.Boolean,
    "view_case_tasks": fields.Boolean,
    "update_case_task": fields.Boolean,
    "delete_case_task": fields.Boolean,
    "create_case_template_task": fields.Boolean,
    "view_case_template_tasks": fields.Boolean,
    "update_case_template_task": fields.Boolean,
    "delete_case_template_task": fields.Boolean,
    "create_case_status": fields.Boolean,
    "update_case_status": fields.Boolean,
    "delete_case_status": fields.Boolean,
    "update_settings": fields.Boolean,
    "add_organization": fields.Boolean,
    "view_organizatons": fields.Boolean,
    "update_organization": fields.Boolean,
    "delete_organization": fields.Boolean,
    "use_api": fields.Boolean,
    "add_list": fields.Boolean,
    "update_list": fields.Boolean,
    "view_lists": fields.Boolean,
    "delete_list": fields.Boolean,
    "create_data_type": fields.Boolean,
    "update_data_type": fields.Boolean,
    "create_persistent_pairing_token": fields.Boolean,
    "create_event_rule": fields.Boolean,
    "view_event_rules": fields.Boolean,
    "update_event_rule": fields.Boolean,
    "delete_event_rule": fields.Boolean,
    "upload_case_files": fields.Boolean,
    "view_case_files": fields.Boolean,
    "delete_case_files": fields.Boolean
}


mod_permission_role_view = Model('PermissionRoleView', {
    **permission_fields,
    **{'uuid': fields.String}})

mod_permission_list = Model('Permission', {
    **permission_fields,
    **{
        'uuid': fields.String,
        'roles': fields.List(fields.Nested(mod_role_uuid))
    }
})

mod_permission_full = Model('PermissionFull', {
    **permission_fields
})

mod_role_list = Model('Role', {
    'uuid': fields.String,
    'name': fields.String,
    'description': fields.String,
    'users': fields.List(fields.Nested(mod_user_list)),
    'permissions': fields.List(fields.Nested(mod_permission_role_view))
})

mod_tag = Model('Tag', {
    'name': fields.String
})

mod_tag_list = Model('TagList', {
    'uuid': fields.String,
    'name': fields.String
})

mod_credential_create = Model('CredentialCreate', {
    'username': fields.String,
    'secret': fields.String,
    'name': fields.String,
    'description': fields.String
})

mod_credential_update = Model('CredentialUpdate', {
    'username': fields.String,
    'secret': fields.String,
    'name': fields.String,
    'description': fields.String
})

mod_credential_full = Model('Credential', {
    'uuid': fields.String,
    'username': fields.String,
    'name': fields.String,
    'description': fields.String
})

mod_credential_list = Model('CredentialLIst', {
    'uuid': fields.String,
    'name': fields.String,
    'description': fields.String
})

mod_credential_return = Model('CredentialReturn', {
    'secret': fields.String
})

mod_bulk_tag = Model('BulkTag', {
    'tags': fields.List(fields.String)
})

mod_credential_decrypt = Model('CredentialDecrypt', {
    'uuid': fields.String,
    'master_password': fields.String
})

mod_credential_decrypted = Model('CredentialDecrypted', {
    'secret': fields.String
})

mod_playbook_create = Model('ProjectCreate', {
    'name': fields.String,
    'description': fields.String,
    'tags': fields.List(fields.String)
})

mod_playbook_full = Model('Project', {
    'uuid': fields.String,
    'name': fields.String,
    'description': fields.String,
    'enabled': fields.String
})

mod_playbook_list = Model('ProjectList', {
    'uuid': fields.String,
    'name': fields.String,
    'description': fields.String,
    'enabled': fields.String,
    'tags': fields.List(fields.Nested(mod_tag_list))
})

mod_observable_create = Model('Observable', {
    'value': fields.String(required=True),
    'ioc': fields.Boolean,
    'tlp': fields.Integer,
    'spotted': fields.Boolean,
    'safe': fields.Boolean,
    'dataType': fields.String(required=True),
    'tags': fields.List(fields.String)
})

mod_observable_type_name = Model('ObservableTypeName', {
    'name': fields.String
})

mod_observable_list = Model('ObservableList', {
    'tags': fields.List(fields.Nested(mod_tag_list)),
    'value': fields.String,
    'ioc': fields.Boolean,
    'tlp': fields.Integer,
    'spotted': fields.Boolean,
    'safe': fields.Boolean,
    'dataType': fields.Nested(mod_observable_type_name),
    'uuid': fields.String
})

mod_observable_list_paged = Model('PagedObservableList', {
    'observables': fields.List(fields.Nested(mod_observable_list)),
    'pagination': JSONField()
})

mod_close_reason_list = Model('CloseReasonList', {
    'uuid': fields.String,
    'title': fields.String,
    'description': fields.String
})

mod_bulk_tag = Model('BulkTag', {
    'tags': fields.List(fields.String)
})

mod_event_create = Model('EventCreate', {
    'title': fields.String(required=True),
    'reference': fields.String(required=True),
    'description': fields.String(required=True),
    'tags': fields.List(fields.String),
    'tlp': fields.Integer,
    'severity': fields.Integer,
    'source': fields.String,
    'observables': fields.List(fields.Nested(mod_observable_create)),
    'raw_log': fields.String
})

mod_event_status = Model('EventStatusString', {
    'name': fields.String,
    'closed': fields.Boolean,
})

mod_case_status_uuid = Model('CaseStatusUUID', {
    'uuid': fields.String
})

mod_case_uuid = Model('CaseUUID', {
    'uuid': fields.String
})

mod_event_bulk_dismiss = Model('EventBulkDismiss', {
    'events': fields.List(fields.String),
    'dismiss_reason_uuid': fields.String,
    'dismiss_comment': fields.String,
})

mod_event_details = Model('EventDetails', {
    'uuid': fields.String,
    'title': fields.String(required=True),
    'reference': fields.String(required=True),
    'description': fields.String(required=True),
    'tlp': fields.Integer,
    'severity': fields.Integer,
    'status': fields.Nested(mod_event_status),
    'source': fields.String,
    'tags': fields.List(fields.Nested(mod_tag_list)),
    'observables': fields.List(fields.Nested(mod_observable_list)),
    'observable_count': ObservableCount(attribute='observables'),
    'ioc_count': IOCCount(attribute='observables'),
    'dismiss_reason': fields.Nested(mod_close_reason_list),
    'case_uuid': fields.String,
    'created_at': ISO8601(attribute='created_at'),
    'modified_at': ISO8601(attribute='modified_at'),
    'raw_log': JSONField(),
    'signature': fields.String
})

mod_event_create_bulk = Model('EventCreateBulk', {
    'events': fields.List(fields.Nested(mod_event_create))
})

mod_forgot_password = Model('ForgotPassword', {
    'email': fields.String
})

mod_observable = Model('ObservableDetails', {
    'tags': fields.List(fields.Nested(mod_tag_list)),
    'value': fields.String,
    'ioc': fields.Boolean,
    'tlp': fields.Integer,
    'spotted': fields.Boolean,
    'dataType': fields.Nested(mod_observable_type_name)
})

mod_observable_brief = Model('ShortObservableDetails', {
    'uuid': fields.String,
    'value': fields.String,
    'dataType': fields.Nested(mod_observable_type_name)
})

mod_event_list = Model('EventList', {
    'uuid': fields.String,
    'title': fields.String(required=True),
    'reference': fields.String(required=True),
    'description': fields.String(required=True),
    'tlp': fields.Integer,
    'severity': fields.Integer,
    'status': fields.Nested(mod_event_status),
    'source': fields.String,
    'tags': fields.List(fields.Nested(mod_tag_list)),
    'observables': fields.List(fields.Nested(mod_observable_brief)),
    'observable_count': ObservableCount(attribute='observables'),
    'ioc_count': IOCCount(attribute='observables'),
    'created_at': ISO8601(attribute='created_at'),
    'modified_at': ISO8601(attribute='modified_at'),
    'case_uuid': fields.String,
    'signature': fields.String,
    'related_events_count': fields.Integer,
    'dismiss_reason': fields.Nested(mod_close_reason_list),
    'new_related_events': fields.List(fields.String)
})

mod_paged_event_list = Model('PagedEventList', {
    'events': fields.List(fields.Nested(mod_event_list)),
    'pagination': JSONField()
})

mod_observable_type = Model('ObservableType', {
    'name': fields.String,
    'uuid': fields.String
})

mod_create_observable_type = Model('ObservableTypeName', {
    'name': fields.String
})

mod_input_list = Model('InputList', {
    'uuid': fields.String,
    'name': fields.String,
    'plugin': fields.String,
    'description': fields.String,
    'enabled': fields.Boolean,
    'credential': fields.Nested(mod_credential_list),
    'tags': fields.List(fields.Nested(mod_tag_list)),
    'config': JSONField(),
    'field_mapping': JSONField(),
    'created_at': ISO8601(attribute='created_at'),
    'modified_at': ISO8601(attribute='modified_at')
})

mod_input_create = Model('CreateInput', {
    'name': fields.String,
    'description': fields.String,
    'plugin': fields.String,
    'enabled': fields.Boolean,
    'credential': fields.String(required=True),
    'tags': fields.List(fields.String),
    'config': JSONField(),
    'field_mapping': JSONField()
})

mod_agent_role_list = Model('AgentRoleList', {
    'name': fields.String,
    'description': fields.String
})

mod_agent_group_list = Model('AgentGroupList', {
    'uuid': fields.String,
    'name': fields.String,
    'description': fields.String
})

mod_paged_agent_group_list = Model('PagedAgentGroupList', {
    'groups': fields.List(fields.Nested(mod_agent_group_list)),
    'pagination': JSONField()
})

mod_agent_group_create = Model('AgentGroupList', {
    'uuid': fields.String,
    'name': fields.String,
    'description': fields.String
})

mod_agent_create = Model('AgentCreate', {
    'name': fields.String,
    'roles': fields.List(fields.String),
    'ip_address': fields.String,
    'inputs': fields.List(fields.String)
})

mod_agent_list = Model('AgentList', {
    'uuid': fields.String,
    'name': fields.String,
    'inputs': fields.List(fields.Nested(mod_input_list)),
    'roles': fields.List(fields.Nested(mod_agent_role_list)),
    'groups': fields.List(fields.Nested(mod_agent_group_list)),
    'active': fields.Boolean,
    'ip_address': fields.String,
    'last_heartbeat': ISO8601(attribute='last_heartbeat')
})

mod_case_template_task_create = Model('CaseTemplateTaskCreate', {
    'title': fields.String,
    'order': fields.Integer,
    'description': fields.String,
    'group_uuid': fields.String,
    'owner_uuid': fields.String,
    'case_template_uuid': fields.String
})

mod_case_template_task_full = Model('CaseTemplateTaskList', {
    'uuid': fields.String,
    'title': fields.String,
    'description': fields.String,
    'order': fields.Integer,
    'created_at': ISO8601(attribute='created_at'),
    'modified_at': ISO8601(attribute='modified_at'),
    'group': fields.Nested(mod_user_group_list),
    'owner': fields.Nested(mod_user_list),
    'case_template_uuid': fields.String,
    'status': fields.Integer
})

mod_case_task_create = Model('CaseTaskCreate', {
    'title': fields.String,
    'order': fields.Integer,
    'description': fields.String,
    'group_uuid': fields.String,
    'owner_uuid': fields.String,
    'case_uuid': fields.String
})

mod_case_task_full = Model('CaseTaskList', {
    'uuid': fields.String,
    'title': fields.String,
    'description': fields.String,
    'order': fields.Integer,
    'created_at': ISO8601(attribute='created_at'),
    'modified_at': ISO8601(attribute='modified_at'),
    'start_date': ISO8601(attribute='start_date'),
    'finish_date': ISO8601(attribute='finish_data'),
    'group': fields.Nested(mod_user_group_list),
    'owner': fields.Nested(mod_user_list),
    'case_uuid': fields.String,
    'status': fields.Integer,
    'from_template': fields.Boolean
})

mod_add_tasks_to_case = Model('TasksToCase', {
    'tasks': fields.List(fields.String)
})

mod_case_create = Model('CaseCreate', {
    'title': fields.String(required=True),
    'owner_uuid': fields.String,
    'description': fields.String(required=True),
    'tags': fields.List(fields.String),
    'tlp': fields.Integer,
    'severity': fields.Integer,
    'observables': fields.List(fields.String),
    'events': fields.List(fields.String)
})

mod_close_reason_create = Model('CreateCloseReason', {
    'title': fields.String,
    'description': fields.String
})

mod_case_template_create = Model('CaseTemplateCreate', {
    'title': fields.String(required=True),
    'owner_uuid': fields.String,
    'description': fields.String(required=True),
    'tags': fields.List(fields.String),
    'tlp': fields.Integer,
    'severity': fields.Integer
})

mod_case_history = Model('CaseHistoryEntry', {
    'message': fields.String,
    'created_at': ISO8601(attribute='created_at'),
    'created_by': fields.Nested(mod_user_list)
})

mod_case_template_full = Model('CaseTemplateList', {
    'uuid': fields.String,
    'title': fields.String,
    'owner': fields.Nested(mod_user_list),
    'description': fields.String,
    'tags': fields.List(fields.Nested(mod_tag_list)),
    'tlp': fields.Integer,
    'severity': fields.Integer,
    'status': fields.Nested(mod_event_status),
    'created_at': ISO8601(attribute='created_at'),
    'modified_at': ISO8601(attribute='modified_at'),
    'tasks': fields.List(fields.Nested(mod_case_template_task_full)),
    'task_count': ValueCount(attribute='tasks')
})


mod_case_status = Model('CaseStatusString', {
    'uuid': fields.String,
    'name': fields.String,
    'closed': fields.Boolean
})

mod_case_status_create = Model('CaseStatusCreate', {
    'name': fields.String,
    'description': fields.String
})

mod_case_status_list = Model('CaseStatusList', {
    'uuid': fields.String,
    'name': fields.String,
    'description': fields.String,
    'closed': fields.Boolean
})

mod_case_close_reason = Model('CaseCloseList', {
    'uuid': fields.String,
    'title': fields.String,
    'description': fields.String
})

mod_comment = Model('CommentDetails', {
    'uuid': fields.String,
    'message': fields.String,
    'edited': fields.Boolean,
    'is_closure_comment': fields.Boolean,
    'closure_reason': fields.Nested(mod_case_close_reason),
    'created_by': fields.Nested(mod_user_list),
    'created_at': ISO8601(attribute='created_at'),
    'case_uuid': fields.String
})

mod_comment_create = Model('CommentCreate', {
    'case_uuid': fields.String,
    'message': fields.String
})


mod_bulk_add_observables = Model('BulkObservables', {
    'observables': fields.List(fields.Nested(mod_observable_create))
})

mod_case_observables = Model('CaseObservables', {
    'observables': fields.List(fields.Nested(mod_observable_list))
})

mod_case_template_brief = Model('CaseTemplateBrief', {
    'uuid': fields.String,
    'title': fields.String,
})

mod_related_case = Model('RelatedCase', {
    'id': fields.Integer,
    'uuid': fields.String,
    'title': fields.String,
    'event_count': ValueCount(attribute='events'),
    'observable_count': ObservableCount(attribute='observables'),
    'owner': fields.Nested(mod_user_list),
    'status': fields.Nested(mod_case_status)
})

mod_case_details = Model('CaseDetails', {
    'id': fields.String,
    'uuid': fields.String,
    'title': fields.String,
    'owner': fields.Nested(mod_user_list),
    'description': fields.String,
    'tags': fields.List(fields.Nested(mod_tag)),
    'tlp': fields.Integer,
    'severity': fields.Integer,
    'status': fields.Nested(mod_case_status),
    'event_count': ValueCount(attribute='events'),
    'open_tasks': OpenTaskCount(attribute='tasks'),
    'total_tasks': ValueCount(attribute='tasks'),
    'created_at': ISO8601(attribute='created_at'),
    'modified_at': ISO8601(attribute='modified_at'),
    'created_by': fields.Nested(mod_user_list),
    'updated_by': fields.Nested(mod_user_list),
    'observable_count': ValueCount(attribute='observables'),
    'close_reason': fields.Nested(mod_close_reason_list),
    'case_template': fields.Nested(mod_case_template_brief)
})

mod_case_list = Model('CaseList', {
    'id': fields.String,
    'uuid': fields.String,
    'title': fields.String,
    'owner': fields.Nested(mod_user_list),
    'description': fields.String,
    'tags': fields.List(fields.Nested(mod_tag)),
    'tlp': fields.Integer,
    'severity': fields.Integer,
    'status': fields.Nested(mod_case_status),
    'event_count': ValueCount(attribute='events'),
    'open_tasks': OpenTaskCount(attribute='tasks'),
    'total_tasks': ValueCount(attribute='tasks'),
    'created_at': ISO8601(attribute='created_at'),
    'modified_at': ISO8601(attribute='modified_at'),
    'created_by': fields.Nested(mod_user_list),
    'updated_by': fields.Nested(mod_user_list),
    'observable_count': ValueCount(attribute='observables'),
    'close_reason': fields.Nested(mod_close_reason_list),
    #'case_template': fields.Nested(mod_case_template_brief)
})

mod_case_paged_list = Model('PagedCaseList', {
   'cases': fields.List(fields.Nested(mod_case_list)),
   'pagination': JSONField()
})

mod_event_short = Model('EventListShort', {
    'uuid': fields.String,
    'title': fields.String(required=True),
    'reference': fields.String(required=True),
    'description': fields.String(required=True),
    'tlp': fields.Integer,
    'severity': fields.Integer,
    'status': fields.Nested(mod_event_status),
    'tags': fields.List(fields.Nested(mod_tag_list)),
    'observable_count': ObservableCount(attribute='observables'),
    'ioc_count': IOCCount(attribute='observables'),
    'created_at': ISO8601(attribute='created_at'),
    'modified_at': ISO8601(attribute='modified_at'),
    'case_uuid': fields.String,
    'signature': fields.String,
})

mod_case_full = Model('CaseDetails', {
    'id': fields.Integer,
    'uuid': fields.String,
    'title': fields.String,
    'owner': fields.Nested(mod_user_list),
    'description': fields.String,
    'tags': fields.List(fields.Nested(mod_tag)),
    'tlp': fields.Integer,
    'severity': fields.Integer,
    'status_uuid': fields.String,
    'status': fields.Nested(mod_case_status),
    'event_count': ValueCount(attribute='events'),
    'observable_count': ObservableCount(attribute='observables'),
    'created_at': ISO8601(attribute='created_at'),
    'modified_at': ISO8601(attribute='modified_at'),
    'created_by': fields.Nested(mod_user_list),
    'updated_by': fields.Nested(mod_user_list),
    'observables': fields.List(fields.Nested(mod_observable_list)),
    'close_reason': fields.Nested(mod_close_reason_list)
})

mod_plugin_create = Model('PluginCreate', {
    "name": fields.String,
    "description": fields.String,
    "filename": fields.String,
    "file_hash": fields.String
})

mod_plugin_name = Model('PluginDetailsLimited', {
    "name": fields.String
})

mod_plugin_config_list = Model('PluginConfigList', {
    "name": fields.String,
    "description": fields.String,
    "plugin": fields.Nested(mod_plugin_name),
    "plugin_uuid": fields.String,
    "config": fields.String,
    'created_at': ISO8601(attribute='created_at'),
    'modified_at': ISO8601(attribute='modified_at')

})

mod_plugin_list = Model('PluginList', {
    "uuid": fields.String,
    "name": fields.String,
    "logo": fields.String,
    "description": fields.String,
    "enabled": fields.Boolean,
    "manifest": JSONField,
    "config_template": JSONField,
    "filename": fields.String,
    "file_hash": fields.String,
    'created_at': ISO8601(attribute='created_at'),
    'modified_at': ISO8601(attribute='modified_at'),
    "configs": fields.List(fields.Nested(mod_plugin_config_list))
})

mod_plugin_config_create = Model('PluginConfigCreate', {
    "name": fields.String,
    "description": fields.String,
    "plugin_uuid": fields.String,
    "config": fields.String
})

mod_settings = Model('SettingsList', {
    'base_url': fields.String,
    'require_case_templates': fields.Boolean,
    'allow_comment_deletion': fields.Boolean,
    'email_from': fields.String,
    'email_server': fields.String,
    'email_secret_uuid': fields.String,
    'playbook_action_timeout': fields.Integer,
    'playbook_timeout': fields.Integer,
    'logon_password_attempts': fields.Integer,
    'api_key_valid_days': fields.Integer,
    'agent_pairing_token_valid_minutes': fields.Integer,
    'persistent_pairing_token': fields.String,
    'require_event_dismiss_comment': fields.Boolean,
    'require_case_close_comment': fields.Boolean,
    'allow_event_deletion': fields.Boolean,
    'assign_case_on_create': fields.Boolean,
    'assign_task_on_start': fields.Boolean,
    'allow_comment_editing': fields.Boolean,
    'events_page_refresh': fields.Integer,
    'events_per_page': fields.Integer
})

mod_case_metrics = Model('CaseMetrics', {
    'counts': fields.List
})

mod_api_key = Model('UserApiKey', {
    'api_key': fields.String
})

mod_persistent_pairing_token = Model('PeristentPairingToken', {
    'token': fields.String
})

mod_list_value = Model('ListValue', {
    'value': fields.String
})

mod_list_list = Model('ListView', {
    'uuid': fields.String,
    'name': fields.String,
    'list_type': fields.String,
    'tag_on_match': fields.Boolean,
    'data_type': fields.Nested(mod_observable_type),
    'values': AsNewLineDelimited(attribute='values'),
    'values_list': fields.List(fields.Nested(mod_list_value), attribute='values'),
    'value_count': ValueCount(attribute='values'),
    'created_at': ISO8601(attribute='created_at'),
    'modified_at': ISO8601(attribute='modified_at')
})

mod_list_create = Model('ListCreate', {
    'name': fields.String,
    'list_type': fields.String,
    'tag_on_match': fields.Boolean,
    'data_type_uuid': fields.String,
    'values': fields.String
})

mod_data_type_list = Model('DataTypeList', {
    'uuid': fields.String,
    'name': fields.String,
    'description': fields.String,
    'regex': fields.String,
    'created_at': ISO8601(attribute='created_at'),
    'modified_at': ISO8601(attribute='modified_at')
})

mod_data_type_create = Model('CreateDataType', {
    'name': fields.String,
    'description': fields.String
})

mod_add_events_to_case = Model('AddEventsToCase', {
    'events': fields.List(fields.String)
})


mod_response_message = Model('ResponseMessage', {
    'message': fields.String
})

mod_add_events_response = Model('AddEventsToCaseResponse', {
    'results': fields.List(fields.Nested(mod_response_message)),
    'success': fields.Boolean,
    'case': fields.Nested(mod_case_full)
})

mod_event_rule_create = Model('CreateEventRule', {
    'name': fields.String,
    'description': fields.String,
    'event_signature': fields.String,
    'merge_into_case': fields.Boolean,
    'target_case_uuid': fields.String,
    'observables': fields.List(fields.Nested(mod_observable_create)),
    'dismiss': fields.Boolean,
    'expire': fields.Boolean,
    'expire_days': fields.Integer,
    'active': fields.Boolean    
})

mod_event_rule_list = Model('EventRuleList', {
    'uuid': fields.String,
    'name': fields.String,
    'description': fields.String,
    'event_signature': fields.String,
    'rule_signature': fields.String,
    'merge_into_case': fields.Boolean,
    'target_case_uuid': fields.String,
    'dismiss': fields.Boolean,
    'expire': fields.Boolean,
    'active': fields.Boolean,
    'observables': fields.List(fields.Nested(mod_observable_list)),
    'expire_at': ISO8601(attribute='expire_at'),
    'created_at': ISO8601(attribute='created_at'),
    'created_by': fields.Nested(mod_user_list),
    'modified_at': ISO8601(attribute='modified_at')
})

mod_case_file = Model('CaseFile', {
    'uuid': fields.String,
    'filename': fields.String,
    'hash_md5': fields.String,
    'hash_sha1': fields.String,
    'hash_sha256': fields.String,
    'mime_type': fields.String,
    'created_by': fields.Nested(mod_user_list),
    'created_at': ISO8601(attribute='created_at')
})

mod_case_file_upload_response = Model('CaseFileUploadResponse', {
    'uuid': fields.String,
    'message': fields.String
})

mod_case_file_upload = Model('CaseFileUpload', {
    'results': fields.List(fields.Nested(mod_case_file_upload_response)),
    'success': fields.Boolean
})

mod_case_file_list = Model('CaseFileList', {
    'files': fields.List(fields.Nested(mod_case_file)),
    'pagination': JSONField()
})

mod_case_task_note = Model('CreateTaskNote', {
    'note': fields.String,
    'task_uuid': fields.String
})

mod_case_task_note_complete = Model('TaskNoteDetails', {
    'uuid': fields.String,
    'note': fields.String,
    'task_uuid': fields.String,
    'created_by': fields.Nested(mod_user_list),
    'created_at': ISO8601(attribute='created_at'),
    'after_complete': fields.Boolean
})

mod_bulk_observable_update = Model('BulkUpdateObservables', {
    'observables': fields.List(fields.String),
    'ioc': fields.Boolean,
    'safe': fields.Boolean,
    'spotted': fields.Boolean
})

schema_models = [mod_auth, mod_auth_success_token, mod_refresh_token, mod_user_full, mod_user_create_success, mod_user_create,
                 mod_user_list, mod_user_self, mod_role_list, mod_role_create,
                 mod_tag, mod_tag_list, mod_credential_create, mod_credential_full, mod_credential_return,
                 mod_credential_decrypted, mod_credential_decrypt, mod_credential_update,
                 mod_permission_full, mod_permission_list, mod_role_uuid, mod_permission_role_view, mod_bulk_tag,
                 mod_playbook_full,  mod_playbook_create, mod_playbook_list, mod_bulk_tag,
                 mod_observable, mod_observable_create, mod_observable_list, mod_observable_type, mod_observable_type_name,
                 mod_event_create, mod_event_details, mod_event_list, mod_credential_list,
                 mod_input_create, mod_input_list, mod_event_create_bulk, mod_event_status,
                 mod_agent_create, mod_agent_list, mod_agent_role_list, mod_case_close_reason, mod_case_details,
                 mod_case_create, mod_case_status, mod_case_full, mod_case_list, mod_case_paged_list,
                 mod_plugin_create, mod_plugin_list, mod_api_key, mod_persistent_pairing_token,
                 mod_agent_group_create, mod_agent_group_list, mod_event_short,
                 mod_plugin_config_list, mod_plugin_config_create, mod_plugin_name,
                 mod_user_group_create, mod_user_group_list, mod_add_user_to_group,
                 mod_case_template_create, mod_case_template_full, mod_add_events_to_case,
                 mod_case_template_task_create, mod_case_template_task_full, mod_add_tasks_to_case, mod_comment, mod_comment_create,
                 mod_case_history, mod_bulk_add_observables, mod_case_observables, mod_bulk_observable_update,
                 mod_case_status_create, mod_case_status_list, mod_organization_basic,
                 mod_case_task_create, mod_case_task_full, mod_user_role, mod_settings, mod_paged_event_list,
                 mod_list_list, mod_list_value, mod_list_create, mod_data_type_list, mod_data_type_create,
                 mod_add_events_response, mod_response_message, mod_event_rule_create, mod_event_rule_list,
                 mod_close_reason_create, mod_close_reason_list, mod_case_template_brief, mod_observable_list_paged,
                 mod_event_bulk_dismiss, mod_related_case, mod_forgot_password, mod_observable_brief, mod_case_file,
                 mod_case_file_upload, mod_case_file_upload_response, mod_case_file_list, mod_case_task_note, mod_case_task_note_complete,
                 mod_paged_agent_group_list]
