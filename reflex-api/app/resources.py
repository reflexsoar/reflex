import os
import re
import datetime
import jwt
import copy
import json
import base64

import hashlib
import itertools
import cryptography
from email.mime.text import MIMEText
from zipfile import ZipFile
from flask_mail import Mail, Message
from flask import request, current_app, abort, make_response, send_from_directory, send_file, Blueprint, render_template
from flask_restx import Api, Resource, Namespace, fields, Model, inputs as xinputs
from sqlalchemy import or_
from sqlalchemy_filters import apply_filters, apply_pagination, apply_sort, apply_loads
from flask_socketio import emit
from werkzeug.utils import secure_filename
from werkzeug.datastructures import FileStorage
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy import desc, asc, func
from sqlalchemy.orm import load_only
from .models import User, UserGroup, db, RefreshToken, GlobalSettings, AuthTokenBlacklist, Role, CaseFile, Credential, CloseReason, Tag, List, ListValue, Permission, Playbook, Event, EventRule, Observable, DataType, Input, EventStatus, Agent, AgentRole, AgentGroup, Case, CaseTask, TaskNote, CaseHistory, CaseTemplate, CaseTemplateTask, CaseComment, CaseStatus, Plugin, PluginConfig, DataType, observable_case_association, case_tag_association
from .utils import token_required, user_has, _get_current_user, generate_token, send_email, check_password_reset_token
from .schemas import *

api_v1 = Blueprint("api", __name__, url_prefix="/api/v1.0")

api = Api(api_v1)
mail = Mail()

# Namespaces
ns_user = api.namespace('User', description='User operations', path='/user')
ns_user_group = api.namespace(
    'UserGroup', description='User Group operations', path='/user_group')
ns_auth = api.namespace(
    'Auth', description='Authentication operations', path='/auth')
ns_role = api.namespace('Role', description='Role operations', path='/role')
ns_perms = api.namespace(
    'Permission', description='Permission operations', path='/permission')
ns_playbook = api.namespace(
    'Playbook', description='Playbook operations', path='/playbook')
ns_input = api.namespace(
    'Input', description='Input operations', path='/input')
ns_tag = api.namespace('Tag', description='Tag operations', path='/tag')
ns_event = api.namespace(
    'Event', description='Event operations', path='/event')
ns_event_rule = api.namespace('EventRule', description='Event Rules control what happens to an event on ingest', path='/event_rule')
ns_case = api.namespace('Case', description='Case operations', path='/case')
ns_case_history = api.namespace('CaseHistory', description='Case history operations', path='/case_history')
ns_case_file = api.namespace('CaseFile', description='Case file attachment operations', path='/case_file')
ns_case_template = api.namespace(
    'CaseTemplate', description='Case Template operations', path='/case_template')
ns_case_template_task = api.namespace(
    'CaseTemplateTask', description='Case Template Task operations', path='/case_template_task')
ns_case_comment = api.namespace(
    'CaseComment', description='Case Comments', path='/case_comment')
ns_case_status = api.namespace(
    'CaseStatus', description='Case Status operations', path='/case_status')
ns_case_task = api.namespace(
    'CaseTask', description='Case Task operations', path='/case_task'
)
ns_case_task_note = api.namespace('CaseTaskNote', description='Task note operations', path='/task_note')
ns_observable = api.namespace('Observable', description='Observable operaitons', path='/observable')
ns_credential = api.namespace(
    'Credential', description='Credential operations', path='/credential')
ns_agent = api.namespace(
    'Agent', description='Agent operations', path='/agent')
ns_agent_group = api.namespace(
    'AgentGroup', description='Agent Group operations', path='/agent_group')
ns_plugin = api.namespace(
    'Plugin', description='Plugin operations', path='/plugin')
ns_plugin_config = api.namespace(
    'PluginConfig', description='Plugin Config operations', path='/plugin_config')
ns_close_reason = api.namespace('CloseReason', description='Closure reason are used when closing a case and can be customized', path='/close_reason')
ns_test = api.namespace('Test', description='Test', path='/test')

ns_settings = api.namespace(
    'GlobalSettings', description='Global settings for the Reflex system', path='/settings'
)
ns_metrics = api.namespace('Metrics', description='Metrics API endpoint for displaying dashboard charts', path='/metrics')
ns_list = api.namespace('List', description='Lists API endpoints for managing indicator lists, lists may be string values or regular expressions', path='/list')
ns_data_type = api.namespace('DataType', description='DataTypes API endpoints for managing what data types observables can be associated with', path='/data_type')


# Expect an API token
expect_token = api.parser()
expect_token.add_argument('Authorization', location='headers')

# Register all the models this is redundant when using api.model() but we don't use this
# TODO: Fix this so this hack isn't required, app factory is jacking this up
for model in schema_models:
    api.models[model.name] = model

upload_parser = api.parser()
upload_parser.add_argument('files', location='files',
                           type=FileStorage, required=True, action="append")

pager_parser = api.parser()
pager_parser.add_argument('page_size', location='args',
                          required=False, type=int, default=25)
pager_parser.add_argument('page', location='args', required=False, type=int, default=1)

def parse_tags(tags, organization_uuid):
    ''' Tags a list of supplied tags and creates Tag objects for each one '''
    _tags = []
    for t in tags:
        tag = Tag.query.filter_by(name=t, organization_uuid=organization_uuid).first()
        if not tag:
            tag = Tag(organization_uuid=organization_uuid, **{'name': t, 'color': '#fffff'})
            tag.create()
            _tags += [tag]
        else:
            _tags += [tag]
    return _tags


def create_observables(observables, organization_uuid):
    _observables = []
    _tags = []
    for o in observables:
        if 'tags' in o:
            tags = o.pop('tags')
            _tags = parse_tags(tags, organization_uuid)

        observable_type = DataType.query.filter_by(name=o['dataType'], organization_uuid=organization_uuid).first()
        if observable_type:
            intel_lists = List.query.filter_by(organization_uuid=organization_uuid, tag_on_match=True, data_type_uuid=observable_type.uuid).all()

            o['dataType'] = observable_type
            observable = Observable(organization_uuid=organization_uuid, **o)
            observable.create()
            _observables += [observable]

            if len(_tags) > 0:
                observable.tags += _tags
                observable.save()

            # Intel list matching, if the value is on a list
            # put the list name in an array so we can tag the observable
            list_matches = []
            for l in intel_lists:
                hits = 0
                if l.list_type == 'values':
                    hits = len([v for v in l.values if v.value.lower() == o['value'].lower()])
                if l.list_type == 'patterns':
                    hits = len([v for v in l.values if re.match(v.value, o['value']) != None])
                if hits > 0:
                    list_matches.append(l.name.replace(' ','-').lower())

            # Process the tags based on the matched intel lists
            if len(list_matches) > 0:
                list_tags = []
                for m in list_matches:
                    tag = Tag.query.filter_by(organization_uuid=organization_uuid, name='list:%s' % m).first()
                    if tag:
                        list_tags.append(tag)
                    else:
                        tag = Tag(organization_uuid=organization_uuid, **{'name':'list:%s' % m, 'color': '#ffffff'})
                        list_tags.append(tag)
                observable.tags += list_tags
                observable.save()

    return _observables


@ns_auth.route("/forgot_password")
class ForgotPassword(Resource):

    @api.expect(mod_forgot_password)
    @api.response(200, 'Success')
    def post(self):
        """
        Initiates a forgot password sequence for a user if they
        exist in the system

        Expects the users e-mail address
        """

        user = User.query.filter_by(email=api.payload['email']).first()
        if user:
            settings = GlobalSettings.query.filter_by(organization_uuid=user.organization_uuid).first()

            mail_user = Credential.query.filter_by(uuid=settings.email_secret_uuid).first()
            msg = MIMEText(render_template('forgot_password.html', name=user.username, reset_link=settings.base_url+"/reset_password/"+user.create_password_reset_token()),'html')
            msg['Subject'] = 'Reflex password reset request'
            msg['From'] = settings.email_from
            msg['To'] = user.email

            send_email(settings, [user.email], settings.email_from, msg)

        return {'message':'Initiated password reset sequence if user exists.'}


@ns_auth.route("/reset_password/<token>")
class ResetPassword(Resource):

    @api.expect(mod_password_reset)
    @api.response(200, 'Success')
    def post(self, token):
        """
        Completes a password reset if the reset token has not been used yet
        and is not expired
        """
        if token:
            user = check_password_reset_token(token)
            if user:
                if 'password' in api.payload:
                    try:
                        user.password = api.payload['password']
                        user.save()
                        expired_token = AuthTokenBlacklist(auth_token = token)
                        expired_token.create()
                        return {'message':'Password successfully changed.'}
                    except Exception as e:
                        print(e)
                        ns_auth.abort(400, 'An error occured while trying to reset the users password.')
                else:
                    ns_auth.abort(400, 'A new password is required.')
            else:
                ns_auth.abort(401, 'Token invalid or expired.')
        else:
            ns_auth.abort(400, 'A password reset token is required.')
        return ""


@ns_auth.route("/login")
class auth(Resource):

    @api.expect(mod_auth)
    @api.response(200, 'Success', mod_auth_success_token)
    @api.response(401, 'Incorrect username or password')
    def post(self):
        ''' Authenticate the user and return their api token '''

        # Check if the user exists
        user = User.query.filter_by(email=api.payload['username'], locked=False).first()
        if not user:
            ns_auth.abort(401, 'Incorrect username or password')

        # Check if the user has entered a good password
        if user.check_password(api.payload['password']):

            # Generate an access token
            _access_token = user.create_access_token()

            # Generate a refresh token
            _refresh_token = user.create_refresh_token(
                request.user_agent.string.encode('utf-8'))

            user.last_logon = datetime.datetime.utcnow()
            user.failed_logons = 0
            user.save()

            return {'access_token': _access_token, 'refresh_token': _refresh_token, 'user': user.uuid}, 200
        
        # If the user fails to logon more than 5 times
        # lock out their account, the counter will reset
        # when an admin unlocks them
        settings = GlobalSettings.query.first()

        if user.failed_logons == None:
            user.failed_logons = 0

        if user.failed_logons > settings.logon_password_attempts:
            user.locked = True
            user.save()
        else:
            user.failed_logons += 1
            user.save()

        ns_auth.abort(401, 'Incorrect username or password')


@ns_auth.route('/refresh')
class refresh(Resource):

    @ns_auth.expect(mod_refresh_token, validate=True)
    @ns_auth.response(200, 'Success', mod_auth_success_token)
    def post(self):
        ''' Refreshes a users access token if their refresh token is still valid '''
        if 'refresh_token' not in api.payload:
            ns_auth.abort(400, 'Invalid request. A refresh token is required.')

        _refresh_token = api.payload['refresh_token']
        try:
            payload = jwt.decode(
                _refresh_token, current_app.config['SECRET_KEY'])

            refresh_token = RefreshToken.query.filter_by(
                user_uuid=payload['uuid'], refresh_token=_refresh_token).first()

            if not refresh_token:
                ns_auth.abort(401, 'Invalid token issuer.')

            # Generate a new pair
            user = User.query.filter_by(uuid=payload['uuid']).first()
            if user:
                access_token = user.create_access_token()
                refresh_token = user.create_refresh_token(
                    request.user_agent.string.encode('utf-8'))
                return {'access_token': access_token, 'refresh_token': refresh_token}, 200
            else:
                return {'message': 'Unauthorized.'}, 401

        except jwt.ExpiredSignatureError as e:
            ns_auth.abort(401, 'Refresh token has expired.')
        except (jwt.DecodeError, jwt.InvalidTokenError)as e:
            ns_auth.abort(401, 'Invalid refresh token.')
        except Exception as e:
            ns_auth.abort(401, 'Unknown token error')


@ns_auth.route('/logout')
class logout(Resource):

    @api.doc(security="Bearer")
    @api.response(200, 'Successfully logged out.')
    @api.response(401, 'Not logged in.')
    @token_required
    def get(self, current_user):
        ''' Logs the user out of their session and blacklists the token so it can't be used again '''
        try:
            auth_header = request.headers.get('Authorization')
            access_token = auth_header.split(' ')[1]
            b_token = AuthTokenBlacklist(auth_token=access_token)
            b_token.create()
            return {'message': 'Successfully logged out.'}, 200
        except:
            return {'message': 'Not logged in.'}, 401

        ns_auth.abort(401, 'Not logged in.')


@ns_user.route("/me")
class Whoami(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_user_self)
    @token_required
    def get(self, current_user):
        ''' Returns all the details about the current user '''
        current_user = _get_current_user()
        return current_user

@ns_user.route('/generate_api_key')
class UserGenerateApiKey(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_api_key)
    @token_required
    @user_has('use_api')
    def get(self, current_user):
        ''' Returns a new API key for the user making the request '''
        return current_user().generate_api_key()


user_parser = api.parser()
user_parser.add_argument('username', location='args', required=False)


@ns_user.route("")
class UserList(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_user_full, as_list=True)
    @api.expect(user_parser)
    @token_required
    @user_has('view_users')
    def get(self, current_user):
        ''' Returns a list of users '''

        args = user_parser.parse_args()

        if args['username']:
            users = User.query.filter(
                User.username.like(args['username']+"%"), User.deleted == False, User.organization_uuid == current_user().organization_uuid).all()
        else:
            users = User.query.filter_by(deleted=False, organization_uuid=current_user().organization_uuid).all()
        return users

    # TODO: Add a lock to this so only the Admin users and those with 'add_user' permission can do this
    @api.doc(security="Bearer")
    @api.expect(mod_user_create)
    @api.marshal_with(mod_user_create_success)
    @api.response('409', 'User already exists.')
    @api.response('200', "Successfully created the user.")
    @token_required
    @user_has('add_user')
    def post(self, current_user):
        ''' Creates a new users '''

        user = User.query.filter_by(email=api.payload['email'], organization_uuid=current_user().organization_uuid).first()

        if user:
            ns_user.abort(409, "User with this email already exists.")
        
        user = User.query.filter_by(username=api.payload['username'], organization_uuid=current_user().organization_uuid).first()
    
        if user:
            ns_user.abort(409, "User with this username already exists.")

        if not user:
            user = User(organization_uuid=current_user().organization_uuid, **api.payload)
            user.create()
            return {'message': 'Successfully created the user.', 'user': user}
        else:
            ns_user.abort(409, "User already exists.")


@ns_user.route("/<uuid>/unlock")
class UnlockUser(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_user_full)
    @token_required
    @user_has('unlock_user')
    def put(self, uuid, current_user):
        ''' Unlocks a user and resets their failed logons back to 0 '''

        user = User.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if user:
            user.locked = False
            user.failed_logons = 0
            user.save()
            return user
        else:
            ns_user.abort(404, 'User not found.')


@ns_user.route("/<uuid>")
class UserDetails(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_user_full)
    @token_required
    @user_has('view_users')
    def get(self, uuid, current_user):
        ''' Returns information about a user '''
        user = User.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if user:
            return user
        else:
            ns_user.abort(404, 'User not found.')

    @api.doc(security="Bearer")
    @api.expect(mod_user_create)
    @api.marshal_with(mod_user_full)
    @token_required
    @user_has('update_user')
    def put(self, uuid, current_user):
        ''' Updates information for a user '''

        user = User.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if user:
            if 'username' in api.payload:
                target_user = User.query.filter_by(username=api.payload['username'], organization_uuid=current_user().organization_uuid).first()
                if target_user:
                    if target_user.uuid == uuid:
                        del api.payload['username']
                    else:
                        ns_user.abort(409, 'Username already taken.')

            if 'email' in api.payload:
                target_user = User.query.filter_by(email=api.payload['email'], organization_uuid=current_user().organization_uuid).first()
                if target_user:
                    if target_user.uuid == uuid:
                        del api.payload['email']
                    else:
                        ns_user.abort(409, 'Email already taken.')
            
            if 'password' in api.payload and not current_user().has_right('reset_user_password'):
                print('not allowed homie')
                api.payload.pop('password')
            if 'password' in api.payload and current_user().has_right('reset_user_password'):
                pw = api.payload.pop('password')
                user.password = pw
                user.save()

            print(api.payload)
            
            user.update(api.payload)
            return user
        else:
            ns_user.abort(404, 'User not found.')

    @api.doc(security="Bearer")
    @token_required
    @user_has('delete_user')
    def delete(self, uuid, current_user):
        ''' 
        Deletes a user 
        
        Users are soft deleted, meaning they never get removed from the database.  Instead,
        their deleted attribute is set and they do not show up in the UI.  This is 
        used to preserve database relationships like ownership, comment history.
        Deleted users can not be restored at this time.        
        '''
        user = User.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if user:
            if current_user().uuid == user.uuid:
                ns_user.abort(403, 'User can not delete themself.')
            else:
                user.deleted = True
                user.save()
                return {'message': 'User successfully deleted.'}
        else:
            ns_user.abort(404, 'User not found.')


@ns_perms.route("")
class PermissionList(Resource):

    @api.marshal_with(mod_permission_list)
    def get(self):
        ''' Gets a list of all the permission sets '''
        return Permission.query.filter_by(organization_uuid=current_user().organization_uuid).all()

    @api.expect(mod_permission_full)
    @api.response('200', 'Successfully created permission set.')
    def post(self):
        ''' Creates a new permission set '''
        perm = Permission(organization_uuid=current_user().organization_uuid, **api.payload)
        perm.create()
        return {'message': 'Successfully created permission set.', 'uuid': perm.uuid}


@ns_perms.route("/<uuid>")
class PermissionDetails(Resource):

    @api.marshal_with(mod_permission_list)
    def get(self, uuid):
        ''' Gets the permissions based '''
        perm = Permission.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if perm:
            return perm
        else:
            ns_perms.abort(404, 'Permission set not found.')

    @api.doc(security="Bearer")
    @api.expect(mod_permission_full)
    @api.marshal_with(mod_permission_list)
    @token_required
    @user_has('set_role_permissions')
    def put(self, uuid, current_user):
        ''' Updates the permission set '''
        perm = Permission.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if perm:
            perm.update(api.payload)
            return perm
        else:
            ns_perms.abort(404, 'Permission set not found.')

    @api.doc(security="Bearer")
    @token_required
    @user_has('delete_role')
    def delete(self, uuid, current_user):
        ''' Removes the permission set '''
        perm = Permission.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if perm:
            if(len(perm.roles) > 0):
                ns_perms.abort(
                    400, 'Cannot delete a permission set attached to an active Role.')
            else:
                perm.delete()
                return {'message': 'Successfully deleted the Permission set.'}
            return perm
        else:
            ns_perms.abort(404, 'Permission set not found.')
        return


@ns_data_type.route("")
class DataTypeList(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_data_type_list)
    @token_required
    def get(self, current_user):
        ''' Gets a list of all the data types '''
        return DataType.query.filter_by(organization_uuid=current_user().organization_uuid).all()

    @api.doc(security="Bearer")
    @api.expect(mod_data_type_create)
    @api.response('200', 'Successfully created data type.')
    @token_required
    @user_has('create_data_type')
    def post(self, current_user):
        ''' Creates a new data_type set '''
        data_type = DataType(organization_uuid=current_user().organization_uuid, **api.payload)
        data_type.create()
        return {'message': 'Successfully created data type.', 'uuid': data_type.uuid}


@ns_data_type.route("/<uuid>")
class DataTypeDetails(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_data_type_list)
    @token_required
    def get(self, uuid, current_user):
        ''' Gets a data type '''
        data_type = DataType.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if data_type:
            return data_type
        else:
            ns_data_type.abort(404, 'Data type not found.')

    @api.doc(security="Bearer")
    @api.expect(mod_data_type_create)
    @api.marshal_with(mod_data_type_list)
    @token_required
    @user_has('update_data_type')
    def put(self, uuid, current_user):
        ''' Updates the data type '''
        data_type = DataType.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if data_type:
            data_type.update(api.payload)
            return data_type
        else:
            ns_data_type.abort(404, 'Data type not found.')


observable_parser = pager_parser.copy()

@ns_observable.route("")
class ObservableList(Resource):

    @api.doc(security="Bearer")
    @api.expect(observable_parser)
    @api.marshal_with(mod_observable_list, as_list=True)
    @token_required
    @user_has('view_observables')
    def get(self, current_user):
        ''' Returns a list of observable '''
        args = observable_parser.parse_args()

        base_query = db.session.query(Observable)
        filter_spec = [
            {
                'model': 'Observable',
                'field': 'organization_uuid',
                'op':'eq',
                'value': current_user().organization_uuid
            }
        ]

        filtered_query = apply_filters(query, filter_spec)
        query, pagination = apply_pagination(filtered_query, page_number=args['page'], page_size=args['page_size'])
        response = {
            'observables': query.all(),
            'pagination': {
                'total_results': pagination.total_results,
                'pages': pagination.num_pages,
                'page': pagination.page_number,
                'page_size': pagination.page_size
                }
            }
        return response


@ns_observable.route("/<uuid>")
class ObservableDetails(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_observable_list)
    @api.response('200', 'Success')
    @api.response('404', 'Observable not found')
    @token_required
    @user_has('view_observables')
    def get(self, uuid, current_user):
        ''' Returns information about a case task '''
        observable = Observable.query.filter_by(
            uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if observable:
            return observable
        else:
            ns_observable.abort(404, 'Observable not found.')

    @api.doc(security="Bearer")
    @api.expect(mod_observable_create)
    @api.marshal_with(mod_observable_list)
    @token_required
    @user_has('update_observable')
    def put(self, uuid, current_user):
        ''' Updates information for a observable '''
        observable = Observable.query.filter_by(
            uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if observable:
            observable.update(api.payload)
            return observable
        else:
            ns_observable.abort(404, 'Observable not found.')


@ns_observable.route("/_bulk")
class BulkObservableDetails(Resource):

    @api.doc(security="Bearer")
    @api.expect(mod_bulk_observable_update)
    @api.marshal_with(mod_observable_list)
    @token_required
    @user_has('update_observable')
    def put(self, current_user):
        ''' Updates information for multiple observables '''
        
        if 'observables' in api.payload:
            _observables = []
            for obs in api.payload.pop('observables'):
                observable = Observable.query.filter_by(
                    uuid=obs, organization_uuid=current_user().organization_uuid).first()
                if observable:
                    observable.update(api.payload)
                    _observables.append(observable)
            return _observables


@ns_case_file.route("/<uuid>")
class CaseFileDetails(Resource):

    @api.doc(security="Bearer")
    @token_required
    @user_has('delete_case_files')
    def delete(self, current_user, uuid):
        """
        Removes a case file from the system, cascades and removes the 
        relationship with the actual case as well
        """

        case_file = CaseFile.query.filter_by(organization_uuid=current_user().organization_uuid, uuid=uuid).first()
        if case_file:
            case_file.delete()
            return {'message': 'Successfully removed filed'}
        else:
            ns_case_file.abort(404, 'Case File not found.')


@ns_case.route("/<uuid>/upload_file")
class UploadCaseFile(Resource):

    @api.doc(security="Bearer")
    @api.expect(upload_parser)
    @api.marshal_with(mod_case_file, envelope="files")
    @token_required
    @user_has('upload_case_files')
    def post(self, current_user, uuid):

        # Make sure the uploads folder exists
        upload_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), current_app.config['CASE_FILES_DIRECTORY'])
        
        if not os.path.exists(upload_dir):
            os.makedirs(upload_dir)

        def allowed_file(filename):
            return '.' in filename and filename.rsplit('.', 1)[1].lower() in current_app.config['CASE_FILE_EXTENSIONS']

        args = upload_parser.parse_args()

        if 'files' not in request.files:
            ns_plugin.abort(400, 'No file selected.')

        _files = []
        
        uploaded_files = args['files']
        for uploaded_file in uploaded_files:

            hasher = hashlib.sha1()
            hasher.update(uploaded_file.read())

            cf = CaseFile.query.filter_by(hash_sha1=hasher.hexdigest()).first()

            # If the file doesn't already exist, upload it
            if not cf:
                # File name can not be empty
                if uploaded_file.filename == '':
                    continue

                if uploaded_file and allowed_file(uploaded_file.filename):
                    case_file = CaseFile(filename=uploaded_file.filename, case_uuid=uuid, organization_uuid=current_user().organization_uuid)
                    case_file.compute_hashes(uploaded_file.read())
                    case_file.extension = case_file.filename.rsplit('.',1)[1]
                    case_file.mime_type = uploaded_file.mimetype
                    case_file.create()
                    case_file.save_to_disk()
                    _files.append(case_file)

        return _files


@ns_case.route("/<uuid>/add_observables/_bulk")
class CaseBulkAddObservables(Resource):

    @api.doc(security="Bearer")
    @api.expect(mod_bulk_add_observables)
    @api.marshal_with(mod_case_observables)
    @api.response(200, 'Success')
    @token_required
    @user_has('update_case')
    def post(self, uuid, current_user):
        ''' 
        Adds a collection of observables to a Case 
        Expects a list of observables using the Observable model.  Note: Duplicate observables are ignored

        '''
        # Fetch the case via its UUID
        case = Case.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        
        if case:

            # Remove observables that are already in the case
            observable_values = [
                observable.value for observable in case.observables]
            observables_list = [observable for observable in api.payload['observables']
                                if observable['value'] not in observable_values]

            # Process all the observables in the API call
            observables = create_observables(observables_list, current_user().organization_uuid)

            # Add the observables to the case
            if(len(case.observables) == 0):
                case.observables = observables
            else:
                case.observables += observables
            case.save()

            case.add_history('%s new observable(s) added' % (len(observables)))
        else:
            ns_case.abort(404, 'Case not found.')

        return case


observable_parser = pager_parser.copy()
observable_parser.add_argument('type', location='args', required=False, type=str, action='split')
observable_parser.add_argument('value', location='args', required=False, type=str, action='split')
observable_parser.add_argument('search', location='args', required=False, type=str, action='split')

@ns_case.route("/<uuid>/observables")
class CaseObservableList(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_observable_list_paged, as_list=True)
    @api.expect(observable_parser)
    @token_required
    @user_has('view_cases')
    def get(self, uuid, current_user):

        args = observable_parser.parse_args()

        filter_spec = []

        base_query = db.session.query(Observable).join(observable_case_association).join(Case)

        filter_spec = [
            {
                'model': 'Case',
                'field': 'uuid',
                'op':'eq',
                'value': uuid
            },
            {
                'model': 'Case',
                'field': 'organization_uuid',
                'op':'eq',
                'value': current_user().organization_uuid
            }
        ]

        if args['type'] and len(args['type']) > 0:
            filter_spec.append({'model':'DataType', 'value': args['type'], 'op':'in', 'field':'name'})
            base_query.join(DataType)
        
        if args['value'] and len(args['value']) > 0:
            filter_spec.append({'model':'Observable','value': args['value'], 'op':'in', 'field':'value'})
        
        if args['search'] and len(args['search']) > 0:
            filter_spec.append({'model':'Observable', 'value': args['search'], 'op':'in', 'field':'value'})

        filtered_query = apply_filters(base_query, filter_spec)
        query, pagination = apply_pagination(filtered_query, page_number=args['page'], page_size=args['page_size'])
        results = query.all()

        response = {
            'observables': results,
            'pagination': {
                'total_results': pagination.total_results,
                'pages': pagination.num_pages,
                'page': pagination.page_number,
                'page_size': pagination.page_size
                }
            }
        return response
        #results = Case.query.filter_by(organization_uuid=current_user().organization_uuid, uuid=uuid).first().observables


case_parser = pager_parser.copy()
case_parser.add_argument('title', location='args', required=False, type=str)
case_parser.add_argument('status', location='args', required=False, action="split", type=str)
case_parser.add_argument('severity', location='args', required=False, action="split", type=str)
case_parser.add_argument('owner', location='args', required=False, action="split", type=str)
case_parser.add_argument('tag', location='args', required=False, action="split", type=str)
case_parser.add_argument('search', location='args', required=False, action="split", type=str)
case_parser.add_argument('my_tasks', location='args', required=False, type=xinputs.boolean)
case_parser.add_argument('my_cases', location='args', required=False, type=xinputs.boolean)

@ns_case.route("")
class CaseList(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_case_paged_list)
    @api.expect(case_parser)
    @token_required
    @user_has('view_cases')
    def get(self, current_user):
        ''' Returns a list of case '''

        args = case_parser.parse_args()


        base_query = db.session.query(Case)

        filter_spec = []
        if args['status']:
            base_query = base_query.join(CaseStatus)
            filter_spec.append({'model':'CaseStatus', 'op':'in', 'value': args['status'], 'field':'name'})

        if args['severity']:
            filter_spec.append({'model':'Case', 'op':'in', 'value':args['severity'], 'field':'severity'})

        if args['tag']:
            base_query = base_query.join(case_tag_association).join(Tag)
            filter_spec.append({'model':'Tag', 'op':'in', 'value':args['tag'], 'field':'name'})

        if args['title']:
            filter_spec.append({'model':'Case', 'op':'ilike', 'value':"%"+args['title']+"%", 'field':'title'})

        # Only can be used if my_tasks is not being flagged
        if (args['owner'] or args['my_cases']) and not args['my_tasks']:
            base_query = base_query.join(User, User.uuid == Case.owner_uuid)

        # Only can be used if my_tasks is not being flagged
        if args['my_cases'] and not args['my_tasks'] and not args['owner']:
            filter_spec.append({'model':'User', 'op':'eq', 'value':current_user().username, 'field':'username'})

        # Only can be used if my_tasks is not being flagged
        if args['owner'] and not args['my_tasks']:            
            filter_spec.append({'model':'User', 'op':'in', 'value':args['owner'], 'field':'username'})

        # Redefine the base query if using the my_task filter
        # we need to relate several tables
        # can't be used if owner and my_cases filters are applied
        if args['my_tasks']:
            base_query = base_query.join(CaseTask, Case.uuid == CaseTask.case_uuid).join(User, User.uuid == CaseTask.owner_uuid).group_by(Case.id)
            filter_spec.append([
                {'model':'User', 'op':'eq', 'value':current_user().username, 'field':'username'},
                {'model':'CaseTask', 'op':'ne', 'value':2, 'field':'status'}
            ])

        # If any of the filters have changed
        # apply them
        if len(filter_spec) > 0:
            base_query = apply_filters(base_query, filter_spec)

        query, pagination = apply_pagination(base_query, page_number=args['page'], page_size=args['page_size'])

        response = {
                'cases': query.all(),
                'pagination': {
                    'total_results': pagination.total_results,
                    'pages': pagination.num_pages,
                    'page': pagination.page_number,
                    'page_size': pagination.page_size
                }
            }

        return response        


    @api.doc(security="Bearer")
    @api.expect(mod_case_create)
    @api.response('409', 'Case already exists.')
    @api.response('200', "Successfully created the case.")
    @token_required
    @user_has('create_case')
    def post(self, current_user):
        ''' Creates a new case '''

        _tags = []
        event_observables = []
        case_template_uuid = None
        
        settings = GlobalSettings.query.filter_by(organization_uuid=current_user().organization_uuid).first()

        if 'case_template_uuid' in api.payload:
            case_template_uuid = api.payload.pop('case_template_uuid')

        if 'tags' in api.payload:
            tags = api.payload.pop('tags')
            _tags = parse_tags(tags, current_user().organization_uuid)

        if 'owner_uuid' in api.payload:
            owner = api.payload.pop('owner_uuid')
            user = User.query.filter_by(uuid=owner, organization_uuid=current_user().organization_uuid).first()
            if user:
                api.payload['owner'] = user
        else:
            # Automatically assign the case to the creator if they didn't pick an owner
            if settings.assign_case_on_create:
                api.payload['owner'] = User.query.filter_by(uuid=current_user().uuid).first()

        if 'observables' in api.payload:
            observables = api.payload.pop('observables')
            api.payload['observables'] = []
            for uuid in observables:
                observable = Observable.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
                if observable:
                    api.payload['observables'].append(observable)

        if 'events' in api.payload:
            api.payload['observables'] = []
            events = api.payload.pop('events')
            api.payload['events'] = []
            observable_collection = {}

            # Pull all the observables out of the events
            # so they can be added to the case
            for uuid in events:
                event = Event.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
                if event:
                    api.payload['events'].append(event)
                if event.observables:
                    for observable in event.observables:
                        if observable.value in observable_collection:
                            observable_collection[observable.value].append(
                                observable)
                        else:
                            observable_collection[observable.value] = [
                                observable]

            # Sort and pull out the most recent observable in the group
            # of observables
            for observable in observable_collection:
                observable_collection[observable] = sorted(
                    observable_collection[observable], key=lambda x: x.created_at, reverse=True)
                api.payload['observables'].append(
                    observable_collection[observable][0])

        case = Case(organization_uuid=current_user().organization_uuid, **api.payload)
        case.create()

        if len(_tags) > 0:
            case.tags += _tags
            case.save()

        # Set the default status to New
        case_status = CaseStatus.query.filter_by(name="New", organization_uuid=current_user().organization_uuid).first()
        case.status = case_status
        case.save()
        
        # If the user selected a case template, take the template items
        # and copy them over to the case
        if case_template_uuid:
            case_template = CaseTemplate.query.filter_by(
                uuid=case_template_uuid,
                organization_uuid=current_user().organization_uuid).first()

            # Append the default tags
            for tag in case_template.tags:

                # If the tag does not already exist
                if tag not in case.tags:
                    case.tags.append(tag)

            # Append the default tasks
            for task in case_template.tasks:
                case_task = CaseTask(title=task.title, description=task.description,
                                     order=task.order, owner=task.owner, group=task.group,
                                     from_template=True,
                                     organization_uuid=current_user().organization_uuid)
                case.tasks.append(case_task)

            # Set the default severity
            case.severity = case_template.severity
            case.tlp = case_template.tlp
            case.case_template_uuid = case_template_uuid
            case.save()


        for event in case.events:
            event.status = EventStatus.query.filter_by(name='Open', organization_uuid=current_user().organization_uuid).first()
            event.save()

        case.add_history(message='Case created')

        return {'message': 'Successfully created the case.', 'uuid': case.uuid}


@ns_case.route("/<uuid>/add_events")
class AddEventsToCase(Resource):

    @api.doc(security="Bearer")
    @api.expect(mod_add_events_to_case)
    @api.marshal_with(mod_add_events_response)
    @api.response(207, 'Success')
    @api.response(404, 'Case not found.')
    @token_required
    @user_has('update_case')
    def put(self, uuid, current_user):

        response = {
            'results': [],
            'success': True,
            'case': None
        }
        case = Case.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if case:
            response['case'] = case

            new_observables = []
            
            if 'events' in api.payload:
                for evt in api.payload['events']:
                    _event_observables = []
                    event = Event.query.filter_by(uuid=evt, organization_uuid=current_user().organization_uuid).first()
                    if event:

                        # If the event is already imported into another case
                        # skip the case
                        if event.case_uuid:
                            response['results'].append({'reference': evt, 'message': 'Event already merged in a different Case.'})
                            continue
                        try:
                            _event_observables += [observable for observable in event.observables]
                            new_observables += [observable for observable in _event_observables if observable.value.lower() not in [o.value.lower() for o in case.observables if o not in new_observables]]
                            event.status = EventStatus.query.filter_by(name='Open', organization_uuid=current_user().organization_uuid).first()
                            case.events.append(event)
                            case.save()
                            response['results'].append({'reference': evt, 'message': 'Event successfully merged into Case.'})
                        except Exception as e:
                            response['results'].append({'reference': evt, 'message': 'An error occurred while processing event observables. {}'.format(e)})
                            response['success'] = False
                    else:
                        response['results'].append({'reference': evt, 'message': 'Event not found.'})
                        response['success'] = False

                case.observables += new_observables
                case.save()
                case.add_history('%s Event(s) were merged into this case' % len([r for r in response['results'] if 'success' in r['message']]))
            return response, 207
                            
        else:
            ns_case.abort(404, 'Case not found.')


@ns_case.route('/<uuid>/relate_cases')
class RelateCases(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_related_case, envelope='related_cases')
    @api.response(207, 'Success')
    @api.response(404, 'Case not found.')
    @token_required
    @user_has('view_cases')
    def get(self, current_user, uuid):
        ''' Returns a list of related cases '''
        case = Case.query.filter_by(organization_uuid=current_user().organization_uuid, uuid=uuid).first()
        _cases = []
        if case:
            if len(case.related_cases) > 0:
                _cases += [c for c in case.related_cases]
            if len(case.parent_cases) > 0:
                _cases += [c for c in case.parent_cases]
            return _cases


    @api.doc(security="Bearer")
    @api.marshal_with(mod_case_list)
    @api.response(207, 'Success')
    @api.response(404, 'Case not found.')
    @token_required
    @user_has('update_case')
    def put(self, current_user, uuid):

        case = Case.query.filter_by(organization_uuid=current_user().organization_uuid, uuid=uuid).first()
        if case:
            if 'cases' in api.payload:
                _cases = api.payload.pop('cases')
                for c in _cases:
                    _case = Case.query.filter_by(organization_uuid=current_user().organization_uuid, uuid=c).all()
                    if _case not in case.related_cases:
                        case.related_cases += _case
                case.save()
        return case

    @api.doc(security="Bearer")
    @api.marshal_with(mod_related_case, envelope='related_cases')
    @api.response(207, 'Success')
    @api.response(404, 'Case not found.')
    @token_required
    @user_has('update_case')
    def delete(self, current_user, uuid):
        ''' Unlinks a case or a group of cases '''

        case = Case.query.filter_by(organization_uuid=current_user().organization_uuid, uuid=uuid).first()
        if case:
            if 'cases' in api.payload:
                _cases = api.payload.pop('cases')
                case.related_cases = [c for c in case.related_cases if c.uuid not in _cases]
                case.save()
        _cases =  case.related_cases+case.parent_cases
        return _cases


case_file_parser = pager_parser.copy()

@ns_case.route('/<uuid>/files')
class GetCaseFiles(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_case_file_list)
    @api.response(207, 'Success')
    @api.response(404, 'Case not found.')
    @token_required
    @user_has('view_cases')
    def get(self, current_user, uuid):
        """
        Returns a list of files associated with a case
        """

        args = case_file_parser.parse_args()

        if args:
            base_query = db.session.query(CaseFile).filter_by(case_uuid=uuid)
            query, pagination = apply_pagination(base_query, page_number=args['page'], page_size=args['page_size'])
            response = {
                'files': query.all(),
                'pagination': {
                    'total_results': pagination.total_results,
                    'pages': pagination.num_pages,
                    'page': pagination.page_number,
                    'page_size': pagination.page_size
                }
            }
            return response


@ns_case.route('/<uuid>/report')
class CaseReport(Resource):
    
    @api.doc(security="Bearer")
    @api.response('200', 'Success')
    @token_required
    @user_has('view_cases')
    def get(self, uuid, current_user):
        ''' Returns a Markdown formatted overview of the Case '''
        case = Case.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()

        report_format = """# {title}
## Observables
{observables}
## Events
{events}
## Tasks
{tasks}
## Comments
## Case History       
        """
        return report_format.format(
            title=case.title, 
            observables="\n".join(["- {} - {}".format(o.value, o.dataType.name) for o in case.observables]),
            events= "\n".join(["### {title}\n{description}\n```{raw_log}```".format(title=e.title, description=e.description, raw_log=e.raw_log) for e in case.events]),
            tasks="\n".join(['### {title}\n{description}\n#### Notes\n {notes}'.format(title=t.title, description=t.description, notes="\n".join(["- {}".format(c) for c in t.notes])) for t in case.tasks])
        )


@ns_case.route("/<uuid>")
class CaseDetails(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_case_details)
    @api.response('200', 'Success')
    @api.response('404', 'Case not found')
    @token_required
    @user_has('view_cases')
    def get(self, uuid, current_user):
        ''' Returns information about a case '''
        case = Case.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if case:
            return case
        else:
            ns_case.abort(404, 'Case not found.')

    @api.doc(security="Bearer")
    @api.expect(mod_case_create)
    @api.marshal_with(mod_case_list)
    @token_required
    @user_has('update_case')
    def put(self, uuid, current_user):
        ''' Updates information for a case '''
        case = Case.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if case:

            for f in ['severity', 'tlp', 'status_uuid', 'owner', 'description', 'owner_uuid']:
                value = ""
                message = None

                # TODO: handle notifications here, asynchronous of course to not block this processing
                if f in api.payload:
                    if f == 'status_uuid':
                        status = CaseStatus.query.filter_by(
                            uuid=api.payload['status_uuid']).first()
                        
                        # Remove the closure reason if the new status re-opens the case
                        if not status.closed: 
                            api.payload['close_reason_uuid'] = None

                        value = status.name
                        f = 'status'

                        # If the case is now set to close, close all the events
                        if(status.closed):
                            for event in case.events:
                                event.status = EventStatus.query.filter_by(organization_uuid=current_user().organization_uuid, name='Closed', closed=True).first()
                                event.save()
                        
                        # If the case is being re-opened
                        if(case.status.closed and not status.closed):
                            for event in case.events:
                                event.status = EventStatus.query.filter_by(organization_uuid=current_user().organization_uuid, name='Open', closed=False).first()
                                event.save()

                    elif f == 'severity':
                        value = {1: 'Low', 2: 'Medium', 3: 'High',
                                 4: 'Critical'}[api.payload[f]]

                    elif f == 'description':
                        message = '**Description** updated'

                    elif f == 'owner_uuid':
                        print("WE ARE HERE!")
                        if api.payload['owner_uuid'] == '':
                            
                            api.payload['owner_uuid'] = None
                            message = 'Case unassigned'
                        else:
                            owner = User.query.filter_by(
                                uuid=api.payload['owner_uuid']).first()
                            value = owner.username
                            message = 'Case assigned to **{}**'.format(
                                owner.username)

                    if message:
                        case.add_history(message=message)
                    else:
                        case.add_history(
                            message="**{}** changed to **{}**".format(f.title(), value))
            
            if 'tags' in api.payload:
                _tags = parse_tags(api.payload.pop('tags'), current_user().organization_uuid)
                case.tags = _tags
                case.add_history(message="**Tags** were modified")
                case.save()
            
            if 'case_template_uuid' in api.payload:

                # If the case already has a template, and none of the tasks have been started, remove the
                # old template and its tasks/tags and add the new stuff
                tasks_started = False
                if case.case_template and api.payload['case_template_uuid'] != case.case_template_uuid:
                    
                    for task in case.tasks:

                        # If any task is already started, don't apply a new template
                        if task.status != 0 and task.from_template:
                            tasks_started = True
                            break
                        else:
                            if task.from_template:
                                task.delete()

                    # Remove the tags from the case that were assigned by the 
                    # template
                    for tag in case.case_template.tags:
                        if tag in case.tags:
                            case.tags = [tag for tag in case.tags if tag.name not in [t.name for t in case.case_template.tags]]

                    case.case_template_uuid = None
                    case.save()
                    
                # If there was an old template or no template at all
                # apply the new template
                if not tasks_started and api.payload['case_template_uuid'] != case.case_template_uuid:

                    case_template = CaseTemplate.query.filter_by(uuid=api.payload['case_template_uuid'], organization_uuid=current_user().organization_uuid).first()
                    if case_template:

                        # Append the default tags
                        for tag in case_template.tags:

                            # If the tag does not already exist
                            if tag not in case.tags:
                                case.tags.append(tag)

                        # Append the default tasks
                        for task in case_template.tasks:
                            case_task = CaseTask(title=task.title, description=task.description,
                                                order=task.order, owner=task.owner, group=task.group,
                                                from_template=True,
                                                organization_uuid=current_user().organization_uuid)
                            case.tasks.append(case_task)
                        case.save()
                        message = 'The case template **{}** was applied'.format(case_template.title)
                        case.add_history(message=message)

            case.update(api.payload)


            


            return case
        else:
            ns_case.abort(404, 'Case not found.')

    @api.doc(security="Bearer")
    @token_required
    @user_has('delete_case')
    def delete(self, uuid, current_user):
        ''' Deletes a case '''
        case = Case.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if case:

            # Delete any associated observables
            #[o.delete() for o in case.observables]

            # Delete comments
            #[c.delete() for c in case.comments]

            # Delete tasks
            #[t.delete() for t in case.tasks]

            # Delete history
            #[h.delete() for t in case.history]

            # Set any associated events back to New status
            for event in case.events:
                event.status = EventStatus.query.filter_by(organization_uuid=current_user().organization_uuid, name='New').first()
                event.save()
            
            case.events = []
            case.save()
            case.observables = []
            case.save()

            case.delete()
            return {'message': 'Sucessfully deleted case.'}

case_task_parser = api.parser()
case_task_parser.add_argument('case_uuid', type=str, location='args', required=False)

@ns_case_task.route("")
class CaseTaskList(Resource):

    @api.doc(security="Bearer")
    @api.expect(case_task_parser)
    @api.marshal_with(mod_case_task_full, as_list=True)
    @token_required
    @user_has('view_case_tasks')
    def get(self, current_user):
        ''' Returns a list of case_task '''
        args = case_task_parser.parse_args()

        if args['case_uuid']:
            return CaseTask.query.filter_by(case_uuid=args['case_uuid'], organization_uuid=current_user().organization_uuid).all()
        return CaseTask.query.filter_by(organization_uuid=current_user().organization_uuid).all()

    @api.doc(security="Bearer")
    @api.expect(mod_case_task_create)
    @api.marshal_with(mod_case_task_full)
    @api.response('409', 'Case Task already exists.')
    @api.response('200', "Successfully created the case task.")
    @token_required
    @user_has('create_case_task')
    def post(self, current_user):
        
        ''' Creates a new case_task '''

        case_task = CaseTask.query.filter_by(
            title=api.payload['title'], case_uuid=api.payload['case_uuid']).first()
        if not case_task:

            case_task = CaseTask(organization_uuid=current_user().organization_uuid, **api.payload)
            case_task.create()

            case = Case.query.filter_by(uuid=api.payload['case_uuid']).first()
            case.add_history("Task **{}** added".format(case_task.title))

            return case_task
        else:
            ns_case_task.abort(
                409, 'Case Task already exists.')


@ns_case_task.route("/<uuid>")
class CaseTaskDetails(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_case_task_full)
    @api.response('200', 'Success')
    @api.response('404', 'Case Task not found')
    @token_required
    @user_has('view_case_tasks')
    def get(self, uuid, current_user):
        ''' Returns information about a case task '''
        case_task = CaseTask.query.filter_by(
            uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if case_task:
            return case_task
        else:
            ns_case_task.abort(404, 'Case Task not found.')

    @api.doc(security="Bearer")
    @api.expect(mod_case_task_create)
    @api.marshal_with(mod_case_task_full)
    @token_required
    @user_has('update_case_task')
    def put(self, uuid, current_user):
        ''' Updates information for a case_task '''

        history_message = None
        settings = GlobalSettings.query.filter_by(organization_uuid=current_user().organization_uuid).first()
        case_task = CaseTask.query.filter_by(
            uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if case_task:

            if 'name' in api.payload and CaseTask.query.filter_by(title=api.payload['title'], case_uuid=api.payload['case_uuid']).first():
                ns_case_task.abort(
                    409, 'Case Task name already exists.')
            else:
                if 'status' in api.payload:

                    # Set the start date on the Task
                    if api.payload['status'] == 1:
                        case_task.start_date = datetime.datetime.utcnow()
                        history_message = "Task **{}** started"

                    # Set the finish date on the Task
                    if api.payload['status'] == 2:
                        case_task.finish_date = datetime.datetime.utcnow()
                        history_message = "Task **{}** completed"

                    # Automatically assign the task to the user who starts the task if set globally
                    if api.payload['status'] == 1 and case_task.owner is None and settings.assign_task_on_start:
                        case_task.owner = current_user()

                    case_task.save()
                    
                case_task.update(api.payload)
                case = Case.query.filter_by(uuid=case_task.case_uuid, organization_uuid=current_user().organization_uuid).first()
                if history_message:
                    case.add_history(message=history_message.format(case_task.title))
                return case_task
        else:
            ns_case_task.abort(404, 'Case Task not found.')

    @api.doc(security="Bearer")
    @token_required
    @user_has('delete_case_task')
    def delete(self, uuid, current_user):
        ''' Deletes a case_task '''
        case_task = CaseTask.query.filter_by(
            uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if case_task:
            case_task.delete()

            case = Case.query.filter_by(uuid=case_task.case_uuid, organization_uuid=current_user().organization_uuid).first()
            case.add_history(message="Task {} deleted".format(case_task.title))
            return {'message': 'Sucessfully deleted case task.'}


task_note_parser = api.parser()
task_note_parser.add_argument('task_uuid', location='args', required=True)

@ns_case_task_note.route("")
class CaseNoteList(Resource):

    @api.doc(security="Bearer")
    @api.expect(task_note_parser)
    @api.marshal_with(mod_case_task_note_complete, as_list=True)
    @api.response(200, 'Success')
    @token_required
    @user_has('view_case_tasks')
    def get(self, current_user):

        args = task_note_parser.parse_args()

        if args:
            notes = TaskNote.query.filter_by(task_uuid=args['task_uuid'], organization_uuid=current_user().organization_uuid).order_by(asc(TaskNote.created_at)).all()
            return notes

    
    @api.doc(security="Bearer")
    @api.expect(mod_case_task_note)
    @api.marshal_with(mod_case_task_note_complete)
    @api.response(200, 'Success')
    @token_required
    @user_has('update_case_task')
    def post(self, current_user):

        if 'task_uuid' in api.payload:
            case_task = CaseTask.query.filter_by(uuid=api.payload['task_uuid'], organization_uuid=current_user().organization_uuid).first()
            if case_task:
                note = TaskNote(note=api.payload['note'], task=case_task, organization_uuid=current_user().organization_uuid)
                note.create()

                # If the case task is already complete, mark this note as occurring after
                # the case was closed
                if case_task.status == 2:
                    note.after_complete = True
                    note.save()

                return note


case_template_parser = api.parser()
case_template_parser.add_argument('title', location='args', required=False)

@ns_case_template.route("")
class CaseTemplateList(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_case_template_full, as_list=True)
    @api.expect(case_template_parser)
    @token_required
    @user_has('view_case_templates')
    def get(self, current_user):
        ''' Returns a list of case_template '''

        args = case_template_parser.parse_args()

        if args['title']:
            case_template = CaseTemplate.query.filter(
                CaseTemplate.title.like(args['title']+"%")).all()
        else:
            case_template = CaseTemplate.query.filter_by(organization_uuid=current_user().organization_uuid).all()

        return case_template

    @api.doc(security="Bearer")
    @api.expect(mod_case_template_create)
    @api.response('409', 'Case Template already exists.')
    @api.response('200', "Successfully created the case_template.")
    @api.marshal_with(mod_case_template_full)
    @token_required
    @user_has('create_case_template')
    def post(self, current_user):

        # Check to see if the case template already exists and
        # return an error indicating as such
        case_template = CaseTemplate.query.filter_by(
            title=api.payload['title']).first()
        if case_template:
            ns_case_template.abort(409, 'Case Template already exists.')
        else:
            _tags = []
            ''' Creates a new case_template template '''
            if 'tags' in api.payload:
                tags = api.payload.pop('tags')
                _tags = parse_tags(tags, current_user().organization_uuid)

            '''if 'owner' in api.payload:
                owner = api.payload.pop('owner')
                user = User.query.filter_by(uuid=owner).first()
                if user:
                    api.payload['owner'] = user'''

            if 'tasks' in api.payload:
                _tasks = []
                tasks = api.payload.pop('tasks')
                for _task in tasks:
                    task = CaseTemplateTask(organization_uuid=current_user().organization_uuid, **_task)
                    _tasks.append(task)
            api.payload['tasks'] = _tasks

            case_template = CaseTemplate(organization_uuid=current_user().organization_uuid, **api.payload)
            case_template.create()

            if len(_tags) > 0:
                case_template.tags += _tags
                case_template.save()

            # Set the default status to New
            case_template_status = CaseStatus.query.filter_by(
                name="New").first()
            case_template.status = case_template_status
            case_template.save()

            return case_template


@ns_case_template.route("/<uuid>/update-tasks")
class AddTasksToCaseTemplate(Resource):

    @api.doc(security="Bearer")
    @api.response('409', 'Task already assigned to this Case Template')
    @api.response('404', 'Case Template not found.')
    @api.response('404', 'Task not found.')
    @api.response('207', 'Tasks added to Case Template.')
    @api.expect(mod_add_tasks_to_case)
    @token_required
    @user_has('update_case_templates')
    def put(self, uuid, current_user):
        ''' Adds a user to a specified Role '''

        _tasks = []
        response = {
            'results': [],
            'success': True
        }
        if 'tasks' in api.payload:
            tasks = api.payload.pop('tasks')
            for task_uuid in tasks:
                task = CaseTemplateTask.query.filter_by(uuid=task_uuid).first()
                if task:
                    _tasks.append(task)
                    response['results'].append(
                        {'reference': task_uuid, 'message': 'Task successfully added.'})
                else:
                    response['results'].append(
                        {'reference': task_uuid, 'message': 'Task not found.'})
                    response['success'] = False

        template = CaseTemplate.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if template:
            template.tasks = _tasks
            template.save()
            return response, 207
        else:
            ns_case_template.abort(404, 'Case Template not found.')


@ns_case_template.route("/<uuid>")
class CaseTemplateDetails(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_case_template_full)
    @api.response('200', 'Success')
    @api.response('404', 'Case Template not found')
    @token_required
    @user_has('view_case_templates')
    def get(self, uuid):
        ''' Returns information about a case_template '''
        case_template = CaseTemplate.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if case_template:
            return case_template
        else:
            ns_case_template.abort(404, 'Case Template not found.')

    @api.doc(security="Bearer")
    @api.expect(mod_case_template_create)
    @api.marshal_with(mod_case_template_full)
    @token_required
    @user_has('update_case_template')
    def put(self, uuid):
        ''' Updates information for a case_template '''
        case_template = CaseTemplate.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if case_template:
            if 'name' in api.payload and CaseTemplate.query.filter_by(name=api.payload['name']).first():
                ns_case_template.abort(
                    409, 'Case Template name already exists.')
            else:
                case_template.update(api.payload)
                return case_template
        else:
            ns_case_template.abort(404, 'Case Template not found.')

    @api.doc(security="Bearer")
    @token_required
    @user_has('delete_case_template')
    def delete(self, uuid):
        ''' Deletes a case_template '''
        case_template = CaseTemplate.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if case_template:
            case_template.delete()
            return {'message': 'Sucessfully deleted case_template.'}


@ns_case_template_task.route("")
class CaseTemplateTaskList(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_case_template_task_full, as_list=True)
    @token_required
    @user_has('view_case_template_tasks')
    def get(self, current_user):
        ''' Returns a list of case_template_task '''
        return CaseTemplateTask.query.filter_by(organization_uuid=current_user().organization_uuid).all()

    @api.doc(security="Bearer")
    @api.expect(mod_case_template_task_create)
    @api.response('409', 'CaseTemplateTask already exists.')
    @api.response('200', "Successfully created the case_template_task.")
    @token_required
    @user_has('create_case_template_task')
    def post(self, current_user):
        _tags = []
        ''' Creates a new case_template_task '''
        case_template_task = CaseTemplateTask.query.filter_by(
            title=api.payload['title'], case_template_uuid=api.payload['case_template_uuid']).first()
        if not case_template_task:

            case_template_task = CaseTemplateTask(organization_uuid=current_user().organization_uuid, **api.payload)
            case_template_task.create()

            if len(_tags) > 0:
                case_template_task.tags += _tags
                case_template_task.save()

            return {'message': 'Successfully created the case_template_task.'}
        else:
            ns_case_template_task.abort(
                409, 'CaseTemplateTask already exists.')


@ns_case_template_task.route("/<uuid>")
class CaseTemplateTaskDetails(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_case_template_task_full)
    @api.response('200', 'Success')
    @api.response('404', 'CaseTemplateTask not found')
    @token_required
    @user_has('view_case_template_tasks')
    def get(self, uuid, current_user):
        ''' Returns information about a case_template_task '''
        case_template_task = CaseTemplateTask.query.filter_by(
            uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if case_template_task:
            return case_template_task
        else:
            ns_case_template_task.abort(404, 'Case Template Task not found.')

    @api.doc(security="Bearer")
    @api.expect(mod_case_template_task_create)
    @api.marshal_with(mod_case_template_task_full)
    @token_required
    @user_has('update_case_template_task')
    def put(self, uuid, current_user):
        ''' Updates information for a case_template_task '''
        case_template_task = CaseTemplateTask.query.filter_by(
            uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if case_template_task:
            if 'name' in api.payload and CaseTemplateTask.query.filter_by(title=api.payload['title']).first():
                ns_case_template_task.abort(
                    409, 'Case Template Task name already exists.')
            else:
                case_template_task.update(api.payload)
                return case_template_task
        else:
            ns_case_template_task.abort(404, 'Case Template Task not found.')

    @api.doc(security="Bearer")
    @token_required
    @user_has('delete_case_template_task')
    def delete(self, uuid, current_user):
        ''' Deletes a case_template_task '''
        case_template_task = CaseTemplateTask.query.filter_by(
            uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if case_template_task:
            case_template_task.delete()
            return {'message': 'Sucessfully deleted case_template_task.'}


case_comment_parser = api.parser()
case_comment_parser.add_argument('case_uuid', type=str, location='args', required=False)

@ns_case_comment.route("")  
class CaseCommentList(Resource):

    @api.doc(security="Bearer")
    @api.expect(case_comment_parser)
    @api.marshal_with(mod_comment, as_list=True)
    @token_required
    @user_has('view_case_comments')
    def get(self, current_user):
        ''' Returns a list of comments '''

        args = case_comment_parser.parse_args()

        if args['case_uuid']:
            return CaseComment.query.filter_by(case_uuid=args['case_uuid'], organization_uuid=current_user().organization_uuid).order_by(asc(CaseComment.created_at)).all()
        else:
            return CaseComment.query.filter_by(organization_uuid=current_user().organization_uuid).order_by(asc(CaseComment.created_at)).all()

    @api.doc(security="Bearer")
    @api.expect(mod_comment_create)
    @api.response(200, 'AMAZING', mod_comment)
    @api.marshal_with(mod_comment)
    @token_required
    @user_has('create_case_comment')
    def post(self, current_user):
        _tags = []
        ''' Creates a new comment '''
        case_comment = CaseComment(organization_uuid=current_user().organization_uuid, **api.payload)
        case_comment.create()

        case = Case.query.filter_by(uuid=api.payload['case_uuid']).first()
        case.add_history(message="Commented added to case")
        return case_comment


@ns_case_comment.route("/<uuid>")
class CaseCommentDetails(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_comment)
    @api.response('200', 'Success')
    @api.response('404', 'Comment not found')
    @token_required
    @user_has('view_case_comments')
    def get(self, uuid, current_user):
        ''' Returns information about a comment '''
        case_comment = CaseComment.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if case_comment:
            return case_comment
        else:
            ns_case_comment.abort(404, 'Comment not found.')

    @api.doc(security="Bearer")
    @api.expect(mod_comment_create)
    @api.marshal_with(mod_comment)
    @token_required
    @user_has('update_case_comment')
    def put(self, uuid, current_user):
        ''' Updates information for a comment '''
        case_comment = CaseComment.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if case_comment:
            case_comment.edited = True
            case_comment.update(api.payload)
            return case_comment
        else:
            ns_case_comment.abort(404, 'Comment not found.')

    @api.doc(security="Bearer")
    @token_required
    @user_has('delete_case_comment')
    def delete(self, uuid, current_user):
        ''' Deletes a comment '''
        case_comment = CaseComment.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if case_comment:
            case_comment.delete()
            return {'message': 'Sucessfully deleted comment.'}


@ns_case_status.route("")
class CaseStatusList(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_case_status_list, as_list=True)
    @token_required
    def get(self, current_user):
        ''' Returns a list of case_statuss '''
        return CaseStatus.query.filter_by(organization_uuid=current_user().organization_uuid).all()

    @api.doc(security="Bearer")
    @api.expect(mod_case_status_create)
    @api.response('409', 'Case Status already exists.')
    @api.response('200', 'Successfully create the CaseStatus.')
    @token_required
    @user_has('add_case_status')
    def post(self, current_user):
        ''' Creates a new Case Status '''
        case_status = CaseStatus.query.filter_by(
            name=api.payload['name']).first()

        if not case_status:
            case_status = CaseStatus(organization_uuid=current_user().organization_uuid, **api.payload)
            case_status.create()
        else:
            ns_case_status.abort(409, 'Case Status already exists.')
        return {'message': 'Successfully created the Case Status.'}


@ns_case_status.route("/<uuid>")
class CaseStatusDetails(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_case_status_list)
    @token_required
    def get(self, uuid, current_user):
        ''' Returns information about an CaseStatus '''
        case_status = CaseStatus.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if case_status:
            return case_status
        else:
            ns_case_status.abort(404, 'Case Status not found.')

    @api.doc(security="Bearer")
    @api.expect(mod_case_status_create)
    @api.marshal_with(mod_case_status_list)
    @token_required
    @user_has('update_case_status')
    def put(self, uuid, current_user):
        ''' Updates information for an Case Status '''
        case_status = CaseStatus.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if case_status:
            if 'name' in api.payload and CaseStatus.query.filter_by(name=api.payload['name']).first():
                ns_case_status.abort(409, 'Case Status name already exists.')
            else:
                case_status.update(api.payload)
                return case_status
        else:
            ns_case_status.abort(404, 'Case Status not found.')

    @api.doc(security="Bearer")
    @token_required
    @user_has('delete_case_status')
    def delete(self, uuid, current_user):
        ''' Deletes an CaseStatus '''
        case_status = CaseStatus.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if case_status:
            case_status.delete()
            return {'message': 'Sucessfully deleted Case Status.'}


case_history_parser = api.parser()
case_history_parser.add_argument('case_uuid', type=str, location='args', required=False)

@ns_case_history.route("")
class CaseHistoryList(Resource):

    @api.doc(security="Bearer")
    @api.expect(case_history_parser)
    @api.marshal_with(mod_case_history, as_list=True)
    @token_required
    @user_has('view_cases')
    def get(self, current_user):
        ''' Returns a list of case history events '''

        args = case_history_parser.parse_args()

        if args['case_uuid']:
            return CaseHistory.query.filter_by(organization_uuid=current_user().organization_uuid, case_uuid=args['case_uuid']).all()
        return CaseHistory.query.filter_by(organization_uuid=current_user().organization_uuid, case_uuid=args['case_uuid']).all()


@ns_close_reason.route("")
class CloseReasonList(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_close_reason_list, as_list=True)
    @token_required
    def get(self, current_user):
        ''' Returns a list of close_reasons '''
        return CloseReason.query.all()

    @api.doc(security="Bearer")
    @api.expect(mod_close_reason_create)
    @api.response('409', 'Close Reason already exists.')
    @api.response('200', 'Successfully create the CloseReason.')
    @token_required
    @user_has('add_close_reason')
    def post(self, current_user):
        ''' Creates a new Close Reason '''
        close_reason = CloseReason.query.filter_by(
            name=api.payload['name']).first()

        if not close_reason:
            close_reason = CloseReason(organization_uuid=current_user().organization_uuid, **api.payload)
            close_reason.create()
        else:
            ns_close_reason.abort(409, 'Close Reason already exists.')
        return {'message': 'Successfully created the Close Reason.'}


@ns_close_reason.route("/<uuid>")
class CloseReasonDetails(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_close_reason_list)
    @token_required
    def get(self, uuid, current_user):
        ''' Returns information about an CloseReason '''
        close_reason = CloseReason.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if close_reason:
            return close_reason
        else:
            ns_close_reason.abort(404, 'Close Reason not found.')

    @api.doc(security="Bearer")
    @api.expect(mod_close_reason_create)
    @api.marshal_with(mod_close_reason_list)
    @token_required
    @user_has('update_close_reason')
    def put(self, uuid, current_user):
        ''' Updates information for an Close Reason '''
        close_reason = CloseReason.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if close_reason:
            if 'name' in api.payload and CloseReason.query.filter_by(name=api.payload['name']).first():
                ns_close_reason.abort(409, 'Close Reason name already exists.')
            else:
                close_reason.update(api.payload)
                return close_reason
        else:
            ns_close_reason.abort(404, 'Close Reason not found.')

    @api.doc(security="Bearer")
    @token_required
    @user_has('delete_close_reason')
    def delete(self, uuid, current_user):
        ''' Deletes an CloseReason '''
        close_reason = CloseReason.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if close_reason:
            close_reason.delete()
            return {'message': 'Sucessfully deleted Close Reason.'}


@ns_playbook.route("")
class PlaybookList(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_playbook_list, as_list=True)
    @token_required
    @user_has('view_playbooks')
    def get(self, current_user):
        ''' Returns a list of playbook '''
        return Playbook.query.filter_by(organization_uuid=current_user().organization_uuid).all()

    @api.doc(security="Bearer")
    @api.expect(mod_playbook_create)
    @api.response('409', 'Playbook already exists.')
    @api.response('200', "Successfully created the playbook.")
    @token_required
    @user_has('create_playbook')
    def post(self, current_user):
        _tags = []
        ''' Creates a new playbook '''
        playbook = Playbook.query.filter_by(name=api.payload['name']).first()
        if not playbook:
            if 'tags' in api.payload:
                tags = api.payload.pop('tags')
                _tags = parse_tags(tags, current_user().organization_uuid)

            playbook = Playbook(organization_uuid=current_user().organization_uuid, **api.payload)
            playbook.create()

            if len(_tags) > 0:
                playbook.tags += _tags
                playbook.save()

            return {'message': 'Successfully created the playbook.'}
        else:
            ns_playbook.abort(409, 'Playbook already exists.')


@ns_playbook.route("/<uuid>")
class PlaybookDetails(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_playbook_full)
    @api.response('200', 'Success')
    @api.response('404', 'Playbook not found')
    @token_required
    @user_has('view_playbooks')
    def get(self, uuid):
        ''' Returns information about a playbook '''
        playbook = Playbook.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if playbook:
            return playbook
        else:
            ns_playbook.abort(404, 'Playbook not found.')

    @api.doc(security="Bearer")
    @api.expect(mod_playbook_create)
    @api.marshal_with(mod_playbook_full)
    @token_required
    @user_has('update_playbook')
    def put(self, uuid):
        ''' Updates information for a playbook '''
        playbook = Playbook.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if playbook:
            if 'name' in api.payload and Playbook.query.filter_by(name=api.payload['name']).first():
                ns_playbook.abort(409, 'Playbook name already exists.')
            else:
                playbook.update(api.payload)
                return playbook
        else:
            ns_playbook.abort(404, 'Playbook not found.')

    @api.doc(security="Bearer")
    @token_required
    @user_has('delete_playbook')
    def delete(self, uuid):
        ''' Deletes a playbook '''
        playbook = Playbook.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if playbook:
            playbook.delete()
            return {'message': 'Sucessfully deleted playbook.'}


@ns_playbook.route('/<uuid>/remove_tag/<name>')
class DeletePlaybookTag(Resource):

    @api.doc(security="Bearer")
    @token_required
    @user_has('remove_tag_from_playbook')
    def delete(self, uuid, name, current_user):
        ''' Removes a tag from an playbook '''
        tag = Tag.query.filter_by(name=name).first()
        if not tag:
            ns_playbook.abort(404, 'Tag not found.')
        playbook = Playbook.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if playbook:
            playbook.tags.remove(tag)
            playbook.save()
        else:
            ns_playbook.abort(404, 'Playbook not found.')
        return {'message': 'Successfully rmeoved tag from playbook.'}


@ns_playbook.route("/<uuid>/tag/<name>")
class TagPlaybook(Resource):

    @api.doc(security="Bearer")
    @token_required
    @user_has('add_tag_to_playbook')
    def post(self, uuid, name, current_user):
        ''' Adds a tag to an playbook '''
        tag = Tag.query.filter_by(name=name).first()
        if not tag:
            tag = Tag(organization_uuid=current_user().organization_uuid, **{'name': name, 'color': '#fffff'})
            tag.create()

        playbook = Playbook.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if playbook:
            playbook.tags += [tag]
            playbook.save()
        else:
            ns_event.abort(404, 'Playbook not found.')
        return {'message': 'Successfully added tag to playbook.'}


@ns_playbook.route("/<uuid>/bulktag")
class BulkTagPlaybook(Resource):

    @api.doc(security="Bearer")
    @api.expect(mod_bulk_tag)
    @token_required
    @user_has('add_tag_to_playbook')
    def post(self, uuid, current_user):
        ''' Adds a tag to an playbook '''
        _tags = []
        if 'tags' in api.payload:
            tags = api.payload['tags']
            for t in tags:
                tag = Tag.query.filter_by(name=t).first()
                if not tag:
                    tag = Tag(organization_uuid=current_user().organization_uuid, **{'name': t, 'color': '#fffff'})
                    tag.create()
                    _tags += [tag]
                else:
                    _tags += [tag]

        playbook = Playbook.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if playbook:
            playbook.tags += _tags
            playbook.save()
        else:
            ns_playbook.abort(404, 'Playbook not found.')
        return {'message': 'Successfully added tag to playbook.'}


@ns_input.route("")
class InputList(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_input_list, as_list=True)
    @token_required
    @user_has('view_inputs')
    def get(self, current_user):
        ''' Returns a list of inputs '''
        return Input.query.filter_by(organization_uuid=current_user().organization_uuid).all()

    @api.doc(security="Bearer")
    @api.expect(mod_input_create)
    @api.response('409', 'Input already exists.')
    @api.response('200', 'Successfully create the input.')
    @token_required
    @user_has('add_input')
    def post(self, current_user):
        ''' Creates a new input '''
        _tags = []
        inp = Input.query.filter_by(name=api.payload['name']).first()

        if not inp:

            if 'credential' in api.payload:
                cred_uuid = api.payload.pop('credential')
                cred = Credential.query.filter_by(uuid=cred_uuid).first()
                api.payload['credential'] = cred

            if 'config' in api.payload:
                try:
                    api.payload['config'] = json.loads(base64.b64decode(
                        api.payload['config']).decode('ascii').strip())
                except Exception:
                    ns_input.abort(
                        400, 'Invalid JSON configuration, check your syntax')

            if 'field_mapping' in api.payload:
                try:
                    api.payload['field_mapping'] = json.loads(base64.b64decode(
                        api.payload['field_mapping']).decode('ascii').strip())
                except Exception:
                    ns_input.abort(
                        400, 'Invalid JSON in field_mapping, check your syntax')

            if 'tags' in api.payload:
                tags = api.payload.pop('tags')
                _tags = parse_tags(tags, current_user().organization_uuid)

            inp = Input(organization_uuid=current_user().organization_uuid, **api.payload)
            inp.create()

            if len(_tags) > 0:
                inp.tags += _tags
                inp.save()
        else:
            ns_input.abort(409, 'Input already exists.')
        return {'message': 'Successfully created the input.'}


@ns_input.route("/<uuid>")
class InputDetails(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_input_list)
    @token_required
    @user_has('view_inputs')
    def get(self, uuid, current_user):
        ''' Returns information about an input '''
        inp = Input.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if inp:
            return inp
        else:
            ns_input.abort(404, 'Input not found.')

    @api.expect(mod_input_create)
    @api.marshal_with(mod_input_list)
    @token_required
    @user_has('update_input')
    def put(self, uuid, current_user):
        ''' Updates information for an input '''
        inp = Input.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if inp:
            if 'name' in api.payload and Input.query.filter_by(name=api.payload['name']).first():
                ns_input.abort(409, 'Input name already exists.')
            else:
                inp.update(api.payload)
                return inp
        else:
            ns_input.abort(404, 'Input not found.')

    @token_required
    @user_has('delete_input')
    def delete(self, uuid, current_user):
        ''' Deletes an input '''
        inp = Input.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if inp:
            inp.delete()
            return {'message': 'Sucessfully deleted input.'}


@ns_plugin.route("/download/<path:path>")
class DownloadPlugin(Resource):

    # TODO: MAKE THIS ONLY ACCESSIBLE FROM AGENT TOKENS
    @api.doc(security="Bearer")
    @token_required
    def get(self, path, current_user):
        plugin_dir = os.path.join(current_app.config['PLUGIN_DIRECTORY'], current_user().organization_uuid)
        return send_from_directory(plugin_dir, path, as_attachment=True)


@ns_plugin.route('/upload')
class UploadPlugin(Resource):

    @api.doc(security="Bearer")
    @api.expect(upload_parser)
    @api.marshal_with(mod_plugin_list, as_list=True)
    @token_required
    @user_has('create_plugin')
    def post(self, current_user):

        plugins = []

        args = upload_parser.parse_args()

        def allowed_file(filename):
            return '.' in filename and filename.rsplit('.', 1)[1].lower() in current_app.config['PLUGIN_EXTENSIONS']

        if 'files' not in request.files:
            ns_plugin.abort(400, 'No file selected.')

        uploaded_files = args['files']
        for uploaded_file in uploaded_files:

            if uploaded_file.filename == '':
                ns_plugin.abort(400, 'No file selected.')

            if uploaded_file and allowed_file(uploaded_file.filename):

                # Make sure the file is one that can be uploaded
                # TODO: Add mime-type checking
                filename = secure_filename(uploaded_file.filename)
                
                # Check to see if the organizations plugin directory exists
                plugin_dir = os.path.join(current_app.config['PLUGIN_DIRECTORY'], current_user().organization_uuid)
                plugin_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), plugin_dir)
                if not os.path.exists(plugin_dir):
                    os.makedirs(plugin_dir)

                # Save the file
                file_path = os.path.join(plugin_dir, filename)
                uploaded_file.save(file_path)
                uploaded_file.close()

                # Hash the file and update the checksum for the plugin
                hasher = hashlib.sha1()
                with open(file_path, 'rb') as f:
                    hasher.update(f.read())

                # Open the file and grab the manifest and the logo
                with ZipFile(file_path, 'r') as z:
                    # TODO: Add plugin structure checks
                    # if 'logo.png' not in z.namelist():
                    #    ns_plugin.abort(400, "Archive does not contain logo.png")
                    # if 'plugin.json' not in z.namelist():
                    #    ns_plugin.abort(400, "Archive does not contain plugin.json")

                    files = [{'name': name, 'data': z.read(
                        name)} for name in z.namelist()]
                    for f in files:
                        if 'logo.png' in f['name']:
                            logo_b64 = base64.b64encode(f['data']).decode()
                        if 'plugin.json' in f['name']:
                            manifest_data = json.loads(f['data'].decode())
                            description = manifest_data['description']
                            name = manifest_data['name']
                            if 'config_template' in manifest_data:
                                config_template = manifest_data['config_template']
                            else:
                                config_template = {}
                

                plugin = Plugin.query.filter_by(filename=filename).first()
                if plugin:
                    plugin.manifest = manifest_data
                    plugin.logo = logo_b64
                    plugin.description = description
                    plugin.config_template = config_template
                    plugin.name = name
                    plugin.file_hash = hasher.hexdigest()
                    plugin.save()
                else:
                    plugin = Plugin(name=name,
                                    filename=filename,
                                    description=description,
                                    manifest=manifest_data,
                                    logo=logo_b64,
                                    config_template=config_template,
                                    file_hash=hasher.hexdigest(),
                                    organization_uuid=current_user().organization_uuid)
                    plugin.create()
                    
                plugins.append(plugin)
        return plugins


@ns_plugin_config.route("")
class PluginConfigList(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_plugin_config_list, as_list=True)
    @token_required
    @user_has('view_plugins')
    def get(self, current_user):
        ''' Returns a list of plugin_configs '''
        return PluginConfig.query.filter_by(organization_uuid=current_user().organization_uuid).all()

    @api.doc(security="Bearer")
    @api.expect(mod_plugin_config_create)
    @api.response('409', 'Plugin Config already exists.')
    @api.response('200', "Successfully created the event.")
    @token_required
    @user_has('create_plugin')
    def post(self, current_user):
        ''' Creates a new plugin_config '''
        plugin_config = PluginConfig.query.filter_by(
            name=api.payload['name']).first()
        if not plugin_config:
            plugin_config = PluginConfig(organization_uuid=current_user().organization_uuid, **api.payload)
            plugin_config.create()
        else:
            ns_plugin_config.abort(409, 'Plugin Config already exists.')
        return {'message': 'Successfully created the plugin config.', 'uuid': plugin_config.uuid}


@ns_plugin_config.route("/<uuid>")
class PluginConfigDetails(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_plugin_config_list)
    @api.response('200', 'Success')
    @api.response('404', 'PluginConfig not found')
    @token_required
    @user_has('view_plugins')
    def get(self, uuid, current_user):
        ''' Returns information about a plugin_config '''
        plugin_config = PluginConfig.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if plugin_config:
            return plugin_config
        else:
            ns_plugin_config.abort(404, 'Plugin Config not found.')

    @api.doc(security="Bearer")
    @api.expect(mod_plugin_config_create)
    @api.marshal_with(mod_plugin_config_list)
    @token_required
    @user_has('update_plugin')
    def put(self, uuid, current_user):
        ''' Updates information for a plugin_config '''
        plugin_config = PluginConfig.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if plugin_config:
            if 'name' in api.payload and PluginConfig.query.filter_by(name=api.payload['name']).first():
                ns_plugin_config.abort(
                    409, 'Plugin Config name already exists.')
            else:
                plugin_config.update(api.payload)
                return plugin_config
        else:
            ns_plugin_config.abort(404, 'Plugin Config not found.')

    @api.doc(security="Bearer")
    @token_required
    @user_has('delete_plugin')
    def delete(self, current_user, uuid):
        ''' Deletes a plugin_config '''
        plugin_config = PluginConfig.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if plugin_config:
            plugin_config.delete()
            return {'message': 'Sucessfully deleted plugin config.'}


@ns_plugin.route("")
class PluginList(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_plugin_list, as_list=True)
    @token_required
    @user_has('view_plugins')
    def get(self, current_user):
        ''' Returns a list of plugins '''
        return Plugin.query.filter_by(organization_uuid=current_user().organization_uuid).all()

    @api.doc(security="Bearer")
    @api.expect(mod_plugin_create)
    @api.response('409', 'Plugin already exists.')
    @api.response('200', "Successfully created the event.")
    @token_required
    @user_has('create_plugin')
    def post(self, current_user):
        ''' Creates a new plugin '''
        plugin = Plugin.query.filter_by(name=api.payload['name']).first()
        if not plugin:
            plugin = Plugin(organization_uuid=current_user().organization_uuid, **api.payload)
            plugin.create()
        else:
            ns_plugin.abort(409, 'Plugin already exists.')
        return {'message': 'Successfully created the plugin.', 'uuid': plugin.uuid}


@ns_plugin.route("/<uuid>")
class PluginDetails(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_plugin_list)
    @api.response('200', 'Success')
    @api.response('404', 'Plugin not found')
    @token_required
    @user_has('view_plugins')
    def get(self, current_user, uuid):
        ''' Returns information about a plugin '''
        plugin = Plugin.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if plugin:
            return plugin
        else:
            ns_plugin.abort(404, 'Plugin not found.')

    @api.doc(security="Bearer")
    @api.expect(mod_plugin_create)
    @api.marshal_with(mod_plugin_list)
    @token_required
    @user_has('update_plugin')
    def put(self, current_user, uuid):
        ''' Updates information for a plugin '''
        plugin = Plugin.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if plugin:
            if 'name' in api.payload and Plugin.query.filter_by(name=api.payload['name']).first():
                ns_plugin.abort(409, 'Plugin name already exists.')
            else:
                plugin.update(api.payload)
                return plugin
        else:
            ns_plugin.abort(404, 'Plugin not found.')

    @api.doc(security="Bearer")
    @token_required
    @user_has('delete_plugin')
    def delete(self, current_user, uuid):
        ''' Deletes a plugin '''
        plugin = Plugin.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if plugin:
            plugin.delete()
            return {'message': 'Sucessfully deleted plugin.'}


def add_event_to_case(case_uuid, event_uuid, organization_uuid):
    '''
    TODO: Move this to a function that can be used in the AddEventToCase route to dedupe code
    Merges an event in to a case, copies all the observables over and sets the Event to open
    '''

    case = Case.query.filter_by(uuid=case_uuid, organization_uuid=organization_uuid).first()
    if case:
        case_observables = [observable.value.lower() for observable in case.observables]
        
        _event_observables = []
        event = Event.query.filter_by(uuid=event_uuid, organization_uuid=organization_uuid).first()
        if event:
            # If the event is already imported into another case
            # skip the case
            if event.case_uuid:
                return False
            _event_observables += [observable for observable in event.observables]
            new_observables = [observable for observable in _event_observables if observable.value.lower() not in case_observables]
            case.observables += new_observables
            event.status = EventStatus.query.filter_by(name='Open', organization_uuid=organization_uuid).first()
            case.events.append(event)
            case.save()
        else:
            return False
        case.add_history('1 Event was merged into this case via an Event Rule')
    return True


@ns_event.route("/_bulk")
class CreateBulkEvents(Resource):

    @api.doc(security="Bearer")
    @api.expect(mod_event_create_bulk)
    @api.response('200', 'Sucessfully created events.')
    @api.response('207', 'Multi-Status')
    @token_required
    @user_has('add_event')
    def post(self, current_user):
        ''' Creates Events in bulk '''
        response = {
            'results': [],
            'success': True
        }
        event_status = EventStatus.query.filter_by(name="New", organization_uuid=current_user().organization_uuid).first()

        start_bulk_process_dt = datetime.datetime.utcnow().timestamp()

        events = api.payload['events']
        for item in events:

            start_event_process_dt = datetime.datetime.utcnow().timestamp()

            _tags = []
            _observables = []

            event = Event.query.filter_by(reference=item['reference'], organization_uuid=current_user().organization_uuid).first()
            if not event:

                if 'tags' in item:
                    tags = item.pop('tags')
                    _tags = parse_tags(tags, current_user().organization_uuid)

                if 'observables' in item:
                    observables = item.pop('observables')
                    _observables = create_observables(observables, current_user().organization_uuid)

                event = Event(organization_uuid=current_user().organization_uuid, **item)
                
                event.create()

                event.status = event_status
                event.save()

                if len(_tags) > 0:
                    event.tags += _tags
                    event.save()

                if len(_observables) > 0:
                    event.observables += _observables
                    event.save()

                event.hash_event()

                # Process event rules against the new event
                event_rules = EventRule.query.filter_by(organization_uuid=current_user().organization_uuid, event_signature=event.signature, active=True).all()
                if event_rules:
                    for rule in event_rules:
                        # Kill switch for if the rule is about to run but the expiration is set
                        # if the rule is expired skip this item
                        if rule.expire and rule.expire_at < datetime.datetime.utcnow():
                            rule.active = False
                            continue

                        # Check to make sure the observables match what the analyst has assigned to the rule
                        # if not skip this item
                        if rule.hash_target_observables(event.observables) == rule.rule_signature:
                            if rule.merge_into_case:
                                add_event_to_case(rule.target_case_uuid, event.uuid, current_user().organization_uuid)
                        else:
                            continue                            

                end_event_process_dt = datetime.datetime.utcnow().timestamp()

                event_process_time = end_event_process_dt - start_event_process_dt

                response['results'].append(
                    {'reference': item['reference'], 'status': 200, 'message': 'Event successfully created.', 'process_time': event_process_time})

            else:
                response['results'].append(
                    {'reference': item['reference'], 'status': 409, 'message': 'Event already exists.', 'process_time': '0'})
                response['success'] = False

            end_bulk_process_dt = datetime.datetime.utcnow().timestamp()
            total_process_time = end_bulk_process_dt - start_bulk_process_dt
            response['process_time'] = total_process_time

        return response, 207


event_list_parser = api.parser()
event_list_parser.add_argument('status', location='args', default=[], type=str, action='split', required=False)
event_list_parser.add_argument('tags', location='args', default=[], type=str, action='split', required=False)
event_list_parser.add_argument('observables', location='args', default=[], type=str, action='split', required=False)
event_list_parser.add_argument('signature', location='args', required=False)
event_list_parser.add_argument('severity', action='split', location='args', required=False)
event_list_parser.add_argument('grouped', type=xinputs.boolean, location='args', required=False)
event_list_parser.add_argument('case_uuid', type=str, location='args', required=False)
event_list_parser.add_argument('search', type=str, location='args', required=False)
event_list_parser.add_argument('title', type=str, location='args', action='split', required=False)
event_list_parser.add_argument('page', type=int, location='args', default=1, required=False)
event_list_parser.add_argument('page_size', type=int, location='args', default=5, required=False)
event_list_parser.add_argument('sort_by', type=str, location='args', default='created_at', required=False)
event_list_parser.add_argument('sort_desc', type=xinputs.boolean, location='args', default=True, required=False)

@ns_event.route("")
class EventList(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_paged_event_list, as_list=True)
    @api.expect(event_list_parser)
    @token_required
    @user_has('view_events')
    def get(self, current_user):
        ''' Returns a list of event '''

        args = event_list_parser.parse_args()

        # The default filter specification
        filter_spec = [{
            'model':'Event',
            'field': 'organization_uuid',
            'op': 'eq',
            'value': current_user().organization_uuid
        }]

        # Restrict what fields we can filter by
        sort_by = args['sort_by']
        if sort_by not in ['created_at','modified_at', 'severity', 'name', 'tlp']:
            sort_by = 'created_at'

        # Add the signature if we pass it
        if 'signature' in args and args['signature']:
            filter_spec.append({'model':'Event','field':'signature', 'op':'eq','value':args['signature']})
            args['grouped'] = False
     
        # Check if any of the observables are in the list (case sensitive)
        if len(args['observables']) > 0 and not '' in args['observables']:
            filter_spec.append({'field':'value', 'op': 'in', 'model':'Observable','value':args['observables']})

        # Check if any of the tags are in the list (case sensitive)
        if len(args['tags']) > 0 and not '' in args['tags']:
            filter_spec.append({'model':'Tag', 'field':'name', 'op': 'in', 'value': args['tags']})

        if args['title'] and not '' in args['title']:
            filter_spec.append({'model':'Event', 'field':'title', 'op':'in', 'value':args['title']})

        # Check if any of the severities are in the list
        if args['severity']:
            filter_spec.append({'model':'Event', 'field':'severity', 'op':'in', 'value': args['severity']})

        if args['case_uuid']:
            filter_spec.append({'model':'Event', 'field':'case_uuid', 'op':'eq', 'value': args['case_uuid']})

        if args['search']:
            filter_spec.append({
                'or': [
                    {'model':'Event', 'field':'title', 'op':'ilike', 'value':'%{}%'.format(args['search'])},
                    {'model':'Event', 'field':'description', 'op':'ilike', 'value':'%{}%'.format(args['search'])},
                    {'model':'Event', 'field':'reference', 'op':'ilike', 'value':'%{}%'.format(args['search'])},
                    {'model':'Event', 'field':'signature', 'op':'ilike', 'value':'%{}%'.format(args['search'])},
                    {'model':'Observable', 'field':'value', 'op':'ilike', 'value':'%{}%'.format(args['search'])},
                    {'model':'Tag', 'field':'name', 'op':'ilike', 'value':'%{}%'.format(args['search'])}
                ]
            })

        new_event_count_filter = copy.deepcopy(filter_spec)
        new_event_count_filter.append({'model':'EventStatus', 'field':'name', 'op': 'eq', 'value': 'New'})

        # Check if any of the statuses picked are in the list
        if len(args['status']) > 0 and not '' in args['status']:
            filter_spec.append({'model':'EventStatus', 'field':'name', 'op': 'in', 'value': args['status']})

        # Import our association tables, many-to-many doesn't have parent/child keys
        from .models import event_tag_association, observable_event_association
        base_query = db.session.query(Event)
        
        if args['search'] or (len(args['tags']) > 0 and not '' in args['tags']):
            base_query = base_query.join(event_tag_association).join(Tag)
            
        if args['search'] or (len(args['observables']) > 0 and not '' in args['observables']):
            base_query = base_query.join(observable_event_association).join(Observable)

        # Bidirectional sorting
        if args['sort_desc']:
            base_query = base_query.order_by(desc(getattr(Event,sort_by)))
        if not args['sort_desc']:
            base_query = base_query.order_by(asc(getattr(Event,sort_by)))

        # Return the default view of grouped events
        if args['grouped']:
            query = base_query.group_by(Event.signature)
            filtered_query = apply_filters(query, filter_spec)
            filtered_query, pagination = apply_pagination(filtered_query, page_number=args['page'], page_size=args['page_size'])
            events = filtered_query.all()
            
            for event in events:

                filter_spec_signed = copy.deepcopy(filter_spec)
                filter_spec_signed.append({'model':'Event','field':'signature','op':'eq','value':event.signature})
                if(args['case_uuid']):
                    related_events_count = Event.query.filter_by(case_uuid=args['case_uuid'], organization_uuid=current_user().organization_uuid, signature=event.signature).count()
                else:
                    related_events_count = Event.query.filter_by(organization_uuid=current_user().organization_uuid, signature=event.signature).count()                   
                
                event.__dict__['related_events_count'] = related_events_count

                new_event_count_filter_signed = copy.deepcopy(new_event_count_filter)
                new_event_count_filter_signed.append({'model':'Event','field':'signature','op':'eq','value':event.signature})
                related_events = apply_filters(base_query, new_event_count_filter_signed).all()
                uuids = [e.uuid for e in related_events]
                event.__dict__['new_related_events'] = uuids

            response = {
                'events': events,
                'pagination': {
                    'total_results': pagination.total_results,
                    'pages': pagination.num_pages,
                    'page': pagination.page_number,
                    'page_size': pagination.page_size
                    }
                }
            return response

        # Return an ungrouped list of a signatures events
        elif not args['grouped'] and args['signature']:
            query = base_query
            filtered_query = apply_filters(query, filter_spec)
            filtered_query, pagination = apply_pagination(filtered_query, page_number=args['page'], page_size=args['page_size'])
            events = filtered_query.all()
            
            response = {
                'events': events,
                'pagination': {
                    'total_results': pagination.total_results,
                    'pages': pagination.num_pages,
                    'page': pagination.page_number,
                    'page_size': pagination.page_size
                    }
                }
            return response

        else:
            query = base_query
            filtered_query = apply_filters(query, filter_spec)
            filtered_query, pagination = apply_pagination(filtered_query, page_number=args['page'], page_size=args['page_size'])
            events = filtered_query.all()
            response = {
                'events': events,
                'pagination': {
                    'total_results': pagination.total_results,
                    'pages': pagination.num_pages,
                    'page': pagination.page_number,
                    'page_size': pagination.page_size
                    }
                }
            return response


    @api.doc(security="Bearer")
    @api.expect(mod_event_create)
    @api.response(409, 'Event already exists.')
    @api.response(200, "Successfully created the event.")
    @token_required
    @user_has('add_event')
    def post(self, current_user):
        _observables = []
        _tags = []
        ''' Creates a new event '''
        event = Event.query.filter_by(
            reference=api.payload['reference']).first()
        if not event:
            if 'tags' in api.payload:
                tags = api.payload.pop('tags')
                _tags = parse_tags(tags, current_user().organization_uuid)

            if 'observables' in api.payload:
                observables = api.payload.pop('observables')
                _observables = create_observables(observables, current_user().organization_uuid)

            event = Event(organization_uuid=current_user().organization_uuid, **api.payload)
            event.create()

            # Set the default status to New
            event_status = EventStatus.query.filter_by(name="New", organization_uuid=current_user().organization_uuid).first()
            event.status = event_status
            event.save()

            if len(_tags) > 0:
                event.tags += _tags
                event.save()

            if len(_observables) > 0:
                event.observables += _observables
                event.save()

            event.hash_event()

            return {'message': 'Successfully created the event.'}
        else:
            ns_event.abort(409, 'Event already exists.')


@ns_event.route("/bulk_delete")
class EventBulkDelete(Resource):

    @api.doc(security="Bearer")
    @api.expect(mod_event_bulk)
    @token_required
    @user_has('delete_event')
    def delete(self, current_user):
        '''
        Takes in a list of event uuids and deletes them all
        '''

        if 'events' in api.payload:
            for uuid in api.payload['events']:
                event = Event.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
                if event:
                    event.delete()

        return {'message': 'Sucessfully deleted events.'}


@ns_event.route('/bulk_dismiss')
class EventBulkUpdate(Resource):

    @api.doc(security="Bearer")
    @api.expect(mod_event_bulk_dismiss)
    @api.marshal_with(mod_event_details, as_list=True)
    @token_required
    @user_has('update_event')
    def put(self, current_user):
        ''' Dismisses multiple events at the same time with the same dismiss reason and comment '''
        _events = []
        if 'events' in api.payload:
            for e in api.payload['events']:
                event = Event.query.filter_by(uuid=e, organization_uuid=current_user().organization_uuid).first()
                if event:
                    # If the event has already closed/dismissed, don't update it again
                    if event.status.closed and ('dismiss_reason_uuid' in api.payload or 'dismiss_comment' in api.payload):
                        if event.close_reason:
                            api.payload.pop('dismiss_reason_uuid')
                            api.payload.pop('dismiss_comment')

                    if 'dismiss_reason_uuid' in api.payload:
                        event_status = EventStatus.query.filter_by(organization_uuid=current_user().organization_uuid, closed=True).first()
                        api.payload['status'] = event_status

                    # Update the event
                    event.update(api.payload)

                    # Add it to a list so we can return it back for display refresh
                    _events.append(event)

        return _events

@ns_event.route("/<uuid>")
class EventDetails(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_event_details)
    @api.response('200', 'Success')
    @api.response('404', 'Event not found')
    @token_required
    @user_has('view_events')
    def get(self, current_user, uuid):
        ''' Returns information about a event '''
        event = Event.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if event:
            return event
        else:
            ns_event.abort(404, 'Event not found.')

    @api.doc(security="Bearer")
    @api.expect(mod_event_create)
    @api.marshal_with(mod_event_details)
    @token_required
    @user_has('update_event')
    def put(self, current_user, uuid):
        ''' Updates information for a event '''
        event = Event.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if event:

            # If the event has already closed/dismissed, don't update it again
            if event.status.closed and ('dismiss_reason_uuid' in api.payload or 'dismiss_comment' in api.payload):
                if event.close_reason:
                    api.payload.pop('dismiss_reason_uuid')
                    api.payload.pop('dismiss_comment')

            if 'dismiss_reason_uuid' in api.payload:
                event_status = EventStatus.query.filter_by(organization_uuid=current_user().organization_uuid, closed=True).first()
                api.payload['status'] = event_status

            if 'status' in api.payload and api.payload['status'] == 0:
                event_status = EventStatus.query.filter_by(organization_uuid=current_user().organization_uuid, closed=False, name='New').first()
                api.payload['status'] = event_status

            event.update(api.payload)
            return event
        else:
            ns_event.abort(404, 'Event not found.')

    @api.doc(security="Bearer")
    @token_required
    @user_has('delete_event')
    def delete(self, current_user, uuid):
        ''' Deletes a event '''
        event = Event.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if event:
            event.delete()
            return {'message': 'Sucessfully deleted event.'}


@ns_event_rule.route("")
class EventRuleList(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_event_rule_list)
    @token_required
    @user_has('view_event_rules')
    def get(self, current_user):
        ''' Gets a list of all the event rules '''
        return EventRule.query.filter_by(organization_uuid=current_user().organization_uuid).all()

    @api.doc(security="Bearer")
    @api.expect(mod_event_rule_create)
    @api.response('200', 'Successfully created event rule.')
    @token_required
    @user_has('create_event_rule')
    def post(self, current_user):
        ''' Creates a new event_rule set '''

        # Computer when the rule should expire
        if 'expire' in api.payload and api.payload['expire']:
            if 'expire_days' in api.payload:
                expire_days = api.payload.pop('expire_days')

                expire_at = datetime.datetime.utcnow() + datetime.timedelta(days=expire_days)
                api.payload['expire_at'] = expire_at
            else:
                ns_event_rule.abort(400, 'Missing expire_days field.')

        # Create the observables
        if 'observables' in api.payload:
            observables = api.payload.pop('observables')
            api.payload['observables'] = create_observables(observables, current_user().organization_uuid)


        event_rule = EventRule(organization_uuid=current_user().organization_uuid, **api.payload)
        event_rule.hash_observables()
        event_rule.create()

        return {'message': 'Successfully created event rule.', 'uuid': event_rule.uuid}


@ns_event_rule.route("/<uuid>")
class EventRuleDetails(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_event_rule_list)
    @token_required
    @user_has('view_event_rules')
    def get(self, uuid, current_user):
        ''' Gets a event rule '''
        event_rule = EventRule.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if event_rule:
            return event_rule
        else:
            ns_event_rule.abort(404, 'Event rule not found.')

    @api.doc(security="Bearer")
    @api.expect(mod_event_rule_create)
    @api.marshal_with(mod_event_rule_list)
    @token_required
    @user_has('update_event_rule')
    def put(self, uuid, current_user):
        ''' Updates the event rule '''
        event_rule = EventRule.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if event_rule:
            event_rule.update(api.payload)
            return event_rule
        else:
            ns_event_rule.abort(404, 'Event rule not found.')

    @api.doc(security="Bearer")
    @token_required
    @user_has('delete_event_rule')
    def delete(self, uuid, current_user):
        ''' Removes an event rule '''
        event_rule = EventRule.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if event_rule:
            event_rule.delete()
            return {'message': 'Sucessfully deleted the event rule.'}


@ns_event.route('/<uuid>/remove_tag/<name>')
class DeleteEventTag(Resource):

    @api.doc(security="Bearer")
    @token_required
    # @user_has('remove_tag_from_event')
    def delete(self, uuid, name, current_user):
        ''' Removes a tag from an event '''
        tag = Tag.query.filter_by(name=name).first()
        if not tag:
            ns_event.abort(404, 'Tag not found.')
        event = Event.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if event:
            event.tags.remove(tag)
            event.save()
        else:
            ns_event.abort(404, 'Event not found.')
        return {'message': 'Successfully removed tag from event.'}


@ns_event.route("/<uuid>/tag/<name>")
class TagEvent(Resource):

    @api.doc(security="Bearer")
    @token_required
    @user_has('add_tag_to_event')
    def post(self, uuid, name, current_user):
        ''' Adds a tag to an event '''
        tag = Tag.query.filter_by(name=name).first()
        if not tag:
            tag = Tag(organization_uuid=current_user().organization_uuid, **{'name': name, 'color': '#fffff'})
            tag.create()

        event = Event.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if event:
            event.tags += [tag]
            event.save()
        else:
            ns_event.abort(404, 'Event not found.')
        return {'message': 'Successfully added tag to event.'}


@ns_event.route("/<uuid>/bulktag")
class BulkTagEvent(Resource):

    @api.doc(security="Bearer")
    @api.expect(mod_bulk_tag)
    @token_required
    @user_has('add_tag_to_event')
    def post(self, uuid, current_user):
        ''' Adds a tag to an event '''
        _tags = []
        if 'tags' in api.payload:
            tags = api.payload['tags']
            for t in tags:
                tag = Tag.query.filter_by(name=t).first()
                if not tag:
                    tag = Tag(organization_uuid=current_user().organization_uuid, **{'name': t, 'color': '#fffff'})
                    tag.create()
                    _tags += [tag]
                else:
                    _tags += [tag]

        event = Event.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if event:
            event.tags += _tags
            event.save()
        else:
            ns_event.abort(404, 'Event not found.')
        return {'message': 'Successfully added tag to event.'}


@ns_agent.route("/pair_token")
class AgentPairToken(Resource):

    @api.doc(security="Bearer")
    @token_required
    @user_has('pair_agent')
    def get(self, current_user):
        ''' 
        Generates a short lived pairing token used by the agent
        to get a long running JWT
        '''

        settings = GlobalSettings.query.filter_by(organization_uuid=current_user().organization_uuid).first()

        return generate_token(None, current_user().organization_uuid, settings.agent_pairing_token_valid_minutes, 'pairing')


@ns_agent.route("")
class AgentList(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_agent_list, as_list=True)
    @token_required
    @user_has('view_agents')
    def get(self, current_user):
        ''' Returns a list of Agents '''
        return Agent.query.filter_by(organization_uuid=current_user().organization_uuid).all()

    @api.doc(security="Bearer")
    @api.expect(mod_agent_create)
    @api.response('409', 'Agent already exists.')
    @api.response('200', "Successfully created the agent.")
    @token_required
    @user_has('add_agent')
    def post(self, current_user):
        ''' Creates a new Agent '''

        groups = None

        agent = Agent.query.filter_by(name=api.payload['name'], organization_uuid=current_user()['organization']).first()
        if not agent:

            if 'roles' in api.payload:
                roles = api.payload.pop('roles')

            if 'groups' in api.payload:
                groups = api.payload.pop('groups')

            agent = Agent(organization_uuid=current_user()['organization'], **api.payload)
            for role in roles:
                agent_role = AgentRole.query.filter_by(name=role).first()
                if agent_role:
                    agent.roles.append(agent_role)
                else:
                    ns_agent.abort(400, 'Invalid agent role type')

            if groups:
                for group_name in groups:
                    group = AgentGroup.query.filter_by(name=group_name, organization_uuid=current_user()['organization']).first()
                    if group:
                        agent.groups.append(group)
                    else:
                        ns_agent.abort(400, 'Agent Group not found.')

            role = Role.query.filter_by(name='Agent').first()
            agent.role = role

            agent.create()

            return {'message': 'Successfully created the agent.', 'uuid': agent.uuid, 'token': generate_token(agent.uuid, current_user()['organization'], 86400, token_type='agent')}
        else:
            ns_agent.abort(409, "Agent already exists.")


@ns_agent.route("/heartbeat/<uuid>")
class AgentHeartbeat(Resource):

    @api.doc(security="Bearer")
    @token_required
    def get(self, uuid, current_user):
        agent = Agent.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if agent:
            agent.last_heartbeat = datetime.datetime.utcnow()
            agent.save()
            return {'message': 'Your heart still beats!'}
        else:
            '''
            If the agent can't be found, revoke the agent token
            '''

            auth_header = request.headers.get('Authorization')
            access_token = auth_header.split(' ')[1]
            token_blacklist = AuthTokenBlacklist(auth_token=access_token)
            token_blacklist.create()
            
            ns_agent.abort(400, 'Your heart stopped.')


@ns_agent.route("/<uuid>")
class AgentDetails(Resource):

    @api.doc(security="Bearer")
    @api.expect(mod_agent_create)
    @api.marshal_with(mod_agent_list)
    @token_required
    @user_has('update_agent')
    def put(self, uuid, current_user):
        ''' Updates an Agent '''
        agent = Agent.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if agent:
            if 'inputs' in api.payload:
                _inputs = []
                inputs = api.payload.pop('inputs')
                if len(inputs) > 0:
                    for inp in inputs:
                        _input = Input.query.filter_by(uuid=inp).first()
                        if _input:
                            _inputs.append(_input)
                agent.inputs = _inputs
                agent.save()

            if 'groups' in api.payload:
                _groups = []
                groups = api.payload.pop('groups')
                if len(groups) > 0:
                    for grp in groups:
                        group = AgentGroup.query.filter_by(uuid=grp).first()
                        if group:
                            _groups.append(group)
                agent.groups = _groups
                agent.save()

            agent.update(api.payload)
            return agent
        else:
            ns_agent.abort(404, 'Agent not found.')

    @api.doc(security="Bearer")
    @token_required
    @user_has('delete_agent')
    def delete(self, uuid, current_user):
        ''' Removes a Agent '''
        agent = Agent.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if agent:
            agent.delete()
            return {'message': 'Agent successfully delete.'}
        else:
            ns_agent.abort(404, 'Agent not found.')

    @api.doc(security="Bearer")
    @api.marshal_with(mod_agent_list)
    @token_required
    @user_has('view_agents')
    def get(self, uuid, current_user):
        ''' Gets the details of a Agent '''
        agent = Agent.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if agent:
            return agent
        else:
            ns_agent.abort(404, 'Agent not found.')

user_group_parser = api.parser()
user_group_parser.add_argument('name', location='args', required=False)

@ns_user_group.route("")
class UserGroupList(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_user_group_list, as_list=True)
    @token_required
    @user_has('view_user_groups')
    def get(self, current_user):
        ''' Gets a list of user_groups '''

        args = user_group_parser.parse_args()

        if args['name']:
            groups = UserGroup.query.filter_by(UserGroup.name.like(args['name']+"%"), organization_uuid=current_user().organization_uuid).all()
        else:
            groups = UserGroup.query.filter_by(organization_uuid=current_user().organization_uuid).all()

        return groups

    @api.doc(security="Bearer")
    @api.expect(mod_user_group_create)
    @api.response('409', 'User Group already exists.')
    @api.response('200', "Successfully created the User Group.")
    @token_required
    @user_has('create_user_group')
    def post(self, current_user):
        ''' Creates a new user_group '''
        user_group = UserGroup.query.filter_by(
            name=api.payload['name']).first()
        if not user_group:
            user_group = UserGroup(organization_uuid=current_user().organization_uuid, **api.payload)
            user_group.create()
            return {'message': 'Successfully created the User Group.'}
        else:
            ns_user_group.abort(409, 'User Group already exists.')
        return

@ns_user_group.route('/<uuid>')
class UserGroupDetails(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_user_group_list)
    @api.response('200', 'Success')
    @api.response('404', 'UserGroup not found')
    @token_required
    @user_has('view_user_groups')
    def get(self, uuid, current_user):
        ''' Gets details on a specific user_group '''
        user_group = UserGroup.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if user_group:
            return user_group
        else:
            ns_user_group.abort(404, 'User Group not found.')
        return

    @api.doc(security="Bearer")
    @api.expect(mod_user_group_create)
    @api.marshal_with(mod_user_group_list)
    @token_required
    @user_has('update_user_groups')
    def put(self, uuid, current_user):
        ''' Updates a user_group '''
        user_group = UserGroup.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()

        if user_group:
            # TODO: Improve the query function so that organization_uuid=current_user().organization_uuid is just natively
            # called on all database calls
            if 'name' in api.payload and UserGroup.query.filter_by(name=api.payload['name'], organization_uuid=current_user().organization_uuid).first():
                ns_user_group.abort(409, 'User Group name already exists.')
            else:
                user_group.update(api.payload)
                return user_group
        else:
            ns_user_group.abort(404, 'User Group not found.')
        return

    @api.doc(security="Bearer")
    @token_required
    @user_has('delete_user_group')
    def delete(self, uuid, current_user):
        ''' Deletes a user_group '''
        user_group = UserGroup.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if user_group:
            user_group.delete()
            return {'message': 'Sucessfully deleted User Group.'}


@ns_user_group.route("/<uuid>/update-users")
class UpdateUserToGroup(Resource):

    @api.doc(security="Bearer")
    @api.response('409', 'User already a member of this Group.')
    @api.response('404', 'Group not found.')
    @api.response('404', 'User not found.')
    @api.response('207', 'Users added to Group.')
    @api.expect(mod_add_user_to_group)
    @token_required
    @user_has('update_user_groups')
    def put(self, uuid, current_user):
        ''' Adds a user to a specified Role '''

        _users = []
        response = {
            'results': [],
            'success': True
        }
        if 'members' in api.payload:
            users = api.payload.pop('members')
            for user_uuid in users:
                user = User.query.filter_by(uuid=user_uuid, organization_uuid=current_user().organization_uuid).first()
                if user:
                    _users.append(user)
                    response['results'].append(
                        {'reference': user_uuid, 'message': 'User successfully added.'})
                else:
                    response['results'].append(
                        {'reference': user_uuid, 'message': 'User not found.'})
                    response['success'] = False

        group = UserGroup.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if group:
            group.members = _users
            group.save()
            return response, 207
        else:
            ns_user_group.abort(404, 'Group not found.')


agent_group_parser = pager_parser.copy()

@ns_agent_group.route("")
class AgentGroupList(Resource):

    @api.doc(security="Bearer")
    @api.expect(agent_group_parser)
    @api.marshal_with(mod_paged_agent_group_list)
    @token_required
    @user_has('view_agent_groups')
    def get(self, current_user):
        ''' Gets a list of agent_groups '''

        args = agent_group_parser.parse_args()

        base_query = db.session.query(AgentGroup).filter_by(organization_uuid=current_user().organization_uuid)
        query, pagination = apply_pagination(base_query, page_number=args['page'], page_size=args['page_size'])
        response = {
            'groups': query.all(),
            'pagination': {
                'total_results': pagination.total_results,
                'pages': pagination.num_pages,
                'page': pagination.page_number,
                'page_size': pagination.page_size
            }
        }
        return response

        return AgentGroup.query.filter_by(organization_uuid=current_user().organization_uuid).all()

    @api.doc(security="Bearer")
    @api.expect(mod_agent_group_create)
    @api.marshal_with(mod_agent_group_list)
    @api.response('409', 'AgentGroup already exists.')
    @api.response('200', "Successfully created the Agent Group.")
    @token_required
    @user_has('create_agent_group')
    def post(self, current_user):
        ''' Creates a new agent_group '''
        agent_group = AgentGroup.query.filter_by(
            name=api.payload['name']).first()
        if not agent_group:
            agent_group = AgentGroup(organization_uuid=current_user().organization_uuid, **api.payload)
            agent_group.create()
            return agent_group
        else:
            ns_agent_group.abort(409, 'Agent Group already exists.')
        return


@ns_agent_group.route('/<uuid>')
class AgentGroupDetails(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_agent_group_list)
    @api.response('200', 'Success')
    @api.response('404', 'AgentGroup not found')
    @token_required
    @user_has('view_agent_groups')
    def get(self, uuid, current_user):
        ''' Gets details on a specific agent_group '''
        agent_group = AgentGroup.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if agent_group:
            return agent_group
        else:
            ns_agent_group.abort(404, 'Agent Group not found.')
        return

    @api.doc(security="Bearer")
    @api.expect(mod_agent_group_create)
    @api.marshal_with(mod_agent_group_list)
    @token_required
    @user_has('update_agent_group')
    def put(self, uuid, current_user):
        ''' Updates a agent_group '''
        agent_group = AgentGroup.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()

        if agent_group:
            exists = AgentGroup.query.filter_by(name=api.payload['name']).first()
            if 'name' in api.payload and exists.uuid != uuid:
                ns_agent_group.abort(409, 'Agent Group name already exists.')
            else:
                agent_group.update(api.payload)
                return agent_group
        else:
            ns_agent_group.abort(404, 'Agent Group not found.')
        return

    @api.doc(security="Bearer")
    @token_required
    @user_has('delete_agent_group')
    def delete(self, uuid):
        ''' Deletes a agent_group '''
        agent_group = AgentGroup.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if agent_group:
            agent_group.delete()
            return {'message': 'Sucessfully deleted Agent Group.'}


@ns_role.route("")
class RoleList(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_role_list, as_list=True)
    @token_required
    @user_has('view_roles')
    def get(self, current_user):
        ''' Returns a list of Roles '''
        return Role.query.filter_by(organization_uuid=current_user().organization_uuid).all()

    @api.doc(security="Bearer")
    @api.expect(mod_role_create)
    @api.response('409', 'Role already exists.')
    @api.response('200', "Successfully created the role.")
    @token_required
    @user_has('add_role')
    def post(self, current_user):
        ''' Creates a new Role '''
        role = Role.query.filter_by(name=api.payload['name'], organization_uuid=current_user().organization_uuid).first()
        if not role:
            role = Role(organization_uuid=current_user().organization_uuid, **api.payload)
            role.create()
            return {'message': 'Successfully created the role.', 'uuid': role.uuid}
        else:
            ns_user.abort(409, "Role already exists.")


@ns_role.route("/<uuid>")
class RoleDetails(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_role_list)
    @token_required
    @user_has('update_role')
    def put(self, uuid, current_user):
        ''' Updates an Role '''
        role = Role.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if role:
            if 'name' in api.payload and Role.query.filter_by(name=api.payload['name'], organization_uuid=current_user().organization_uuid).first():
                ns_role.abort(409, 'Role with that name already exists.')
            else:
                role.update(api.payload)
                return role
        else:
            ns_role.abort(404, 'Role not found.')

    @api.doc(security="Bearer")
    @token_required
    @user_has('delete_role')
    def delete(self, uuid, current_user):
        ''' Removes a Role '''
        role = Role.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if role:
            if len(role.users) > 0:
                ns_role.abort(
                    400, 'Can not delete a role with assigned users.  Assign the users to a new role first.')
            else:
                role.delete()
                return {'message': 'Role successfully delete.'}
        else:
            ns_role.abort(404, 'Role not found.')

    @api.doc(security="Bearer")
    @api.marshal_with(mod_role_list)
    @token_required
    @user_has('view_roles')
    def get(self, uuid, current_user):
        ''' Gets the details of a Role '''
        role = Role.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if role:
            return role
        else:
            ns_role.abort(404, 'Role not found.')


@ns_list.route("")
class ListList(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_list_list, as_list=True)
    @token_required
    @user_has('view_lists')
    def get(self, current_user):
        ''' Returns a list of Lists '''
        return List.query.filter_by(organization_uuid=current_user().organization_uuid).all()

    @api.doc(security="Bearer")
    @api.expect(mod_list_create)
    @api.marshal_with(mod_list_list)
    @api.response('409', 'List already exists.')
    @api.response('200', "Successfully created the list.")
    @token_required
    @user_has('add_list')
    def post(self, current_user):
        '''
        Creates a new List 
        
        Supported list types: `values|pattern`
        
        '''

        if 'values' in api.payload:
            _values = api.payload.pop('values')
            if not isinstance(_values, list):
                _values = _values.split('\n')
            values = []
            for value in _values:
                if value == '':
                    continue
                v = ListValue(value=value, organization_uuid=current_user().organization_uuid)
                values.append(v)

            api.payload['values'] = values

        data_type = DataType.query.filter_by(uuid=api.payload['data_type_uuid']).first()
        if not data_type:
            ns_list.abort(409, "Data type not found.")

        value_list = List.query.filter_by(name=api.payload['name'], organization_uuid=current_user().organization_uuid).first()

        if not value_list:
            value_list = List(organization_uuid=current_user().organization_uuid, **api.payload)
            value_list.create()
            return value_list
        else:
            ns_list.abort(409, "List already exists.")


@ns_list.route("/<uuid>")
class ListDetails(Resource):

    @api.doc(security="Bearer")
    @api.expect(mod_list_create)
    @api.marshal_with(mod_list_list)
    @token_required
    @user_has('update_list')
    def put(self, uuid, current_user):
        ''' Updates a List '''
        value_list = List.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if value_list:
            
            if 'name' in api.payload:
                l =  List.query.filter_by(name=api.payload['name'], organization_uuid=current_user().organization_uuid).first()
                if l and l.uuid != uuid:
                    ns_list.abort(409, 'List with that name already exists.')
                else:
                    if 'values' in api.payload:

                        # Get the current values in the list
                        current_values = [v.value for v in value_list.values]

                        # Determine what the new values should be, current, new or removed
                        _values = api.payload.pop('values')

                        # Detect if the user sent it as a list or a \n delimited string
                        if not isinstance(_values, list):
                            _values = _values.split('\n')

                        removed_values = [v for v in current_values if v not in _values and v != '']
                        new_values = [v for v in _values if v not in current_values and v != '']

                        # For all values not in the new list
                        # delete them from the database and disassociate them 
                        # from the list
                        for v in removed_values:
                            value = ListValue.query.filter_by(value=v, organization_uuid=current_user().organization_uuid, parent_list_uuid=value_list.uuid).first()
                            value.delete()

                        for v in new_values:
                            value = ListValue(value=v, organization_uuid=current_user().organization_uuid)
                            value_list.values.append(value)

                    value_list.update(api.payload)
                    return value_list
        else:
            ns_list.abort(404, 'List not found.')

    @api.doc(security="Bearer")
    @token_required
    @user_has('delete_list')
    def delete(self, uuid, current_user):
        ''' Removes a List '''
        value_list = List.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if value_list:
            
            # Delete all the values so they aren't orphaned
            for value in value_list.values:
                value.delete()

            value_list.delete()
            return {'message': 'List successfully delete.'}
        else:
            ns_list.abort(404, 'List not found.')

    @api.doc(security="Bearer")
    @api.marshal_with(mod_list_list)
    @token_required
    @user_has('view_lists')
    def get(self, uuid, current_user):
        ''' Gets the details of a List '''

        value_list = List.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if value_list:
            return value_list
        else:
            ns_list.abort(404, 'List not found.')


@ns_role.route("/<uuid>/add-user/<user_uuid>")
class AddUserToRole(Resource):

    @api.doc(security="Bearer")
    @api.response('409', 'User already a member of this Role.')
    @api.response('404', 'Role not found.')
    @api.response('404', 'User not found.')
    @api.response('200', 'User added to Role.')
    @token_required
    @user_has('add_user_to_role')
    def put(self, uuid, user_uuid, current_user):
        ''' Adds a user to a specified Role '''
        user = User.query.filter_by(uuid=user_uuid, organization_uuid=current_user().organization_uuid).first()
        if user:
            role = Role.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
            if role:
                user.role = role
                user.save()
                return {'message': 'Successfully added {} to the {} role.'.format(user.username, role.name)}
            else:
                ns_role.abort(404, 'Role not found.')
        else:
            ns_role.abort(404, 'User not found.')


@ns_role.route("/<uuid>/remove-user/<user_uuid>")
class RemoveUserFromRole(Resource):

    @api.doc(security="Bearer")
    @api.response('404', 'User not a member of this Role.')
    @api.response('404', 'Role not found.')
    @api.response('200', 'User removed from Role.')
    @token_required
    @user_has('remove_user_from_role')
    def put(self, uuid, user_uuid, current_user):
        ''' Removes a user to a specified Role '''
        user = User.query.filter_by(uuid=user_uuid, organization_uuid=current_user().organization_uuid).first()
        if not user:
            ns_role.abort(404, 'User not found.')

        role = Role.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if role:
            role.users = [u for u in role.users if u.uuid != user.uuid]
            role.save()
            return {'message': 'Successfully removed User from Role.'}
        else:
            ns_role.abort(404, 'Role not found.')


@ns_credential.route('/encrypt')
class EncryptPassword(Resource):

    @api.doc(security="Bearer")
    @api.expect(mod_credential_create)
    @api.marshal_with(mod_credential_full)
    @api.response('400', 'Successfully created credential.')
    @api.response('409', 'Credential already exists.')
    @token_required
    @user_has('add_credential')
    def post(self, current_user):
        ''' Encrypts the password '''
        credential = Credential.query.filter_by(
            name=api.payload['name'], organization_uuid=current_user().organization_uuid).first()
        if not credential:
            credential = Credential(organization_uuid=current_user().organization_uuid, **api.payload)
            credential.encrypt(api.payload['secret'].encode(
            ), current_app.config['MASTER_PASSWORD'])
            credential.create()
            return credential
        else:
            ns_credential.abort(409, 'Credential already exists.')


@ns_credential.route("")
class CredentialList(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_credential_list)
    @token_required
    @user_has('view_credentials')
    def get(self, current_user):
        credentials = Credential.query.filter_by(organization_uuid=current_user().organization_uuid).all()
        if credentials:
            return credentials
        else:
            return []
            #ns_credential.abort(404,'No credentials found.')


@ns_credential.route('/decrypt/<uuid>')
class DecryptPassword(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_credential_return)
    @api.response('404', 'Credential not found.')
    @token_required
    @user_has('decrypt_credential')
    def get(self, uuid, current_user):
        ''' Decrypts the credential for use '''
        credential = Credential.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if credential:
            value = credential.decrypt(current_app.config['MASTER_PASSWORD'])
            if value:
                return {'secret': value}
            else:
                ns_credential.abort(401, 'Invalid master password.')
        else:
            ns_credential.abort(404, 'Credential not found.')


@ns_credential.route('/<uuid>')
class DeletePassword(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_credential_full)
    @api.response('404', 'Credential not found.')
    @token_required
    @user_has('view_credentials')
    def get(self, uuid, current_user):
        ''' Gets the full details of a credential '''
        credential = Credential.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if credential:
            return credential
        else:
            ns_credential.abort(409, 'Credential not found.')

    @api.doc(security="Bearer")
    @api.expect(mod_credential_update, validate=True)
    @api.marshal_with(mod_credential_full)
    @api.response('404', 'Credential not found.')
    @api.response('409', 'Credential name already exists.')
    @token_required
    @user_has('update_credential')
    def put(self, uuid, current_user):
        ''' Updates a credential '''
        print(api.payload)
        credential = Credential.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if credential:
            cred = Credential.query.filter_by(name=api.payload['name']).first()
            if cred:
                if 'name' in api.payload and cred.uuid != uuid:
                    ns_credential.abort(409, 'Credential name already exists.')
            
            if 'secret' in api.payload:
                credential.encrypt(api.payload.pop('secret').encode(
                                    ), current_app.config['MASTER_PASSWORD'])
                credential.save()
            credential.update(api.payload)
            credential.save()
            return credential
        else:
            ns_credential.abort(404, 'Credential not found.')

    @api.doc(security="Bearer")
    @api.response('404', 'Credential not found.')
    @api.response('200', "Credential sucessfully deleted.")
    @token_required
    @user_has('delete_credential')
    def delete(self, uuid, current_user):
        ''' Deletes a credential '''
        credential = Credential.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if credential:
            credential.delete()
            return {'message': 'Credential successfully deleted.'}
        else:
            ns_credential.abort(404, 'Credential not found.')


def do_math():
    return 100*10

@ns_test.route("")
class Test(Resource):

    @api.doc(security="Bearer")
    def get(self):
        test_task.delay('amazing!')
        return "Okay"


@ns_tag.route("")
class TagList(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_tag_list, as_list=True)
    @token_required
    def get(self, current_user):
        ''' Gets a list of tags '''
        return Tag.query.filter_by(organization_uuid=current_user().organization_uuid).all()

    @api.doc(security="Bearer")
    @api.expect(mod_tag)
    @api.response('409', 'Tag already exists.')
    @api.response('200', "Successfully created the tag.")
    @token_required
    def post(self, current_user):
        ''' Creates a new tag '''
        tag = Tag.query.filter_by(name=api.payload['name']).first()
        if not tag:
            tag = Tag(organization_uuid=current_user().organization_uuid, **api.payload)
            tag.create()
            return {'message': 'Successfully created the tag.'}
        else:
            ns_tag.abort(409, 'Tag already exists.')
        return


@ns_tag.route('/<uuid>')
class TagDetails(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_tag_list)
    @api.response('200', 'Success')
    @api.response('404', 'Tag not found')
    @token_required
    def get(self, uuid, current_user):
        ''' Gets details on a specific tag '''
        tag = Tag.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if tag:
            return tag
        else:
            ns_tag.abort(404, 'Tag not found.')
        return

    @api.doc(security="Bearer")
    @api.expect(mod_tag)
    @api.marshal_with(mod_tag)
    @token_required
    def put(self, uuid, current_user):
        ''' Updates a tag '''
        tag = Tag.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if tag:
            if 'name' in api.payload and Tag.query.filter_by(name=api.payload['name']).first():
                ns_tag.abort(409, 'Tag name already exists.')
            else:
                tag.update(api.payload)
                return tag
        else:
            ns_tag.abort(404, 'Tag not found.')
        return

    @api.doc(security="Bearer")
    @token_required
    def delete(self, uuid, current_user):
        ''' Deletes a tag '''
        tag = Tag.query.filter_by(uuid=uuid, organization_uuid=current_user().organization_uuid).first()
        if tag:
            tag.delete()
            return {'message': 'Sucessfully deleted tag.'}


@ns_settings.route("")
class Settings(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_settings)
    @token_required
    @user_has('view_settings')    
    def get(self, current_user):
        ''' Retrieves the global settings for the system '''
        settings = GlobalSettings.query.filter_by(organization_uuid=current_user().organization_uuid).first()
        return settings

    @api.doc(security="Bearer")
    @api.expect(mod_settings)
    @token_required    
    @user_has('update_settings')
    def put(self, current_user):

        if 'agent_pairing_token_valid_minutes' in api.payload:
            if int(api.payload['agent_pairing_token_valid_minutes']) > 365:
                ns_settings.abort(400, 'agent_pairing_token_valid_minutes can not be greated than 365 days.')

        settings = GlobalSettings.query.filter_by(organization_uuid=current_user().organization_uuid).first()
        settings.update(api.payload)

        return {'message': 'Succesfully updated settings'}


@ns_settings.route("/generate_persistent_pairing_token")
class PersistentPairingToken(Resource):

    @api.doc(security="Bearer")
    @api.marshal_with(mod_persistent_pairing_token)
    @token_required
    @user_has('create_persistent_pairing_token')
    def get(self, current_user):
        ''' Returns a new API key for the user making the request '''
        settings = GlobalSettings.query.filter_by(organization_uuid = current_user().organization_uuid).first()
        return settings.generate_persistent_pairing_token()


@ns_metrics.route("/case_trend")
class CaseTrend(Resource):

    @api.doc(security="Bearer")
    @token_required
    def get(self, current_user):
        cases = Case.query.filter_by(organization_uuid=current_user().organization_uuid).group_by(func.strftime('%Y-%m-%d', Case.created_at)).all()
        print(cases)
        return {}


