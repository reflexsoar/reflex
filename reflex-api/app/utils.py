import jwt
import base64
import datetime
import smtplib
import logging

from flask import request, current_app, abort
from .models import User, AuthTokenBlacklist, Agent

def send_email(settings, to=[], from_mail="", message=""):
    mail_server = settings.email_server.split(':')
         
    with smtplib.SMTP(mail_server[0], port=mail_server[1]) as server:
        server.sendmail(from_mail, to, message.as_string())

def generate_token(uuid, organization_uuid, duration=10, token_type='agent'):
    token_data = {
        'uuid': uuid,
        'organization': organization_uuid,
        'iat': datetime.datetime.utcnow(),
        'type': token_type
    }

    if duration:
        token_data['exp'] = datetime.datetime.utcnow() + datetime.timedelta(minutes=duration)
    _access_token = jwt.encode(token_data, current_app.config['SECRET_KEY']).decode('utf-8')
    
    return _access_token


def token_required(f):
    # Token Wrapper

    def wrapper(*args, **kwargs):
        current_user = _check_token
        return f(*args, **kwargs, current_user=current_user)

    wrapper.__doc__ = f.__doc__
    wrapper.__name__ = f.__name__
    return wrapper


def user_has(permission):
    # User permissions

    def decorator(f):
        def wrapper(*args, **kwargs):
            if(current_app.config['PERMISSIONS_DISABLED']):
                return f(*args, **kwargs)
            current_user = _check_token()

            # If this is a pairing token and its the add_agent permission
            # bypass the route guard and let the route finish
            if isinstance(current_user, dict) and current_user['type'] == 'pairing' and permission == 'add_agent':
                return f(*args, **kwargs)
            if not isinstance(current_user, list) and current_user.has_right(permission):
                return f(*args, **kwargs)
            else:
                abort(401, 'You do not have permission to perform this action.')

        wrapper.__doc__ = f.__doc__
        wrapper.__name__ = f.__name__
        return wrapper
    return decorator


def _get_current_user():
    ''' Just returns the current user via their JWT '''

    current_user = _check_token()
    return current_user


def check_password_reset_token(token):
    '''
    Checks the validity of a password reset token
    '''

    try:
        decoded_token = jwt.decode(token, current_app.config['SECRET_KEY'])

        blacklisted = AuthTokenBlacklist.query.filter_by(auth_token=token).first()
        if blacklisted:
            abort(401, 'Token retired.')

        if 'type' in decoded_token and decoded_token['type'] == 'password_reset':
            user = User.query.filter_by(uuid=decoded_token['uuid']).first()
            return user
        
    except ValueError:
        abort(401, 'Token retired.')
    except jwt.ExpiredSignatureError:
        abort(401, 'Access token expired.')
    except (jwt.DecodeError, jwt.InvalidTokenError):
        abort(401, 'Invalid access token.')
    except Exception as e:
        abort(401, str(e))


def _check_token():
    ''' Check the validity of the token provided '''

    auth_header = request.headers.get('Authorization')
    current_user = None
    if auth_header:
        try:
            access_token = auth_header.split(' ')[1]   
            try:
                token = jwt.decode(access_token, current_app.config['SECRET_KEY'])

                # If this is an agents token pull the agents information and
                # set it to current_user
                if 'type' in token and token['type'] == 'agent':
                    current_user = Agent.query.filter_by(uuid=token['uuid']).first()

                # Refresh and Password Reset tokens should not be used to access the API
                # only to refresh an access token or reset the password
                elif 'type' in token and token['type'] in ['refresh','password_reset']:
                    abort(401, 'Unauthorized')
                    
                # The pairing token can only be used on the add_agent endpoint
                # and because the token is signed we don't have to worry about 
                # someone adding a the pairing type to their token
                elif 'type' in token and token['type'] == 'pairing':
                    current_user = token
                else:
                    current_user = User.query.filter_by(uuid=token['uuid']).first()

                    # If the user is currently locked
                    # reject the accesss_token and expire it
                    if current_user.locked:
                        blacklist = AuthTokenBlacklist(auth_token = access_token)
                        blacklist.create()
                        
                        abort(401, 'Unauthorized')
                
                blacklisted = AuthTokenBlacklist.query.filter_by(auth_token=access_token).first()
                if blacklisted:
                    raise ValueError('Token retired.')

            except ValueError:
                abort(401, 'Token retired.')
            except jwt.ExpiredSignatureError:
                abort(401, 'Access token expired.')
            except (jwt.DecodeError, jwt.InvalidTokenError):
                abort(401, 'Invalid access token.')
            except:
                abort(401, 'Unknown token error.')

        except IndexError:
            raise jwt.InvalidTokenError
    else:
        abort(403, 'Access token required.')
    return current_user


def build_search_filters(args,model='Event'):
    '''
    Creates a sqlalchemy-filter spec that can be applied
    to a base query for the sake of filtering
    '''

    operators = {
        '!': 'ne',
        '>': 'gt',
        '>:': 'ge',
        '<': 'lt',
        '<:': 'le',
        '~': 'ilike',
        '-~': 'not_ilike'
    }

    url_operators = ['!','>','<','~','>:','<:','-~']

    filters = []

    for key in args:
        if key in ['signature','title','tlp','severity','source','reference']:
            if args[key]:
                data = args[key]
                op = list(filter(data.startswith, url_operators))
                if op != []:
                    operation = operators[op[0]]
                    data = data.replace(op[0],'')
                else:
                    operation = 'eq'

                filter_spec = {
                    'model': model,
                    'field': key,
                    'value': data,
                    'op': operation
                }

                # Fuzzy matching
                if operation in ['ilike','not_ilike']:
                    filter_spec['value'] = '%{}%'.format(data)
                
                filters.append(filter_spec)
    return filters