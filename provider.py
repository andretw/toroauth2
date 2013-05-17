from models import Application
from pyoauth2.provider import AuthorizationProvider
import tornadoredis
import json
import logging
import redis
import tornado.gen as gen
from mongotor.database import Database

db = Database.connect(['localhost:27017'], 'auth')

r = tornadoredis.Client()
r.connect()

class Toroauth2AuthorizationProvider(AuthorizationProvider):

    @gen.engine
    def validate_client_id(self, client_id, callback=None):
        """Check that the client_id represents a valid application.

        :param client_id: Client id.
        :type client_id: str
        """
        result, error = yield gen.Task(db.application.find_one, {"app_key": client_id})
        
        if callback:
            raise Exception if result is None 
            callback(result)

    @gen.engine
    def validate_client_secret(self, client_id, client_secret, callback=None):
        """Check that the client secret matches the application secret.

        :param client_id: Client Id.
        :type client_id: str
        :param client_secret: Client secret.
        :type client_secret: str
        """

        result, error = yield gen.Task(db.application.find_one, {"app_key": client_id})

        if callback:
            raise Exception if result["app_secret"] is not client_secret
            callback(result)

    @gen.engine
    def validate_redirect_uri(self, client_id, redirect_uri, callback=None):
        """Validate that the redirect_uri requested is available for the app.

        :param redirect_uri: Redirect URI.
        :type redirect_uri: str
        """

        app = Application.objects.get(app_key=client_id)

        # When matching against a redirect_uri, it is very important to 
        # ignore the query parameters, or else this step will fail as the 
        # parameters change with every request
        logging.info(app) 
        if app is not None and app.redirect_uri == redirect_uri.split('?')[0]:
            return True
        return False

    def validate_access(self):
        """Validate that an OAuth token can be generated from the
        current session."""
#        return session.user is not None
        return True

    def validate_scope(self, client_id, scope):
        """Validate that the scope requested is available for the app.

        :param client_id: Client id.
        :type client_id: str
        :param scope: Requested scope.
        :type scope: str
        """
        app = Application.objects.get(app_key=client_id)

        if scope == app.scope:
            return True
        else:
            return False 

    @gen.engine
    def persist_authorization_code(self, client_id, code, scope, callback=None):
        """Store important session information (user_id) along with the
        authorization code to later allow an access token to be created.

        :param client_id: Client Id.
        :type client_id: str
        :param code: Authorization code.
        :type code: str
        :param scope: Scope.
        :type scope: str
        """
        key = 'oauth2.authorization_code.%s:%s' % (client_id, code)

        # Store any information about the current session that is needed
        # to later authenticate the user.
        
        data = {'client_id': client_id,
                'scope': scope,
#                'user_id': session.user.id}
                }
        
        result = yield gen.Task(
            # Authorization codes expire in 1 minute
            r.setex, key, 60, json.dumps(data))
        
        if callback:
            callback(result)

    @gen.engine
    def persist_token_information(self, client_id, access_token,
                                  token_type, expires_in, refresh_token,
                                  data, callback=None):
        """Save OAuth access and refresh token information.

        :param client_id: Client Id.
        :type client_id: str
        :param access_token: Access token.
        :type access_token: str
        :param token_type: Token type (currently only Bearer)
        :type token_type: str
        :param expires_in: Access token expiration seconds.
        :type expires_in: int
        :param refresh_token: Refresh token.
        :type refresh_token: str
        :param data: Data from authorization code grant.
        :type data: mixed
        """

        # Set access token with proper expiration
        access_key = 'oauth2.access_token:%s' % access_token
        
        result = yield gen.Task(r.setex, access_key, expires_in, json.dumps(data))

        # Set refresh token with no expiration
        refresh_key = 'oauth2.refresh_token.%s:%s' % (client_id, refresh_token)
        result = yield gen.Task(r.set, refresh_key, json.dumps(data))

        # Associate tokens to user for easy token revocation per app user
        key = 'oauth2.client_user.%s:%s' % (client_id, data.get('user_id'))
        result = yield gen.Task(r.sadd, key, access_key, refresh_key)

        if callback:
            callback(result)

    @gen.engine
    def from_authorization_code(self, client_id, code, callback=None):
        """Get session data from authorization code.

        :param client_id: Client ID.
        :type client_id: str
        :param code: Authorization code.
        :type code: str
        :rtype: dict if valid else None
        """
        key = 'oauth2.authorization_code.%s:%s' % (client_id, code)
        data = yield gen.Task(r.get, key)
        
        if callback:
            callback(json.loads(data))

    def from_refresh_token(self, client_id, refresh_token, scope):
        """Get session data from refresh token.

        :param client_id: Client Id.
        :type client_id: str
        :param refresh_token: Refresh token.
        :type refresh_token: str
        :param scope: Scope to validate.
        :type scope: str
        :rtype: dict if valid else None
        """
        key = 'oauth2.refresh_token.%s:%s' % (client_id, refresh_token)
        data = self.r.get(key)
        if data is not None:
            data = json.loads(data)

            # Validate scope and client_id
            if (scope == '' or scope == data.get('scope')) and \
                data.get('client_id') == client_id:
                return data

        return None  # The OAuth token refresh will fail at this point

    @gen.engine
    def discard_authorization_code(self, client_id, code, callback=None):
        """Delete authorization code from the store.

        :param client_id: Client Id.
        :type client_id: str
        :param code: Authorization code.
        :type code: str
        """
        key = 'oauth2.authorization_code.%s:%s' % (client_id, code)
        
        result = yield gen.Task(r.delete, key)
        
        if callback:
            callback(result)

    def discard_refresh_token(self, client_id, refresh_token):
        """Delete refresh token from the store.

        :param client_id: Client Id.
        :type client_id: str
        :param refresh_token: Refresh token.
        :type refresh_token: str

        """
        key = 'oauth2.refresh_token.%s:%s' % (client_id, refresh_token)
        self.r.delete(key)

    def discard_client_user_tokens(self, client_id, user_id):
        """Delete access and refresh tokens from the store.

        :param client_id: Client Id.
        :type client_id: str
        :param user_id: User Id.
        :type user_id: str

        """
        keys = 'oauth2.client_user.%s:%s' % (client_id, user_id)
        pipe = self.r.pipeline()
        for key in self.r.smembers(keys):
            pipe.delete(key)
        pipe.execute()
