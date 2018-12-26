import duo_client

class Duo:
    """Duo management class"""
    def __init__(self, **kwargs):
        """Initiates the Authy parameters"""
        self.auth_api = duo_client.Auth(
            ikey=kwargs['ikey'],
            skey=kwargs['skey'],
            host=kwargs['host']
        )

    def create_user(self, email, country_code='+55', number=None, use_push=False):
        """Creates a Duo user and return a user_id"""
        username = email.split('@')[0]
        try:
            enroll_res = self.auth_api.enroll(username=username)
        except RuntimeError as e:
            if str(e) == 'Received 400 Invalid request parameters (username already exists)':
                return {'user_id': username}

        return {'user_id': enroll_res['username']}

    def push_request(self, user_id):
        """Initiates an Authy OneTouch request for this user"""
        auth_result = self.auth_api.auth(
            factor='push',
            username=user_id,
            device='auto'
        )
        
        return auth_result.get('result') == 'allow'

    def verify_token_request(self, user_id, token):
        """Verify token validation (not using OneTouch)"""
        auth_result = self.auth_api.auth(
            factor='passcode',
            username=user_id,
            passcode=token
        )

        return auth_result.get('result') == 'allow'
