"""Requires AUTHY API KEY"""
import time
from botocore.vendored import requests

class Authy:
    """Authy management class"""
    def __init__(self, **kwargs):
        """Initiates the Authy parameters"""
        authy_api_key = kwargs["AUTHY_API_KEY"]
        self.headers = {
            'X-Authy-API-Key': authy_api_key,
            'Cache-Control': "no-cache",
            'Content-Type': "application/x-www-form-urlencoded"
            }

    def create_user(self, email, number, country_code="+55", use_push=False):
        """Creates an Authy user"""
        url = "https://api.authy.com/protected/json/users/new"

        payload = (
            "user%5Bemail%5D={}"
            "&user%5Bcellphone%5D={}"
            "&user%5Bcountry_code%5D={}"
            "&send_install_link_via_sms={}").format(
                email, number, country_code, use_push
            )

        response = requests.request("POST", url, data=payload, headers=self.headers)

        return response.json()

    def get_qr_code(self, email, user_id):
        """Generate a QR Code with the OTP code for the User"""
        url = "https://api.authy.com/protected/json/users/{}/secret".format(user_id)
        payload = "label=Observer ({})".format(email)

        response = requests.request("POST", url, data=payload, headers=self.headers)

        return response.json()

    def push_request(self, user_id):
        """Initiates an Authy OneTouch request for this user"""
        url = "https://api.authy.com/onetouch/json/users/{}/approval_requests".format(user_id)
        payload = "message=Credentials requested for a Observer account&seconds_to_expire=30"

        response = requests.request("POST", url, data=payload, headers=self.headers)

        return response.json()

    def verify_push_request(self, uuid):
        """Verify token validation (using OneTouch)"""
        url = "https://api.authy.com/onetouch/json/approval_requests/{}".format(uuid)

        while True:
            response = requests.request("GET", url, headers=self.headers)
            status = response.json()["approval_request"]["status"]
            if status != "pending":
                return response.json()

            time.sleep(1)

        return None

    def verify_token_request(self, token, user_id):
        """Verify token validation (not using OneTouch)"""
        url = "https://api.authy.com/protected/json/verify/{}/{}".format(token, user_id)

        response = requests.request("GET", url, headers=self.headers)

        return response.json()
