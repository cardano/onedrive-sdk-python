'''
------------------------------------------------------------------------------
 Copyright (c) 2015 Microsoft Corporation

 Permission is hereby granted, free of charge, to any person obtaining a copy
 of this software and associated documentation files (the "Software"), to deal
 in the Software without restriction, including without limitation the rights
 to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 copies of the Software, and to permit persons to whom the Software is
 furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included in
 all copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 THE SOFTWARE.
------------------------------------------------------------------------------
'''
from __future__ import unicode_literals
import json
from .auth_provider_base import AuthProviderBase
from .options import *
from .session import Session
import sys
import time

try:
    from urllib.parse import urlencode
except ImportError:
    from urllib import urlencode


class AuthProvider(AuthProviderBase):

    def __init__(self, http_provider, client_id=None, tenant_id=None, access_token=None, session_type=None, loop=None):
        """Initialize the authentication provider for authenticating
        requests sent to OneDrive

        Args:
            http_provider (:class:`HttpProviderBase<onedrivesdk.http_provider_base>`):
                The HTTP provider to use for all auth requests
            client_id (str): Defaults to None, the client id for your
                application
            access_token (str): Defaults to None
            session_type (:class:`SessionBase<onedrivesdk.session_base.SessionBase>`):
                Defaults to :class:`Session<onedrivesdk.session.Session>`,
                the implementation of SessionBase that stores your
                session. WARNING: THE DEFAULT IMPLEMENTATION ONLY
                STORES SESSIONS TO THE RUN DIRECTORY IN PLAIN TEXT.
                THIS IS UNSAFE. IT IS HIGHLY RECOMMENDED THAT YOU
                IMPLEMENT YOUR OWN VERSION.
            loop (BaseEventLoop): Defaults to None, the asyncio
                loop to use for all async requests. If none is provided,
                asyncio.get_event_loop() will be called. If using Python
                3.3 or below this does not need to be specified
            tenant_id (str): The tenant ID of the directory where your App Registration exists
        """
        self._http_provider = http_provider
        self._client_id = client_id
        self._tenant_id = tenant_id
        self._session_type = Session if session_type is None else session_type
        self._session = None
        self._auth_token_url = "https://login.microsoftonline.com/" + self._tenant_id + "/oauth2/token"

        if sys.version_info >= (3, 4, 0):
            import asyncio
            self._loop = loop if loop else asyncio.get_event_loop()

    @property
    def client_id(self):
        """Gets and sets the client_id for the
        AuthProvider

        Returns:
            str: The client id
        """
        return self._client_id

    @client_id.setter
    def client_id(self, value):
        self._client_id = value

    @property
    def tenant_id(self):
        """Gets and sets the tenant ID

        Returns:
            str: the tenant ID
        """
        return self._tenant_id

    @tenant_id.setter
    def tenant_id(self, value):
        self._tenant_id = value

    @property
    def access_token(self):
        """Gets and sets the access_token for the
            :class:`AuthProvider`

        Returns:
            str: The access token. Looks at the session to figure out what the access token is, since this
                class does not directly store the access token.
        """
        if self._session is not None:
            return self._session.access_token
        return None

    @property
    def auth_token_url(self):
        """Gets and sets the authorization token url for the
        AuthProvider

        Returns:
            str: The auth token url
        """
        return self._auth_token_url

    @auth_token_url.setter
    def auth_token_url(self, value):
        self._auth_token_url = value

    def get_auth_url(self, resource):
        """Build the auth url using the params provided
        and the auth_provider

        Args:
            response_type (str): Response type query param value.
                If not provided, defaults to 'code'. Should be either
                'code' or 'token'.
        """

        params = {
            "client_id": self.client_id,
            "resource": resource
            }

        return "{}?{}".format(self._auth_token_url, urlencode(params))

    def authenticate(self, resource):
        """Gets the access token and creates a session.
        """
        params = {
            "client_id": self.client_id,
            "resource": resource
        }

        auth_url = self._auth_token_url
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        response = self._http_provider.send(method="POST",
                                            headers=headers,
                                            url=auth_url,
                                            data=params)

        rcont = json.loads(response.content)
        device_code = rcont["device_code"]
        expires_in = rcont["expires_in"]
        interval = rcont["interval"]
        message = rcont["message"].str()

        print(message)

        params = {
            "resource": resource,
            "client_id": self.client_id,
            "grant_type": "device_code",
            "code": device_code
        }

        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        rcont = None

        t_end = time.time() + int(expires_in)
        while time.time() < t_end:
            try:
                response = self._http_provider.send(method="POST",
                                                    headers=headers,
                                                    url=auth_url,
                                                    data=params)
                rcont = json.loads(response.content)
            except:
                time.sleep(interval)

        if time.time() >= t_end:
            raise RuntimeError("""Timed out waiting for user to verify""")
        else:
            self._session = self._session_type(rcont["token_type"],
                                    rcont["expires_in"],
                                    rcont["access_token"],
                                    self.client_id,
                                    self._auth_token_url,
                                    rcont["refresh_token"] if "refresh_token" in rcont else None)

    def authenticate_request(self, request):
        """Append the required authentication headers
        to the specified request. This will only function
        if a session has been successfully created using
        :func:`authenticate`. This will also refresh the
        authentication token if necessary.

        Args:
            request (:class:`RequestBase<onedrivesdk.request_base.RequestBase>`):
                The request to authenticate
        """
        if self._session is None:
            raise RuntimeError("""Session must be authenticated 
                before applying authentication to a request.""")

        if self._session.is_expired():
            self.refresh_token()

        request.append_option(
            HeaderOption("Authorization",
                         "bearer {}".format(self._session.access_token)))

    def refresh_token(self):
        """Refresh the token currently used by the session"""
        if self._session is None:
            raise RuntimeError("""Session must be authenticated 
                before refreshing token.""")

        if self._session.refresh_token is None:
            raise RuntimeError("""Refresh token not present.""")

        params = {
            "refresh_token": self._session.refresh_token,
            "client_id": self._session.client_id,
            "grant_type": "refresh_token"
        }

        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        response = self._http_provider.send(method="POST",
                                            headers=headers,
                                            url=self._session.auth_token_url,
                                            data=params)
        rcont = json.loads(response.content)
        self._session.refresh_session(rcont["expires_in"],
                                      rcont["access_token"],
                                      rcont["refresh_token"])

    def redeem_refresh_token(self, resource):
        """Redeem a refresh token against a new resource. Used
        only by OneDrive for Business apps.

        Args:
            resource (str): URL to resource to be accessed.
                Can be a 'serviceResourceId' value obtained from
                Discovery Service."""
        if self._session is None:
            raise RuntimeError("""Session must be authenticated
                before refreshing token.""")

        if self._session.refresh_token is None:
            raise RuntimeError("""Refresh token not present.""")

        params = {
            "client_id": self._session.client_id,
            "refresh_token": self._session.refresh_token,
            "grant_type": "refresh_token",
            "resource": resource
        }

        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        response = self._http_provider.send(method="POST",
                                            headers=headers,
                                            url=self.auth_token_url,
                                            data=params)
        rcont = json.loads(response.content)
        self._session.refresh_session(rcont["expires_in"],
                                      "",
                                      rcont["access_token"],
                                      rcont["refresh_token"])

    def save_session(self, **save_session_kwargs):
        """Save the current session. Must have already
        obtained an access_token.
        
        Args:
            save_session_kwargs (dict): Arguments to 
                be passed to save_session.
        """
        if self._session is None:
            raise RuntimeError("""Session must be authenticated before
            it can be saved. """)
        self._session.save_session(**save_session_kwargs)

    def load_session(self, **load_session_kwargs):
        """Load session. This will overwrite the current session.

        Args:
            load_session_kwargs (dict): Arguments to
                be passed to load_session.
        """
        self._session = self._session_type.load_session(**load_session_kwargs)
