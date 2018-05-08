# System Imports
from abc import ABC, abstractmethod
from json import dumps, loads
from typing import Dict, NoReturn, Tuple, TypeVar, Union

# Third-Party Imports
from falcon import HTTPBadRequest, Request, Response
from falcon.status_codes import HTTP_400, HTTP_401, HTTP_403, HTTP_404
from jose import jwt
from six.moves.urllib.request import urlopen

# Local Source Imports
from .__http_factory import http_error_factory
from .logger import logger

__author__ = 'H.D. "Chip" McCullough IV'
# See https://auth0.com/docs/quickstart/backend/python/01-authorization

__version__ = '1.0.7'
VERSION = __version__

__name__ = 'Auth0Middleware'

AM = TypeVar('AM', bound='AbstractBaseMiddleware')
A0M = TypeVar('A0M', bound='Auth0Middleware')

class AbstractBaseMiddleware(ABC):

    def __init__(self, middleware_config: dict = None, claims_config: dict = None, *args, **kwargs):
        self.__config = middleware_config
        self.__claims = claims_config

    @property
    def config(self) -> dict:
        return self.__config

    @property
    def claims(self) -> dict:
        return self.__claims

    @abstractmethod
    def process_request(self, req: Request, resp: Response) -> NoReturn:
        """ Processes the incoming request before routing it.

        :param req: Request object that will be routed to an appropriate on_* responder method.
        :param resp: Response object that will be routed to the on_* responder.
        """
        raise NotImplementedError

    @abstractmethod
    def process_resource(self, req: Request, resp: Response, resource, params) -> NoReturn:
        """ Processes the request after being routed to an on_* responder.

        :Note:
            This method is only called when the request matches a route to a resource.

        :param req: Request object that will be passed to the routed responder.
        :param resp: Response object that will be passed to the responder.
        :param resource: Resource object to which the request was routed.
        :param params: A dict-like object representing any additional params derived from the route's URI template
            fields, that will be passed to the resource's responder method as keyword arguments.
        """
        raise NotImplementedError

    @abstractmethod
    def process_response(self, req: Request, resp: Response, resource, req_succeeded: bool) -> NoReturn:
        """ Post-Processing of the response, after routing.

        :param req: Request object.
        :param resp: Response object.
        :param resource: Resource object to which the request was routed. May be None if no route was found for the
            request.
        :param req_succeeded: True if no exceptions were raised while the framework processed and routed the request,
            otherwise False.
        """
        raise NotImplementedError

class Auth0Middleware(AbstractBaseMiddleware):

    def __init__(self, auth_config: Dict[str, Union[str, Dict[str, str]]], claims_config: dict = None,
                 jwt_options: Dict[str, Union[bool, int]] = None, digest_access_token: bool = True,
                 environment: str = None):
        """ Falcon Middleware for Auth0 Authorization using Bearer Tokens.

        :param auth_config: Dictionary containing configuration variables for Auth0.

            Example:
            {
                'alg': ['RS256'],
                'access_token': 'access_token', # This is optional. This variable points to the key in the Request body
                                                  that holds the access_token. If it's not provided, it defaults to
                                                  'access_token'.
                'audience': <Auth0 Client ID>,
                'domain': 'my.app.name.auth0.com', # or 'https://my.app.name.auth0.com/'
                'jwks_uri': 'https://my.app.name.auth0.com/.well-known/jwks.json'
            }
        :type auth_config: Dict[str, Union[str, Dict[str, str]]]
        :param claims_config: TODO: I'll write this once I actually get valid claims back.
        :type claims_config: Dict[]
        :param jwt_options: A configurable list of options that dictates what validation is performed (or not performed)
            when decoding the JWT. The options Dictionary takes the form of:
            {
                'verify_signature': True,
                'verify_aud': True,
                'verify_iat': True,
                'verify_exp': True,
                'verify_nbf': True,
                'verify_iss': True,
                'verify_sub': True,
                'verify_jti': True,
                'verify_at_hash': True,
                'leeway': 0
            }
        :type jwt_options: Dict[str, Union[bool, int]]
        :param digest_access_token: The Auth0 Middleware will automatically "digest", the access_token contained in the
            body of the incoming Request.
        :type digest_access_token: bool
        :param environment: Environment specification for the configuration if you have different configurations for
            different environments. If an environment is not provided, it will assume the config is in the format
            listed above.

            Example:
            {
                'dev': {
                    'alg': ['RS256'],
                    'audience': <Auth0 Client ID>,
                    'domain': 'my.dev.environment.auth0.com', # or 'https://my.dev.environment.auth0.com/'
                    'jwks_uri': 'https://my.dev.environment.auth0.com/.well-known/jwks.json'
                },
                'test': {
                    'alg': ['RS256'],
                    'audience': <Auth0 Client ID>,
                    'domain': 'my.test.environment.auth0.com', # or 'https://my.test.environment.auth0.com/'
                    'jwks_uri': 'https://my.test.environment.auth0.com/.well-known/jwks.json'
                },
                'uat': {
                    'alg': ['RS256'],
                    'audience': <Auth0 Client ID>,
                    'domain': 'my.uat.environment.auth0.com', # or 'https://my.uat.environment.auth0.com/'
                    'jwks_uri': 'https://my.uat.environment.auth0.com/.well-known/jwks.json'
                },
                'prod': {
                    'alg': ['RS256'],
                    'audience': <Auth0 Client ID>,
                    'domain': 'my.prod.environment.auth0.com', # or 'https://my.prod.environment.auth0.com/'
                    'jwks_uri': 'https://my.prod.environment.auth0.com/.well-known/jwks.json'
                }
            }
        :type environment: str
        """
        super().__init__(middleware_config=auth_config, claims_config=claims_config)
        self.__jwt_options = jwt_options
        self.__digest = digest_access_token
        self.__environment: str = environment
        self.__jwks = self.__create_jwks()

    @staticmethod
    def __get_token_auth_header(req: Request) -> Tuple[Union[str, None], Union[str, None]]:
        """ Returns the value of Authorization Header in the HTTP Request.

        :param req: Request object that will be routed to an appropriate on_* responder method.
        :type req: Request

        :raises: HTTPError := HTTPUnauthorized
        """
        try:
            _auth_token: str = req.get_header('Authorization')
            (_bearer, _token) = _auth_token.split()
            return _bearer, _token
        except HTTPBadRequest:
            raise http_error_factory(
                status=HTTP_401,
                title='No \'Authorization\' Header',
                description='No \'Authorization\' header was present in the request.',
                href=None,
                href_text=None,
                code=None
            )
        except ValueError:
            raise http_error_factory(
                status=HTTP_401,
                title='Improper \'Authorization\' Header Formatting',
                description='The \'Authorization\' header was improperly formatted.',
                href=None,
                href_text=None,
                code=None
            )
        except AttributeError:
            logger.info('No Authorization provided.')
            return None, None

    def __get_access_token(self, req: Request) -> str:
        """ Pulls the User's access_token from the body of the incoming Request. If the :code`digest_access_token`
            parameter was not entered in the constructor, it will automatically remove the access_token from the
            Request body.

        :param req: Request object that will be routed to an appropriate on_* responder method.
        :return: The access_token
        """
        _environment_config = self.config.get(self.__environment, self.config)
        _access_token = req.get_header('X-Auth-Token', None)
        if _access_token is None:
            if req.method in ['HEAD', 'GET']:
                _access_token = (req.params.pop(_environment_config.get('access_token', 'access_token')) if self.__digest
                                    else req.params.get(_environment_config.get('access_token', 'access_token')))
            else:
                _access_token = (req.context.pop(_environment_config.get('access_token', 'access_token')) if self.__digest
                                    else req.context.get(_environment_config.get('access_token', 'access_token')))
        return _access_token

    def __create_jwks(self) -> Union[dict, None]:
        """ Creates the JSON Web Key Set from the Auth0 .well_known/jwks.json end point.

        :return: JWKS Dictionary or None if the endpoint could not be reached.
        :rtype: Union[dict, None]
        """
        _jwks_uri = self.config.get(self.__environment, self.config).get('jwks_uri', None)
        _jwks_raw = urlopen(_jwks_uri).read()
        return loads(_jwks_raw) if _jwks_raw is not None else None

    def __process_claims(self, claims: dict) -> dict:
        """ Process claims returned by parsing the JWT Authorization based on the claims config.

        :param claims:
        :return:
        """
        if self.__claims:
            print(type(self.__claims))
        print(claims)
        return claims

    def process_request(self, req: Request, resp: Response) -> NoReturn:
        """ Processes the incoming request before routing it by parsing the Authorization header, and attaching the
            claims from the JWT to the req context under the key 'auth'.

        :param req: Request object that will be routed to an appropriate on_* responder method.
        :param resp: Response object that will be routed to the on_* responder.
        """
        if self.__jwks is None:
            self.__jwks = self.__create_jwks()

        _bearer, _token = self.__get_token_auth_header(req)

        if _bearer is None:
            req.context.update({'auth': _bearer})
        elif _bearer.lower() == 'bearer':
            _unverified_header = jwt.get_unverified_header(_token)
            _rsa_key = {}

            for key in self.__jwks.get('keys', []):
                if key.get('kid') == _unverified_header.get('kid'):
                    _rsa_key = {
                        'kty': key['kty'],
                        'kid': key['kid'],
                        'use': key['use'],
                        'n': key['n'],
                        'e': key['e']
                    }
                if _rsa_key:
                    try:
                        _claims = jwt.decode(
                            token=_token,
                            key=dumps(_rsa_key),
                            algorithms=self.config.get(self.__environment, self.config).get('alg', ['RS256']),
                            options=self.__jwt_options,
                            audience=self.config.get(self.__environment, self.config).get('audience', None),
                            issuer=self.config.get(self.__environment, self.config).get('domain', None),
                            # subject=None,
                            access_token=self.__get_access_token(req)
                        )
                        req.context.update({ 'auth': self.__process_claims(_claims) })
                    except jwt.ExpiredSignatureError as e:
                        print(type(e))
                        print(e)
                        raise http_error_factory(
                            status=HTTP_401,
                            title='Expired Token',
                            description='The provided token has expired.',
                            href=None,
                            href_text=None,
                            code=None
                        )
                    except jwt.JWTClaimsError as e:
                        print(type(e))
                        print(e)
                        raise http_error_factory(
                            status=HTTP_401,
                            title='Invalid Claims',
                            description='The claims are incorrect. Please check the Audience and the Issuer.',
                            href=None,
                            href_text=None,
                            code=None
                        )
                    except Exception as e:
                        print(type(e))
                        print(e)
                        raise http_error_factory()
        else:
            raise http_error_factory(
                status=HTTP_401,
                title='Invalid \'Authorization\' Header',
                description='The \'Authorization\' header started with {bearer}.'.format(bearer=_bearer),
                href=None,
                href_text=None,
                code=None
            )

    def process_resource(self, req: Request, resp: Response, resource, params) -> NoReturn:
        """ Processes the request after being routed to an on_* responder.

        :Note:
            This method is only called when the request matches a route to a resource.

        :param req: Request object that will be passed to the routed responder.
        :param resp: Response object that will be passed to the responder.
        :param resource: Resource object to which the request was routed.
        :param params: A dict-like object representing any additional params derived from the route's URI template
            fields, that will be passed to the resource's responder method as keyword arguments.
        """
        pass

    def process_response(self, req: Request, resp: Response, resource, req_succeeded: bool) -> NoReturn:
        """ Post-Processing of the response, after routing.

        :param req: Request object.
        :param resp: Response object.
        :param resource: Resource object to which the request was routed. May be None if no route was found for the
            request.
        :param req_succeeded: True if no exceptions were raised while the framework processed and routed the request,
            otherwise False.
        """
        pass