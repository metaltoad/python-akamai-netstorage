# System imports
from urllib import urlencode
from xml.etree.ElementTree import fromstring as xml_fromstring
from hashlib import md5
# I am running a terribly old version of python/lxml here :(
from xml.parsers.expat import ExpatError
from os.path import join as path_join
from os.path import getsize,getmtime
from datetime import datetime

# Third party imports
import requests

# Internal imports
from netstorage.auth import AkamaiAuth
from netstorage.exception import *
from netstorage.constants import AKAMAI_PROTOCOL_VERSION, AKAMAI_HOST_POSTFIX


class Methods(object):
    GET = 'GET'
    PUT = 'PUT'
    POST = 'POST'
    DELETE = 'DELETE'

    @staticmethod
    def get_methods():
        return [x for x in dir(Methods) if '_' not in x]

    @staticmethod
    def validate_method(method):
        return method in Methods.get_methods()


class Actions(object):
    DU = 'du'
    DIR = 'dir'
    MKDIR = 'mkdir'
    UPLOAD = 'upload'
    STAT = 'stat'
    # To implement...
    LIST = 'list'
    RMDIR = 'rmdir'
    DOWNLOAD = 'download'
    MTIME = 'mtime'
    SYMLINK = 'symlink'


class Binding(object):
    host = None
    key = None
    key_name = None
    cp_code = None

    def __init__(self, account, key, key_name, cp_code=None, path=None):
        self.host = '%s%s' % (account, AKAMAI_HOST_POSTFIX)
        self.key = key
        self.key_name = key_name
        self.cp_code = cp_code
        self.path = path

        # To ensure you will not delete a content by mistake
        # Call allow_delete method before requesting a delete action
        self.allow_delete = False

    def __get_url(self, cp_code, path):
        if path is not None:
            url = 'http://%s/%s/%s' % (self.host, cp_code, path)
        else:
            url = 'http://%s/%s' % (self.host, cp_code)

        # Ensures that there is no trailing slash
        return url if url[-1:] != '/' else url[:-1]

    def __get_relative_url(self, cp_code, path):
        relative = '/%s/%s' % (cp_code, path)

        # Ensures that there is no trailing slash
        return relative if relative[-1:] != '/' else relative[:-1]

    def __get_headers(self, action):
        return {
            'Host': self.host,
            'X-Akamai-ACS-Action': action
        }

    # Transform the element into a well know dict format
    # It will look for these attributes:
    # 'type', 'name', 'mtime' and, if present, also include the
    # 'size', 'target' attributes
    def __dir_action_entry(self, element, path=None):
        attribs = dict(**element.attrib)
        entry = {
            'type': attribs['type'],
            'name': attribs['name'],
            'path': path_join(path, attribs['name']) if path else attribs['name']
        }

        # Optional keys
        for k in ('size', 'target', 'mtime', 'md5'):
            try:
                entry[k] = attribs[k]
            except KeyError:
                pass

        # Integer keys
        for k in ('size', 'mtime', 'files'):
            try:
                entry[k] = int(entry[k])
            except (KeyError, ValueError, ):
                pass

        # Datetime keys
        for k in ('mtime', ):
            try:
                entry[k] = datetime.fromtimestamp(entry[k])
            except (KeyError, ValueError, ):
                pass

        return entry

    def __check_params(self, params=None):
        params = params or {}
        params['version'] = params.get('version', AKAMAI_PROTOCOL_VERSION) # Ensures version param exists just in case
        params['format'] = params.get('format', 'xml') # Ensures format param exists

        if 'action' not in params:
            raise AkamaiInvalidActionException()

    # Thank you http://stackoverflow.com/questions/3431825/generating-a-md5-checksum-of-a-file
    def __hashfile(self, afile, hasher, blocksize=65536):
        buf = afile.read(blocksize)
        while len(buf) > 0:
            hasher.update(buf)
            buf = afile.read(blocksize)
        return hasher.digest()

    def send(self, cp_code, path, params, method=Methods.GET, body=None):
        self.__check_params(params)
        path = path or self.path
        cp_code = cp_code or self.cp_code
        url = self.__get_url(cp_code, path)
        relative = self.__get_relative_url(cp_code, path)
        action = urlencode(params)

        try:
            cp_code = int(cp_code)
            assert cp_code >= 0
        except (TypeError, AssertionError):
            raise AkamaiInvalidCpCodeException()

        if not Methods.validate_method(method):
            raise AkamaiInvalidMethodException()

        if method == Methods.DELETE and not self.allow_delete:
            raise AkamaiDeleteNotAllowedException()

        r = requests.request(method, url, headers=self.__get_headers(action),
                             auth=AkamaiAuth(self.key, self.key_name, relative, action), data=body)

        return r.text, r.status_code

    def upload(self, cp_code=None, local_path='', ns_path=''):
        params = {}
        params['action'] = Actions.UPLOAD

        params['size'] = getsize(local_path)
        params['mtime'] = getmtime(local_path)
        method=Methods.POST
        # Open a stream to the file in binary mode
        try:
            params['md5'] = self.__hashfile(open(local_path, 'rb'), md5())
            contents = open(local_path, 'rb')
        except Exception:
            return

        response, status = self.send(cp_code, ns_path, params, method, body=contents)
        if status == 200:
            return response
        elif status == 403:
            raise AkamaiForbiddenException((cp_code or self.cp_code, ns_path, response, status, ))
        elif status == 404:
            raise AkamaiFileNotFoundException((cp_code or self.cp_code, ns_path, response, status, ))
        elif status == 503:
            raise AkamaiServiceUnavailableException((cp_code or self.cp_code, ns_path, response, status, ))
        return response, status


    def mkdir(self, cp_code=None, path=''):
        params = {}
        params['action'] = Actions.MKDIR
        method=Methods.POST
        response, status = self.send(cp_code, path, params, method)
        if status == 200:
            return True
        elif status == 403:
            raise AkamaiForbiddenException((cp_code or self.cp_code, path, response, status, ))
        elif status == 404:
            raise AkamaiFileNotFoundException((cp_code or self.cp_code, path, response, status, ))
        elif status == 503:
            raise AkamaiServiceUnavailableException((cp_code or self.cp_code, path, response, status, ))
        return response, status


    def stat(self, cp_code=None, path=''):
        params = {}
        params['action'] = Actions.STAT
        response, status = self.send(cp_code, path, params)
        if status == 200:
            try:
                stats = xml_fromstring(response)
                element = stats.find('file')
                return self.__dir_action_entry(element, path)
            except ExpatError, parse_error:
                raise AkamaiResponseMalformedException(str(parse_error))
        elif status == 403:
            raise AkamaiForbiddenException((cp_code or self.cp_code, path, response, status, ))
        elif status == 404:
            raise AkamaiFileNotFoundException((cp_code or self.cp_code, path, response, status, ))
        elif status == 503:
            raise AkamaiServiceUnavailableException((cp_code or self.cp_code, path, response, status, ))
        return response, status


    def allow_deleting(self):
        self.allow_delete = True

    #####
    #
    # Helpers
    #
    #####

    def du(self, cp_code=None, path=None, params=None):
        params = params or {}
        params['action'] = Actions.DU

        # Making the request
        response, status = self.send(cp_code, path, params)

        if status == 200:
            try:
                tree = xml_fromstring(response)
                info = tree.find('du-info').attrib
                return {'files': int(info['files']), 'bytes': int(info['bytes'])}
            except ExpatError, parse_error:
                raise AkamaiResponseMalformedException(str(parse_error))
        elif status == 403:
            raise AkamaiForbiddenException((cp_code or self.cp_code, path, response, status, ))
        elif status == 404:
            raise AkamaiFileNotFoundException((cp_code or self.cp_code, path, response, status, ))
        elif status == 503:
            raise AkamaiServiceUnavailableException((cp_code or self.cp_code, path, response, status, ))
        else:
            return response

    def dir(self, cp_code=None, path=None, params=None):
        params = params or {}
        params['action'] = Actions.DIR

        # Making the request
        response, status = self.send(cp_code, path, params)


        if status == 200:
            try:
                tree = xml_fromstring(response)
                return [self.__dir_action_entry(element, path) for element in tree.findall('file')]
            except ExpatError, parse_error:
                raise AkamaiResponseMalformedException(str(parse_error))
        elif status == 403:
            raise AkamaiForbiddenException((cp_code or self.cp_code, path, response, status, ))
        elif status == 404:
            raise AkamaiFileNotFoundException((cp_code or self.cp_code, path, response, status, ))
        elif status == 503:
            raise AkamaiServiceUnavailableException((cp_code or self.cp_code, path, response, status, ))
        else:
            return response



