#!/usr/bin/env python
import logging
import re
import sys
import traceback

from saml2.config import config_factory
from saml2.httputil import Response, Unauthorized
from saml2.httputil import NotFound
from saml2.httputil import ServiceError
from back import SamlSP
from front import SamlIDP

LOGGER = logging.getLogger("")
LOGFILE_NAME = 's2s.log'
hdlr = logging.FileHandler(LOGFILE_NAME)
base_formatter = logging.Formatter(
    "%(asctime)s %(name)s:%(levelname)s %(message)s")

hdlr.setFormatter(base_formatter)
LOGGER.addHandler(hdlr)
LOGGER.setLevel(logging.DEBUG)

IDP = None
SP = None
Config = None

# ==============================================================================


def incomming(info, instance, environ, start_response, relay_state):
    """
    An Authentication request has been requested, this is the second step
    in the sequence

    :param info: Information about the authentication request
    :param instance: IDP instance that received the Authentication request
    :param environ: WSGI environment
    :param start_response: WSGI start_response
    :param relay_state:

    :return: response
    """

    # If I know which IdP to authenticate at return a redirect to it
    if EntityID:
        inst = SamlSP(environ, start_response, CONFIG["SP"], CACHE, outgoing)
        state_key = inst.store_state(info["authn_req"], relay_state,
                                     info["req_args"])
        return inst.authn_request(EntityID, state_key)
    else:
        # start the process by finding out which IdP to authenticate at
        return instance.disco_query(info["authn_request"], relay_state,
                                    info["req_args"])


def outgoing(response, instance):
    """
    An authentication response has been received and now an authentication
    response from this server should be constructed.

    :param response: The Authentication response
    :param instance: SP instance that received the authentication response
    :return: response
    """

    _idp = SamlIDP(instance.environ, instance.start_response,
                   CONFIG["SP"], CACHE, outgoing)

    _state = instance.sp.state[response.in_response_to]
    orig_authn_req, relay_state = instance.sp.state[_state]

    # The Subject NameID
    subject = response.get_subject()
    # Diverse arguments needed to construct the response
    resp_args = _idp.idp.response_args(orig_authn_req)

    # Slightly awkward, should be done better
    _authn_info = response.authn_info()[0]
    _authn = {"class_ref": _authn_info[0], "authn_auth": _authn_info[1][0]}

    # This is where any possible modification of the assertion is made

    # Will signed the response by default
    resp = _idp.construct_authn_response(
        response.ava, name_id=subject, authn=_authn,
        resp_args=resp_args, relay_state=relay_state, sign_response=True)

    return resp

# ==============================================================================


def static(environ, start_response, path):
    LOGGER.info("[static]sending: %s" % (path,))

    try:
        text = open(path).read()
        if path.endswith(".ico"):
            start_response('200 OK', [('Content-Type', "image/x-icon")])
        elif path.endswith(".html"):
            start_response('200 OK', [('Content-Type', 'text/html')])
        elif path.endswith(".json"):
            start_response('200 OK', [('Content-Type', 'application/json')])
        elif path.endswith(".txt"):
            start_response('200 OK', [('Content-Type', 'text/plain')])
        elif path.endswith(".css"):
            start_response('200 OK', [('Content-Type', 'text/css')])
        else:
            start_response('200 OK', [('Content-Type', "text/xml")])
        return [text]
    except IOError:
        resp = NotFound()
        return resp(environ, start_response)


def css(environ, start_response):
    try:
        info = open(environ["PATH_INFO"]).read()
        resp = Response(info)
    except (OSError, IOError):
        resp = NotFound(environ["PATH_INFO"])

    return resp(environ, start_response)


URLS = [
    (r'.+\.css$', css),
]


def run(spec, environ, start_response):
    """
    Picks entity and method to run by that entity.

    :param spec: a tuple (entity_type, response_type, binding)
    :param environ: WSGI environ
    :param start_response: WSGI start_response
    :return:
    """

    if isinstance(spec, tuple):
        if spec[0] == "SP":
            inst = SamlSP(environ, start_response, CONFIG["SP"], CACHE,
                          outgoing, **SP_ARGS)
        else:
            inst = SamlIDP(environ, start_response, CONFIG["IDP"], CACHE,
                           incomming)

        func = getattr(inst, spec[1])
        return func(*spec[2:])
    else:
        return spec()


def application(environ, start_response):
    """
    The main WSGI application.

    If nothing matches return NotFound.

    :param environ: The HTTP application environment
    :param start_response: The application to run when the handling of the
        request is done
    :return: The response as a list of lines
    """

    path = environ.get('PATH_INFO', '').lstrip('/')
    if ".." in path:
        resp = Unauthorized()
        return resp(environ, start_response)

    if path == "robots.txt":
        return static(environ, start_response, "static/robots.txt")
    elif path.startswith("static/"):
        return static(environ, start_response, path)

    for regex, spec in URLS:
        match = re.search(regex, path)
        if match is not None:
            try:
                environ['oic.url_args'] = match.groups()[0]
            except IndexError:
                environ['oic.url_args'] = path

            try:
                return run(spec, environ, start_response)
            except Exception, err:
                print >> sys.stderr, "%s" % err
                message = traceback.format_exception(*sys.exc_info())
                print >> sys.stderr, message
                LOGGER.exception("%s" % err)
                resp = ServiceError("%s" % err)
                return resp(environ, start_response)

    LOGGER.debug("unknown side: %s" % path)
    resp = NotFound("Couldn't find the side you asked for!")
    return resp(environ, start_response)


# ----------------------------------------------------------------------------


if __name__ == '__main__':
    import argparse
    import importlib

    from cherrypy import wsgiserver
    from cherrypy.wsgiserver import ssl_pyopenssl

    parser = argparse.ArgumentParser()
    parser.add_argument('-d', dest='debug', action='store_true')
    parser.add_argument('-e', dest="entityid")
    parser.add_argument(dest="config")
    args = parser.parse_args()

    # read the configuration file
    sys.path.insert(0, ".")
    Config = importlib.import_module(args.config)

    # deal with metadata only once
    _metadata_conf = Config.CONFIG["metadata"]
    Config.CONFIG["metadata"] = {}

    CONFIG = {
        "SP": config_factory("sp", args.config),
        "IDP": config_factory("idp", args.config)}

    _spc = CONFIG["SP"]
    mds = _spc.load_metadata(_metadata_conf)

    CONFIG["SP"].metadata = mds
    CONFIG["IDP"].metadata = mds

    # If entityID is set it means this is a proxy in front of one IdP
    if args.entityid:
        EntityID = args.entityid
        SP_ARGS = {}
    else:
        EntityID = None
        SP_ARGS = {"discosrv": Config.DISCO_SRV}

    CACHE = {}
    sp = SamlSP(None, None, CONFIG["SP"], CACHE)
    URLS.extend(sp.register_endpoints())

    idp = SamlIDP(None, None, CONFIG["IDP"], CACHE, None)
    URLS.extend(idp.register_endpoints())

    # ============== Web server ===============

    SRV = wsgiserver.CherryPyWSGIServer((Config.HOST, Config.PORT), application)

    if Config.HTTPS:
        SRV.ssl_adapter = ssl_pyopenssl.pyOpenSSLAdapter(
            Config.SERVER_CERT, Config.SERVER_KEY, Config.CERT_CHAIN)

    LOGGER.info("Server starting")
    if Config.HTTPS:
        print "S2S listening on %s:%s using HTTPS" % (Config.HOST, Config.PORT)
    else:
        print "S2S listening on %s:%s" % (Config.HOST, Config.PORT)

    try:
        SRV.start()
    except KeyboardInterrupt:
        SRV.stop()
