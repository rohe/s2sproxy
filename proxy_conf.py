#!/usr/bin/env python
# -*- coding: utf-8 -*-
from saml2 import BINDING_HTTP_REDIRECT
from saml2 import BINDING_HTTP_POST
from saml2.extension.idpdisc import BINDING_DISCO
from saml2.saml import NAME_FORMAT_URI
from saml2.saml import NAMEID_FORMAT_TRANSIENT
from saml2.saml import NAMEID_FORMAT_PERSISTENT
import os.path

try:
    from saml2.sigver import get_xmlsec_binary
except ImportError:
    get_xmlsec_binary = None

if get_xmlsec_binary:
    xmlsec_path = get_xmlsec_binary(["/opt/local/bin"])
else:
    xmlsec_path = '/usr/bin/xmlsec1'

BASEDIR = os.path.abspath(os.path.dirname(__file__))


def full_path(local_file):
    return os.path.join(BASEDIR, local_file)

HOST = 'localhost'
PORT = 8090

BASE = "https://%s:%s" % (HOST, PORT)

HTTPS = True
# HTTPS cert information
SERVER_CERT = "pki/mycert.pem"
SERVER_KEY = "pki/mykey.pem"
CERT_CHAIN = ""

DISCO_SRV = "https://md.nordu.net/role/idp.ds"

CONFIG = {
    "entityid": "%s/proxy.xml" % BASE,
    "description": "A SAML2SAML proxy",
    "valid_for": 168,
    "service": {
        "idp": {
            "name": "Rolands IdP",
            "endpoints": {
                "single_sign_on_service": [
                    ("%s/sso/redirect" % BASE, BINDING_HTTP_REDIRECT),
                    ("%s/sso/post" % BASE, BINDING_HTTP_POST),
                ],
            },
            "policy": {
                "default": {
                    "lifetime": {"minutes": 15},
                    "attribute_restrictions": None,  # means all I have
                    "name_form": NAME_FORMAT_URI,
                    "entity_categories": ["swamid", "edugain"],
                    "fail_on_missing_requested": False
                },
            },
            "subject_data": "./idp.subject",
            "name_id_format": [NAMEID_FORMAT_TRANSIENT,
                               NAMEID_FORMAT_PERSISTENT],
            "want_authn_requests_signed": False
        },
        "sp": {
            "required_attributes": ["sn", "givenname", "uid",
                                    "edupersonaffiliation"],
            "optional_attributes": ["title"],
            "endpoints": {
                "assertion_consumer_service": [
                    ("%s/acs/post" % BASE, BINDING_HTTP_POST),
                    ("%s/acs/redirect" % BASE, BINDING_HTTP_REDIRECT)
                ],
                "discovery_response": [
                    ("%s/disco" % BASE, BINDING_DISCO)
                ]
            }
        },
    },
    "debug": 1,
    "key_file": full_path("pki/new_server.key"),
    "cert_file": full_path("pki/new_server.crt"),
    "metadata": {
        #"mdfile": ["swamid2.md"],
        "local": ["/Users/rolandh/code/pysaml2/example/sp-wsgi/sp.xml",
                  "/Users/rolandh/code/pysaml2/example/idp2/idp.xml"]
    },
    "organization": {
        "display_name": "Rolands Identiteter",
        "name": "Rolands Identiteter",
        "url": "http://www.example.com",
    },
    "contact_person": [
        {
            "contact_type": "technical",
            "given_name": "Roland",
            "sur_name": "Hedberg",
            "email_address": "technical@example.com"
        }, {
            "contact_type": "support",
            "given_name": "Support",
            "email_address": "support@example.com"
        },
    ],
    # This database holds the map between a subjects local identifier and
    # the identifier returned to a SP
    "xmlsec_binary": xmlsec_path,
    "logger": {
        "rotating": {
            "filename": "idp.log",
            "maxBytes": 500000,
            "backupCount": 5,
        },
        "loglevel": "debug",
    }
}
