# app.py

import os
import logging
import json
import uuid
import ldap

from requests import request
from flask import Flask

LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO').upper()

logging.basicConfig(
    encoding='utf-8',
    level=LOG_LEVEL,
    format='%(asctime)s [%(levelname)s] %(message)s'
)

logging.basicConfig(encoding='utf-8', level=LOG_LEVEL)

VAULT_ADDR = os.environ.get('VAULT_ADDR', 'http://localhost:8200')
VAULT_TOKEN = os.environ.get('VAULT_TOKEN', '?')
  
app = Flask(__name__)

oidc_accessor = None

vault_default_headers = {
        "X-Vault-Token": VAULT_TOKEN,
        "Content-Type": "application/json"
}

def pretty(data):
    try:
        return json.dumps(json.loads(data), sort_keys=True, indent=4)
    except:
        return data
class Ldap(object):
    
    def __init__(self):
        # Establish connection with LDAP...
        try:
            ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, 0)
            ldap.set_option(ldap.OPT_X_TLS_DEMAND, True)

            self.session = ldap.initialize(os.environ['LDAP_HOST'])
            self.session.simple_bind_s(
                os.environ['LDAP_BIND_DN'],
                os.environ['LDAP_PASSWORD']
            )

        except Exception as e:
            logging.error("Problem connecting to LDAP {} error: {}".format(os.environ['LDAP_HOST'], str(e)))

        self.people = {}
        self.groups = {}

    def __enter__(self):
        self.get_people()
        self.get_groups()

        return self

    def __exit__(self, exception_type, exception_value, traceback):
        self.session.unbind_s()

    def __repr__(self):
        return json.dumps(self.json(), indent=4, sort_keys=True)

    def json(self):
        return {
            'people': self.people,
            'groups': self.groups
        }

    def search(self, dn, searchScope=ldap.SCOPE_SUBTREE,
            searchFilter="(objectclass=*)",
            retrieveAttributes=[]):

        result = None
        try:
            result_set = []

            ldap_result_id = self.session.search(
                dn, searchScope,
                searchFilter,
                retrieveAttributes
            )
            while 1:
                result_type, result_data = self.session.result(ldap_result_id, 0)
                if (result_data == []):
                    break
                elif result_type == ldap.RES_SEARCH_ENTRY:
                    result_set.append(result_data)

            result = result_set

        except ldap.LDAPError as e:
            result = None
            logging.error("[LDAP] SEARCH: '%s' ERROR: %s\n" % (dn, str(e)))

        return result

    @staticmethod
    def get_attributes(x):
        attributes = {}

        for a in x.keys():
            attributes[a] = []
            for v in x[a]:
                attributes[a].append(v.decode())

        return attributes

    def get_people(self):
        ldap_user_key = os.environ.get('LDAP_USER_KEY', 'uid')

        for i in self.search(
                os.environ.get('LDAP_BASE_DN',''),
                searchFilter="(&(objectClass=inetOrgPerson)({}=*))".format(ldap_user_key),
                retrieveAttributes=[]):

            attributes = self.get_attributes(i[0][1])

            if ldap_user_key not in attributes:
                logging.error("Missing '{}' attribute in LDAP USER Object !".format(ldap_user_key))
                continue

            if len(attributes[ldap_user_key]) > 1:
                logging.error("LDAP User key '{}' must be 1 value !".format(ldap_user_key))
                continue

            key = attributes[ldap_user_key][0]

            self.people[key] = {
                'attributes': attributes
            }

    def get_groups(self):
        ldap_group_key = os.environ.get('LDAP_GROUP_KEY', 'cn')

        for i in self.search(
            os.environ.get('LDAP_BASE_DN',''),
            searchFilter="({})".format(
                    os.environ.get(
                        'LDAP_FILTER', "objectClass=groupOfMembers"
                    )
                ),
            retrieveAttributes=[]):

            attributes = self.get_attributes(i[0][1])

            if ldap_group_key not in attributes:
                logging.error("Missing '{}' attribute in LDAP GROUP Object !".format(ldap_group_key))
                continue

            if len(attributes[ldap_group_key]) > 1:
                logging.error("LDAP Group key '{}' must be 1 value !".format(ldap_group_key))
                continue

            key = attributes[ldap_group_key][0]

            members = []

            if 'member' in attributes:

                for member in attributes['member']:

                    m = member.split(',')[0].split('=')[1]

                    if m not in self.people:
                        logging.error("Member {} not in LDAP People !".format(m))
                        continue

                    members.append(m)

            attributes['member'] = members

            self.groups[key] = {
                'attributes': attributes
            }

def vault(uri, method="GET", payload={}, headers=vault_default_headers):
    logging.debug("[VAULT] {}: {}".format(method, uri))
    
    if payload:
        logging.debug("[VAULT] DATA: {}".format(pretty(payload)))

    response = request(method, "{}{}".format(VAULT_ADDR, uri), json=payload, headers=headers)

    logging.debug(pretty(response.text))
    
    return response.status_code, response.text

def create_policy(policy, path, capabilities):
    payload = {"policy": "path \"{}\" {{ capabilities = {} }}".format(path, capabilities)}

    (rc, _) = vault("/v1/sys/policy/{}".format(policy), method="PUT", payload=payload)

    if rc not in [200, 204]:
        logging.error("Error creating policy {} does not exist !".format(policy))

def check_policy(policy):
    (rc, _) = vault("/v1/sys/policy/{}".format(policy))

    if rc != 200:
        logging.error("Policy {} does not exist !".format(policy))

def create_secret(path, secret):
    vault("/v1/{}".format(path), method="DELETE")
    vault("/v1/{}".format(path), method="POST", payload={ "data": secret })

def get_secret(path, key):
    (rc, data) = vault("/v1/{}".format(path))

    if rc != 200:
        logging.error("Secret {} does not exist !".format(path))
    else:
        try:
            secrets = json.loads(data)
            return secrets['data']['data'][key]
        except:
            logging.error("Key {} not found in secrets {} does not exist !".format(data))

    return None
            
def create_user(username, password=None, policies="default"):
    
    payload = {}

    if password:
        payload['password'] = password
    
    if policies:
        payload['policies'] = policies

    (rc, _) = vault("/v1/auth/userpass/users/{}".format(username), method="POST", payload=payload)
    if rc not in [200, 204]:
        logging.error("Create user {} not succeeded !".format(username))

def check_user(username):
    (rc, _) = vault("/v1/auth/userpass/users/{}".format(username))

    if rc != 200:
        logging.error("User {} does not exist !".format(username))
        return False

    return True

def get_accessor(type):
    (rc, data) = vault("/v1/sys/auth")
    
    if rc == 200:
        for k, v in json.loads(data).items():
            logging.debug("Checking: {}".format(k))
            if v['type'] == type:
                logging.debug("Auth {} found: {}".format(type, v['accessor']))
                return v['accessor']

    return None

def create_entity_alias(username, accessor, alias):
    payload = {
        "name": username,
        "metadata": {
            "organization": "ACME Inc.",
            "team": "QA"
        },
        "policies": ["default","secrets","{}".format(username)]
    }
    (rc, _) = vault("/v1/identity/entity", method="POST", payload=payload)

    if rc not in [200, 204]:
        logging.error("Error creating identity {} !".format(username))
        return

    (rc, data) = vault("/v1/identity/entity/name/{}".format(username))

    if rc not in [200]:
        logging.error("Error reading identity {} !".format(username))
        return

    id = json.loads(data)['data']['id']

    payload = {
        "name": alias,
        "canonical_id": id,
        "mount_accessor": accessor
    }

    vault("/v1/identity/entity-alias", method="POST", payload=payload)

def login_user(username, password):
    payload = {
        "password": password
    }

    (rc, user) = vault("/v1/auth/userpass/login/{}".format(username), method="POST", payload=payload, headers=None)

    if rc != 200:
        logging.error("Login {} not succeeded !".format(username))
    else:
        logging.info(pretty(user))

def setup_user_vault(username, alias):
    path = 'secret/data/{}'.format(username)

    create_policy(username, path=path, capabilities="[\"list\", \"read\"]")
    create_secret(path, { 'password': str(uuid.uuid4()) })
    password = get_secret(path, "password")
    create_user(username, password=password, policies="default,secrets,{}".format(username))
#   login_user(username, password)
    create_entity_alias(username, oidc_accessor, alias)

@app.route('/setup')
def setup():

    vault("/v1/sys/auth/oidc", method="DELETE")
    vault("/v1/auth/oidc/role/oidc_role", method="DELETE")

    vault("/v1/sys/auth/userpass",
        method="POST",
        payload= {
            "type": "userpass"
        }
    )

    vault("/v1/sys/auth/oidc",
        method="POST",
        payload= {
            "type": "oidc",
            "path": "oidc"
        }
    )

    vault("/v1/auth/oidc/config",
        method="PUT",
        payload= {
            "oidc_discovery_url": os.environ.get('OIDC_PROVIDER', "http://localhost:8080"),
            "oidc_client_id": os.environ.get('OIDC_CLIENT_ID','?'),
            "oidc_client_secret": os.environ.get('OIDC_CLIENT_SECRET','?'),
            "default_role": "oidc_role"
        }
    )

    vault("/v1/auth/oidc/role/oidc_role",
        method="PUT",
        payload= {
            "bound_audiences": os.environ.get('OIDC_CLIENT_ID','?'),
            "allowed_redirect_uris": [os.environ.get('OIDC_REDIRECT_URL', 'http://localhost:8200/ui/vault/auth/oidc/oidc/callback')],
            "user_claim": "sub",
            "oidc_scopes": "openid",
            "policies": ["default"],
            "role_type": "jwt",
            "ttl": "1h"
        }
    )

    create_policy('secrets', path='/secret/*', capabilities="[\"list\"]")

    global oidc_accessor
    oidc_accessor = get_accessor('oidc')

    return "OK"

@app.route('/sync')
def sync():
    if not oidc_accessor:
        setup()

    users = []
    groups = []

    try:
        (rc, data) = vault('/v1/identity/entity/name', method='LIST')
        if rc == 200:
            users += json.loads(data)['data']['keys']
    except:
        pass

    try:
        (rc, data) = vault('/v1/identity/group/name', method='LIST')
        if rc == 200:
            groups += json.loads(data)['data']['keys']
    except:
        pass

    logging.debug('[EXISTING USERS] {}'.format(users))
    logging.debug('[EXISTING GROUPS] {}'.format(groups))

    with Ldap() as my_ldap:

        for u in users:
            if u not in my_ldap.people:
                logging.info("[DELETE USER]: {}".format(u))

                (rc, data) = vault('/v1/identity/entity/name/{}'.format(u))
                if rc == 200:
                    try:
                        for alias in json.loads(data)['data']['aliases']:
                            vault('/v1/identity/entity-alias/id/{}'.format(alias['id']), method='DELETE')
                    except:
                        pass

                vault('/v1/auth/userpass/users/{}'.format(u), method='DELETE')
                vault('/v1/identity/entity/name/{}'.format(u), method='DELETE')
                vault('/v1/sys/policy/{}'.format(u), method='DELETE')
                vault('/v1/secret/data/{}'.format(u), method='DELETE')

        for g in groups:
            if g not in my_ldap.groups:
                logging.info("[DELETE GROUP]: {}".format(g))

                vault('/v1/identity/group/name/{}'.format(g), method='DELETE')


        for u in my_ldap.people.keys():
            
            if u not in users:
                logging.info("[ADD USER]: {}".format(u))

                setup_user_vault(u, my_ldap.people[u]['attributes']['cn'][0])

        for g in my_ldap.groups.keys():
            if g not in groups:
                logging.info("[ADD GROUP]: {}".format(g))

                vault('/v1/identity/group',
                    method='POST',
                    payload= {
                        "name": g
                    }
                )

            members = []
            for m in my_ldap.groups[g]['attributes']['member']:
                (rc, data) = vault('/v1/identity/entity/name/{}'.format(m))
                if rc == 200:
                    members.append(json.loads(data)['data']['id'])

            vault('/v1/identity/group',
                method='POST',
                payload= {
                    "name": g,
                    "member_entity_ids": members,
                    "policies": ["default"]
                }
            )

    return 'OK !'

if __name__ == '__main__':
    app.run(debug=(LOG_LEVEL == "DEBUG"))