#!/usr/bin/env python

import ldap, ldap.modlist
from subprocess import Popen, PIPE
from samba.param import LoadParm

smb_conf = None
def get_smb_conf():
    global smb_conf
    if not smb_conf:
        smb_conf = Popen(['grep', 'CONFIGFILE'], stdin=Popen(['/usr/sbin/smbd', '-b'], stdout=PIPE).stdout, stdout=PIPE).communicate()[0].strip().split(':')[-1].strip()
    return smb_conf

default_realm = None
def get_default_realm():
    global default_realm
    if not default_realm:
        lp = LoadParm()
        lp.load(get_smb_conf())
        default_realm = lp.get('realm')
    return default_realm

class GPQuery:
    def __init__(self, realm, user, password):
        self.l = ldap.open(realm)
        self.l.bind_s('%s@%s' % (user, realm), password)
        self.realm = realm

    def __realm_to_dn(self, realm):
        return ','.join(['dc=%s' % part for part in realm.split('.')])

    def well_known_container(self, container):
        if container == 'system':
            wkguiduc = 'AB1D30F3768811D1ADED00C04FD8D5CD'
        elif container == 'computers':
            wkguiduc = 'AA312825768811D1ADED00C04FD8D5CD'
        elif container == 'dcs':
            wkguiduc = 'A361B2FFFFD211D1AA4B00C04FD7D83A'
        elif container == 'users':
            wkguiduc = 'A9D1CA15768811D1ADED00C04FD8D5CD'
        result = self.l.search_s('<WKGUID=%s,%s>' % (wkguiduc, self.__realm_to_dn(self.realm)), ldap.SCOPE_SUBTREE, '(objectClass=container)', ['distinguishedName'])
        if result and len(result) > 0 and len(result[0]) > 1 and 'distinguishedName' in result[0][1] and len(result[0][1]['distinguishedName']) > 0:
            return result[0][1]['distinguishedName'][-1]

    def gpo_list(self):
        return self.l.search_s(self.well_known_container('system'), ldap.SCOPE_SUBTREE, '(objectCategory=groupPolicyContainer)', [])

    def set_attrs(self, dn, old_values, new_values):
        l.modify(dn, ldap.modlist.modifyModlist(old_values, new_values))

