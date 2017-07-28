#!/usr/bin/env python

import ldap, ldap.modlist
from samba import smb
from ConfigParser import ConfigParser
from StringIO import StringIO

class GPOConnection:
    def __init__(self, lp, creds, gpo_path):
        path_parts = [n for n in gpo_path.split('\\') if n]
        self.path = '\\'.join(path_parts[2:])
        try:
            self.conn = smb.SMB(path_parts[0], path_parts[1], lp=lp, creds=creds)
        except:
            self.conn = None

    def parse_inf(self, filename):
        inf_conf = ConfigParser()
        if self.conn:
            try:
                policy = self.conn.loadfile(self.path + filename)
            except:
                policy = ''
            inf_conf.optionxform=str
            try:
                inf_conf.readfp(StringIO(policy))
            except:
                inf_conf.readfp(StringIO(policy.decode('utf-16')))
        return inf_conf

    def write_inf(self, filename, inf_config):
        out = StringIO()
        inf_config.write(out)
        self.conn.savefile(self.path + filename, out.getvalue().replace('\n', '\r\n'))

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

