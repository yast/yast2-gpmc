#!/usr/bin/env python

import ldap, ldap.modlist, ldap.sasl
from samba import smb
from ConfigParser import ConfigParser
from StringIO import StringIO
import xml.etree.ElementTree as etree
import os.path, sys
from samba.net import Net
from samba.dcerpc import nbt
from subprocess import Popen, PIPE
import uuid
from ldap.modlist import addModlist as addlist
import re

class GPOConnection:
    def __init__(self, lp, creds, gpo_path):
        self.lp = lp
        self.creds = creds
        path_parts = [n for n in gpo_path.split('\\') if n]
        self.path = '\\'.join(path_parts[2:])
        try:
            self.conn = smb.SMB(path_parts[0], path_parts[1], lp=lp, creds=creds)
        except:
            self.conn = None

    def update_machine_gpe_ini(self, extension):
        ini_conf = self.parse('Group Policy\\GPE.INI')
        if not ini_conf.has_section('General'):
            ini_conf.add_section('General')
        machine_extension_versions = ''
        if ini_conf.has_option('General', 'MachineExtensionVersions'):
            machine_extension_versions = ini_conf.get('General', 'MachineExtensionVersions').encode('ascii')
        itr = re.finditer('\[%s:\d+]' % extension, machine_extension_versions)
        try:
            new_ext_str = machine_extension_versions[:m.start()] + machine_extension_versions[m.end():]
            machine_extension_versions = new_ext_str
        except:
            pass

        _, version = self.__get_gpo_version()
        machine_extension_versions += '[%s:%d]' % (extension, version-1)
        ini_conf.set('General', 'MachineExtensionVersions', machine_extension_versions)
        self.write('Group Policy\\GPE.INI', ini_conf)

    def initialize_empty_gpo(self):
        self.__smb_mkdir_p('\\'.join([self.path, 'MACHINE']))
        self.__smb_mkdir_p('\\'.join([self.path, 'USER']))
        self.__increment_gpt_ini()

    def __get_gpo_version(self, ini_conf=None):
        if not ini_conf:
            ini_conf = self.parse('GPT.INI')
        current = 0
        cur_user = 0
        cur_comp = 0
        if ini_conf.has_option('General', 'Version'):
            current = int(ini_conf.get('General', 'Version').encode('ascii'))
            cur_user = current >> 16
            cur_comp = current & 0x0000FFFF
        return (cur_user, cur_comp)

    def __increment_gpt_ini(self, user=False, computer=False):
        ini_conf = self.parse('GPT.INI')
        cur_user, cur_comp = self.__get_gpo_version(ini_conf)
        if user:
            cur_user += 1
        if computer:
            cur_comp += 1
        current = (cur_user << 16) + cur_comp

        if not ini_conf.has_section('General'):
            ini_conf.add_section('General')
        ini_conf.set('General', 'Version', current)
        self.write('GPT.INI', ini_conf)

        ldap = GPQuery(self.lp, self.creds)
        name = self.path.split('\\')[2]
        realm_dn = self.lp.get('realm')
        gpo_dn = 'CN=%s,CN=Policies,CN=System,%s' % (name, realm_dn)
        ldap.set_attr(gpo_dn, 'versionNumber', current)

    def parse(self, filename):
        ext = os.path.splitext(filename)[-1].lower()
        if ext == '.inf' or ext == '.ini':
            return self.__parse_inf(filename)
        elif ext == '.xml':
            return self.__parse_xml(filename)
        return ''

    def write(self, filename, config):
        ext = os.path.splitext(filename)[-1].lower()
        if ext == '.inf' or ext == '.ini':
            self.__write_inf(filename, config)
        elif ext == '.xml':
            self.__write_xml(filename, config)

        if '\\machine' in filename.lower():
            self.__increment_gpt_ini(computer=True)
        elif '\\user' in filename.lower():
            self.__increment_gpt_ini(user=True)

    def __parse_inf(self, filename):
        inf_conf = ConfigParser()
        if self.conn:
            try:
                policy = self.conn.loadfile('\\'.join([self.path, filename]))
            except:
                policy = ''
            inf_conf.optionxform=str
            try:
                inf_conf.readfp(StringIO(policy))
            except:
                inf_conf.readfp(StringIO(policy.decode('utf-16')))
        return inf_conf

    def __parse_xml(self, filename):
        xml_conf = None
        if self.conn:
            try:
                policy = self.conn.loadfile('\\'.join([self.path, filename]))
                xml_conf = etree.fromstring(policy)
            except:
                xml_conf = None
        return xml_conf

    def __smb_mkdir_p(self, path):
        directory = os.path.dirname(path.replace('\\', '/')).replace('/', '\\')
        try:
            self.conn.mkdir(directory)
        except Exception as e:
            if e[0] == -1073741766: # 0xC000003A: STATUS_OBJECT_PATH_NOT_FOUND
                self.__smb_mkdir_p(directory)
            elif e[0] == -1073741771: # 0xC0000035: STATUS_OBJECT_NAME_COLLISION
                pass
            else:
                print e[1]
        try:
            self.conn.mkdir(path)
        except Exception as e:
            if e[0] == -1073741771: # 0xC0000035: STATUS_OBJECT_NAME_COLLISION
                pass
            else:
                print e[1]

    def __write(self, filename, text):
        path = '\\'.join([self.path, filename])
        filedir = os.path.dirname((path).replace('\\', '/')).replace('/', '\\')
        self.__smb_mkdir_p(filedir)
        try:
            self.conn.savefile(path, text)
        except Exception as e:
            if e[0] == -1073741766: # 0xC000003A: STATUS_OBJECT_PATH_NOT_FOUND
                print e[1] % (path)
            else:
                print e[1]

    def __write_inf(self, filename, inf_config):
        out = StringIO()
        inf_config.write(out)
        value = out.getvalue().replace('\n', '\r\n').encode('utf-16')
        self.__write(filename, value)

    def __write_xml(self, filename, xml_config):
        value = '<?xml version="1.0" encoding="utf-8"?>\r\n' + etree.tostring(xml_config, 'utf-8')
        self.__write(filename, value)

    def upload_file(self, local, remote_dir):
        remote_path = '\\'.join([self.path, remote_dir])
        self.__smb_mkdir_p(remote_path)
        if os.path.exists(local):
            value = open(local).read()
            filename = '\\'.join([remote_path, os.path.basename(local)])
            try:
                self.conn.savefile(filename, value)
            except Exception as e:
                if e[0] == -1073741771: # 0xC0000035: STATUS_OBJECT_NAME_COLLISION
                    sys.stderr.write('The file \'%s\' already exists at \'%s\' and could not be saved.' % (os.path.basename(local), remote_path))
                else:
                    sys.stderr.write(e[1])

class GPQuery:
    def __init__(self, lp, creds):
        self.realm = lp.get('realm')
        net = Net(creds=creds, lp=lp)
        cldap_ret = net.finddc(domain=self.realm, flags=(nbt.NBT_SERVER_LDAP | nbt.NBT_SERVER_DS))
        self.l = ldap.initialize('ldap://%s' % cldap_ret.pdc_dns_name)
        if self.__kinit_for_gssapi(creds):
            auth_tokens = ldap.sasl.gssapi('')
            self.l.sasl_interactive_bind_s('', auth_tokens)
        else:
            self.l.bind_s('%s@%s' % (creds.get_username(), self.realm) if not self.realm in creds.get_username() else creds.get_username(), creds.get_password())

    def __kinit_for_gssapi(self, creds):
        p = Popen(['kinit', '%s@%s' % (creds.get_username(), self.realm) if not self.realm in creds.get_username() else creds.get_username()], stdin=PIPE, stdout=PIPE)
        p.stdin.write('%s\n' % creds.get_password())
        return p.wait() == 0

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

    def set_attr(self, dn, key, value):
        self.l.modify(dn, [(1, key, None), (0, key, value)])

def realm_to_dn(realm):
    return ','.join(['dc=%s' % part for part in realm.split('.')])

class CreateGPO:
    def __init__(self, displayName, ldap, lp, creds):
        self.uuid = uuid.uuid4()
        self.realm = lp.get('realm')
        self.l = ldap
        self.lp = lp
        self.creds = creds
        self.__propogate(displayName)

    def __propogate(self, displayName):
        realm_dn = realm_to_dn(self.realm)
        name = '{%s}' % str(self.uuid).upper()
        dn = 'CN=%s,CN=Policies,CN=System,%s' % (name, realm_dn)
        ldap_mod = { 'displayName': [displayName], 'gPCFileSysPath': ['\\\\%s\\SysVol\\%s\\Policies\\%s' % (self.realm, self.realm, name)], 'objectClass': ['top', 'container', 'groupPolicyContainer'], 'gPCFunctionalityVersion': ['2'], 'flags': ['0'], 'versionNumber': ['0'] }
        # gPCMachineExtensionNames MUST be assigned as gpos are modified (currently not doing this!)

        machine_dn = 'CN=Machine,%s' % dn
        user_dn = 'CN=User,%s' % dn
        sub_ldap_mod = { 'objectClass': ['top', 'container'] }

        smb = GPOConnection(self.lp, self.creds, ldap_mod['gPCFileSysPath'][-1])
        try:
            self.l.add_s(dn, addlist(ldap_mod))
            self.l.add_s(machine_dn, addlist(sub_ldap_mod))
            self.l.add_s(user_dn, addlist(sub_ldap_mod))

            smb.initialize_empty_gpo()
            # TODO: GPO links
        except Exception as e:
            print str(e)

