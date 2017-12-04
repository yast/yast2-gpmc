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
from ldap.modlist import modifyModlist as modlist
import re

class GPConnection:
    def __init__(self, lp, creds):
        self.lp = lp
        self.creds = creds
        self.realm = lp.get('realm')
        net = Net(creds=creds, lp=lp)
        cldap_ret = net.finddc(domain=self.realm, flags=(nbt.NBT_SERVER_LDAP | nbt.NBT_SERVER_DS))
        self.l = ldap.initialize('ldap://%s' % cldap_ret.pdc_dns_name)
        if self.__kinit_for_gssapi():
            auth_tokens = ldap.sasl.gssapi('')
            self.l.sasl_interactive_bind_s('', auth_tokens)
        else:
            self.l.bind_s('%s@%s' % (creds.get_username(), self.realm) if not self.realm in creds.get_username() else creds.get_username(), creds.get_password())

    def __kinit_for_gssapi(self):
        p = Popen(['kinit', '%s@%s' % (self.creds.get_username(), self.realm) if not self.realm in self.creds.get_username() else self.creds.get_username()], stdin=PIPE, stdout=PIPE)
        p.stdin.write('%s\n' % self.creds.get_password())
        return p.wait() == 0

    def realm_to_dn(self, realm):
        return ','.join(['DC=%s' % part for part in realm.lower().split('.')])

    def __well_known_container(self, container):
        if container == 'system':
            wkguiduc = 'AB1D30F3768811D1ADED00C04FD8D5CD'
        elif container == 'computers':
            wkguiduc = 'AA312825768811D1ADED00C04FD8D5CD'
        elif container == 'dcs':
            wkguiduc = 'A361B2FFFFD211D1AA4B00C04FD7D83A'
        elif container == 'users':
            wkguiduc = 'A9D1CA15768811D1ADED00C04FD8D5CD'
        result = self.l.search_s('<WKGUID=%s,%s>' % (wkguiduc, self.realm_to_dn(self.realm)), ldap.SCOPE_SUBTREE, '(objectClass=container)', ['distinguishedName'])
        if result and len(result) > 0 and len(result[0]) > 1 and 'distinguishedName' in result[0][1] and len(result[0][1]['distinguishedName']) > 0:
            return result[0][1]['distinguishedName'][-1]

    def gpo_list(self):
        return self.l.search_s(self.__well_known_container('system'), ldap.SCOPE_SUBTREE, '(objectCategory=groupPolicyContainer)', [])

    def set_attr(self, dn, key, value):
        self.l.modify(dn, [(1, key, None), (0, key, value)])

    def create_gpo(self, displayName):
        gpouuid = uuid.uuid4()
        realm_dn = self.realm_to_dn(self.realm)
        name = '{%s}' % str(gpouuid).upper()
        dn = 'CN=%s,CN=Policies,CN=System,%s' % (name, realm_dn)
        ldap_mod = { 'displayName': [displayName], 'gPCFileSysPath': ['\\\\%s\\SysVol\\%s\\Policies\\%s' % (self.realm, self.realm, name)], 'objectClass': ['top', 'container', 'groupPolicyContainer'], 'gPCFunctionalityVersion': ['2'], 'flags': ['0'], 'versionNumber': ['0'] }
        # gPCMachineExtensionNames MUST be assigned as gpos are modified (currently not doing this!)

        machine_dn = 'CN=Machine,%s' % dn
        user_dn = 'CN=User,%s' % dn
        sub_ldap_mod = { 'objectClass': ['top', 'container'] }

        gpo = GPOConnection(self.lp, self.creds, ldap_mod['gPCFileSysPath'][-1])
        try:
            self.l.add_s(dn, addlist(ldap_mod))
            self.l.add_s(machine_dn, addlist(sub_ldap_mod))
            self.l.add_s(user_dn, addlist(sub_ldap_mod))

            gpo.initialize_empty_gpo()
            # TODO: GPO links
        except Exception as e:
            print(str(e))

class GPOConnection(GPConnection):
    def __init__(self, lp, creds, gpo_path):
        GPConnection.__init__(self, lp, creds)
        path_parts = [n for n in gpo_path.split('\\') if n]
        self.path_start = '\\\\' + '\\'.join(path_parts[:2])
        self.path = '\\'.join(path_parts[2:])
        self.name = path_parts[-1]
        self.realm_dn = self.realm_to_dn(self.realm)
        self.gpo_dn = 'CN=%s,CN=Policies,CN=System,%s' % (self.name, self.realm_dn)
        try:
            self.conn = smb.SMB(path_parts[0], path_parts[1], lp=self.lp, creds=self.creds)
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

        self.set_attr(self.gpo_dn, 'versionNumber', current)

    def parse(self, filename):
        if len(re.findall('CN=[A-Za-z ]+,', filename)) > 0:
            return self.__parse_dn(filename)
        else:
            ext = os.path.splitext(filename)[-1].lower()
            if ext in ['.inf', '.ini', '.ins']:
                return self.__parse_inf(filename)
            elif ext == '.xml':
                return self.__parse_xml(filename)
            return ''

    def write(self, filename, config):
        if len(re.findall('CN=[A-Za-z ]+,', filename)) > 0:
            self.__write_dn(filename, config)
        else:
            ext = os.path.splitext(filename)[-1].lower()
            if ext in ['.inf', '.ini', '.ins']:
                self.__write_inf(filename, config)
            elif ext == '.xml':
                self.__write_xml(filename, config)

            if '\\machine' in filename.lower():
                self.__increment_gpt_ini(computer=True)
            elif '\\user' in filename.lower():
                self.__increment_gpt_ini(user=True)

    def __parse_dn(self, dn):
        dn = dn % self.gpo_dn
        try:
            resp = self.l.search_s(dn, ldap.SCOPE_SUBTREE, '(objectCategory=packageRegistration)', [])
            keys = ['objectClass', 'msiFileList', 'msiScriptPath', 'displayName', 'versionNumberHi', 'versionNumberLo']
            results = {a[-1]['name'][-1]: {k: a[-1][k] for k in a[-1].keys() if k in keys} for a in resp}
        except Exception as e:
            if 'No such object' in str(e):
                results = {}
            else:
                raise
        return results

    def __mkdn_p(self, dn):
        attrs = { 'objectClass' : ['top', 'container'] }
        try:
            self.l.add_s(dn, addlist(attrs))
        except Exception as e:
            if e.args[-1]['desc'] == 'No such object':
                self.__mkdn_p(','.join(dn.split(',')[1:]))
            elif e.args[-1]['desc'] == 'Already exists':
                return
            else:
                sys.stderr.write(e.args[-1]['info'])
        try:
            self.l.add_s(dn, addlist(attrs))
        except Exception as e:
            if e.args[-1]['desc'] != 'Already exists':
                sys.stderr.write(e.args[-1]['info'])

    def __write_dn(self, dn, ldap_config):
        for cn in ldap_config.keys():
            obj_dn = 'CN=%s,%s' % (cn, dn % self.gpo_dn)
            if 'objectClass' not in ldap_config[cn]:
                ldap_config[cn]['objectClass'] = ['top', 'packageRegistration']
            if 'msiFileList' not in ldap_config[cn]:
                ldap_config[cn]['msiFileList'] = os.path.splitext(ldap_config[cn]['msiScriptPath'][-1])[0] + '.zap'
            self.__mkdn_p(','.join(obj_dn.split(',')[1:]))
            try:
                self.l.add_s(obj_dn, addlist(ldap_config[cn]))
            except Exception as e:
                if e.args[-1]['desc'] == 'Already exists':
                    try:
                        self.l.modify_s(obj_dn, modlist({}, ldap_config[cn]))
                    except Exception as e:
                        sys.stderr.write(e.args[-1]['info'])
                else:
                    sys.stderr.write(e.args[-1]['info'])

            if os.path.splitext(ldap_config[cn]['msiFileList'][-1])[-1] == '.zap':
                inf_conf = self.__parse_inf(ldap_config[cn]['msiFileList'][-1])
                if not inf_conf.has_section('Application'):
                    inf_conf.add_section('Application')
                inf_conf.set('Application', 'FriendlyName', ldap_config[cn]['displayName'][-1])
                inf_conf.set('Application', 'SetupCommand', 'rpm -i "%s"' % ldap_config[cn]['msiScriptPath'][-1])
                self.__write_inf(ldap_config[cn]['msiFileList'][-1], inf_conf)

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
                print(e[1])
        try:
            self.conn.mkdir(path)
        except Exception as e:
            if e[0] == -1073741771: # 0xC0000035: STATUS_OBJECT_NAME_COLLISION
                pass
            else:
                print(e[1])

    def __write(self, filename, text):
        path = '\\'.join([self.path, filename])
        filedir = os.path.dirname((path).replace('\\', '/')).replace('/', '\\')
        self.__smb_mkdir_p(filedir)
        try:
            self.conn.savefile(path, text)
        except Exception as e:
            if e[0] == -1073741766: # 0xC000003A: STATUS_OBJECT_PATH_NOT_FOUND
                print(e[1] % (path))
            else:
                print(e[1])

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
            return filename

