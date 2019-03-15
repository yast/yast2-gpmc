from __future__ import absolute_import, division, print_function, unicode_literals
from samba.samba3 import libsmb_samba_internal as smb, param as s3param
import six
if six.PY3:
    def ConfigParser(**kwargs):
        import configparser
        return configparser.ConfigParser(interpolation=None, **kwargs)
else:
    from ConfigParser import ConfigParser
from io import StringIO
import xml.etree.ElementTree as etree
import os.path, sys
from samba.net import Net
from samba.dcerpc import nbt
from subprocess import Popen, PIPE
import uuid
import re
import traceback
import ldb
from samba.dcerpc import security
import samba.security
from samba.ntacls import dsacl2fsacl
from yast import ycpbuiltins
import struct
from samba import registry
from collections import OrderedDict
from samba.ndr import ndr_unpack, ndr_pack
from samba.dcerpc import preg
from adcommon.creds import kinit_for_gssapi
from adcommon.yldap import Ldap, LdapException, SCOPE_SUBTREE, SCOPE_ONELEVEL, SCOPE_BASE, addlist, modlist
from adcommon.strings import strcmp, strcasecmp

def open_bytes(filename):
    if six.PY3:
        return open(filename, errors='ignore')
    else:
        return open(filename, 'rb')

def dict_to_bytes(d):
    for key in d.keys():
        if type(d[key]) is dict:
            d[key] = dict_to_bytes(d[key])
        elif type(d[key]) is list:
            vals = []
            for val in d[key]:
                if type(val) is str:
                    vals.append(val.encode('utf-8'))
                else:
                    vals.append(val)
            d[key] = vals
        elif type(d[key]) is str:
            d[key] = d[key].encode('utf-8')
    return d

def stringify_ldap(data):
    if type(data) == dict:
        for key, value in data.items():
            data[key] = stringify_ldap(value)
        return data
    elif type(data) == list:
        new_list = []
        for item in data:
            new_list.append(stringify_ldap(item))
        return new_list
    elif type(data) == tuple:
        new_tuple = []
        for item in data:
            new_tuple.append(stringify_ldap(item))
        return tuple(new_tuple)
    elif six.PY2 and type(data) == unicode:
        return str(data)
    elif six.PY3 and type(data) == bytes:
        try:
            return data.decode('utf-8')
        except UnicodeDecodeError:
            return data
    else:
        return data

def parse_unc(unc):
    '''Parse UNC string into a hostname, a service, and a filepath'''
    if unc.startswith('\\\\') and unc.startswith('//'):
        raise ValueError("UNC doesn't start with \\\\ or //")
    tmp = unc[2:].split('/', 2)
    if len(tmp) == 3:
        return tmp
    tmp = unc[2:].split('\\', 2)
    if len(tmp) == 3:
        return tmp
    raise ValueError("Invalid UNC string: %s" % unc)

def dn_to_path(realm, dn):
    base_dn = (','.join(['DC=%s' % part for part in realm.lower().split('.')])).encode('utf-8')
    parts = [p.split(b'=')[-1].title() for p in dn.lower().replace(base_dn.lower(), b'').split(b',') if p]
    parts.append(realm.encode('utf-8'))
    return b'/'.join(reversed(parts))

def parse_gplink(gplink):
    '''parse a gPLink into an array of dn and options'''
    ret = {}
    a = gplink.split(b']')
    for g in a:
        if not g:
            continue
        d = g.split(b';')
        if len(d) != 2 or not d[0].startswith(b"[LDAP://"):
            raise RuntimeError("Badly formed gPLink '%s'" % g)
        options = bin(int(d[1]))[2:].zfill(2)
        name = d[0][8:].split(b',')[0][3:].decode()
        ret[name] = {'enforced' : 'Yes' if int(options[-2]) else 'No', 'enabled' : 'No' if int(options[-1]) else 'Yes', 'dn' : d[0][8:].decode(), 'options' : int(d[1])}
    return ret

def encode_gplink(gplist):
    '''Encode an array of dn and options into gPLink string'''
    ret = ''
    for g in gplist:
        ret += "[LDAP://%s;%d]" % (g['dn'], g['options'])
    return ret

class GPConnection(Ldap):
    def __init__(self, lp, creds):
        super().__init__(lp, creds)
        self.kinit = False

    def realm_to_dn(self, realm):
        return ','.join(['DC=%s' % part for part in realm.lower().split('.')])

    def __well_known_container(self, container):
        res = None
        if strcmp(container, 'system'):
            wkguiduc = 'AB1D30F3768811D1ADED00C04FD8D5CD'
        elif strcmp(container, 'computers'):
            wkguiduc = 'AA312825768811D1ADED00C04FD8D5CD'
        elif strcmp(container, 'dcs'):
            wkguiduc = 'A361B2FFFFD211D1AA4B00C04FD7D83A'
        elif strcmp(container, 'users'):
            wkguiduc = 'A9D1CA15768811D1ADED00C04FD8D5CD'
        result = self.ldap_search_s('<WKGUID=%s,%s>' % (wkguiduc, self.realm_to_dn(self.realm)), SCOPE_SUBTREE, '(objectClass=container)', stringify_ldap(['distinguishedName']))
        result = stringify_ldap(result)
        if result and len(result) > 0 and len(result[0]) > 1 and 'distinguishedName' in result[0][1] and len(result[0][1]['distinguishedName']) > 0:
            res = result[0][1]['distinguishedName'][-1]

        return stringify_ldap(res)

    def user_from_sid(self, sid, attrs=[]):
        res = self.ldap_search(self.__well_known_container('users'), SCOPE_SUBTREE, '(objectSID=%s)' % sid, stringify_ldap(attrs))
        return res[0][1]

    def get_domain_sid(self):
        res = self.ldap_search(self.realm_to_dn(self.realm), SCOPE_BASE, "(objectClass=*)", [])
        return ndr_unpack(security.dom_sid, res[0][1]["objectSid"][0])

    def gpo_list(self, displayName=None, attrs=[]):
        result = None
        res = self.__well_known_container('system')
        search_expr = '(objectClass=groupPolicyContainer)'
        if displayName is not None:
            search_expr = '(&(objectClass=groupPolicyContainer)(displayname=%s))' % ldb.binary_encode(displayName)
        result = self.ldap_search(res, SCOPE_SUBTREE, search_expr, stringify_ldap(attrs))
        result = stringify_ldap(result)
        return result

    def set_attr(self, dn, key, value):
        self.ldap_modify(dn, stringify_ldap([(1, key, None), (0, key, value)]))

    def create_gpo(self, displayName, container=None):
        msg = self.gpo_list(displayName)
        if len(msg) > 0:
            ycpbuiltins.y2debug("A GPO already existing with name '%s'" % displayName)
            return

        gpouuid = uuid.uuid4()
        realm_dn = self.realm_to_dn(self.realm)
        name = '{%s}' % str(gpouuid).upper()
        dn = 'CN=%s,CN=Policies,CN=System,%s' % (name, realm_dn)
        unc_path = "\\\\%s\\sysvol\\%s\\Policies\\%s" % (self.realm, self.realm, name)
        ldap_mod = { 'displayName': [displayName.encode('utf-8')], 'gPCFileSysPath': [unc_path.encode('utf-8')], 'objectClass': [b'groupPolicyContainer'], 'gPCFunctionalityVersion': [b'2'], 'flags': [b'0'], 'versionNumber': [b'0'] }
        # gPCMachineExtensionNames MUST be assigned as gpos are modified (currently not doing this!)

        machine_dn = 'CN=Machine,%s' % dn
        user_dn = 'CN=User,%s' % dn
        sub_ldap_mod = { 'objectClass': [b'container'] }

        gpo = GPOConnection(self.lp, self.creds, unc_path)
        try:
            self.ldap_add(dn, addlist(ldap_mod))
            self.ldap_add(machine_dn, addlist(stringify_ldap(sub_ldap_mod)))
            self.ldap_add(user_dn, addlist(stringify_ldap(sub_ldap_mod)))
        except LdapException as e:
            ycpbuiltins.y2error(traceback.format_exc())
            ycpbuiltins.y2error('ldap.add_s: %s\n' % e.info if e.info else e.msg)
        gpo.initialize_empty_gpo(displayName)
        if container:
            self.set_link(dn, container)

    def set_link(self, gpo_dn, container_dn, disabled=False, enforced=False):
        gplink_options = 0
        if disabled:
            gplink_options |= (1 << 0)
        if enforced:
            gplink_options |= (1 << 1)

        # Check if valid Container DN
        msg = self.ldap_search(container_dn, SCOPE_BASE,
                               "(objectClass=*)",
                               stringify_ldap(['gPLink']))[0][1]

        # Update existing GPlinks or Add new one
        existing_gplink = False
        if 'gPLink' in msg:
            gplist = parse_gplink(msg['gPLink'][0])
            gplist = [gplist[k] for k in gplist]
            existing_gplink = True
            found = False
            for g in gplist:
                if strcasecmp(g['dn'], gpo_dn):
                    found = True
                    break
            if found:
                ycpbuiltins.y2debug("GPO '%s' already linked to this container" % gpo)
                return
            else:
                gplist.insert(0, { 'dn' : gpo_dn, 'options' : gplink_options })
        else:
            gplist = []
            gplist.append({ 'dn' : gpo_dn, 'options' : gplink_options })

        gplink_str = encode_gplink(gplist)

        if existing_gplink:
            self.ldap_modify(container_dn, stringify_ldap([(1, 'gPLink', None), (0, 'gPLink', [gplink_str.encode('utf-8')])]))
        else:
            self.ldap_modify(container_dn, stringify_ldap([(0, 'gPLink', [gplink_str.encode('utf-8')])]))

    def delete_link(self, gpo_dn, container_dn):
        # Check if valid Container DN
        msg = self.ldap_search(container_dn, SCOPE_BASE,
                               "(objectClass=*)",
                               stringify_ldap(['gPLink']))[0][1]

        found = False
        if 'gPLink' in msg:
            gplist = parse_gplink(msg['gPLink'][0])
            gplist = [gplist[k] for k in gplist]
            for g in gplist:
                if strcasecmp(g['dn'], gpo_dn):
                    gplist.remove(g)
                    found = True
                    break
        else:
            raise Exception("No GPO(s) linked to this container")

        if not found:
            raise Exception("GPO '%s' not linked to this container" % gpo_dn)

        if gplist:
            gplink_str = encode_gplink(gplist)
            self.ldap_modify(container_dn, stringify_ldap([(ldap.MOD_DELETE, 'gPLink', None), (ldap.MOD_ADD, 'gPLink', [gplink_str.encode('utf-8')])]))
        else:
            self.ldap_modify(container_dn, stringify_ldap([(ldap.MOD_DELETE, 'gPLink', None)]))

    def delete_gpo(self, displayName):
        msg = self.gpo_list(displayName)
        if len(msg) == 0:
            raise Exception("GPO '%s' does not exist" % displayName)

        unc_path = msg[0][1]['gPCFileSysPath'][0]
        gpo_dn = msg[0][1]['distinguishedName'][0]

        # Remove links before deleting
        linked_containers = self.get_gpo_containers(gpo_dn)
        for container in linked_containers:
            self.delete_link(gpo_dn, container['distinguishedName'][0].decode())

        # Remove LDAP entries
        self.ldap_delete("CN=User,%s" % str(gpo_dn))
        self.ldap_delete("CN=Machine,%s" % str(gpo_dn))
        self.ldap_delete(gpo_dn)
        try:
            # Remove GPO files
            gpo = GPOConnection(self.lp, self.creds, unc_path)
            gpo.cleanup_gpo()
        except Exception as e:
            ycpbuiltins.y2error(traceback.format_exc())
            ycpbuiltins.y2error(str(e))

    def get_gpo_containers(self, gpo):
        '''lists dn of containers for a GPO'''

        search_expr = "(&(objectClass=*)(gPLink=*%s*))" % gpo
        msg = self.ldap_search(self.realm_to_dn(self.realm), SCOPE_SUBTREE, search_expr, [])
        if not msg:
            return []

        return [res[1] for res in msg if type(res[1]) is dict]

    def get_gpos_for_container(self, container_dn):
        search_expr = '(distinguishedName=%s)' % container_dn
        msg = self.ldap_search(self.realm_to_dn(self.realm), SCOPE_SUBTREE, search_expr, [])
        if not msg:
            return None

        results = []
        if 'gPLink' in msg[0][1]:
            gpos = parse_gplink(msg[0][1]['gPLink'][-1])
        else:
            gpos = []
        for gpo in gpos:
            search_expr = '(distinguishedName=%s)' % gpos[gpo]['dn']
            msg = self.ldap_search(self.realm_to_dn(self.realm), SCOPE_SUBTREE, search_expr, [])
            results.append(msg[0])

        return results

    def get_containers_with_gpos(self):
        search_expr = "(|(objectClass=organizationalUnit)(objectClass=domain))"
        msg = self.ldap_search(self.realm_to_dn(self.realm), SCOPE_SUBTREE, search_expr, [])
        if not msg:
            return []

        return [res[1] for res in msg if type(res[1]) is dict]

class GPOConnection(GPConnection):
    def __init__(self, lp, creds, gpo_path):
        GPConnection.__init__(self, lp, creds)
        if six.PY3 and isinstance(gpo_path, bytes):
            gpo_path = gpo_path.decode()
        [dom_name, service, self.path] = parse_unc(gpo_path)
        path_parts = [n for n in gpo_path.split('\\') if n]
        self.path_start = '\\\\' + '\\'.join([dom_name, service])
        self.name = gpo_path.split('\\')[-1]
        self.realm_dn = self.realm_to_dn(self.realm)
        self.gpo_dn = 'CN=%s,CN=Policies,CN=System,%s' % (self.name, self.realm_dn)
        # the SMB bindings rely on having a s3 loadparm
        s3_lp = s3param.get_context()
        s3_lp.load(self.lp.configfile)
        s3_lp.set('realm', self.lp.get('realm'))
        try:
            self.conn = smb.Conn(self.dc_hostname, service, lp=s3_lp, creds=self.creds, sign=True)
        except Exception as e:
            ycpbuiltins.y2error(traceback.format_exc())
            ycpbuiltins.y2error("Exception %s"%str(e))
            self.conn = None

    def update_machine_gpe_ini(self, extension):
        ini_conf = self.parse('Group Policy\\GPE.INI')
        if not ini_conf.has_section('General'):
            ini_conf.add_section('General')
        machine_extension_versions = ''
        if ini_conf.has_option('General', 'MachineExtensionVersions'):
            machine_extension_versions = ini_conf.get('General', 'MachineExtensionVersions').encode('ascii')
        if type(machine_extension_versions) is bytes:
            machine_extension_versions = machine_extension_versions.decode('utf-8')
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

    def initialize_empty_gpo(self, displayName):
        # Get new security descriptor
        ds_sd_flags = ( security.SECINFO_OWNER |
                        security.SECINFO_GROUP |
                        security.SECINFO_DACL )
        msg = self.gpo_list(displayName, attrs=stringify_ldap(['nTSecurityDescriptor']))
        ds_sd_ndr = msg[0][1]['nTSecurityDescriptor'][0]
        ds_sd = ndr_unpack(security.descriptor, ds_sd_ndr).as_sddl()

        # Create a file system security descriptor
        domain_sid = self.get_domain_sid()
        sddl = dsacl2fsacl(ds_sd, domain_sid)
        fs_sd = security.descriptor.from_sddl(sddl, domain_sid)

        self.__smb_mkdir_p('\\'.join([self.path, 'MACHINE']))
        self.__smb_mkdir_p('\\'.join([self.path, 'USER']))

        # Set ACL
        sio = ( security.SECINFO_OWNER |
                security.SECINFO_GROUP |
                security.SECINFO_DACL |
                security.SECINFO_PROTECTED_DACL )
        self.conn.set_acl(self.path, fs_sd, sio)

        self.__increment_gpt_ini()

    def cleanup_gpo(self):
        self.conn.deltree(self.path)

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
        ini_conf.set('General', 'Version', str(current))
        self.write('GPT.INI', ini_conf)

        self.set_attr(self.gpo_dn, 'versionNumber', current)

    def list(self, path):
        path = os.path.relpath(os.path.join(self.path, path).replace('\\', '/'))
        return self.conn.list(path)

    def parse(self, filename):
        if len(re.findall('CN=[A-Za-z ]+,', filename)) > 0:
            return self.__parse_dn(filename)
        else:
            ext = os.path.splitext(filename)[-1].lower()
            if ext in ['.inf', '.ini', '.ins']:
                return self.__parse_inf(filename)
            elif ext in ['.xml', '.admx', '.adml']:
                return self.__parse_xml(filename)
            elif ext == '.pol':
                return self.__parse_reg(filename)
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
            elif ext == '.pol':
                return self.__write_reg(filename, config)

            if '\\machine' in filename.lower():
                self.__increment_gpt_ini(computer=True)
            elif '\\user' in filename.lower():
                self.__increment_gpt_ini(user=True)

    def __parse_dn(self, dn):
        dn = dn % self.gpo_dn
        resp = self.ldap_search(dn, SCOPE_SUBTREE, '(objectCategory=packageRegistration)', [])
        resp = stringify_ldap(resp)
        if resp:
            keys = ['objectClass', 'msiFileList', 'msiScriptPath', 'displayName', 'versionNumberHi', 'versionNumberLo']
            results = {a[-1]['name'][-1]: {k: a[-1][k] for k in a[-1].keys() if k in keys} for a in resp}
        else:
            results = {}
        return results

    def __mkdn_p(self, dn):
        attrs = { 'objectClass' : [b'top', b'container'] }
        try:
            self.ldap_add(dn, addlist(stringify_ldap(attrs)))
        except LdapException as e:
            if strcmp(e.msg, 'No such object'):
                self.__mkdn_p(','.join(dn.split(',')[1:]))
            elif strcmp(e.msg, 'Already exists'):
                return
            else:
                ycpbuiltins.y2error(traceback.format_exc())
                ycpbuiltins.y2error('ldap.add_s: %s\n' % e.info if e.info else e.msg)
        try:
            self.ldap_add(dn, addlist(stringify_ldap(attrs)))
        except LdapException as e:
            if not strcmp(e.msg, 'Already exists'):
                ycpbuiltins.y2error(traceback.format_exc())
                ycpbuiltins.y2error('ldap.add_s: %s\n' % e.info if e.info else e.msg)

    def __write_dn(self, dn, ldap_config):
        for cn in ldap_config.keys():
            obj_dn = 'CN=%s,%s' % (cn, dn % self.gpo_dn)
            if 'objectClass' not in ldap_config[cn]:
                ldap_config[cn]['objectClass'] = [b'top', b'packageRegistration']
            if 'msiFileList' not in ldap_config[cn]:
                ldap_config[cn]['msiFileList'] = [os.path.splitext(ldap_config[cn]['msiScriptPath'][-1])[0] + '.zap']
            self.__mkdn_p(','.join(obj_dn.split(',')[1:]))
            ldap_config[cn] = dict_to_bytes(ldap_config[cn])
            try:
                self.ldap_add(obj_dn, addlist(stringify_ldap(ldap_config[cn])))
            except LdapException as e:
                if strcmp(e.msg, 'Already exists'):
                    self.ldap_modify(obj_dn, modlist({}, stringify_ldap(ldap_config[cn])))
                else:
                    ycpbuiltins.y2error(traceback.format_exc())
                    ycpbuiltins.y2error('ldap.add_s: %s\n' % e.info if e.info else e.msg)

            if strcmp(os.path.splitext(ldap_config[cn]['msiFileList'][-1])[-1], b'.zap'):
                inf_conf = self.__parse_inf(ldap_config[cn]['msiFileList'][-1])
                if not inf_conf.has_section('Application'):
                    inf_conf.add_section('Application')
                inf_conf.set('Application', 'FriendlyName', ldap_config[cn]['displayName'][-1].decode('utf-8'))
                inf_conf.set('Application', 'SetupCommand', 'rpm -i "%s"' % ldap_config[cn]['msiScriptPath'][-1].decode('utf-8'))
                filename = ldap_config[cn]['msiFileList'][-1].split(self.path.encode('utf-8'))[-1]
                self.__write_inf(filename, inf_conf)

    def __parse_inf(self, filename):
        inf_conf = ConfigParser()
        if self.conn:
            try:
                policy = self.conn.loadfile('\\'.join([self.path, filename]))
            except Exception as e:
                ycpbuiltins.y2error(str(e))
                policy = ''
            inf_conf.optionxform=str
            if six.PY3 and type(policy) is str:
                inf_conf.readfp(StringIO(policy))
            else:
                try:
                    inf_conf.readfp(StringIO(policy.decode('utf-8')))
                except:
                    inf_conf.readfp(StringIO(policy.decode('utf-16')))
        return inf_conf

    def __parse_xml(self, filename):
        xml_conf = None
        if self.conn:
            try:
                path = os.path.relpath(os.path.join(self.path, filename).replace('\\', '/')).replace('/', '\\')
                policy = self.conn.loadfile(path)
                xml_conf = etree.fromstring(policy)
            except:
                xml_conf = None
        return xml_conf

    def __parse_reg(self, filename):
        pol_conf = None
        if self.conn:
            try:
                path = os.path.relpath(os.path.join(self.path, filename).replace('\\', '/')).replace('/', '\\')
                raw = self.conn.loadfile(path)
                pol_conf = ndr_unpack(preg.file, raw)
            except:
                pol_conf = preg.file()
        return pol_conf

    def __smb_mkdir_p(self, path):
        directory = os.path.dirname(path.replace('\\', '/')).replace('/', '\\')
        try:
            self.conn.mkdir(directory)
        except Exception as e:
            if e.args[0] == 0xC000003A: # STATUS_OBJECT_PATH_NOT_FOUND
                self.__smb_mkdir_p(directory)
            elif e.args[0] == 0xC0000035: # STATUS_OBJECT_NAME_COLLISION
                pass
            else:
                ycpbuiltins.y2warning(e.args[1])
        try:
            self.conn.mkdir(path)
        except Exception as e:
            if e.args[0] == 0xC0000035: # STATUS_OBJECT_NAME_COLLISION
                pass
            else:
                ycpbuiltins.y2warning(e.args[1])

    def __write(self, filename, text):
        if type(filename) is bytes:
            filename = filename.decode('utf-8')
        path = '\\'.join([self.path, filename])
        filedir = os.path.dirname((path).replace('\\', '/')).replace('/', '\\')
        self.__smb_mkdir_p(filedir)
        if six.PY3 and type(text) is str:
            text = text.encode('utf-8')
        try:
            self.conn.unlink(path)
            self.conn.savefile(path, text)
        except Exception as e:
            if e.args[0] == 0xC000003A: # STATUS_OBJECT_PATH_NOT_FOUND
                ycpbuiltins.y2warning(e.args[1] % (path))
            else:
                ycpbuiltins.y2warning(str(e))

    def __write_inf(self, filename, inf_config):
        out = StringIO()
        inf_config.write(out)
        value = out.getvalue().replace('\n', '\r\n').encode('utf-16')
        self.__write(filename, value)

    def __write_xml(self, filename, xml_config):
        value = '<?xml version="1.0" encoding="utf-8"?>\r\n' + etree.tostring(xml_config, 'utf-8').decode('utf-8')
        self.__write(filename, value)

    def __write_reg(self, filename, pol_conf):
        buf = ndr_pack(pol_conf)
        self.__write(filename, buf)

    def upload_file(self, local, remote_dir):
        remote_path = '\\'.join([self.path, remote_dir])
        self.__smb_mkdir_p(remote_path)
        if os.path.exists(local):
            value = open_bytes(local).read()
            filename = '\\'.join([remote_path, os.path.basename(local)])
            if six.PY3 and type(value) is str:
                value = value.encode('utf-8')
            try:
                self.conn.unlink(filename)
                self.conn.savefile(filename, value)
            except Exception as e:
                if e.args[0] == 0xC0000035: # STATUS_OBJECT_NAME_COLLISION
                    ycpbuiltins.y2error('The file \'%s\' already exists at \'%s\' and could not be saved.' % (os.path.basename(local), remote_path))
                else:
                    ycpbuiltins.y2error(e.args[1])
            return filename
