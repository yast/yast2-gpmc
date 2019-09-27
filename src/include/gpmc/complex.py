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
from samba import NTSTATUSError
from tempfile import NamedTemporaryFile
from optparse import OptionParser
from samba.netcmd import gpo
from samba.netcmd import CommandError
from samba import NTSTATUSError, WERRORError

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
    a = re.findall(b'(LDAP://[^;]*);(\d+)', gplink)
    for d in a:
        options = bin(int(d[1]))[2:].zfill(2)
        name = d[0][7:].split(b',')[0][3:].decode()
        ret[name] = {'enforced' : 'Yes' if int(options[-2]) else 'No', 'enabled' : 'No' if int(options[-1]) else 'Yes', 'dn' : d[0][7:].decode(), 'options' : int(d[1])}
    return ret

def encode_gplink(gplist):
    '''Encode an array of dn and options into gPLink string'''
    ret = ''
    for g in gplist:
        ret += "[LDAP://%s;%d]" % (g['dn'], g['options'])
    return ret

def smb_connection(dc_hostname, service, lp, creds, sign=False):
    # SMB connect to DC
    # the SMB bindings rely on having a s3 loadparm
    s3_lp = s3param.get_context()
    if lp.configfile:
        s3_lp.load(lp.configfile)
    else:
        with NamedTemporaryFile('w') as smb_conf:
            smb_conf.write('[global]\nREALM = %s' % lp.get('realm'))
            s3_lp.load(smb_conf.name)
    try:
        conn = smb.Conn(dc_hostname, service, lp=s3_lp, creds=creds, sign=sign)
    except Exception:
        raise CommandError("Error connecting to '%s' using SMB" % dc_hostname)
    return conn

# The samba-tool smb_connection function doesn't handle a missing smb.conf
gpo.smb_connection = smb_connection

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
        cmd_create = gpo_create(self.lp, self.creds, self)
        ycpbuiltins.y2debug(cmd_create.run(displayName))
        cmd_setlink = gpo_setlink(self.lp, self.creds, self)
        if container:
            ycpbuiltins.y2debug(cmd_setlink.run(container, cmd_create.get_name()))

    def delete_link(self, gpo_dn, container_dn):
        cmd_dellink = gpo_dellink(self.lp, self.creds, self)
        gpo_cn = re.split(',?\w\w=', gpo_dn)[1]
        ycpbuiltins.y2debug(cmd_dellink.run(container_dn, gpo_cn))

    def delete_gpo(self, displayName):
        msg = self.gpo_list(displayName, attrs=['cn'])
        if len(msg) == 0:
            raise Exception("GPO '%s' does not exist" % displayName)
        gpo_cn = msg[0][1]['cn'][0]

        cmd_del = gpo_del(self.lp, self.creds, self)
        ycpbuiltins.y2debug(cmd_del.run(gpo_cn))

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
        try:
            self.conn = smb_connection(self.dc_hostname, service, self.lp, self.creds, sign=True)
        except CommandError as e:
            ycpbuiltins.y2error(traceback.format_exc())
            ycpbuiltins.y2error(e.args[-1])
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
        try:
            return self.conn.list(path)
        except NTSTATUSError as e:
            if e.args[0] == 0xC0000034: # Object not found
                ycpbuiltins.y2warning(str(e))
                return []
            else:
                raise

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
        except Exception as e:
            if e.args[0] != 0xC0000034: # Object not found
                ycpbuiltins.y2warning(str(e))
        try:
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

class SambaOptions():
    def __init__(self, lp):
        self.lp = lp

    def get_loadparm(self):
        return self.lp

class CredentialsOptions():
    def __init__(self, creds):
        self.creds = creds

    def get_credentials(self, *args, **kwargs):
        return self.creds

class gpo_create(gpo.cmd_create):
    def __init__(self, lp, creds, samdb):
        super().__init__()
        self.sambaopts = SambaOptions(lp)
        self.credopts = CredentialsOptions(creds)
        self.samdb = samdb
        self.outf = StringIO()

    def samdb_connect(self):
        pass # Our samdb is already connected

    def get_name(self):
        return self.gpo_name

    def run(self, displayname):
        try:
            super().run(displayname, sambaopts=self.sambaopts, credopts=self.credopts)
        except (CommandError, NTSTATUSError, WERRORError, Exception) as e:
            ycpbuiltins.y2error(traceback.format_exc())
            ycpbuiltins.y2error(str(e))
        return self.outf.getvalue()

class gpo_setlink(gpo.cmd_setlink):
    def __init__(self, lp, creds, samdb):
        super().__init__()
        self.sambaopts = SambaOptions(lp)
        self.credopts = CredentialsOptions(creds)
        self.samdb = samdb
        self.outf = StringIO()

    def samdb_connect(self):
        pass # Our samdb is already connected

    def run(self, container_dn, gpo):
        try:
            super().run(container_dn, gpo, sambaopts=self.sambaopts, credopts=self.credopts)
        except (CommandError, NTSTATUSError, WERRORError, Exception) as e:
            ycpbuiltins.y2error(traceback.format_exc())
            ycpbuiltins.y2error(str(e))
        return self.outf.getvalue()

class gpo_dellink(gpo.cmd_dellink):
    def __init__(self, lp, creds, samdb):
        super().__init__()
        self.sambaopts = SambaOptions(lp)
        self.credopts = CredentialsOptions(creds)
        self.samdb = samdb
        self.outf = StringIO()

    def samdb_connect(self):
        pass # Our samdb is already connected

    def run(self, container, gpo):
        try:
            super().run(container, gpo, sambaopts=self.sambaopts, credopts=self.credopts)
        except (CommandError, NTSTATUSError, WERRORError, Exception) as e:
            ycpbuiltins.y2error(traceback.format_exc())
            ycpbuiltins.y2error(str(e))
        return self.outf.getvalue()

class gpo_del(gpo.cmd_del):
    def __init__(self, lp, creds, samdb):
        super().__init__()
        self.sambaopts = SambaOptions(lp)
        self.credopts = CredentialsOptions(creds)
        self.samdb = samdb
        self.outf = StringIO()

    def samdb_connect(self):
        pass # Our samdb is already connected

    def run(self, gpo):
        try:
            super().run(gpo, sambaopts=self.sambaopts, credopts=self.credopts)
        except (CommandError, NTSTATUSError, WERRORError, Exception) as e:
            ycpbuiltins.y2error(traceback.format_exc())
            ycpbuiltins.y2error(str(e))
        return self.outf.getvalue()
