from __future__ import absolute_import, division, print_function, unicode_literals
import ldap, ldap.modlist, ldap.sasl
from samba import smb
from configparser import ConfigParser
from io import StringIO
import xml.etree.ElementTree as etree
import os.path, sys
from samba.net import Net
from samba.dcerpc import nbt
from subprocess import Popen, PIPE
import uuid
from ldap.modlist import addModlist as addlist
from ldap.modlist import modifyModlist as modlist
import re
import traceback
import ldb
from samba.dcerpc import security
from samba.ndr import ndr_unpack
import samba.security
from samba.ntacls import dsacl2fsacl
from yast import ycpbuiltins
import struct
from samba import registry
from collections import OrderedDict

import six

class LdapException(Exception):
    def __init__(self, *args, **kwargs):
        Exception.__init__(self, *args, **kwargs)
        if len(self.args) > 0:
            self.msg = self.args[0]
        else:
            self.msg = None
        if len(self.args) > 1:
            self.info = self.args[1]
        else:
            self.info = None

def _ldap_exc_msg(e):
    if len(e.args) > 0 and \
      type(e.args[-1]) is dict and \
      'desc' in e.args[-1]:
        return e.args[-1]['desc']
    else:
        return str(e)

def _ldap_exc_info(e):
    if len(e.args) > 0 and \
      type(e.args[-1]) is dict and \
      'info' in e.args[-1]:
        return e.args[-1]['info']
    else:
        return ''

def ldap_search(l, *args):
    try:
        return l.search_s(*args)
    except Exception as e:
        ycpbuiltins.y2error(traceback.format_exc())
        ycpbuiltins.y2error('ldap.search_s: %s\n' % _ldap_exc_msg(e))

def ldap_add(l, *args):
    try:
        return l.add_s(*args)
    except Exception as e:
        raise LdapException(_ldap_exc_msg(e), _ldap_exc_info(e))

def ldap_modify(l, *args):
    try:
        return l.modify(*args)
    except Exception as e:
        ycpbuiltins.y2error(traceback.format_exc())
        ycpbuiltins.y2error('ldap.modify: %s\n' % _ldap_exc_msg(e))

def ldap_delete(l, *args):
    try:
        return l.delete_s(*args)
    except Exception as e:
        ycpbuiltins.y2error(traceback.format_exc())
        ycpbuiltins.y2error('ldap.delete_s: %s\n' % _ldap_exc_msg(e))

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

REGFILE_SIGNATURE = 0x67655250
REGISTRY_FILE_VERSION = 1
def unpack_registry_pol(data):
    pol_conf = OrderedDict()
    sig = struct.unpack('<L', data[:4])[0]
    if sig != REGFILE_SIGNATURE:
        raise IOError('Registry file signature did not match')
    vers = struct.unpack('<L', data[4:8])[0]
    if vers != REGISTRY_FILE_VERSION:
        raise IOError('Registry file version did not match')
    o = 7
    while o < len(data)-1:
        obrack = data[o:o+2].decode('utf-16-be')
        if obrack != '[':
            raise IOError('Failed unpacking data from registry pol')
        o += 2
        rk_epos = data[o:].find(b';')-1
        if rk_epos < 0:
            raise IOError('Failed unpacking data from registry pol')
        try:
            reg_key = data[o:o+rk_epos-2].decode('utf-16-be')
        except UnicodeDecodeError:
            raise IOError('Failed unpacking data from registry pol')
        if not reg_key in pol_conf.keys():
            pol_conf[reg_key] = {}
        o += rk_epos
        osep = data[o:o+2].decode('utf-16-be')
        if osep != ';':
            raise IOError('Failed unpacking data from registry pol')
        o += 2
        rk_epos = data[o:].find(b';')-1
        if rk_epos < 0:
            raise IOError('Failed unpacking data from registry pol')
        key = data[o:o+rk_epos-2].decode('utf-16-be')
        o += rk_epos
        osep = data[o:o+2].decode('utf-16-be')
        if osep != ';':
            raise IOError('Failed unpacking data from registry pol')
        o += 2
        rk_epos = data[o:].find(b';')-1
        if rk_epos < 0:
            raise IOError('Failed unpacking data from registry pol')
        ntype = struct.unpack(">Hxx", data[o:o+rk_epos])[0]
        rtype = registry.str_regtype(ntype)
        o += rk_epos
        osep = data[o:o+2].decode('utf-16-be')
        if osep != ';':
            raise IOError('Failed unpacking data from registry pol')
        o += 2
        rsize = struct.unpack("<xHx", data[o:o+4])[0]
        o += 4
        osep = data[o:o+2].decode('utf-16-be')
        if osep != ';':
            raise IOError('Failed unpacking data from registry pol')
        o += 2
        if rtype == 'REG_SZ':
            val = data[o:o+rsize][:-2].decode('utf-16-be')
        elif rtype == 'REG_DWORD':
            val = struct.unpack("<xHx", data[o:o+rsize])[0]
        elif rtype == 'REG_BINARY':
            val = data[o:o+rsize]
        elif rtype == 'REG_NONE':
            val = None
        else:
            ycpbuiltins.y2warning('%s Not Implemented' % rtype)
            raise IOError('Failed unpacking value from registry pol')
        o += rsize
        cbrack = data[o:o+2]
        if cbrack != b'\x00]' and cbrack != b'<]':
            raise IOError('Failed unpacking data from registry pol')
        o += 2

        pol_conf[reg_key][key] = {}
        pol_conf[reg_key][key]['value'] = val
        pol_conf[reg_key][key]['type'] = ntype
        pol_conf[reg_key][key]['size'] = rsize
    return pol_conf

def pack_registry_pol(pol_conf):
    ret = struct.pack('<L', REGFILE_SIGNATURE)
    ret += struct.pack('<Hx', REGISTRY_FILE_VERSION)
    for reg_key in pol_conf.keys():
        for key in pol_conf[reg_key].keys():
            ret += b'\x00['
            ret += reg_key.encode('utf-16-be')
            ret += b'\x00\x00'
            ret += b'\x00;'
            ret += key.encode('utf-16-be')
            ret += b'\x00\x00'
            ret += b'\x00;'
            ret += struct.pack(">Hxx", pol_conf[reg_key][key]['type'])
            ret += b'\x00;'
            ret += struct.pack("<xHx", pol_conf[reg_key][key]['size'])
            ret += b'\x00;'
            rtype = registry.str_regtype(pol_conf[reg_key][key]['type'])
            if rtype == 'REG_SZ':
                ret += pol_conf[reg_key][key]['value'].encode('utf-16-be') + b'\x00\x00'
            elif rtype == 'REG_DWORD':
                ret += struct.pack("<xHx", pol_conf[reg_key][key]['value'])
            elif rtype == 'REG_BINARY':
                ret += pol_conf[reg_key][key]['value']
            elif rtype == 'REG_NONE':
                pass
            else:
                raise IOError('Failed packing value for registry pol')
            if rtype == 'REG_BINARY':
                ret += b'<]'
            else:
                ret += b'\x00]'
    ret += b'\x00'
    return ret

class GPConnection:
    def __init__(self, lp, creds):
        self.lp = lp
        self.creds = creds
        net = Net(creds=creds, lp=lp)
        cldap_ret = net.finddc(domain=lp.get('realm'), flags=(nbt.NBT_SERVER_LDAP | nbt.NBT_SERVER_DS | nbt.NBT_SERVER_WRITABLE))
        self.realm = cldap_ret.dns_domain
        self.dc_hostname = cldap_ret.pdc_dns_name
        self.l = ldap.initialize('ldap://%s' % cldap_ret.pdc_dns_name)
        if self.__kinit_for_gssapi():
            auth_tokens = ldap.sasl.gssapi('')
            self.l.sasl_interactive_bind_s('', auth_tokens)
        else:
            self.l.bind_s('%s@%s' % (creds.get_username(), self.realm) if not self.realm in creds.get_username() else creds.get_username(), creds.get_password())
        self.l.set_option(ldap.OPT_REFERRALS,0)

    def __kinit_for_gssapi(self):
        p = Popen(['kinit', '%s@%s' % (self.creds.get_username(), self.realm) if not self.realm in self.creds.get_username() else self.creds.get_username()], stdin=PIPE, stdout=PIPE, stderr=PIPE)
        p.stdin.write(('%s\n'%self.creds.get_password()).encode())
        p.stdin.flush()
        return p.wait() == 0

    def realm_to_dn(self, realm):
        return ','.join(['DC=%s' % part for part in realm.lower().split('.')])

    def __well_known_container(self, container):
        res = None
        if container == 'system':
            wkguiduc = 'AB1D30F3768811D1ADED00C04FD8D5CD'
        elif container == 'computers':
            wkguiduc = 'AA312825768811D1ADED00C04FD8D5CD'
        elif container == 'dcs':
            wkguiduc = 'A361B2FFFFD211D1AA4B00C04FD7D83A'
        elif container == 'users':
            wkguiduc = 'A9D1CA15768811D1ADED00C04FD8D5CD'
        result = ldap_search(self.l, '<WKGUID=%s,%s>' % (wkguiduc, self.realm_to_dn(self.realm)), ldap.SCOPE_SUBTREE, '(objectClass=container)', stringify_ldap(['distinguishedName']))
        result = stringify_ldap(result)
        if result and len(result) > 0 and len(result[0]) > 1 and 'distinguishedName' in result[0][1] and len(result[0][1]['distinguishedName']) > 0:
            res = result[0][1]['distinguishedName'][-1]

        return stringify_ldap(res)

    def user_from_sid(self, sid, attrs=[]):
        res = ldap_search(self.l, self.__well_known_container('users'), ldap.SCOPE_SUBTREE, '(objectSID=%s)' % sid, stringify_ldap(attrs))
        return res[0][1]

    def get_domain_sid(self):
        res = ldap_search(self.l, self.realm_to_dn(self.realm), ldap.SCOPE_BASE, "(objectClass=*)", [])
        return ndr_unpack(security.dom_sid, res[0][1]["objectSid"][0])

    def gpo_list(self, displayName=None, attrs=[]):
        result = None
        res = self.__well_known_container('system')
        search_expr = '(objectClass=groupPolicyContainer)'
        if displayName is not None:
            search_expr = '(&(objectClass=groupPolicyContainer)(displayname=%s))' % ldb.binary_encode(displayName)
        result = ldap_search(self.l, res, ldap.SCOPE_SUBTREE, search_expr, stringify_ldap(attrs))
        result = stringify_ldap(result)
        return result

    def set_attr(self, dn, key, value):
        ldap_modify(self.l, dn, stringify_ldap([(1, key, None), (0, key, value)]))

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
            ldap_add(self.l, dn, addlist(stringify_ldap(ldap_mod)))
            ldap_add(self.l, machine_dn, addlist(stringify_ldap(sub_ldap_mod)))
            ldap_add(self.l, user_dn, addlist(stringify_ldap(sub_ldap_mod)))
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
        msg = ldap_search(self.l,
                         container_dn, ldap.SCOPE_BASE,
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
                if g['dn'].lower() == gpo_dn.lower():
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
            ldap_modify(self.l, container_dn, stringify_ldap([(1, 'gPLink', None), (0, 'gPLink', [gplink_str.encode('utf-8')])]))
        else:
            ldap_modify(self.l, container_dn, stringify_ldap([(0, 'gPLink', [gplink_str.encode('utf-8')])]))

    def delete_link(self, gpo_dn, container_dn):
        # Check if valid Container DN
        msg = ldap_search(self.l,
                         container_dn, ldap.SCOPE_BASE,
                         "(objectClass=*)",
                         stringify_ldap(['gPLink']))[0][1]

        found = False
        if 'gPLink' in msg:
            gplist = parse_gplink(msg['gPLink'][0])
            gplist = [gplist[k] for k in gplist]
            for g in gplist:
                if g['dn'].lower() == gpo_dn.lower():
                    gplist.remove(g)
                    found = True
                    break
        else:
            raise Exception("No GPO(s) linked to this container")

        if not found:
            raise Exception("GPO '%s' not linked to this container" % gpo_dn)

        if gplist:
            gplink_str = encode_gplink(gplist)
            ldap_modify(self.l, container_dn, stringify_ldap([(ldap.MOD_DELETE, 'gPLink', None), (ldap.MOD_ADD, 'gPLink', [gplink_str.encode('utf-8')])]))
        else:
            ldap_modify(self.l, container_dn, stringify_ldap([(ldap.MOD_DELETE, 'gPLink', None)]))

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
        ldap_delete(self.l, "CN=User,%s" % str(gpo_dn))
        ldap_delete(self.l, "CN=Machine,%s" % str(gpo_dn))
        ldap_delete(self.l, gpo_dn)
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
        msg = ldap_search(self.l, self.realm_to_dn(self.realm), ldap.SCOPE_SUBTREE, search_expr, [])
        if not msg:
            return []

        return [res[1] for res in msg if type(res[1]) is dict]

    def get_gpos_for_container(self, container_dn):
        search_expr = '(distinguishedName=%s)' % container_dn
        msg = ldap_search(self.l, self.realm_to_dn(self.realm), ldap.SCOPE_SUBTREE, search_expr, [])
        if not msg:
            return None

        results = []
        if 'gPLink' in msg[0][1]:
            gpos = parse_gplink(msg[0][1]['gPLink'][-1])
        else:
            gpos = []
        for gpo in gpos:
            search_expr = '(distinguishedName=%s)' % gpos[gpo]['dn']
            msg = ldap_search(self.l, self.realm_to_dn(self.realm), ldap.SCOPE_SUBTREE, search_expr, [])
            results.append(msg[0])

        return results

    def get_containers_with_gpos(self):
        search_expr = "(|(objectClass=organizationalUnit)(objectClass=domain))"
        msg = ldap_search(self.l, self.realm_to_dn(self.realm), ldap.SCOPE_SUBTREE, search_expr, [])
        if not msg:
            return []

        return [res[1] for res in msg if type(res[1]) is dict]

class GPOConnection(GPConnection):
    def __init__(self, lp, creds, gpo_path):
        GPConnection.__init__(self, lp, creds)
        [dom_name, service, self.path] = parse_unc(gpo_path)
        path_parts = [n for n in gpo_path.split('\\') if n]
        self.path_start = '\\\\' + '\\'.join([dom_name, service])
        self.name = gpo_path.split('\\')[-1]
        self.realm_dn = self.realm_to_dn(self.realm)
        self.gpo_dn = 'CN=%s,CN=Policies,CN=System,%s' % (self.name, self.realm_dn)
        try:
            self.conn = smb.SMB(self.dc_hostname, service, lp=self.lp, creds=self.creds)
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
        resp = ldap_search(self.l, dn, ldap.SCOPE_SUBTREE, '(objectCategory=packageRegistration)', [])
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
            ldap_add(self.l, dn, addlist(stringify_ldap(attrs)))
        except LdapException as e:
            if e.msg == 'No such object':
                self.__mkdn_p(','.join(dn.split(',')[1:]))
            elif e.msg == 'Already exists':
                return
            else:
                ycpbuiltins.y2error(traceback.format_exc())
                ycpbuiltins.y2error('ldap.add_s: %s\n' % e.info if e.info else e.msg)
        try:
            ldap_add(self.l, dn, addlist(stringify_ldap(attrs)))
        except LdapException as e:
            if e.msg != 'Already exists':
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
                ldap_add(self.l, obj_dn, addlist(stringify_ldap(ldap_config[cn])))
            except LdapException as e:
                if e.msg == 'Already exists':
                    ldap_modify(self.l, obj_dn, modlist({}, stringify_ldap(ldap_config[cn])))
                else:
                    ycpbuiltins.y2error(traceback.format_exc())
                    ycpbuiltins.y2error('ldap.add_s: %s\n' % e.info if e.info else e.msg)

            if os.path.splitext(ldap_config[cn]['msiFileList'][-1])[-1] == b'.zap':
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
                pol_conf = unpack_registry_pol(raw)
            except:
                pol_conf = None
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
        buf = pack_registry_pol(pol_conf)
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
                self.conn.savefile(filename, value)
            except Exception as e:
                if e.args[0] == 0xC0000035: # STATUS_OBJECT_NAME_COLLISION
                    ycpbuiltins.y2error('The file \'%s\' already exists at \'%s\' and could not be saved.' % (os.path.basename(local), remote_path))
                else:
                    ycpbuiltins.y2error(e.args[1])
            return filename
