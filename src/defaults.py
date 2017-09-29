#!/usr/bin/env python
import xml.etree.ElementTree as etree
import uuid
import os.path
from subprocess import Popen, PIPE

import ycp
ycp.import_module('UI')
from ycp import *
def select_script(title, script_type, conn):
    full_path = UI.AskForExistingFile('/', '*.sh *.py *.pl', title)
    conn.upload_file(full_path, 'MACHINE\\Scripts\\%s' % script_type)
    return ({}, os.path.basename(full_path))

def query_rpm(filename):
    out,_ = Popen(['rpm', '-qip', filename], stdout=PIPE, stderr=PIPE).communicate()
    return {line.split(':')[0].strip() : ':'.join(line.split(':')[1:]).strip() for line in out.strip().split('\n')}

def select_exec(title, policy, conn):
    full_path = UI.AskForExistingFile('/', '*.rpm', title)
    rpm_data = query_rpm(full_path)
    others = {'Name' : rpm_data['Name'], 'Version': rpm_data['Release']}
    path = '%s\\%s' % (conn.path_start, conn.upload_file(full_path, 'MACHINE\\Applications'))
    return (others, path)

def fetch_inf_value(inf_conf, section, key):
    return inf_conf.get(section, key).encode('ascii') if inf_conf.has_section(section) and inf_conf.has_option(section, key) else None

def set_inf_value(inf_conf, section, key, value):
    if not inf_conf.has_section('Unicode'):
        inf_conf.add_section('Unicode')
        inf_conf.set('Unicode', 'Unicode', 'yes')
    if not inf_conf.has_section('Version'):
        inf_conf.add_section('Version')
        inf_conf.set('Version', 'signature', '"$CHICAGO$"')
        inf_conf.set('Version', 'Revision', '1')
    if value:
        if not inf_conf.has_section(section):
            inf_conf.add_section(section)
        inf_conf.set(section, key, value)
    elif inf_conf.has_section(section) and inf_conf.has_option(section, key):
        inf_conf.remove_option(section, key)

def set_ins_value(ins_conf, section, key, value):
    if value:
        if not ins_conf.has_section(section):
            ins_conf.add_section(section)
        ins_conf.set(section, key, value)
    elif ins_conf.has_section(section) and ins_conf.has_option(section, key):
        ins_conf.remove_option(section, key)

def fetch_ins_value(ins_conf, section, key):
    return ins_conf.get(section, key).encode('ascii') if ins_conf.has_section(section) and ins_conf.has_option(section, key) else ''

def iter_scripts_conf(inf_conf, section):
    if inf_conf.has_section(section):
        for option in inf_conf.options(section):
            if 'CmdLine' in option:
                yield option.encode('ascii')
    else:
        for option in []:
            yield option

def script_get_next_option(inf_conf, section):
    if inf_conf.has_section(section):
        high_digit = -1
        for option in inf_conf.options(section):
            if 'CmdLine' in option:
                val = int(option[:-7])
                if val > high_digit:
                    high_digit = val
        return '%dCmdLine' % (high_digit+1)
    else:
        return '0CmdLine'

def software_install_set_option(ldap_conf, section, option, v):
    ldap_conf[section][option] = [v]

def software_install_set_version(ldap_conf, section, v):
    software_install_set_option(ldap_conf, section, 'versionNumberHi', v.split('.')[0])
    software_install_set_option(ldap_conf, section, 'versionNumberLo', '.'.join(v.split('.')[1:]))

def software_install_new_option(ldap_conf):
    siuuid = str(uuid.uuid4()).upper()
    ldap_conf[siuuid] = {}
    return siuuid

def script_set_option(inf_conf, section, option, v):
    if not inf_conf.has_section(section):
        inf_conf.add_section(section)
    inf_conf.set(section, option, v)

def new_environment_tree():
    top = etree.Element('EnvironmentVariables')
    top.set('clsid', '{%s}' % str(uuid.uuid4()).upper())
    etree.ElementTree(top)
    return top

def env_add(xml_conf):
    top = etree.SubElement(xml_conf, 'EnvironmentVariable')
    clsid = None
    others = xml_conf.findall('EnvironmentVariable')
    if len(others) > 0 and 'clsid' in others[0].attrib.keys():
        clsid = others[0].attrib['clsid']
    if not clsid:
        clsid = '{%s}' % str(uuid.uuid4()).upper()
    top.set('clsid', clsid)
    top.set('uid', '{%s}' % str(uuid.uuid4()).upper())
    prop = etree.SubElement(top, 'Properties')
    return top

Policies = {
    'comp_passwd' : {
        'file' : '\\MACHINE\\Microsoft\\Windows NT\\SecEdit\\GptTmpl.inf',
        'opts' : (lambda inf_conf : {
            'MinimumPasswordAge' : {
                'values' : Policies['comp_passwd']['values'](
                    inf_conf, 'MinimumPasswordAge', 'Minimum password age',
                    (lambda v : '%s days' % v if v else 'Not Defined'),
                    {
                        'type' : 'TextEntry',
                        'options' : None,
                    },
                ),
            },
            'MaximumPasswordAge' : {
                'values' : Policies['comp_passwd']['values'](
                    inf_conf, 'MaximumPasswordAge', 'Maximum password age',
                    (lambda v : '%s days' % v if v else 'Not Defined'),
                    {
                        'type' : 'TextEntry',
                        'options' : None,
                    },
                ),
            },
            'MinimumPasswordLength' : {
                'values' : Policies['comp_passwd']['values'](
                    inf_conf, 'MinimumPasswordLength', 'Minimum password length',
                    (lambda v : '%s characters' % v if v else 'Not Defined'),
                    {
                        'type' : 'TextEntry',
                        'options' : None,
                    },
                ),
            },
            'PasswordComplexity' : {
                'values' : Policies['comp_passwd']['values'](
                    inf_conf, 'PasswordComplexity', 'Password must meet complexity requirements',
                    (lambda v : 'Not Defined' if not v else 'Disabled' if int(v) == 0 else 'Enabled'),
                    {
                        'type' : 'ComboBox',
                        'options' : {'Enabled' : '1', 'Disabled' : '0'},
                    },
                ),
            },
            'PasswordHistorySize' : {
                'values' : Policies['comp_passwd']['values'](
                    inf_conf, 'PasswordHistorySize', 'Enforce password history',
                    (lambda v : '%s passwords remembered' % v if v else 'Not Defined'),
                    {
                        'type' : 'TextEntry',
                        'options' : None,
                    },
                ),
            },
            'ClearTextPassword' : {
                'values' : Policies['comp_passwd']['values'](
                    inf_conf, 'ClearTextPassword', 'Store passwords using reversible encryption',
                    (lambda v : 'Not Defined' if not v else 'Disabled' if int(v) == 0 else 'Enabled'),
                    {
                        'type' : 'ComboBox',
                        'options' : {'Enabled' : '1', 'Disabled' : '0'},
                    },
                ),
            },
        } ),
        'gpe_extension' : None,
        'new' : None,
        'add' : None,
        'header' : (lambda : ['Policy', 'Policy Setting']),
        'values' : (lambda conf, setting, desc, valstr, _input : {
            'policy' : {
                'order' : 0,
                'title' : 'Policy',
                'get' : setting,
                'set' : None,
                'valstr' : (lambda v : desc),
                'input' : {
                    'type' : 'Label',
                    'options' : None,
                },
            },
            'value' : {
                'order' : 1,
                'title' : 'Policy Setting',
                'get' : fetch_inf_value(conf, 'System Access', setting),
                'set' : (lambda v : set_inf_value(conf, 'System Access', setting, v)),
                'valstr' : valstr,
                'input' : _input,
            },
        } ),
    },
    'comp_lockout' : {
        'file' : '\\MACHINE\\Microsoft\\Windows NT\\SecEdit\\GptTmpl.inf',
        'opts' : (lambda inf_conf : {
            'LockoutDuration' : {
                'values' : Policies['comp_lockout']['values'](
                    inf_conf, 'LockoutDuration', 'Account lockout duration',
                    (lambda v : '%s minutes' % v if v else 'Not Defined'),
                    {
                        'type' : 'TextEntry',
                        'options' : None,
                    },
                ),
            },
            'LockoutBadCount' : {
                'values' : Policies['comp_lockout']['values'](
                    inf_conf, 'LockoutBadCount', 'Account lockout threshold',
                    (lambda v : '%s invalid logon attempts' % v if v else 'Not Defined'),
                    {
                        'type' : 'TextEntry',
                        'options' : None,
                    },
                ),
            },
            'ResetLockoutCount' : {
                'values' : Policies['comp_lockout']['values'](
                    inf_conf, 'ResetLockoutCount', 'Reset account lockout counter after',
                    (lambda v : '%s minutes' % v if v else 'Not Defined'),
                    {
                        'type' : 'TextEntry',
                        'options' : None,
                    },
                ),
            },
        } ),
        'gpe_extension' : None,
        'new' : None,
        'add' : None,
        'header' : (lambda : ['Policy', 'Policy Setting']),
        'values' : (lambda conf, setting, desc, valstr, _input : {
            'policy' : {
                'order' : 0,
                'title' : 'Policy',
                'get' : setting,
                'set' : None,
                'valstr' : (lambda v : desc),
                'input' : {
                    'type' : 'Label',
                    'options' : None,
                },
            },
            'value' : {
                'order' : 1,
                'title' : 'Policy Setting',
                'get' : fetch_inf_value(conf, 'System Access', setting),
                'set' : (lambda v : set_inf_value(conf, 'System Access', setting, v)),
                'valstr' : valstr,
                'input' : _input,
            },
        } ),
    },
    'comp_krb' : {
        'file' : '\\MACHINE\\Microsoft\\Windows NT\\SecEdit\\GptTmpl.inf',
        'opts' : (lambda inf_conf : {
            'MaxTicketAge' : {
                'values' : Policies['comp_krb']['values'](
                    inf_conf, 'MaxTicketAge', 'Maximum lifetime for user ticket',
                    (lambda v : '%s hours' % v if v else 'Not Defined'),
                    {
                        'type' : 'TextEntry',
                        'options' : None,
                    },
                ),
            },
            'MaxRenewAge' : {
                'values' : Policies['comp_krb']['values'](
                    inf_conf, 'MaxRenewAge', 'Maximum lifetime for user ticket renewal',
                    (lambda v : '%s minutes' % v if v else 'Not Defined'),
                    {
                        'type' : 'TextEntry',
                        'options' : None,
                    },
                ),
            },
            'MaxServiceAge' : {
                'values' : Policies['comp_krb']['values'](
                    inf_conf, 'MaxServiceAge', 'Maximum lifetime for service ticket',
                    (lambda v : '%s minutes' % v if v else 'Not Defined'),
                    {
                        'type' : 'TextEntry',
                        'options' : None,
                    },
                ),
            },
            'MaxClockSkew' : {
                'values' : Policies['comp_krb']['values'](
                    inf_conf, 'MaxClockSkew', 'Maximum tolerance for computer clock synchronization',
                    (lambda v : '%s minutes' % v if v else 'Not Defined'),
                    {
                        'type' : 'TextEntry',
                        'options' : None,
                    },
                ),
            },
            'TicketValidateClient' : {
                'values' : Policies['comp_krb']['values'](
                    inf_conf, 'TicketValidateClient', 'Enforce user logon restrictions',
                    (lambda v : 'Not Defined' if not v else 'Disabled' if int(v) == 0 else 'Enabled'),
                    {
                        'type' : 'ComboBox',
                        'options' : {'Enabled' : '1', 'Disabled' : '0'},
                    }
                ),
            },
        } ),
        'gpe_extension' : None,
        'new' : None,
        'add' : None,
        'header' : (lambda : ['Policy', 'Policy Setting']),
        'values' : (lambda conf, setting, desc, valstr, _input : {
            'policy' : {
                'order' : 0,
                'title' : 'Policy',
                'get' : setting,
                'set' : None,
                'valstr' : (lambda v : desc),
                'input' : {
                    'type' : 'Label',
                    'options' : None,
                },
            },
            'value' : {
                'order' : 1,
                'title' : 'Policy Setting',
                'get' : fetch_inf_value(conf, 'Kerberos Policy', setting),
                'set' : (lambda v : set_inf_value(conf, 'Kerberos Policy', setting, v)),
                'valstr' : valstr,
                'input' : _input,
            },
        } ),
    },
    'comp_env_var' : {
        'file': '\\MACHINE\\Preferences\\EnvironmentVariables\\EnvironmentVariables.xml',
        'opts' : (lambda xml_conf : {
            a.attrib['name']: {
                'values' : Policies['comp_env_var']['values'](a),
            } for a in xml_conf.findall('EnvironmentVariable')
        } ),
        'gpe_extension' : '{0E28E245-9368-4853-AD84-6DA3BA35BB75}{35141B6B-498A-4CC7-AD59-CEF93D89B2CE}',
        'new' : (lambda : new_environment_tree()),
        'add' : (lambda xml_conf : Policies['comp_env_var']['values'](env_add(xml_conf))),
        'header' : (lambda : [k['title'] for k in sorted(Policies['comp_env_var']['values'](None).values(), key=(lambda x : x['order']))]),
        'values' : (lambda a : {
            'name' : {
                'order' : 0,
                'title' : 'Name',
                'get' : a.attrib['name'] if a is not None and 'name' in a.attrib.keys() else '',
                'set' : (lambda v : [a.set('name', v), a.find('Properties').set('name', v), a.set('status', '%s = %s' % (v, a.attrib['value'] if 'value' in a.attrib.keys() else ''))]),
                'valstr' : (lambda v : v),
                'input' : {
                    'type' : 'TextEntry',
                    'options' : None,
                },
            },
            'value' : {
                'order' : 2,
                'title' : 'Value',
                'get' : a.find('Properties').attrib['value'] if a is not None and a.find('Properties') is not None and 'value' in a.find('Properties').attrib.keys() else '',
                'set' : (lambda v : [a.find('Properties').set('value', v), a.set('status', '%s = %s' % (a.attrib['name'] if 'name' in a.attrib.keys() else '', v))]),
                'valstr' : (lambda v : v),
                'input' : {
                    'type' : 'TextEntry',
                    'options' : None,
                },
            },
            'user' : {
                'order' : 3,
                'title' : 'User',
                'get' : a.find('Properties').attrib['user'] if a is not None and a.find('Properties') is not None and 'user' in a.find('Properties').attrib.keys() else '0',
                'set' : (lambda v : a.find('Properties').set('user', v)),
                'valstr' : (lambda v : 'No' if int(v) == 0 else 'Yes'),
                'input' : {
                    'type' : 'ComboBox',
                    'options' : {'Yes' : '1', 'No' : '0'},
                },
            },
            'action' : {
                'order' : 1,
                'title' : 'Action',
                'get' : a.find('Properties').attrib['action'] if a is not None and a.find('Properties') is not None and 'action' in a.find('Properties').attrib.keys() else 'U',
                'set' : (lambda v : a.find('Properties').set('action', v)),
                'valstr' : (lambda v : {'U' : 'Update', 'C' : 'Create', 'R' : 'Replace', 'D' : 'Delete'}[v]),
                'input' : {
                    'type' : 'ComboBox',
                    'options' : {'Update' : 'U', 'Create' : 'C', 'Replace' : 'R', 'Delete' : 'D'},
                },
            },
        } ),
    },
    'comp_scripts_startup': {
        'file' : '\\MACHINE\\Scripts\\scripts.ini',
        'opts' : (lambda inf_conf : {
            option : {
                'values' : Policies['comp_scripts_startup']['values'](inf_conf, option),
            } for option in iter_scripts_conf(inf_conf, 'Startup')
        } ),
        'gpe_extension' : None,
        'new' : None,
        'add' : (lambda inf_conf : Policies['comp_scripts_startup']['values'](inf_conf, script_get_next_option(inf_conf, 'Startup'))),
        'header' : (lambda : [k['title'] for k in sorted(Policies['comp_scripts_startup']['values'](None, None).values(), key=(lambda x : x['order']))]),
        'values' : (lambda inf_conf, option : {
            'CmdLine' : {
                'order' : 0,
                'title' : 'CmdLine',
                'get' : inf_conf.get('Startup', option).encode('ascii') if inf_conf and inf_conf.has_option('Startup', option) else '',
                'set' : (lambda v : script_set_option(inf_conf, 'Startup', option, v)),
                'valstr' : (lambda v : v),
                'input' : {
                    'type' : 'ButtonEntry',
                    'options' : None,
                    'action' : select_script,
                },
            },
            'Parameters' : {
                'order' : 1,
                'title' : 'Parameters',
                'get' : inf_conf.get('Startup', '%sParameters' % option[:-7]).encode('ascii') if inf_conf and inf_conf.has_option('Startup', '%sParameters' % option[:-7]) else '',
                'set' : (lambda v : script_set_option(inf_conf, 'Startup', '%sParameters' % option[:-7], v)),
                'valstr' : (lambda v : v),
                'input' : {
                    'type' : 'TextEntry',
                    'options' : None,
                },
            },
        } ),
    },
    'comp_scripts_shutdown': {
        'file' : '\\MACHINE\\Scripts\\scripts.ini',
        'opts' : (lambda inf_conf : {
            option : {
                'values' : Policies['comp_scripts_shutdown']['values'](inf_conf, option),
            } for option in iter_scripts_conf(inf_conf, 'Shutdown')
        } ),
        'gpe_extension' : None,
        'new' : None,
        'add' : (lambda inf_conf : Policies['comp_scripts_shutdown']['values'](inf_conf, script_get_next_option(inf_conf, 'Shutdown'))),
        'header' : (lambda : [k['title'] for k in sorted(Policies['comp_scripts_shutdown']['values'](None, None).values(), key=(lambda x : x['order']))]),
        'values' : (lambda inf_conf, option : {
            'CmdLine' : {
                'order' : 0,
                'title' : 'CmdLine',
                'get' : inf_conf.get('Shutdown', option).encode('ascii') if inf_conf and inf_conf.has_option('Shutdown', option) else '',
                'set' : (lambda v : script_set_option(inf_conf, 'Shutdown', option, v)),
                'valstr' : (lambda v : v),
                'input' : {
                    'type' : 'ButtonEntry',
                    'options' : None,
                    'action' : select_script,
                },
            },
            'Parameters' : {
                'order' : 1,
                'title' : 'Parameters',
                'get' : inf_conf.get('Shutdown', '%sParameters' % option[:-7]).encode('ascii') if inf_conf and inf_conf.has_option('Shutdown', '%sParameters' % option[:-7]) else '',
                'set' : (lambda v : script_set_option(inf_conf, 'Shutdown', '%sParameters' % option[:-7], v)),
                'valstr' : (lambda v : v),
                'input' : {
                    'type' : 'TextEntry',
                    'options' : None,
                },
            },
        } ),
    },
    'comp_software_install': {
        'file' : 'CN=Packages,CN=Class Store,CN=Machine,%s',
        'opts' : (lambda ldap_conf : {
            option : {
                'values' : Policies['comp_software_install']['values'](ldap_conf, option)
            } for option in ldap_conf.keys()
        } ),
        'gpe_extension' : None,
        'new' : None,
        'add' : (lambda ldap_conf : Policies['comp_software_install']['values'](ldap_conf, software_install_new_option(ldap_conf))),
        'header' : (lambda : [k['title'] for k in sorted(Policies['comp_software_install']['values'](None, None).values(), key=(lambda x : x['order']))]),
        'values' : (lambda ldap_conf, option : {
            'Name' : {
                'order' : 0,
                'title' : 'Name',
                'get' : ldap_conf[option]['displayName'][-1] if ldap_conf and 'displayName' in ldap_conf[option].keys() else '',
                'set' : (lambda v : software_install_set_option(ldap_conf, option, 'displayName', v)),
                'valstr' : (lambda v : v),
                'input' : {
                    'type' : 'TextEntry',
                    'options' : None,
                },
            },
            'Version' : {
                'order' : 1,
                'title' : 'Version',
                'get' : '%s.%s' % (ldap_conf[option]['versionNumberHi'][-1], ldap_conf[option]['versionNumberLo'][-1]) if ldap_conf and 'versionNumberHi' in ldap_conf[option].keys() and 'versionNumberLo' in ldap_conf[option].keys() else '',
                'set' : (lambda v : software_install_set_version(ldap_conf, option, v)),
                'valstr' : (lambda v : v),
                'input' : {
                    'type' : 'TextEntry',
                    'options' : None,
                },
            },
            'Source' : {
                'order' : 2,
                'title' : 'Source',
                'get' : ldap_conf[option]['msiScriptPath'][-1] if ldap_conf and 'msiScriptPath' in ldap_conf[option].keys() else '',
                'set' : (lambda v : software_install_set_option(ldap_conf, option, 'msiScriptPath', v)),
                'valstr' : (lambda v : v),
                'input' : {
                    'type' : 'ButtonEntry',
                    'options' : None,
                    'action' : select_exec,
                },
            },
        } ),
    },
    'user_internet_maint_conn' : {
        'file': '\\USER\\MICROSOFT\\IEAK\\install.ins',
        'opts' : (lambda ins_conf : {
            'Proxy Settings' : {
                'values' : {
                    'Name' : {
                        'order' : 0,
                        'title' : 'Name',
                        'get' : 'Proxy Settings',
                        'set' : None,
                        'valstr' : (lambda v : v),
                        'input' : {
                            'type' : None,
                            'options' : None,
                        },
                    },
                    'Description' : {
                        'order' : 1,
                        'title' : 'Description',
                        'get' : 'Settings for proxy',
                        'set' : None,
                        'valstr' : (lambda v : v),
                        'input' : {
                            'type' : 'Label',
                            'options' : None,
                        },
                    },
                    'Proxy_Enable' : {
                        'order' : 2,
                        'title' : 'Enable proxy settings',
                        'get' : fetch_ins_value(ins_conf, 'Proxy', 'Proxy_Enable'),
                        'set' : (lambda v : set_ins_value(ins_conf, 'Proxy', 'Proxy_Enable', v)),
                        'valstr' : (lambda v : 'Disabled' if not v else 'Disabled' if int(v) == 0 else 'Enabled'),
                        'input' : {
                            'type' : 'ComboBox',
                            'options' : {'Enabled' : '1', 'Disabled' : '0'},
                        },
                    },
                    'HTTP_Proxy_Server' : {
                        'order' : 3,
                        'title' : 'Address of HTTP proxy',
                        'get' : fetch_ins_value(ins_conf, 'Proxy', 'HTTP_Proxy_Server'),
                        'set' : (lambda v : set_ins_value(ins_conf, 'Proxy', 'HTTP_Proxy_Server', v)),
                        'valstr' : (lambda v : v),
                        'input' : {
                            'type' : 'TextEntry',
                            'options' : None,
                        },
                    },
                    'Secure_Proxy_Server' : {
                        'order' : 4,
                        'title' : 'Address of Secure proxy',
                        'get' : fetch_ins_value(ins_conf, 'Proxy', 'Secure_Proxy_Server'),
                        'set' : (lambda v : set_ins_value(ins_conf, 'Proxy', 'Secure_Proxy_Server', v)),
                        'valstr' : (lambda v : v),
                        'input' : {
                            'type' : 'TextEntry',
                            'options' : None,
                        },
                    },
                    'FTP_Proxy_Server' : {
                        'order' : 5,
                        'title' : 'Address of FTP proxy',
                        'get' : fetch_ins_value(ins_conf, 'Proxy', 'FTP_Proxy_Server'),
                        'set' : (lambda v : set_ins_value(ins_conf, 'Proxy', 'FTP_Proxy_Server', v)),
                        'valstr' : (lambda v : v),
                        'input' : {
                            'type' : 'TextEntry',
                            'options' : None,
                        },
                    },
                    'Gopher_Proxy_Server' : {
                        'order' : 6,
                        'title' : 'Address of Gopher proxy',
                        'get' : fetch_ins_value(ins_conf, 'Proxy', 'Gopher_Proxy_Server'),
                        'set' : (lambda v : set_ins_value(ins_conf, 'Proxy', 'Gopher_Proxy_Server', v)),
                        'valstr' : (lambda v : v),
                        'input' : {
                            'type' : 'TextEntry',
                            'options' : None,
                        },
                    },
                    'Socks_Proxy_Server' : {
                        'order' : 7,
                        'title' : 'Address of Socks proxy',
                        'get' : fetch_ins_value(ins_conf, 'Proxy', 'Socks_Proxy_Server'),
                        'set' : (lambda v : set_ins_value(ins_conf, 'Proxy', 'Socks_Proxy_Server', v)),
                        'valstr' : (lambda v : v),
                        'input' : {
                            'type' : 'TextEntry',
                            'options' : None,
                        },
                    },
                    'Use_Same_Proxy' : {
                        'order' : 8,
                        'title' : 'Use the same proxy server for all addresses',
                        'get' : fetch_ins_value(ins_conf, 'Proxy', 'Use_Same_Proxy'),
                        'set' : (lambda v : set_ins_value(ins_conf, 'Proxy', 'Use_Same_Proxy', v)),
                        'valstr' : (lambda v : 'Disabled' if not v else 'Disabled' if int(v) == 0 else 'Enabled'),
                        'input' : {
                            'type' : 'ComboBox',
                            'options' : {'Enabled' : '1', 'Disabled' : '0'},
                        },
                    },
                    'Proxy_Override' : {
                        'order' : 9,
                        'title' : 'Do not use proxy server for addresses beginning with:',
                        'get' : fetch_ins_value(ins_conf, 'Proxy', 'Proxy_Override'),
                        'set' : (lambda v : set_ins_value(ins_conf, 'Proxy', 'Proxy_Override', v)),
                        'valstr' : (lambda v : v),
                        'input' : {
                            'type' : 'TextEntry',
                            'options' : None,
                        },
                    },
                },
            },
            'User Agent String' : {
                'values' : {
                    'Name' : {
                        'order' : 0,
                        'title' : 'Name',
                        'get' : 'User Agent String',
                        'set' : None,
                        'valstr' : (lambda v : v),
                        'input' : {
                            'type' : None,
                            'options' : None,
                        },
                    },
                    'Description' : {
                        'order' : 1,
                        'title' : 'Description',
                        'get' : 'Settings for user agent string',
                        'set' : None,
                        'valstr' : (lambda v : v),
                        'input' : {
                            'type' : None,
                            'options' : None,
                        },
                    },
                    'User Agent' : {
                        'order' : 2,
                        'title' : 'Custom string to be appended to user agent string:',
                        'get' : fetch_ins_value(ins_conf, 'Branding', 'User Agent'),
                        'set' : (lambda v : set_ins_value(ins_conf, 'Branding', 'User Agent', v)),
                        'valstr' : (lambda v : v),
                        'input' : {
                            'type' : 'TextEntry',
                            'options' : None,
                        },
                    },
                },
            },
            'Automatic Browser Configuration' : {
                'values' : {
                    'Name' : {
                        'order' : 0,
                        'title' : 'Name',
                        'get' : 'Automatic Browser Configuration',
                        'set' : None,
                        'valstr' : (lambda v : v),
                        'input' : {
                            'type' : None,
                            'options' : None,
                        },
                    },
                    'Description' : {
                        'order' : 1,
                        'title' : 'Description',
                        'get' : 'Settings for automatic browser configuration',
                        'set' : None,
                        'valstr' : (lambda v : v),
                        'input' : {
                            'type' : None,
                            'options' : None,
                        },
                    },
                    'AutoDetect' : {
                        'order' : 2,
                        'title' : 'Automatically detect configuration settings',
                        'get' : fetch_ins_value(ins_conf, 'URL', 'AutoDetect'),
                        'set' : (lambda v : set_ins_value(ins_conf, 'URL', 'AutoDetect', v)),
                        'valstr' : (lambda v : 'Disabled' if not v else 'Disabled' if int(v) == 0 else 'Enabled'),
                        'input' : {
                            'type' : 'ComboBox',
                            'options' : {'Enabled' : '1', 'Disabled' : '0'},
                        },
                    },
                    'AutoConfig' : {
                        'order' : 3,
                        'title' : 'Enable Automatic Configuration',
                        'get' : fetch_ins_value(ins_conf, 'URL', 'AutoConfig'),
                        'set' : (lambda v : set_ins_value(ins_conf, 'URL', 'AutoConfig', v)),
                        'valstr' : (lambda v : 'Disabled' if not v else 'Disabled' if int(v) == 0 else 'Enabled'),
                        'input' : {
                            'type' : 'ComboBox',
                            'options' : {'Enabled' : '1', 'Disabled' : '0'},
                        },
                    },
                    'AutoConfigTime' : {
                        'order' : 4,
                        'title' : 'Automatically configure interval in minutes',
                        'get' : fetch_ins_value(ins_conf, 'URL', 'AutoConfigTime'),
                        'set' : (lambda v : set_ins_value(ins_conf, 'URL', 'AutoConfigTime', v)),
                        'valstr' : (lambda v : '%s minutes' % v if v else ''),
                        'input' : {
                            'type' : 'TextEntry',
                            'options' : None,
                        },
                    },
                    'AutoConfigURL' : {
                        'order' : 5,
                        'title' : 'Auto-config URL (.INS file):',
                        'get' : fetch_ins_value(ins_conf, 'URL', 'AutoConfigURL'),
                        'set' : (lambda v : set_ins_value(ins_conf, 'URL', 'AutoConfigURL', v)),
                        'valstr' : (lambda v : v),
                        'input' : {
                            'type' : 'TextEntry',
                            'options' : None,
                        },
                    },
                    'AutoConfigJSURL' : {
                        'order' : 6,
                        'title' : 'Auto-proxy URL (.JS, .JVS, or .PAC file):',
                        'get' : fetch_ins_value(ins_conf, 'URL', 'AutoConfigJSURL'),
                        'set' : (lambda v : set_ins_value(ins_conf, 'URL', 'AutoConfigJSURL', v)),
                        'valstr' : (lambda v : v),
                        'input' : {
                            'type' : 'TextEntry',
                            'options' : None,
                        },
                    },
                },
            },
        }),
        'gpe_extension' : None,
        'new' : None,
        'add' : None,
        'header' : (lambda : ['Name', 'Description']),
    },
    'user_internet_maint_urls' : {
        'file': '\\USER\\MICROSOFT\\IEAK\\install.ins',
        'opts' : (lambda ins_conf : {
            'Important URLs' : {
                'values' : {
                    'Name' : {
                        'order' : 0,
                        'title' : 'Name',
                        'get' : 'Important URLs',
                        'set' : None,
                        'valstr' : (lambda v : v),
                        'input' : {
                            'type' : None,
                            'options' : None,
                        },
                    },
                    'Description' : {
                        'order' : 1,
                        'title' : 'Description',
                        'get' : 'Settings for home, search, online support URLs',
                        'set' : None,
                        'valstr' : (lambda v : v),
                        'input' : {
                            'type' : 'Label',
                            'options' : None,
                        },
                    },
                    'Home_Page' : {
                        'order' : 2,
                        'title' : 'Home page URL:',
                        'get' : fetch_ins_value(ins_conf, 'URL', 'Home_Page'),
                        'set' : (lambda v : set_ins_value(ins_conf, 'URL', 'Home_Page', v)),
                        'valstr' : (lambda v : v),
                        'input' : {
                            'type' : 'TextEntry',
                            'options' : None,
                        },
                    },
                    'Search_Page' : {
                        'order' : 3,
                        'title' : 'Search bar URL:',
                        'get' : fetch_ins_value(ins_conf, 'URL', 'Search_Page'),
                        'set' : (lambda v : set_ins_value(ins_conf, 'URL', 'Search_Page', v)),
                        'valstr' : (lambda v : v),
                        'input' : {
                            'type' : 'TextEntry',
                            'options' : None,
                        },
                    },
                    'Help_Page' : {
                        'order' : 4,
                        'title' : 'Online support page URL',
                        'get' : fetch_ins_value(ins_conf, 'URL', 'Help_Page'),
                        'set' : (lambda v : set_ins_value(ins_conf, 'URL', 'Help_Page', v)),
                        'valstr' : (lambda v : v),
                        'input' : {
                            'type' : 'TextEntry',
                            'options' : None,
                        },
                    },
                },
            },
        }),
        'gpe_extension' : None,
        'new' : None,
        'add' : None,
        'header' : (lambda : ['Name', 'Description']),

    },
}

if __name__ == "__main__":
    print Policies

