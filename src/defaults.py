#!/usr/bin/env python
import xml.etree.ElementTree as etree
import uuid

def fetch_inf_value(inf_conf, section, key):
    return inf_conf.get(section, key).encode('ascii') if inf_conf.has_section(section) and inf_conf.has_option(section, key) else None

def set_inf_value(inf_conf, section, key, value):
    if value:
        if not inf_conf.has_section(section):
            inf_conf.add_section(section)
        inf_conf.set(section, key, value)
    elif inf_conf.has_section(section) and inf_conf.has_option(section, key):
        inf_conf.remove_option(section, key)

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

def script_set_option(inf_conf, section, option):
    if not inf_conf.has_section(section):
        inf_conf.add_section(section)
    inf_conf.set(section, option)

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
    'Password Policy' : {
        'file' : '\\MACHINE\\Microsoft\\Windows NT\\SecEdit\\GptTmpl.inf',
        'opts' : (lambda inf_conf : {
            'MinimumPasswordAge' : {
                'values' : Policies['Password Policy']['values'](
                    inf_conf, 'MinimumPasswordAge', 'Minimum password age',
                    (lambda v : '%s days' % v if v else 'Not Defined'),
                    {
                        'type' : 'TextEntry',
                        'options' : None,
                    },
                ),
            },
            'MaximumPasswordAge' : {
                'values' : Policies['Password Policy']['values'](
                    inf_conf, 'MaximumPasswordAge', 'Maximum password age',
                    (lambda v : '%s days' % v if v else 'Not Defined'),
                    {
                        'type' : 'TextEntry',
                        'options' : None,
                    },
                ),
            },
            'MinimumPasswordLength' : {
                'values' : Policies['Password Policy']['values'](
                    inf_conf, 'MinimumPasswordLength', 'Minimum password length',
                    (lambda v : '%s characters' % v if v else 'Not Defined'),
                    {
                        'type' : 'TextEntry',
                        'options' : None,
                    },
                ),
            },
            'PasswordComplexity' : {
                'values' : Policies['Password Policy']['values'](
                    inf_conf, 'PasswordComplexity', 'Password must meet complexity requirements',
                    (lambda v : 'Not Defined' if not v else 'Disabled' if int(v) == 0 else 'Enabled'),
                    {
                        'type' : 'ComboBox',
                        'options' : {'Enabled' : '1', 'Disabled' : '0'},
                    },
                ),
            },
            'PasswordHistorySize' : {
                'values' : Policies['Password Policy']['values'](
                    inf_conf, 'PasswordHistorySize', 'Enforce password history',
                    (lambda v : '%s passwords remembered' % v if v else 'Not Defined'),
                    {
                        'type' : 'TextEntry',
                        'options' : None,
                    },
                ),
            },
            'ClearTextPassword' : {
                'values' : Policies['Password Policy']['values'](
                    inf_conf, 'ClearTextPassword', 'Store passwords using reversible encryption',
                    (lambda v : 'Not Defined' if not v else 'Disabled' if int(v) == 0 else 'Enabled'),
                    {
                        'type' : 'ComboBox',
                        'options' : {'Enabled' : '1', 'Disabled' : '0'},
                    },
                ),
            },
        } ),
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
    'Account Lockout Policy' : {
        'file' : '\\MACHINE\\Microsoft\\Windows NT\\SecEdit\\GptTmpl.inf',
        'opts' : (lambda inf_conf : {
            'LockoutDuration' : {
                'values' : Policies['Account Lockout Policy']['values'](
                    inf_conf, 'LockoutDuration', 'Account lockout duration',
                    (lambda v : '%s minutes' % v if v else 'Not Defined'),
                    {
                        'type' : 'TextEntry',
                        'options' : None,
                    },
                ),
            },
            'LockoutBadCount' : {
                'values' : Policies['Account Lockout Policy']['values'](
                    inf_conf, 'LockoutBadCount', 'Account lockout threshold',
                    (lambda v : '%s invalid logon attempts' % v if v else 'Not Defined'),
                    {
                        'type' : 'TextEntry',
                        'options' : None,
                    },
                ),
            },
            'ResetLockoutCount' : {
                'values' : Policies['Account Lockout Policy']['values'](
                    inf_conf, 'ResetLockoutCount', 'Reset account lockout counter after',
                    (lambda v : '%s minutes' % v if v else 'Not Defined'),
                    {
                        'type' : 'TextEntry',
                        'options' : None,
                    },
                ),
            },
        } ),
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
    'Kerberos Policy' : {
        'file' : '\\MACHINE\\Microsoft\\Windows NT\\SecEdit\\GptTmpl.inf',
        'opts' : (lambda inf_conf : {
            'MaxTicketAge' : {
                'values' : Policies['Kerberos Policy']['values'](
                    inf_conf, 'MaxTicketAge', 'Maximum lifetime for user ticket',
                    (lambda v : '%s hours' % v if v else 'Not Defined'),
                    {
                        'type' : 'TextEntry',
                        'options' : None,
                    },
                ),
            },
            'MaxRenewAge' : {
                'values' : Policies['Kerberos Policy']['values'](
                    inf_conf, 'MaxRenewAge', 'Maximum lifetime for user ticket renewal',
                    (lambda v : '%s minutes' % v if v else 'Not Defined'),
                    {
                        'type' : 'TextEntry',
                        'options' : None,
                    },
                ),
            },
            'MaxServiceAge' : {
                'values' : Policies['Kerberos Policy']['values'](
                    inf_conf, 'MaxServiceAge', 'Maximum lifetime for service ticket',
                    (lambda v : '%s minutes' % v if v else 'Not Defined'),
                    {
                        'type' : 'TextEntry',
                        'options' : None,
                    },
                ),
            },
            'MaxClockSkew' : {
                'values' : Policies['Kerberos Policy']['values'](
                    inf_conf, 'MaxClockSkew', 'Maximum tolerance for computer clock synchronization',
                    (lambda v : '%s minutes' % v if v else 'Not Defined'),
                    {
                        'type' : 'TextEntry',
                        'options' : None,
                    },
                ),
            },
            'TicketValidateClient' : {
                'values' : Policies['Kerberos Policy']['values'](
                    inf_conf, 'TicketValidateClient', 'Enforce user logon restrictions',
                    (lambda v : 'Not Defined' if not v else 'Disabled' if int(v) == 0 else 'Enabled'),
                    {
                        'type' : 'ComboBox',
                        'options' : {'Enabled' : '1', 'Disabled' : '0'},
                    }
                ),
            },
        } ),
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
    'Environment' : {
        'file': '\\MACHINE\\Preferences\\EnvironmentVariables\\EnvironmentVariables.xml',
        'opts' : (lambda xml_conf : {
            a.attrib['name']: {
                'values' : Policies['Environment']['values'](a),
            } for a in xml_conf.findall('EnvironmentVariable')
        } ),
        'new' : (lambda : new_environment_tree()),
        'add' : (lambda xml_conf : Policies['Environment']['values'](env_add(xml_conf))),
        'header' : (lambda : [k['title'] for k in sorted(Policies['Environment']['values'](None).values(), key=(lambda x : x['order']))]),
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
    'Startup': {
        'file' : '\\MACHINE\\Scripts\\scripts.ini',
        'opts' : (lambda inf_conf : {
            option : {
                'values' : Policies['Startup']['values'](inf_conf, option),
            } for option in iter_scripts_conf(inf_conf, 'Startup')
        } ),
        'new' : None,
        'add' : (lambda inf_conf : Policies['Startup']['values'](inf_conf, script_get_next_option(inf_conf, 'Startup'))),
        'header' : (lambda : [k['title'] for k in sorted(Policies['Startup']['values'](None, None).values(), key=(lambda x : x['order']))]),
        'values' : (lambda inf_conf, option : {
            'CmdLine' : {
                'order' : 0,
                'title' : 'CmdLine',
                'get' : inf_conf.get('Startup', option).encode('ascii') if inf_conf and inf_conf.has_option('Startup', option) else '',
                'set' : (lambda v : script_set_option(inf_conf, 'Startup', option, v)),
                'valstr' : (lambda v : v),
                'input' : {
                    'type' : 'TextEntry',
                    'options' : None,
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
    'Shutdown': {
        'file' : '\\MACHINE\\Scripts\\scripts.ini',
        'opts' : (lambda inf_conf : {
            option : {
                'values' : Policies['Shutdown']['values'](inf_conf, option),
            } for option in iter_scripts_conf(inf_conf, 'Shutdown')
        } ),
        'new' : None,
        'add' : (lambda inf_conf : Policies['Shutdown']['values'](inf_conf, script_get_next_option(inf_conf, 'Shutdown'))),
        'header' : (lambda : [k['title'] for k in sorted(Policies['Shutdown']['values'](None, None).values(), key=(lambda x : x['order']))]),
        'values' : (lambda inf_conf, option : {
            'CmdLine' : {
                'order' : 0,
                'title' : 'CmdLine',
                'get' : inf_conf.get('Shutdown', option).encode('ascii') if inf_conf and inf_conf.has_option('Shutdown', option) else '',
                'set' : (lambda v : script_set_option(inf_conf, 'Shutdown', option, v)),
                'valstr' : (lambda v : v),
                'input' : {
                    'type' : 'TextEntry',
                    'options' : None,
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
}

if __name__ == "__main__":
    print Policies

