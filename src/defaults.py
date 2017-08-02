#!/usr/bin/env python

def fetch_inf_value(inf_conf, section, key):
    return inf_conf.get(section, key).encode('ascii') if inf_conf.has_section(section) and inf_conf.has_option(section, key) else None

def set_inf_value(inf_conf, section, key, value):
    if value:
        if not inf_conf.has_section(section):
            inf_conf.add_section(section)
        inf_conf.set(section, key, value)
    elif inf_conf.has_section(section) and inf_conf.has_option(section, key):
        inf_conf.remove_option(section, key)

def iter_scripts_conf(inf_conf):
    for section in inf_conf.sections():
        for option in inf_conf.options(section):
            if 'CmdLine' in option:
                yield option, section

Policies = {
    'Password Policy' : {
        'file' : '\\MACHINE\\Microsoft\\Windows NT\\SecEdit\\GptTmpl.inf',
        'opts' : (lambda inf_conf : {
            'MinimumPasswordAge' : {
                'desc' : 'Minimum password age',
                'title' : 'Policy',
                'values' : Policies['Password Policy']['values'](
                    inf_conf, 'MinimumPasswordAge',
                    (lambda v : '%s days' % v if v else 'Not Defined'),
                    {
                        'type' : 'TextEntry',
                        'options' : None,
                    },
                ),
            },
            'MaximumPasswordAge' : {
                'desc' : 'Maximum password age',
                'title' : 'Policy',
                'values' : Policies['Password Policy']['values'](
                    inf_conf, 'MaximumPasswordAge',
                    (lambda v : '%s days' % v if v else 'Not Defined'),
                    {
                        'type' : 'TextEntry',
                        'options' : None,
                    },
                ),
            },
            'MinimumPasswordLength' : {
                'desc' : 'Minimum password length',
                'title' : 'Policy',
                'values' : Policies['Password Policy']['values'](
                    inf_conf, 'MinimumPasswordLength',
                    (lambda v : '%s characters' % v if v else 'Not Defined'),
                    {
                        'type' : 'TextEntry',
                        'options' : None,
                    },
                ),
            },
            'PasswordComplexity' : {
                'desc' : 'Password must meet complexity requirements',
                'title' : 'Policy',
                'values' : Policies['Password Policy']['values'](
                    inf_conf, 'PasswordComplexity',
                    (lambda v : 'Not Defined' if not v else 'Disabled' if int(v) == 0 else 'Enabled'),
                    {
                        'type' : 'ComboBox',
                        'options' : {'Enabled' : '1', 'Disabled' : '0'},
                    },
                ),
            },
            'PasswordHistorySize' : {
                'desc' : 'Enforce password history',
                'title' : 'Policy',
                'values' : Policies['Password Policy']['values'](
                    inf_conf, 'PasswordHistorySize',
                    (lambda v : '%s passwords remembered' % v if v else 'Not Defined'),
                    {
                        'type' : 'TextEntry',
                        'options' : None,
                    },
                ),
            },
            'ClearTextPassword' : {
                'desc' : 'Store passwords using reversible encryption',
                'title' : 'Policy',
                'values' : Policies['Password Policy']['values'](
                    inf_conf, 'ClearTextPassword',
                    (lambda v : 'Not Defined' if not v else 'Disabled' if int(v) == 0 else 'Enabled'),
                    {
                        'type' : 'ComboBox',
                        'options' : {'Enabled' : '1', 'Disabled' : '0'},
                    },
                ),
            },
        } ),
        'values' : (lambda conf, setting, valstr, _input : {
            'value' : {
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
                'desc' : 'Account lockout duration',
                'title' : 'Policy',
                'values' : Policies['Account Lockout Policy']['values'](
                    inf_conf, 'LockoutDuration',
                    (lambda v : '%s minutes' % v if v else 'Not Defined'),
                    {
                        'type' : 'TextEntry',
                        'options' : None,
                    },
                ),
            },
            'LockoutBadCount' : {
                'desc' : 'Account lockout threshold',
                'title' : 'Policy',
                'values' : Policies['Account Lockout Policy']['values'](
                    inf_conf, 'LockoutBadCount',
                    (lambda v : '%s invalid logon attempts' % v if v else 'Not Defined'),
                    {
                        'type' : 'TextEntry',
                        'options' : None,
                    },
                ),
            },
            'ResetLockoutCount' : {
                'desc' : 'Reset account lockout counter after',
                'title' : 'Policy',
                'values' : Policies['Account Lockout Policy']['values'](
                    inf_conf, 'ResetLockoutCount',
                    (lambda v : '%s minutes' % v if v else 'Not Defined'),
                    {
                        'type' : 'TextEntry',
                        'options' : None,
                    },
                ),
            },
        } ),
        'values' : (lambda conf, setting, valstr, _input : {
            'value' : {
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
                'desc' : 'Maximum lifetime for user ticket',
                'title' : 'Policy',
                'values' : Policies['Kerberos Policy']['values'](
                    inf_conf, 'MaxTicketAge',
                    (lambda v : '%s hours' % v if v else 'Not Defined'),
                    {
                        'type' : 'TextEntry',
                        'options' : None,
                    },
                ),
            },
            'MaxRenewAge' : {
                'desc' : 'Maximum lifetime for user ticket renewal',
                'title' : 'Policy',
                'values' : Policies['Kerberos Policy']['values'](
                    inf_conf, 'MaxRenewAge',
                    (lambda v : '%s minutes' % v if v else 'Not Defined'),
                    {
                        'type' : 'TextEntry',
                        'options' : None,
                    },
                ),
            },
            'MaxServiceAge' : {
                'desc' : 'Maximum lifetime for service ticket',
                'title' : 'Policy',
                'values' : Policies['Kerberos Policy']['values'](
                    inf_conf, 'MaxServiceAge',
                    (lambda v : '%s minutes' % v if v else 'Not Defined'),
                    {
                        'type' : 'TextEntry',
                        'options' : None,
                    },
                ),
            },
            'MaxClockSkew' : {
                'desc' : 'Maximum tolerance for computer clock synchronization',
                'title' : 'Policy',
                'values' : Policies['Kerberos Policy']['values'](
                    inf_conf, 'MaxClockSkew',
                    (lambda v : '%s minutes' % v if v else 'Not Defined'),
                    {
                        'type' : 'TextEntry',
                        'options' : None,
                    },
                ),
            },
            'TicketValidateClient' : {
                'desc' : 'Enforce user logon restrictions',
                'title' : 'Policy',
                'values' : Policies['Kerberos Policy']['values'](
                    inf_conf, 'TicketValidateClient',
                    (lambda v : 'Not Defined' if not v else 'Disabled' if int(v) == 0 else 'Enabled'),
                    {
                        'type' : 'ComboBox',
                        'options' : {'Enabled' : '1', 'Disabled' : '0'},
                    }
                ),
            },
        } ),
        'values' : (lambda conf, setting, valstr, _input : {
            'value' : {
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
                'desc' : a.attrib['name'],
                'title' : 'Name',
                'values' : Policies['Environment']['values'](a),
            } for a in xml_conf.findall('EnvironmentVariable')
        } ),
        'values' : (lambda a : {
            'value' : {
                'title' : 'Value',
                'get' : a.find('Properties').attrib['value'],
                'set' : (lambda v : a.find('Properties').set('value', v)),
                'valstr' : (lambda v : v),
                'input' : {
                    'type' : 'TextEntry',
                    'options' : None,
                },
            },
            'user' : {
                'title' : 'User',
                'get' : a.find('Properties').attrib['user'],
                'set' : (lambda v : a.find('Properties').set('user', v)),
                'valstr' : (lambda v : 'No' if int(v) == 0 else 'Yes'),
                'input' : {
                    'type' : 'ComboBox',
                    'options' : {'Yes' : '1', 'No' : '0'},
                },
            },
            'action' : {
                'title' : 'Action',
                'get' : a.find('Properties').attrib['action'],
                'set' : (lambda v : a.find('Properties').set('action', v)),
                'valstr' : (lambda v : {'U' : 'Update', 'C' : 'Create', 'R' : 'Replace', 'D' : 'Delete'}[v]),
                'input' : {
                    'type' : 'ComboBox',
                    'options' : {'Update' : 'U', 'Create' : 'C', 'Replace' : 'R', 'Delete' : 'D'},
                },
            },
        } ),
    },
    'Scripts': {
        'file' : '\\MACHINE\\Scripts\\scripts.ini',
        'opts' : (lambda inf_conf : {
            '%s:%s' % (option, section) : {
                'desc' : inf_conf.get(section, option),
                'title' : 'Name',
                'values' : Policies['Scripts']['values'](inf_conf, section, option),
            } for option, section in iter_scripts_conf(inf_conf)
        } ),
        'values' : (lambda inf_conf, section, option : {
            'type' : {
                'title' : 'Type',
                'get' : section,
                'set' : None,
                'valstr' : (lambda v : v),
                'input' : {
                    'type' : 'Label',
                    'options' : None,
                },
            },
            'Parameters' : {
                'title' : 'Parameters',
                'get' : inf_conf.get(section, '%sParameters' % option[:-7]),
                'set' : (lambda v : inf_conf.set(section, '%sParameters' % option[:-7], v)),
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

