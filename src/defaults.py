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

Policies = {
    'Password Policy' : {
        'file' : '\\MACHINE\\Microsoft\\Windows NT\\SecEdit\\GptTmpl.inf',
        'opts' : (lambda inf_conf : {
            'MinimumPasswordAge' : {
                'desc' : 'Minimum password age',
                'value' : fetch_inf_value(inf_conf, 'System Access', 'MinimumPasswordAge'),
                'valstr' : (lambda v : '%s days' % v),
                'modify' : (lambda v : set_inf_value(inf_conf, 'System Access', 'MinimumPasswordAge', v)),
            },
            'MaximumPasswordAge' : {
                'desc' : 'Maximum password age',
                'value' : fetch_inf_value(inf_conf, 'System Access', 'MaximumPasswordAge'),
                'valstr' : (lambda v : '%s days' % v),
                'modify' : (lambda v : set_inf_value(inf_conf, 'System Access', 'MaximumPasswordAge', v)),
            },
            'MinimumPasswordLength' : {
                'desc' : 'Minimum password length',
                'value' : fetch_inf_value(inf_conf, 'System Access', 'MinimumPasswordLength'),
                'valstr' : (lambda v : '%s characters' % v),
                'modify' : (lambda v : set_inf_value(inf_conf, 'System Access', 'MinimumPasswordLength', v)),
            },
            'PasswordComplexity' : {
                'desc' : 'Password must meet complexity requirements',
                'value' : fetch_inf_value(inf_conf, 'System Access', 'PasswordComplexity'),
                'valstr' : (lambda v : 'Disabled' if int(v) == 0 else 'Enabled'),
                'modify' : (lambda v : set_inf_value(inf_conf, 'System Access', 'PasswordComplexity', v)),
            },
            'PasswordHistorySize' : {
                'desc' : 'Enforce password history',
                'value' : fetch_inf_value(inf_conf, 'System Access', 'PasswordHistorySize'),
                'valstr' : (lambda v : '%s passwords remembered' % v),
                'modify' : (lambda v : set_inf_value(inf_conf, 'System Access', 'PasswordComplexity', v)),
            },
            'ClearTextPassword' : {
                'desc' : 'Store passwords using reversible encryption',
                'value' : fetch_inf_value(inf_conf, 'System Access', 'ClearTextPassword'),
                'valstr' : (lambda v : 'Disabled' if int(v) == 0 else 'Enabled'),
                'modify' : (lambda v : set_inf_value(inf_conf, 'System Access', 'ClearTextPassword', v)),
            },
        } ),
    },
    'Account Lockout Policy' : {
        'file' : '\\MACHINE\\Microsoft\\Windows NT\\SecEdit\\GptTmpl.inf',
        'opts' : (lambda inf_conf : {
            'LockoutDuration' : {
                'desc' : 'Account lockout duration',
                'value' : fetch_inf_value(inf_conf, 'System Access', 'LockoutDuration'),
                'valstr' : (lambda v : '%s minutes' % v),
                'modify' : (lambda v : set_inf_value(inf_conf, 'System Access', 'LockoutDuration', v)),
            },
            'LockoutBadCount' : {
                'desc' : 'Account lockout threshold',
                'value' : fetch_inf_value(inf_conf, 'System Access', 'LockoutBadCount'),
                'valstr' : (lambda v : '%s invalid logon attempts' % v),
                'modify' : (lambda v : set_inf_value(inf_conf, 'System Access', 'LockoutBadCount', v)),
            },
            'ResetLockoutCount' : {
                'desc' : 'Reset account lockout counter after',
                'value' : fetch_inf_value(inf_conf, 'System Access', 'ResetLockoutCount'),
                'valstr' : (lambda v : '%s minutes' % v),
                'modify' : (lambda v : set_inf_value(inf_conf, 'System Access', 'ResetLockoutCount', v)),
            },
        } ),
    },
    'Kerberos Policy' : {
        'file' : '\\MACHINE\\Microsoft\\Windows NT\\SecEdit\\GptTmpl.inf',
        'opts' : (lambda inf_conf : {
            'MaxTicketAge' : {
                'desc' : 'Maximum lifetime for user ticket',
                'value' : fetch_inf_value(inf_conf, 'Kerberos Policy', 'MaxTicketAge'),
                'valstr' : (lambda v : '%s hours' % v),
                'modify' : (lambda v : set_inf_value(inf_conf, 'Kerberos Policy', 'MaxTicketAge', v)),
            },
            'MaxRenewAge' : {
                'desc' : 'Maximum lifetime for user ticket renewal',
                'value' : fetch_inf_value(inf_conf, 'Kerberos Policy', 'MaxRenewAge'),
                'valstr' : (lambda v : '%s days' % v),
                'modify' : (lambda v : set_inf_value(inf_conf, 'Kerberos Policy', 'MaxRenewAge', v)),
            },
            'MaxServiceAge' : {
                'desc' : 'Maximum lifetime for service ticket',
                'value' : fetch_inf_value(inf_conf, 'Kerberos Policy', 'MaxServiceAge'),
                'valstr' : (lambda v : '%s minutes' % v),
                'modify' : (lambda v : set_inf_value(inf_conf, 'Kerberos Policy', 'MaxServiceAge', v)),
            },
            'MaxClockSkew' : {
                'desc' : 'Maximum tolerance for computer clock synchronization',
                'value' : fetch_inf_value(inf_conf, 'Kerberos Policy', 'MaxClockSkew'),
                'valstr' : (lambda v : '%s minutes' % v),
                'modify' : (lambda v : set_inf_value(inf_conf, 'Kerberos Policy', 'MaxClockSkew', v)),
            },
            'TicketValidateClient' : {
                'desc' : 'Enforce user logon restrictions',
                'value' : fetch_inf_value(inf_conf, 'Kerberos Policy', 'TicketValidateClient'),
                'valstr' : (lambda v : 'Disabled' if int(v) == 0 else 'Enabled'),
                'modify' : (lambda v : set_inf_value(inf_conf, 'Kerberos Policy', 'TicketValidateClient', v)),
            },
        } ),
    },
    'Environment' : {
        'file': '\\MACHINE\\Preferences\\EnvironmentVariables\\EnvironmentVariables.xml',
        'opts' : (lambda xml_conf : {
            a.attrib['clsid']: {
                'desc' : a.attrib['name'],
                'value' : a.find('Properties').attrib['value'],
                'valstr' : (lambda v : v),
                'modify' : (lambda v : a.find('Properties').set('value', v)),
            } for a in xml_conf.findall('EnvironmentVariable')
        } ),
    },
    'Scripts (Startup/Shutdown)' : {
    },
    'Software installation' : {
    },
}

if __name__ == "__main__":
    print Policies['Kerberos Policy']
    print Policies['Environment']
    print Policies['Password Policy']
    print Policies
