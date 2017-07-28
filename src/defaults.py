#!/usr/bin/env python

Policies = {
    'Password Policy' : {
        'file' : '\\MACHINE\\Microsoft\\Windows NT\\SecEdit\\GptTmpl.inf',
        'sect' : 'System Access',
        'opts' : {
            'MinimumPasswordAge' : {
                'desc' : 'Minimum password age',
                'valstr' : (lambda v : '%s days' % v),
            },
            'MaximumPasswordAge' : {
                'desc' : 'Maximum password age',
                'valstr' : (lambda v : '%s days' % v),
            },
            'MinimumPasswordLength' : {
                'desc' : 'Minimum password length',
                'valstr' : (lambda v : '%s characters' % v),
            },
            'PasswordComplexity' : {
                'desc' : 'Password must meet complexity requirements',
                'valstr' : (lambda v : 'Disabled' if int(v) == 0 else 'Enabled'),
            },
            'PasswordHistorySize' : {
                'desc' : 'Enforce password history',
                'valstr' : (lambda v : '%s passwords remembered' % v),
            },
            'ClearTextPassword' : {
                'desc' : 'Store passwords using reversible encryption',
                'valstr' : (lambda v : 'Disabled' if int(v) == 0 else 'Enabled'),
            },
        },
    },
    'Account Lockout Policy' : {
        'file' : '\\MACHINE\\Microsoft\\Windows NT\\SecEdit\\GptTmpl.inf',
        'sect' : 'System Access',
        'opts' : {
            'LockoutDuration' : {
                'desc' : 'Account lockout duration',
                'valstr' : (lambda v : '%s minutes' % v),
            },
            'LockoutBadCount' : {
                'desc' : 'Account lockout threshold',
                'valstr' : (lambda v : '%s invalid logon attempts' % v),
            },
            'ResetLockoutCount' : {
                'desc' : 'Reset account lockout counter after',
                'valstr' : (lambda v : '%s minutes' % v),
            },
        },
    },
    'Kerberos Policy' : {
        'file' : '\\MACHINE\\Microsoft\\Windows NT\\SecEdit\\GptTmpl.inf',
        'sect' : 'Kerberos Policy',
        'opts' : {
            'MaxTicketAge' : {
                'desc' : 'Maximum lifetime for user ticket',
                'valstr' : (lambda v : '%s hours' % v),
            },
            'MaxRenewAge' : {
                'desc' : 'Maximum lifetime for user ticket renewal',
                'valstr' : (lambda v : '%s days' % v),
            },
            'MaxServiceAge' : {
                'desc' : 'Maximum lifetime for service ticket',
                'valstr' : (lambda v : '%s minutes' % v),
            },
            'MaxClockSkew' : {
                'desc' : 'Maximum tolerance for computer clock synchronization',
                'valstr' : (lambda v : '%s minutes' % v),
            },
            'TicketValidateClient' : {
                'desc' : 'Enforce user logon restrictions',
                'valstr' : (lambda v : 'Disabled' if int(v) == 0 else 'Enabled'),
            },
        },
    },
    'Scripts (Startup/Shutdown)' : {
    },
    'Software installation' : {
    },
}

