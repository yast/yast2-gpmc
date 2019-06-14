from __future__ import absolute_import, division, print_function, unicode_literals
from dialogs import GPMC, GPME
from yast import import_module
import_module('Wizard')
import_module('UI')
import_module('Sequencer')
from yast import Wizard, UI, Sequencer, Code, Symbol

def GPMCSequence(lp, creds):
    aliases = {
        'gpmc' : [(lambda lp, creds: GPMC(lp, creds).Show()), lp, creds],
        'gpme' : [(lambda lp, creds: GPME(lp, creds).Show()), lp, creds]
    }

    sequence = {
        'ws_start' : 'gpmc',
        'gpmc' : {
            Symbol('abort') : Symbol('abort'),
            Symbol('next') : 'gpme',
        },
        'gpme' : {
            Symbol('abort') : Symbol('abort'),
            Symbol('next') : Symbol('next'),
        }
    }

    Wizard.CreateDialog()
    Wizard.SetTitleIcon('yast-gpmc')

    ret = Sequencer.Run(aliases, sequence)

    UI.CloseDialog()
    return ret

