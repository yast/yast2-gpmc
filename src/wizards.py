#!/usr/bin/env python

from ycp import *
import gettext
from gettext import textdomain
textdomain('gpmc')


import_module('Sequencer')
import_module('Wizard')
import_module('UI')


from ycp import *
import dialogs
import Gpmc

def show_gpmc():
    g = dialogs.GPMC()
    return g.Show()

def show_gpme():
    g = dialogs.GPME()
    return g.Show()

def GPMCSequence():
    aliases = {
        'read' : [Code(Gpmc.ReadDialog), True],
        'gpmc' : Code(show_gpmc),
        'gpme' : Code(show_gpme),
        'write' : Code(Gpmc.WriteDialog)
    }

    sequence = {
        'ws_start' : 'gpmc',
        'read' : {
            Symbol('abort') : Symbol('abort'),
            Symbol('next') : 'gpmc'
        },
        'gpmc' : {
            Symbol('abort') : Symbol('abort'),
            Symbol('next') : 'gpme',
        },
        'gpme' : {
            Symbol('abort') : Symbol('abort'),
            Symbol('next') : Symbol('next')
        },
        'write' : {
            Symbol('abort') : Symbol('abort'),
            Symbol('next') : Symbol('next')
        }
    }

    Wizard.CreateDialog()
    Wizard.SetTitleIcon('yast-gpmc')

    ret = Sequencer.Run(aliases, sequence)

    UI.CloseDialog()
    return ret

