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

gpo = None

def show_gpmc():
    global gpo
    g = dialogs.GPMC()
    gpo, resp = g.Show()
    return resp

def show_gpme():
    global gpo
    g = dialogs.GPME(gpo)
    return g.Show()

def GPMCSequence(lp, creds):
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

