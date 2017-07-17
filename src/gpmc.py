#!/usr/bin/env python

from ycp import *
import gettext
from gettext import textdomain
textdomain('gpmc')

import sys
if '--ncurses' in sys.argv:
    init_ui('ncurses')
else:
    init_ui('qt')

import_module('Progress')
import_module('Report')
import_module('CommandLine')
import_module('Path')

import  wizards
import  Gpmc

from ycp import *

cmdline_description = {
    'id' 	: 'gpmc',
    'help'		: 'Group Policy Management Console',
    'guihandler'        : wizards.GPMCSequence,
    'initialize'        : Code(Gpmc.Read),
    'finish'            : Code(Gpmc.Write),
    }

if __name__ == "__main__":
	print CommandLine.Run(cmdline_description);

