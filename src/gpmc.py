#!/usr/bin/env python

import optparse
from samba import getopt as options
from samba.auth import system_session

from ycp import *
import gettext
from gettext import textdomain
textdomain('gpmc')

import sys

if __name__ == "__main__":
    parser = optparse.OptionParser('gpmc [options]')
    sambaopts = options.SambaOptions(parser)

    # Yast command line args
    yast_opt = optparse.OptionGroup(parser, 'Command line options for the YaST2 Qt UI')
    yast_opt.add_option('--nothreads', help='run without additional UI threads', action='store_true')
    yast_opt.add_option('--fullscreen', help='use full screen for `opt(`defaultsize) dialogs', action='store_true')
    yast_opt.add_option('--noborder', help='no window manager border for `opt(`defaultsize) dialogs', action='store_true')
    yast_opt.add_option('--auto-fonts', help='automatically pick fonts, disregard Qt standard settings', action='store_true')
    yast_opt.add_option('--macro', help='play a macro right on startup')
    parser.add_option_group(yast_opt)

    # Get the command line options
    parser.add_option_group(sambaopts)
    parser.add_option_group(options.VersionOptions(parser))
    credopts = options.CredentialsOptions(parser)
    parser.add_option('--ncurses', dest='ncurses', help='Whether to run yast via ncurses interface', action='store_true')
    parser.add_option_group(credopts)

    # Set the options and the arguments
    (opts, args) = parser.parse_args()

    # Set the loadparm context
    lp = sambaopts.get_loadparm()

    # Initialize the session
    creds = credopts.get_credentials(lp, fallback_machine=True)
    session = system_session()

    if opts.ncurses:
        init_ui('ncurses')
    else:
        init_ui('qt')

    import_module('CommandLine')
    import  wizards, Gpmc
    from ycp import *

    cmdline_description = {
        'id'    : 'gpmc',
        'guihandler'        : Code(wizards.GPMCSequence(lp, creds)),
        'initialize'        : Code(Gpmc.Read),
        'finish'            : Code(Gpmc.Write),
    }

    CommandLine.Run(cmdline_description);

