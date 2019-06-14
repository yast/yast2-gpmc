from __future__ import absolute_import, division, print_function, unicode_literals
import sys, os, traceback
import optparse
from yast import ycpbuiltins

from samba.param import LoadParm
from samba.credentials import Credentials

from subprocess import Popen, PIPE

sys.path.append(sys.path[0]+"/../include/gpmc")

from wizards import GPMCSequence

if __name__ == "__main__":
    parser = optparse.OptionParser('gpmc [options]')

    # Yast command line args
    yast_opt = optparse.OptionGroup(parser, 'Command line options for the YaST2 Qt UI')
    yast_opt.add_option('--nothreads', help='run without additional UI threads', action='store_true')
    yast_opt.add_option('--fullscreen', help='use full screen for `opt(`defaultsize) dialogs', action='store_true')
    yast_opt.add_option('--noborder', help='no window manager border for `opt(`defaultsize) dialogs', action='store_true')
    yast_opt.add_option('--auto-fonts', help='automatically pick fonts, disregard Qt standard settings', action='store_true')
    yast_opt.add_option('--macro', help='play a macro right on startup')
    parser.add_option_group(yast_opt)

    # Get the command line options
    parser.add_option('--ncurses', dest='ncurses', help='Whether to run yast via ncurses interface', action='store_true')
    credopts = optparse.OptionGroup(parser, 'Credentials Options')
    credopts.add_option('--password', dest='password', help='Password')
    credopts.add_option('-U', '--username', dest='username', help='Username')
    credopts.add_option('--krb5-ccache', dest='krb5_ccache', help='Kerberos Credentials cache')
    parser.add_option_group(credopts)

    # Set the options and the arguments
    (opts, args) = parser.parse_args()

    # Set the loadparm context
    lp = LoadParm()
    if os.getenv("SMB_CONF_PATH") is not None:
        lp.load(os.getenv("SMB_CONF_PATH"))
    else:
        try:
            lp.load_default()
        except RuntimeError:
            pass

    # Initialize the session
    creds = Credentials()
    if opts.username and opts.password:
        creds.set_username(opts.username)
        creds.set_password(opts.password)
    elif opts.krb5_ccache:
        creds.set_named_ccache(opts.krb5_ccache)
    creds.guess(lp)

    try:
        GPMCSequence(lp, creds)
    except:
        ycpbuiltins.y2error(traceback.format_exc())

