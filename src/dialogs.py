#!/usr/bin/env python

import gettext
from gettext import textdomain

textdomain('gpmc')

import ycp
ycp.import_module('UI')
from ycp import *
ycp.widget_names()
import Wizard
ycp.import_module('Label')

import Gpmc
from complex import GPQuery, get_default_realm
import re
from samba import smb


class GPME:
    def __init__(self, selected_gpo, lp, creds):
        self.selected_gpo = selected_gpo
        self.gpo_path = self.selected_gpo[1]['gPCFileSysPath'][-1]
        path_parts = [n for n in self.gpo_path.split('\\') if n]
        self.path = '/'.join(path_parts[2:])
        self.lp = lp
        self.creds = creds
        try:
            self.conn = smb.SMB(path_parts[0], path_parts[1], lp=self.lp, creds=self.creds)
        except:
            self.conn = None

    def Show(self):
        if not self.conn:
            return Symbol('back')
        Wizard.SetContentsButtons(gettext.gettext('Group Policy Management Editor'), self.__gpme_page(), 'Group Policy Management Editor', 'Back', 'Finish')

        ret = Symbol('abort')
        while True:
            ret = UI.UserInput()

            if str(ret) in ['back', 'abort', 'next']:
                break
            if str(ret) == 'gpme_tree':
                selection = UI.QueryWidget(Term('id', 'gpme_tree'), Symbol('CurrentItem'))
                if selection == 'Password Policy':
                    UI.ReplaceWidget(Term('id', 'rightPane'), self.__password_policy())
                elif selection == 'Account Lockout Policy':
                    UI.ReplaceWidget(Term('id', 'rightPane'), self.__account_lockout_policy())
                elif selection == 'Kerberos Policy':
                    UI.ReplaceWidget(Term('id', 'rightPane'), self.__kerberos_policy())
                elif selection == 'Scripts (Startup/Shutdown)':
                    UI.ReplaceWidget(Term('id', 'rightPane'), self.__scripts())
                elif selection == 'Software installation':
                    UI.ReplaceWidget(Term('id', 'rightPane'), self.__software_installation())
                else:
                    UI.ReplaceWidget(Term('id', 'rightPane'), Term('Empty'))

        return ret

    def __password_policy(self):
        from ycp import *
        ycp.widget_names()

        return RichText('contents')

    def __account_lockout_policy(self):
        from ycp import *
        ycp.widget_names()

        return RichText('contents')

    def __kerberos_policy(self):
        from ycp import *
        ycp.widget_names()

        items = []
        items.append(Term('item', 'Enforce user logon restrictions', 'Enabled'))

        return Table(Term('header', 'Policy', 'Policy Setting'), items)

    def __scripts(self):
        from ycp import *
        ycp.widget_names()

        return RichText('contents')

    def __software_installation(self):
        from ycp import *
        ycp.widget_names()

        return RichText('contents')

    def __contents(self):
        from ycp import *
        ycp.widget_names()
        return RichText('Contents of the Group Policy Management Editor')

    def __gpme_page(self):
        from ycp import *
        ycp.widget_names()

        return HBox(
            HWeight(1, self.__policy_tree()),
            HWeight(2, ReplacePoint(Term('id', 'rightPane'), Term('Empty'))),
            )

    def __policy_tree(self):
        from ycp import *
        ycp.widget_names()

        computer_config = [
            Term('item', 'Policies', False,
                [
                    Term('item', 'Software Settings', False,
                        [
                            Term('item', 'Software installation', False, []),
                        ]
                    ),
                    Term('item', 'Windows Settings', False,
                        [
                            Term('item', 'Scripts (Startup/Shutdown)', False, []),
                            Term('item', 'Security Settings', False,
                                [
                                    Term('item', 'Account Policy', False,
                                        [
                                            Term('item', 'Password Policy', False, []),
                                            Term('item', 'Account Lockout Policy', False, []),
                                            Term('item', 'Kerberos Policy', False, []),
                                        ]
                                    ),
                                ]
                            ),
                        ]
                    ),
                ]
            ),
        ]

        contents = Tree(Term('id', 'gpme_tree'), Term('opt', Symbol('notify')), self.selected_gpo[1]['displayName'][-1],
            [
                Term('item', 'Computer Configuration', True,
                    computer_config
                ),
                Term('item', 'User Configuration', True,
                    []
                )
            ]
        )
        return contents

class GPMC:
    def __init__(self, creds):
        self.realm = get_default_realm().lower()
        try:
            self.q = GPQuery(self.realm, creds.get_username(), creds.get_password())
            self.gpos = self.q.gpo_list()
        except:
            self.gpos = []
        self.selected_gpo = None

    def __select_gpo(self, gpo_guid):
        selected_gpo = None
        for gpo in self.gpos:
            if gpo[1]['name'][-1] == gpo_guid:
                selected_gpo = gpo
                break
        return selected_gpo

    def Show(self):
        Wizard.SetContentsButtons(gettext.gettext('Group Policy Management Console'), self.__gpmc_page(), self.__help(), 'Back', 'Edit GPO')
        Wizard.DisableBackButton()

        ret = Symbol('abort')
        current_page = 'Domains'
        old_gpo_guid = None
        gpo_guid = None
        while True:
            ret = UI.UserInput()

            old_gpo_guid = gpo_guid
            gpo_guid = UI.QueryWidget(Term('id', 'gpmc_tree'), Symbol('CurrentItem'))
            if str(ret) in ['back', 'abort']:
                break
            elif str(ret) == 'next':
                if gpo_guid != 'Domains' and gpo_guid != self.realm:
                    break
                else:
                    continue
            elif UI.HasSpecialWidget(Symbol('DumbTab')):
                if gpo_guid == 'Domains':
                    if current_page != 'Domains':
                        UI.ReplaceWidget(Term('id', 'rightPane'), self.__domains())
                        current_page = 'Domains'
                elif gpo_guid == self.realm:
                    if current_page != 'Realm':
                        UI.ReplaceWidget(Term('id', 'rightPane'), self.__realm())
                        current_page = 'Realm'
                else:
                    if str(ret) == 'advanced':
                        self.__gpo_tab_adv(gpo_guid)
                        continue
                    if current_page != 'Dumbtab' or old_gpo_guid != gpo_guid:
                        self.selected_gpo = self.__select_gpo(gpo_guid)
                        UI.ReplaceWidget(Term('id', 'rightPane'), self.__gpo_tab(gpo_guid))
                        current_page = 'Dumbtab'
                    if str(ret) == 'Scope':
                        UI.ReplaceWidget(Term('id', 'gpo_tabContents'), self.__scope_page())
                    elif str(ret) == 'Details':
                        UI.ReplaceWidget(Term('id', 'gpo_tabContents'), self.__details_page(gpo_guid))
                    elif str(ret) == 'Settings':
                        UI.ReplaceWidget(Term('id', 'gpo_tabContents'), self.__settings_page())
                    elif str(ret) == 'Delegation':
                        UI.ReplaceWidget(Term('id', 'gpo_tabContents'), self.__delegation_page())
                    elif str(ret) == 'gpo_status' and self.q:
                        combo_choice = UI.QueryWidget(Term('id', 'gpo_status'), Symbol('Value'))
                        if combo_choice == 'All settings disabled':
                            self.q.set_attrs(self.selected_gpo[0], {'flags': self.selected_gpo[1]['flags']}, {'flags': ['3']})
                        elif combo_choice == 'Computer configuration settings disabled':
                            self.q.set_attrs(self.selected_gpo[0], {'flags': self.selected_gpo[1]['flags']}, {'flags': ['2']})
                        elif combo_choice == 'Enabled':
                            self.q.set_attrs(self.selected_gpo[0], {'flags': self.selected_gpo[1]['flags']}, {'flags': ['0']})
                        elif combo_choice == 'User configuration settings disabled':
                            self.q.set_attrs(self.selected_gpo[0], {'flags': self.selected_gpo[1]['flags']}, {'flags': ['1']})

        return (self.selected_gpo, ret)

    def __help(self):
        return 'Group Policy Management Console'

    def __scope_page(self):
        from ycp import *
        ycp.widget_names()
        return RichText('Contents of the scope page')

    def __ms_time_to_readable(self, timestamp):
        m = re.match('(?P<year>\d\d\d\d)(?P<month>\d\d)(?P<day>\d\d)(?P<hour>\d\d)(?P<minute>\d\d)(?P<second>\d\d)\..*', timestamp)
        if m:
            return '%s/%s/%s %s:%s:%s UTC' % (m.group('month'), m.group('day'), m.group('year'), m.group('hour'), m.group('minute'), m.group('second'))

    def __details_page(self, gpo_guid):
        from ycp import *
        ycp.widget_names()

        status_selection = [False, False, False, False]
        if self.selected_gpo[1]['flags'][-1] == '0':
            status_selection[2] = True
        elif self.selected_gpo[1]['flags'][-1] == '1':
            status_selection[3] = True
        elif self.selected_gpo[1]['flags'][-1] == '2':
            status_selection[1] = True
        elif self.selected_gpo[1]['flags'][-1] == '3':
            status_selection[0] = True
        combo_options = [Term('item', 'All settings disabled', status_selection[0]), Term('item', 'Computer configuration settings disabled', status_selection[1]), Term('item', 'Enabled', status_selection[2]), Term('item', 'User configuration settings disabled', status_selection[3])]

        return Top(
            HBox(
                HWeight(1, VBox(
                    Left(Label('Domain:')), VSpacing(),
                    Left(Label('Owner:')), VSpacing(),
                    Left(Label('Created:')), VSpacing(),
                    Left(Label('Modified:')), VSpacing(),
                    Left(Label('User version:')), VSpacing(),
                    Left(Label('Computer version:')), VSpacing(),
                    Left(Label('Unique ID:')), VSpacing(),
                    Left(Label('GPO Status:')), VSpacing(),
                )),
                HWeight(2, VBox(
                    Left(Label(self.realm)), VSpacing(),
                    Left(Label('Unknown')), VSpacing(),
                    Left(Label(self.__ms_time_to_readable(self.selected_gpo[1]['whenCreated'][-1]))), VSpacing(),
                    Left(Label(self.__ms_time_to_readable(self.selected_gpo[1]['whenChanged'][-1]))), VSpacing(),
                    Left(Label('%d' % (int(self.selected_gpo[1]['versionNumber'][-1]) >> 16))), VSpacing(),
                    Left(Label('%d' % (int(self.selected_gpo[1]['versionNumber'][-1]) & 0x0F))), VSpacing(),
                    Left(Label(gpo_guid)), VSpacing(),
                    Left(ComboBox(Term('id', 'gpo_status'), Term('opt', Symbol('notify')), '', combo_options)), VSpacing(),
                )),
            )
        )

    def __settings_page(self):
        from ycp import *
        ycp.widget_names()
        return RichText('Contents of the settings page')

    def __delegation_page(self):
        from ycp import *
        ycp.widget_names()
        return RichText('Contents of the delegation page')

    def __forest(self):
        from ycp import *
        ycp.widget_names()

        items = []
        for gpo in self.gpos:
            items.append(Term('item', Term('id', gpo[1]['name'][-1]), gpo[1]['displayName'][-1]))
        forest = [Term('item', 'Domains', True, [Term('item', self.realm, True, items)])]
        contents = Tree(Term('id', 'gpmc_tree'), Term('opt', Symbol('notify')), 'Group Policy Management', forest)
        
        return contents

    def __domains(self):
        from ycp import *
        ycp.widget_names()

        return Frame('Domains', DumbTab(['Contents'], RichText(self.realm)))

    def __realm(self):
        from ycp import *
        ycp.widget_names()

        return Frame(self.realm, DumbTab(['Linked Group Policy Objects', 'Group Policy Inheritance', 'Delegation'], RichText(self.realm)))

    def __gpo_tab(self, gpo_guid):
        from ycp import *
        ycp.widget_names()

        gpo_name = self.selected_gpo[1]['displayName'][-1]

        return Frame(gpo_name, ReplacePoint(Term('id', 'gpo_tabContainer'), VBox(self.__details_page(gpo_guid), Right(PushButton(Term('id', 'advanced'), 'Advanced')))))

    def __gpo_tab_adv(self, gpo_guid):
        from ycp import *
        ycp.widget_names()

        UI.ReplaceWidget(Term('id', 'gpo_tabContainer'), DumbTab(Term('id', 'gpo_tab'), ['Scope', 'Details', 'Settings', 'Delegation'], ReplacePoint(Term('id', 'gpo_tabContents'), self.__scope_page())))

    def __gpmc_page(self):
        from ycp import *
        ycp.widget_names()

        return HBox(
            HWeight(1, self.__forest()),
            HWeight(2, ReplacePoint(Term('id', 'rightPane'), self.__domains())),
            )

