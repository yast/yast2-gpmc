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
from defaults import Policies, fetch_inf_value
from complex import GPConnection, GPOConnection
import re

class GPME:
    def __init__(self, selected_gpo, lp, creds):
        self.selected_gpo = selected_gpo
        self.conn = GPOConnection(lp, creds, self.selected_gpo[1]['gPCFileSysPath'][-1])

    def Show(self):
        if not self.conn:
            return Symbol('back')
        Wizard.SetContentsButtons(gettext.gettext('Group Policy Management Editor'), self.__gpme_page(), 'Group Policy Management Editor', 'Back', 'Close')
        Wizard.DisableAbortButton()
        UI.SetFocus(Term('id', 'gpme_tree'))

        policy = None
        ret = Symbol('abort')
        while True:
            ret = UI.UserInput()

            if str(ret) in ['back', 'abort', 'next']:
                break
            elif str(ret) == 'gpme_tree':
                policy = UI.QueryWidget(Term('id', 'gpme_tree'), Symbol('CurrentItem'))
                UI.ReplaceWidget(Term('id', 'rightPane'), self.__display_policy(policy))
                continue
            if str(ret) == 'policy_table' or str(ret) == 'add_policy':
                conf = self.conn.parse(Policies[policy]['file'])
                if conf is None:
                    conf = Policies[policy]['new']()
                if str(ret) == 'policy_table':
                    selection = UI.QueryWidget(Term('id', str(ret)), Symbol('CurrentItem'))
                    values = Policies[policy]['opts'](conf)[selection]['values']
                elif str(ret) == 'add_policy':
                    values = Policies[policy]['add'](conf)
                UI.OpenDialog(self.__change_setting(values))
                while True:
                    subret = UI.UserInput()
                    if str(subret) == 'ok_change_setting' or str(subret) == 'apply_change_setting':
                        for k in values.keys():
                            value = UI.QueryWidget(Term('id', 'entry_%s' % k), Symbol('Value'))
                            if values[k]['input']['options']:
                                value = values[k]['input']['options'][value.strip()]
                            if values[k]['set']:
                                values[k]['set'](value.strip())
                        self.conn.write(Policies[policy]['file'], conf)
                        if Policies[policy]['gpe_extension']:
                            self.conn.update_machine_gpe_ini(Policies[policy]['gpe_extension'])
                    elif str(subret).startswith('select_entry_'):
                        option = str(subret)[13:]
                        selection = values[option]['input']['action'](option, policy, self.conn)
                        UI.ReplaceWidget(Term('id', 'button_entry_%s' % option), self.__button_entry(option, values, selection))
                        continue
                    if str(subret) == 'cancel_change_setting' or str(subret) == 'ok_change_setting':
                        UI.CloseDialog()
                        break
                UI.ReplaceWidget(Term('id', 'rightPane'), self.__display_policy(policy))
                UI.SetFocus(Term('id', str(ret)))

        return ret

    def __button_entry(self, k, values, value):
        from ycp import *
        ycp.widget_names()

        return TextEntry(Term('id', 'entry_%s' % k), values[k]['title'], value)

    def __change_values_prompt(self, values):
        from ycp import *
        ycp.widget_names()

        items = []
        for k in values.keys():
            if values[k]['input']['type'] == 'TextEntry':
                items.append(Left(TextEntry(Term('id', 'entry_%s' % k), values[k]['title'], values[k]['get'] if values[k]['get'] else '')))
            elif values[k]['input']['type'] == 'ComboBox':
                combo_options = []
                current = values[k]['valstr'](values[k]['get'])
                for sk in values[k]['input']['options'].keys():
                    combo_options.append(Term('item', sk, current == sk))
                items.append(Left(ComboBox(Term('id', 'entry_%s' % k), values[k]['title'], combo_options)))
            elif values[k]['input']['type'] == 'Label':
                items.append(Left(Label('%s: %s' % (values[k]['title'], values[k]['valstr'](values[k]['get'])))))
            elif values[k]['input']['type'] == 'ButtonEntry':
                items.append(Left(
                    VBox(
                        ReplacePoint(Term('id', 'button_entry_%s' % k), self.__button_entry(k, values, values[k]['get'] if values[k]['get'] else '')),
                        PushButton(Term('id', 'select_entry_%s' % k), 'Select'),
                    )
                ))
        items = tuple(items)
        return VBox(*items)

    def __change_setting(self, values):
        from ycp import *
        ycp.widget_names()

        contents = MinWidth(30, HBox(HSpacing(), VBox(
            VSpacing(),
            self.__change_values_prompt(values),
            VSpacing(),
            Right(HBox(
                PushButton(Term('id', 'ok_change_setting'), 'OK'),
                PushButton(Term('id', 'cancel_change_setting'), 'Cancel'),
                PushButton(Term('id', 'apply_change_setting'), 'Apply'),
            )),
            VSpacing(),
        ), HSpacing() ))
        return contents

    def __display_policy(self, label):
        from ycp import *
        ycp.widget_names()

        if not label in Policies.keys():
            return Term('Empty')
        terms = Policies[label]
        items = []
        conf = self.conn.parse(terms['file'])
        if conf is None:
            conf = terms['new']()
        opts = terms['opts'](conf)
        header = terms['header']()
        for key in opts:
            values = sorted(opts[key]['values'].values(), key=(lambda x : x['order']))
            vals = tuple([k['valstr'](k['get']) for k in values])
            items.append(Term('item', Term('id', key), *vals))
        buttons = []
        if terms['add']:
            buttons.append(PushButton(Term('id', 'add_policy'), Term('opt', 'disabled'), 'Add'))
        buttons.append(PushButton(Term('id', 'delete_policy'), 'Delete'))
        buttons = tuple(buttons)

        return VBox(
            Table(Term('id', 'policy_table'), Term('opt', Symbol('notify')), Term('header', *header), items),
            Right(HBox(*buttons)),
        )

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
                            Term('item', 'Scripts', False,
                                [
                                    Term('item', 'Startup', False, []),
                                    Term('item', 'Shutdown', False, []),
                                ]
                            ),
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
            Term('item', 'Preferences', False,
                [
                    Term('item', 'Windows Settings', False,
                        [
                            Term('item', 'Environment', False, []),
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
    def __init__(self, lp, creds):
        self.__get_creds(creds)
        self.realm = lp.get('realm')
        self.lp = lp
        self.creds = creds
        try:
            self.q = GPConnection(lp, creds)
            self.gpos = self.q.gpo_list()
        except:
            self.gpos = []
        self.selected_gpo = None

    def __get_creds(self, creds):
        if not creds.get_username() or not creds.get_password():
            UI.OpenDialog(self.__password_prompt(creds.get_username(), creds.get_password()))
            while True:
                subret = UI.UserInput()
                if str(subret) == 'creds_ok':
                    user = UI.QueryWidget(Term('id', 'username_prompt'), Symbol('Value'))
                    password = UI.QueryWidget(Term('id', 'password_prompt'), Symbol('Value'))
                    creds.set_username(user)
                    creds.set_password(password)
                if str(subret) == 'creds_cancel' or str(subret) == 'creds_ok':
                    UI.CloseDialog()
                    break

    def __password_prompt(self, user, password):
        from ycp import *
        ycp.widget_names()

        return MinWidth(30, VBox(
            Left(TextEntry(Term('id', 'username_prompt'), 'Username', '')),
            Left(Password(Term('id', 'password_prompt'), 'Password', '')),
            Right(HBox(
                PushButton(Term('id', 'creds_ok'), 'OK'),
                PushButton(Term('id', 'creds_cancel'), 'Cancel'),
            ))
        ))

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
        Wizard.DisableNextButton()
        UI.SetFocus(Term('id', 'gpmc_tree'))

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
                break
            elif str(ret) == 'add_gpo':
                UI.OpenDialog(self.__name_gpo())
                while True:
                    sret = UI.UserInput()
                    if str(sret) == 'ok_name_gpo':
                        gpo_name = UI.QueryWidget(Term('id', 'gpo_name_entry'), Symbol('Value'))
                        self.q.create_gpo(gpo_name)
                    UI.CloseDialog()
                    try:
                        self.gpos = self.q.gpo_list()
                    except:
                        self.gpos = []
                    Wizard.SetContentsButtons(gettext.gettext('Group Policy Management Console'), self.__gpmc_page(), self.__help(), 'Back', 'Edit GPO')
                    break
            elif UI.HasSpecialWidget(Symbol('DumbTab')):
                if gpo_guid == 'Domains':
                    if current_page != None:
                        Wizard.DisableNextButton()
                        UI.ReplaceWidget(Term('id', 'rightPane'), Term('Empty'))
                        current_page = None
                elif gpo_guid == self.realm:
                    if current_page != 'Realm':
                        Wizard.DisableNextButton()
                        UI.ReplaceWidget(Term('id', 'rightPane'), self.__realm())
                        current_page = 'Realm'
                else:
                    if str(ret) == 'advanced':
                        self.__gpo_tab_adv(gpo_guid)
                        continue
                    if current_page != 'Dumbtab' or old_gpo_guid != gpo_guid:
                        Wizard.EnableNextButton()
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
                            self.q.set_attr(self.selected_gpo[0], 'flags', ['3'])
                        elif combo_choice == 'Computer configuration settings disabled':
                            self.q.set_attr(self.selected_gpo[0], 'flags', ['2'])
                        elif combo_choice == 'Enabled':
                            self.q.set_attr(self.selected_gpo[0], 'flags', ['0'])
                        elif combo_choice == 'User configuration settings disabled':
                            self.q.set_attr(self.selected_gpo[0], 'flags', ['1'])

        return (self.selected_gpo, ret)

    def __name_gpo(self):
        from ycp import *
        ycp.widget_names()

        return MinWidth(30, VBox(
            TextEntry(Term('id', 'gpo_name_entry'), 'GPO Name', ''),
            Right(HBox(
                PushButton(Term('id', 'ok_name_gpo'), 'OK'),
                PushButton(Term('id', 'cancel_name_gpo'), 'Cancel')
            ))
        ))

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
                    Left(Label('%d' % (int(self.selected_gpo[1]['versionNumber'][-1]) & 0x0000FFFF))), VSpacing(),
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

    def __realm(self):
        from ycp import *
        ycp.widget_names()

        return VBox(
            Frame(self.realm, DumbTab(['Linked Group Policy Objects', 'Group Policy Inheritance', 'Delegation'], ReplacePoint(Term('id', 'realm_tabContainer'), self.__realm_links()))),
            Right(HBox(PushButton(Term('id', 'add_gpo'), 'Create a GPO'))),
        )

    def __realm_links(self):
        from ycp import *
        ycp.widget_names()

        header = ('Link Order', 'GPO', 'Enforced', 'Link Enabled', 'GPO Status', 'WMI Filter', 'Modified', 'Domain')
        contents = []
        for gpo in self.gpos:
            status = ''
            if gpo[1]['flags'][-1] == '0':
                status = 'Enabled'
            elif gpo[1]['flags'][-1] == '1':
                status = 'User configuration settings disabled'
            elif gpo[1]['flags'][-1] == '2':
                status = 'Computer configuration settings disabled'
            elif gpo[1]['flags'][-1] == '3':
                status = 'All settings disabled'
            vals = ('', gpo[1]['displayName'][-1], '', '', status, '', self.__ms_time_to_readable(gpo[1]['whenChanged'][-1]), '')
            contents.append(Term('item', *vals))

        return Table(Term('id', 'link_order'), Term('header', *header), contents)

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
            HWeight(2, ReplacePoint(Term('id', 'rightPane'), Term('Empty'))),
            )

