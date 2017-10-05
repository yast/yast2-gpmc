#!/usr/bin/env python

from defaults import Policies, fetch_inf_value
from complex import GPConnection, GPOConnection
from yast import *
import re

class GPME:
    def __init__(self, selected_gpo, lp, creds):
        self.selected_gpo = selected_gpo
        self.conn = GPOConnection(lp, creds, self.selected_gpo[1]['gPCFileSysPath'][-1])

    def Show(self):
        if not self.conn:
            return Symbol('back')
        Wizard.SetContentsButtons('Group Policy Management Editor', self.__gpme_page(), 'Group Policy Management Editor', 'Back', 'Close')
        Wizard.DisableAbortButton()
        UI.SetFocus('gpme_tree')

        policy = None
        while True:
            ret = UI.UserInput()
            if str(ret) in ['back', 'abort', 'next']:
                break
            elif str(ret) == 'gpme_tree':
                policy = UI.QueryWidget('gpme_tree', 'CurrentItem')
                UI.ReplaceWidget('rightPane', self.__display_policy(policy))
                continue
            if str(ret) == 'policy_table' or str(ret) == 'add_policy':
                conf = self.conn.parse(Policies[policy]['file'])
                if conf is None:
                    conf = Policies[policy]['new']()
                if str(ret) == 'policy_table':
                    selection = UI.QueryWidget(str(ret), 'CurrentItem')
                    values = Policies[policy]['opts'](conf)[selection]['values']
                elif str(ret) == 'add_policy':
                    values = Policies[policy]['add'](conf)
                UI.OpenDialog(self.__change_setting(values))
                while True:
                    subret = UI.UserInput()
                    if str(subret) == 'ok_change_setting' or str(subret) == 'apply_change_setting':
                        for k in values.keys():
                            value = UI.QueryWidget('entry_%s' % k, 'Value')
                            if values[k]['input']['options']:
                                value = values[k]['input']['options'][value.strip()]
                            if values[k]['set']:
                                values[k]['set'](value.strip())
                        self.conn.write(Policies[policy]['file'], conf)
                        if Policies[policy]['gpe_extension']:
                            self.conn.update_machine_gpe_ini(Policies[policy]['gpe_extension'])
                    elif str(subret).startswith('select_entry_'):
                        option = str(subret)[13:]
                        others, selection = values[option]['input']['action'](option, policy, self.conn)
                        UI.ReplaceWidget('button_entry_%s' % option, self.__button_entry(option, values, selection))
                        for k in others.keys():
                            UI.ReplaceWidget('text_entry_%s' % k, self.__button_entry(k, values, others[k]))
                        continue
                    if str(subret) == 'cancel_change_setting' or str(subret) == 'ok_change_setting':
                        UI.CloseDialog()
                        break
                UI.ReplaceWidget('rightPane', self.__display_policy(policy))
                UI.SetFocus(str(ret))

        return ret

    def __button_entry(self, k, values, value):
        return TextEntry(values[k]['title'], value, ID='entry_%s' % k)

    def __label_display(self, k, values, value):
        return Label('%s: %s' % (values[k]['title'], values[k]['valstr'](value)))

    def __change_values_prompt(self, values):
        items = []
        for value in sorted(values.iteritems(), cmp=(lambda a,b : a[-1]['order']-b[-1]['order'])):
            k = value[0]
            if not value[-1]['input']:
                continue
            if value[-1]['input']['type'] == 'TextEntry':
                items.append(Left(
                    ReplacePoint(TextEntry(value[-1]['title'], value[-1]['get'] if value[-1]['get'] else '', ID='entry_%s' % k), ID='text_entry_%s' % k),
                ))
            elif value[-1]['input']['type'] == 'ComboBox':
                combo_options = []
                current = value[-1]['valstr'](value[-1]['get'])
                for sk in value[-1]['input']['options'].keys():
                    combo_options.append((sk, current == sk))
                items.append(Left(ComboBox(value[-1]['title'], combo_options, ID='entry_%s' % k)))
            elif value[-1]['input']['type'] == 'Label':
                items.append(Left(
                    ReplacePoint(self.__label_display(k, values, value[-1]['get'] if value[-1]['get'] else ''), ID='label_%s' % k),
                ))
            elif value[-1]['input']['type'] == 'ButtonEntry':
                items.append(Left(
                    VBox(
                        ReplacePoint(self.__button_entry(k, values, value[-1]['get'] if value[-1]['get'] else ''), ID='button_entry_%s' % k),
                        PushButton('Select', ID='select_entry_%s' % k),
                    )
                ))
        items = tuple(items)
        return VBox(*items)

    def __change_setting(self, values):
        contents = MinWidth(30, HBox(HSpacing(), VBox(
            VSpacing(),
            self.__change_values_prompt(values),
            VSpacing(),
            Right(HBox(
                PushButton('OK', ID='ok_change_setting'),
                PushButton('Cancel', ID='cancel_change_setting'),
                PushButton('Apply', ID='apply_change_setting'),
            )),
            VSpacing(),
        ), HSpacing() ))
        return contents

    def __display_policy(self, label):
        if not label in Policies.keys():
            return Empty()
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
            items.append([key, vals])
        buttons = []
        if terms['add']:
            buttons.append(PushButton('Add', ID='add_policy'))
        buttons.append(PushButton('Delete', ID='delete_policy'))
        buttons = tuple(buttons)

        return VBox(
            Table(header, items, ID='policy_table', opts=['notify']),
            Right(HBox(*buttons)),
        )

    def __gpme_page(self):
        return HBox(
            HWeight(1, self.__policy_tree()),
            HWeight(2, ReplacePoint(Empty(), ID='rightPane')),
            )

    def __policy_tree(self):
        computer_config = [
            Node('Policies', False,
                [
                    Node('Software Settings', False,
                        [
                            Node('Software installation', False, [], ID='comp_software_install'),
                        ]
                    ),
                    Node('OS Settings', False,
                        [
                            Node('Scripts', False,
                                [
                                    Node('Startup', False, [], ID='comp_scripts_startup'),
                                    Node('Shutdown', False, [], ID='comp_scripts_shutdown'),
                                ]
                            ),
                            Node('Security Settings', False,
                                [
                                    Node('Account Policy', False,
                                        [
                                            Node('Password Policy', False, [], ID='comp_passwd'),
                                            Node('Account Lockout Policy', False, [], ID='comp_lockout'),
                                            Node('Kerberos Policy', False, [], ID='comp_krb'),
                                        ]
                                    ),
                                ]
                            ),
                        ]
                    ),
                ]
            ),
            Node('Preferences', False,
                [
                    Node('OS Settings', False,
                        [
                            Node('Environment', False, [], ID='comp_env_var'),
                        ]
                    ),
                ]
            ),
        ]

        user_config = [
            Node('Policies', False,
                [
                    Node('OS Settings', False,
                        [
                            Node('Internet Browser Maintenance', False,
                                [
                                    Node('Connection', False, [], ID='user_internet_maint_conn'),
                                    Node('URLs', False,
                                        [
                                            Node('Favorites and Links', False, [], ID='user_internet_maint_links'),
                                        ], ID='user_internet_maint_urls'),
                                ]
                            ),
                        ]
                    ),
                ]
            ),
        ]

        contents = Tree(self.selected_gpo[1]['displayName'][-1],
            [
                Node('Computer Configuration', True,
                    computer_config
                ),
                Node('User Configuration', True,
                    user_config
                ),
            ],
        ID='gpme_tree', opts=['notify'])
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
                    user = UI.QueryWidget('username_prompt', 'Value')
                    password = UI.QueryWidget('password_prompt', 'Value')
                    creds.set_username(user)
                    creds.set_password(password)
                if str(subret) == 'creds_cancel' or str(subret) == 'creds_ok':
                    UI.CloseDialog()
                    break

    def __password_prompt(self, user, password):
        return MinWidth(30, VBox(
            Left(TextEntry('Username', ID='username_prompt')),
            Left(Password('Password', ID='password_prompt')),
            Right(HBox(
                PushButton('OK', ID='creds_ok'),
                PushButton('Cancel', ID='creds_cancel'),
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
        Wizard.SetContentsButtons('Group Policy Management Console', self.__gpmc_page(), self.__help(), 'Back', 'Edit GPO')
        Wizard.DisableBackButton()
        Wizard.DisableNextButton()
        UI.SetFocus('gpmc_tree')

        current_page = 'Domains'
        old_gpo_guid = None
        gpo_guid = None
        while True:
            ret = UI.UserInput()
            old_gpo_guid = gpo_guid
            gpo_guid = UI.QueryWidget('gpmc_tree', 'CurrentItem')
            if str(ret) in ['back', 'abort']:
                break
            elif str(ret) == 'next':
                break
            elif str(ret) == 'add_gpo':
                UI.OpenDialog(self.__name_gpo())
                while True:
                    sret = UI.UserInput()
                    if str(sret) == 'ok_name_gpo':
                        gpo_name = UI.QueryWidget('gpo_name_entry', 'Value')
                        self.q.create_gpo(gpo_name)
                    UI.CloseDialog()
                    try:
                        self.gpos = self.q.gpo_list()
                    except:
                        self.gpos = []
                    Wizard.SetContentsButtons('Group Policy Management Console', self.__gpmc_page(), self.__help(), 'Back', 'Edit GPO')
                    break
            elif UI.HasSpecialWidget('DumbTab'):
                if gpo_guid == 'Domains':
                    if current_page != None:
                        Wizard.DisableNextButton()
                        UI.ReplaceWidget('rightPane', Empty())
                        current_page = None
                elif gpo_guid == self.realm:
                    if current_page != 'Realm':
                        Wizard.DisableNextButton()
                        UI.ReplaceWidget('rightPane', self.__realm())
                        current_page = 'Realm'
                else:
                    if str(ret) == 'advanced':
                        self.__gpo_tab_adv(gpo_guid)
                        continue
                    if current_page != 'Dumbtab' or old_gpo_guid != gpo_guid:
                        Wizard.EnableNextButton()
                        self.selected_gpo = self.__select_gpo(gpo_guid)
                        UI.ReplaceWidget('rightPane', self.__gpo_tab(gpo_guid))
                        current_page = 'Dumbtab'
                    if str(ret) == 'Scope':
                        UI.ReplaceWidget('gpo_tabContents', self.__scope_page())
                    elif str(ret) == 'Details':
                        UI.ReplaceWidget('gpo_tabContents', self.__details_page(gpo_guid))
                    elif str(ret) == 'Settings':
                        UI.ReplaceWidget('gpo_tabContents', self.__settings_page())
                    elif str(ret) == 'Delegation':
                        UI.ReplaceWidget('gpo_tabContents', self.__delegation_page())
                    elif str(ret) == 'gpo_status' and self.q:
                        combo_choice = UI.QueryWidget('gpo_status', 'Value')
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
        return MinWidth(30, VBox(
            TextEntry('GPO Name', ID='gpo_name_entry'),
            Right(HBox(
                PushButton('OK', ID='ok_name_gpo'),
                PushButton('Cancel', ID='cancel_name_gpo')
            ))
        ))

    def __help(self):
        return 'Group Policy Management Console'

    def __scope_page(self):
        return RichText('Contents of the scope page')

    def __ms_time_to_readable(self, timestamp):
        m = re.match('(?P<year>\d\d\d\d)(?P<month>\d\d)(?P<day>\d\d)(?P<hour>\d\d)(?P<minute>\d\d)(?P<second>\d\d)\..*', timestamp)
        if m:
            return '%s/%s/%s %s:%s:%s UTC' % (m.group('month'), m.group('day'), m.group('year'), m.group('hour'), m.group('minute'), m.group('second'))

    def __details_page(self, gpo_guid):
        status_selection = [False, False, False, False]
        if self.selected_gpo[1]['flags'][-1] == '0':
            status_selection[2] = True
        elif self.selected_gpo[1]['flags'][-1] == '1':
            status_selection[3] = True
        elif self.selected_gpo[1]['flags'][-1] == '2':
            status_selection[1] = True
        elif self.selected_gpo[1]['flags'][-1] == '3':
            status_selection[0] = True
        combo_options = [('All settings disabled', status_selection[0]), ('Computer configuration settings disabled', status_selection[1]), ('Enabled', status_selection[2]), ('User configuration settings disabled', status_selection[3])]

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
                    Left(ComboBox('', combo_options, ID='gpo_status', opts=['notify'])), VSpacing(),
                )),
            )
        )

    def __settings_page(self):
        return RichText('Contents of the settings page')

    def __delegation_page(self):
        return RichText('Contents of the delegation page')

    def __forest(self):
        items = []
        for gpo in self.gpos:
            items.append(Node(gpo[1]['displayName'][-1], ID=gpo[1]['name'][-1]))
        forest = [Node('Domains', True, [Node(self.realm, True, items)])]
        contents = Tree('Group Policy Management', forest, ID='gpmc_tree', opts=['notify'])
        
        return contents

    def __realm(self):
        return VBox(
            Frame(self.realm, DumbTab(['Linked Group Policy Objects', 'Group Policy Inheritance', 'Delegation'], ReplacePoint(self.__realm_links(), ID='realm_tabContainer'))),
            Right(HBox(PushButton('Create a GPO', ID='add_gpo'))),
        )

    def __realm_links(self):
        header = ['Link Order', 'GPO', 'Enforced', 'Link Enabled', 'GPO Status', 'WMI Filter', 'Modified', 'Domain']
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
            contents.append(vals)

        return Table(header, items=contents, ID='link_order')

    def __gpo_tab(self, gpo_guid):
        gpo_name = self.selected_gpo[1]['displayName'][-1]
        return Frame(gpo_name, ReplacePoint(VBox(self.__details_page(gpo_guid), Right(PushButton('Advanced', ID='advanced'))), ID='gpo_tabContainer'))

    def __gpo_tab_adv(self, gpo_guid):
        UI.ReplaceWidget('gpo_tabContainer', DumbTab(['Scope', 'Details', 'Settings', 'Delegation'], ReplacePoint(self.__scope_page(), ID='gpo_tabContents'), ID='gpo_tab'))

    def __gpmc_page(self):
        return HBox(
            HWeight(1, self.__forest()),
            HWeight(2, ReplacePoint(Empty(), ID='rightPane')),
            )

