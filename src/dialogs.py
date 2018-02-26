from defaults import Policies, fetch_inf_value
from complex import GPConnection, GPOConnection
from yast import import_module
import_module('Wizard')
import_module('UI')
from yast import *
import re
from functools import cmp_to_key

selected_gpo = None

class GPME:
    def __init__(self, lp, creds):
        global selected_gpo
        self.conn = GPOConnection(lp, creds, selected_gpo[1]['gPCFileSysPath'][-1])

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
                            if values[k]['set'] or values[k]['input']['options']:
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

        return Symbol(ret)

    def __button_entry(self, k, values, value):
        return TextEntry(Id('entry_%s' % k), Opt('hstretch'), values[k]['title'], value)

    def __label_display(self, k, values, value):
        return Label('%s: %s' % (values[k]['title'], values[k]['valstr'](value)))

    def __change_values_prompt(self, values):
        items = []
        ckey = cmp_to_key(lambda a,b : a[-1]['order']-b[-1]['order'])
        for value in sorted(values.items(), key=ckey):
            k = value[0]
            if not value[-1]['input']:
                continue
            if value[-1]['input']['type'] == 'TextEntry':
                items.append(Left(
                    ReplacePoint(Id('text_entry_%s' % k), TextEntry(Id('entry_%s' % k), Opt('hstretch'), value[-1]['title'], value[-1]['get'] if value[-1]['get'] else '')),
                ))
            elif value[-1]['input']['type'] == 'ComboBox':
                combo_options = []
                current = value[-1]['valstr'](value[-1]['get'])
                for sk in value[-1]['input']['options'].keys():
                    combo_options.append(Item(sk, current == sk))
                items.append(Left(ComboBox(Id('entry_%s' % k), Opt('hstretch'), value[-1]['title'], combo_options)))
            elif value[-1]['input']['type'] == 'Label':
                items.append(Left(
                    ReplacePoint(Id('label_%s' % k), self.__label_display(k, values, value[-1]['get'] if value[-1]['get'] else '')),
                ))
            elif value[-1]['input']['type'] == 'ButtonEntry':
                items.append(Left(
                    VBox(
                        ReplacePoint(Id('button_entry_%s' % k), self.__button_entry(k, values, value[-1]['get'] if value[-1]['get'] else '')),
                        PushButton(Id('select_entry_%s' % k), 'Select'),
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
                PushButton(Id('ok_change_setting'), 'OK'),
                PushButton(Id('cancel_change_setting'), 'Cancel'),
                PushButton(Id('apply_change_setting'), 'Apply'),
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
        header = tuple(terms['header']())
        header = Header(*header)
        for key in opts:
            values = sorted(opts[key]['values'].values(), key=(lambda x : x['order']))
            vals = tuple([k['valstr'](k['get'].decode('utf-8')) if type(k['get']) is bytes else k['valstr'](k['get']) for k in values])
            items.append(Item(Id(key), *vals))
        buttons = []
        if terms['add']:
            buttons.append(PushButton(Id('add_policy'), 'Add'))
        buttons.append(PushButton(Id('delete_policy'), 'Delete'))
        buttons = tuple(buttons)

        return VBox(
            Table(Id('policy_table'), Opt('notify'), header, items),
            Right(HBox(*buttons)),
        )

    def __gpme_page(self):
        return HBox(
            HWeight(1, self.__policy_tree()),
            HWeight(2, ReplacePoint(Id('rightPane'), Empty())),
            )

    def __policy_tree(self):
        global selected_gpo
        computer_config = [
            Item('Policies', False,
                [
                    Item('Software Settings', False,
                        [
                            Item(Id('comp_software_install'), 'Software installation', False, []),
                        ]
                    ),
                    Item('OS Settings', False,
                        [
                            Item('Scripts', False,
                                [
                                    Item(Id('comp_scripts_startup'), 'Startup', False, []),
                                    Item(Id('comp_scripts_shutdown'), 'Shutdown', False, []),
                                ]
                            ),
                            Item('Security Settings', False,
                                [
                                    Item('Account Policy', False,
                                        [
                                            Item(Id('comp_passwd'), 'Password Policy', False, []),
                                            Item(Id('comp_lockout'), 'Account Lockout Policy', False, []),
                                            Item(Id('comp_krb'), 'Kerberos Policy', False, []),
                                        ]
                                    ),
                                ]
                            ),
                        ]
                    ),
                ]
            ),
            Item('Preferences', False,
                [
                    Item('OS Settings', False,
                        [
                            Item(Id('comp_env_var'), 'Environment', False, []),
                        ]
                    ),
                ]
            ),
        ]

        user_config = [
            Item('Policies', False,
                [
                    Item('OS Settings', False,
                        [
                            Item('Internet Browser Maintenance', False,
                                [
                                    Item(Id('user_internet_maint_conn'), 'Connection', False, []),
                                    Item(Id('user_internet_maint_urls'), 'URLs', False,
                                        [
                                            Item(Id('user_internet_maint_links'), 'Favorites and Links', False, []),
                                        ]),
                                ]
                            ),
                        ]
                    ),
                ]
            ),
        ]

        contents = Tree(Id('gpme_tree'), Opt('notify'), selected_gpo[1]['displayName'][-1],
            [
                Item('Computer Configuration', True,
                    computer_config
                ),
                Item('User Configuration', True,
                    user_config
                ),
            ],
        )
        return contents

class GPMC:
    def __init__(self, lp, creds):
        global selected_gpo
        self.realm = lp.get('realm')
        self.lp = lp
        self.creds = creds
        self.gpos = []
        selected_gpo = None
        self.got_creds = self.__get_creds(creds)
        while self.got_creds:
            try:
                self.q = GPConnection(lp, creds)
                self.gpos = self.q.gpo_list()
                break
            except Exception as e:
                print(str(e))
                self.got_creds = self.__get_creds(creds)

    def __get_creds(self, creds):
        UI.OpenDialog(self.__password_prompt(creds.get_username()))
        while True:
            subret = UI.UserInput()
            if str(subret) == 'creds_ok':
                user = UI.QueryWidget('username_prompt', 'Value')
                password = UI.QueryWidget('password_prompt', 'Value')
                UI.CloseDialog()
                if not password:
                    return False
                creds.set_username(user)
                creds.set_password(password)
                return True
            if str(subret) == 'creds_cancel':
                UI.CloseDialog()
                return False

    def __password_prompt(self, user):
        return MinWidth(30, VBox(
            Left(Label('To continue, type an administrator password')),
            Left(TextEntry(Id('username_prompt'), Opt('hstretch'), 'Username', user)),
            Left(Password(Id('password_prompt'), Opt('hstretch'), 'Password')),
            Right(HBox(
                PushButton(Id('creds_ok'), 'OK'),
                PushButton(Id('creds_cancel'), 'Cancel'),
            ))
        ))

    def __select_gpo(self, gpo_guid):
        global selected_gpo
        selected_gpo = None
        for gpo in self.gpos:
            if gpo[1]['name'][-1] == gpo_guid:
                selected_gpo = gpo
                break
        return selected_gpo

    def Show(self):
        global selected_gpo
        if not self.got_creds:
            return Symbol('abort')
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
                        selected_gpo = self.__select_gpo(gpo_guid)
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
                            self.q.set_attr(selected_gpo[0], 'flags', ['3'])
                        elif combo_choice == 'Computer configuration settings disabled':
                            self.q.set_attr(selected_gpo[0], 'flags', ['2'])
                        elif combo_choice == 'Enabled':
                            self.q.set_attr(selected_gpo[0], 'flags', ['0'])
                        elif combo_choice == 'User configuration settings disabled':
                            self.q.set_attr(selected_gpo[0], 'flags', ['1'])

        return Symbol(ret)

    def __name_gpo(self):
        return MinWidth(30, VBox(
            TextEntry(Id('gpo_name_entry'), Opt('hstretch'), 'GPO Name'),
            Right(HBox(
                PushButton(Id('ok_name_gpo'), 'OK'),
                PushButton(Id('cancel_name_gpo'), 'Cancel')
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
        global selected_gpo
        status_selection = [False, False, False, False]
        if selected_gpo[1]['flags'][-1] == '0':
            status_selection[2] = True
        elif selected_gpo[1]['flags'][-1] == '1':
            status_selection[3] = True
        elif selected_gpo[1]['flags'][-1] == '2':
            status_selection[1] = True
        elif selected_gpo[1]['flags'][-1] == '3':
            status_selection[0] = True
        combo_options = [Item('All settings disabled', status_selection[0]), Item('Computer configuration settings disabled', status_selection[1]), Item('Enabled', status_selection[2]), Item('User configuration settings disabled', status_selection[3])]

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
                    Left(Label(self.__ms_time_to_readable(selected_gpo[1]['whenCreated'][-1]))), VSpacing(),
                    Left(Label(self.__ms_time_to_readable(selected_gpo[1]['whenChanged'][-1]))), VSpacing(),
                    Left(Label('%d' % (int(selected_gpo[1]['versionNumber'][-1]) >> 16))), VSpacing(),
                    Left(Label('%d' % (int(selected_gpo[1]['versionNumber'][-1]) & 0x0000FFFF))), VSpacing(),
                    Left(Label(gpo_guid)), VSpacing(),
                    Left(ComboBox(Id('gpo_status'), Opt('notify', 'hstretch'), '', combo_options)), VSpacing(),
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
            items.append(Item(Id(gpo[1]['name'][-1]), gpo[1]['displayName'][-1]))
        forest = [Item('Domains', True, [Item(self.realm, True, items)])]
        contents = Tree(Id('gpmc_tree'), Opt('notify'), 'Group Policy Management', forest)
        
        return contents

    def __realm(self):
        return VBox(
            Frame(self.realm, DumbTab(['Linked Group Policy Objects', 'Group Policy Inheritance', 'Delegation'], ReplacePoint(Id('realm_tabContainer'), self.__realm_links()))),
            Right(HBox(PushButton(Id('add_gpo'), 'Create a GPO'))),
        )

    def __realm_links(self):
        header = Header('Link Order', 'GPO', 'Enforced', 'Link Enabled', 'GPO Status', 'WMI Filter', 'Modified', 'Domain')
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
            vals = Item('', gpo[1]['displayName'][-1], '', '', status, '', self.__ms_time_to_readable(gpo[1]['whenChanged'][-1]), '')
            contents.append(vals)

        return Table(Id('link_order'), header, contents)

    def __gpo_tab(self, gpo_guid):
        global selected_gpo
        gpo_name = selected_gpo[1]['displayName'][-1]
        return Frame(gpo_name, ReplacePoint(Id('gpo_tabContainer'), VBox(self.__details_page(gpo_guid), Right(PushButton(Id('advanced'), 'Advanced')))))

    def __gpo_tab_adv(self, gpo_guid):
        UI.ReplaceWidget('gpo_tabContainer', DumbTab(Id('gpo_tab'), ['Scope', 'Details', 'Settings', 'Delegation'], ReplacePoint(Id('gpo_tabContents'), self.__scope_page())))

    def __gpmc_page(self):
        return HBox(
            HWeight(1, self.__forest()),
            HWeight(2, ReplacePoint(Id('rightPane'), Empty())),
            )

