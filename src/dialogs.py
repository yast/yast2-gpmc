#!/usr/bin/env python

from defaults import Policies, fetch_inf_value
from complex import GPConnection, GPOConnection
from yui import *
import re

class GPME:
    def __init__(self, selected_gpo, lp, creds):
        self.selected_gpo = selected_gpo
        self.conn = GPOConnection(lp, creds, self.selected_gpo[1]['gPCFileSysPath'][-1])

    def Show(self):
        if not self.conn:
            return Symbol('back')
        WizardDialog.SetContentsButtons('Group Policy Management Editor', self.__gpme_page(), 'Group Policy Management Editor', 'Back', 'Close')
        WizardDialog.DisableAbortButton()
        WizardDialog.SetFocus('gpme_tree')

        policy = None
        for ret in WizardDialog.UserInput():
            if str(ret) in ['back', 'abort', 'next']:
                break
            elif str(ret) == 'gpme_tree':
                policy = WizardDialog.QueryWidget('gpme_tree', 'CurrentItem')
                WizardDialog.ReplaceWidget('rightPane', self.__display_policy(policy))
                continue
            if str(ret) == 'policy_table' or str(ret) == 'add_policy':
                conf = self.conn.parse(Policies[policy]['file'])
                if conf is None:
                    conf = Policies[policy]['new']()
                if str(ret) == 'policy_table':
                    selection = WizardDialog.QueryWidget(str(ret), 'CurrentItem')
                    values = Policies[policy]['opts'](conf)[selection]['values']
                elif str(ret) == 'add_policy':
                    values = Policies[policy]['add'](conf)
                Dialog.OpenDialog(self.__change_setting(values))
                for subret in Dialog.UserInput():
                    if str(subret) == 'ok_change_setting' or str(subret) == 'apply_change_setting':
                        for k in values.keys():
                            value = Dialog.QueryWidget('entry_%s' % k, 'Value')
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
                        Dialog.ReplaceWidget('button_entry_%s' % option, self.__button_entry(option, values, selection))
                        for k in others.keys():
                            Dialog.ReplaceWidget('text_entry_%s' % k, self.__button_entry(k, values, others[k]))
                        continue
                    if str(subret) == 'cancel_change_setting' or str(subret) == 'ok_change_setting':
                        Dialog.CloseDialog()
                        break
                WizardDialog.ReplaceWidget('rightPane', self.__display_policy(policy))
                WizardDialog.SetFocus(str(ret))

        return ret

    def __button_entry(self, k, values, value):
        return TextEntry(values[k]['title'], value, ID='entry_%s' % k)

    def __label_display(self, k, values, value):
        return Label('%s: %s' % (values[k]['title'], values[k]['valstr'](value)))

    def __change_values_prompt(self, values):
        items = []
        for k in values.keys():
            if not values[k]['input']:
                continue
            if values[k]['input']['type'] == 'TextEntry':
                items.append(Left(
                    ReplacePoint(TextEntry(values[k]['title'], values[k]['get'] if values[k]['get'] else '', ID='entry_%s' % k), ID='text_entry_%s' % k),
                ))
            elif values[k]['input']['type'] == 'ComboBox':
                combo_options = []
                current = values[k]['valstr'](values[k]['get'])
                for sk in values[k]['input']['options'].keys():
                    combo_options.append((sk, current == sk))
                items.append(Left(ComboBox(values[k]['title'], combo_options, ID='entry_%s' % k)))
            elif values[k]['input']['type'] == 'Label':
                items.append(Left(
                    ReplacePoint(self.__label_display(k, values, values[k]['get'] if values[k]['get'] else ''), ID='label_%s' % k),
                ))
            elif values[k]['input']['type'] == 'ButtonEntry':
                items.append(Left(
                    VBox(
                        ReplacePoint(self.__button_entry(k, values, values[k]['get'] if values[k]['get'] else ''), ID='button_entry_%s' % k),
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
                            Node('Software installation', False, []),
                        ]
                    ),
                    Node('Windows Settings', False,
                        [
                            Node('Scripts', False,
                                [
                                    Node('Startup', False, []),
                                    Node('Shutdown', False, []),
                                ]
                            ),
                            Node('Security Settings', False,
                                [
                                    Node('Account Policy', False,
                                        [
                                            Node('Password Policy', False, []),
                                            Node('Account Lockout Policy', False, []),
                                            Node('Kerberos Policy', False, []),
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
                    Node('Windows Settings', False,
                        [
                            Node('Environment', False, []),
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
            Dialog.OpenDialog(self.__password_prompt(creds.get_username(), creds.get_password()))
            for subret in Dialog.UserInput():
                if str(subret) == 'creds_ok':
                    user = Dialog.QueryWidget('username_prompt', 'Value')
                    password = Dialog.QueryWidget('password_prompt', 'Value')
                    creds.set_username(user)
                    creds.set_password(password)
                if str(subret) == 'creds_cancel' or str(subret) == 'creds_ok':
                    Dialog.CloseDialog()
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
        WizardDialog.SetContentsButtons('Group Policy Management Console', self.__gpmc_page(), self.__help(), 'Back', 'Edit GPO')
        WizardDialog.DisableBackButton()
        WizardDialog.DisableNextButton()
        WizardDialog.SetFocus('gpmc_tree')

        current_page = 'Domains'
        old_gpo_guid = None
        gpo_guid = None
        for ret in WizardDialog.UserInput():
            old_gpo_guid = gpo_guid
            gpo_guid = WizardDialog.QueryWidget('gpmc_tree', 'CurrentItem')
            if str(ret) in ['back', 'abort']:
                break
            elif str(ret) == 'next':
                break
            elif str(ret) == 'add_gpo':
                Dialog.OpenDialog(self.__name_gpo())
                for sret in Dialog.UserInput():
                    if str(sret) == 'ok_name_gpo':
                        gpo_name = Dialog.QueryWidget('gpo_name_entry', 'Value')
                        self.q.create_gpo(gpo_name)
                    Dialog.CloseDialog()
                    try:
                        self.gpos = self.q.gpo_list()
                    except:
                        self.gpos = []
                    WizardDialog.SetContentsButtons('Group Policy Management Console', self.__gpmc_page(), self.__help(), 'Back', 'Edit GPO')
                    break
            elif WizardDialog.HasSpecialWidget('DumbTab'):
                if gpo_guid == 'Domains':
                    if current_page != None:
                        WizardDialog.DisableNextButton()
                        WizardDialog.ReplaceWidget('rightPane', Empty())
                        current_page = None
                elif gpo_guid == self.realm:
                    if current_page != 'Realm':
                        WizardDialog.DisableNextButton()
                        WizardDialog.ReplaceWidget('rightPane', self.__realm())
                        current_page = 'Realm'
                else:
                    if str(ret) == 'advanced':
                        self.__gpo_tab_adv(gpo_guid)
                        continue
                    if current_page != 'Dumbtab' or old_gpo_guid != gpo_guid:
                        WizardDialog.EnableNextButton()
                        self.selected_gpo = self.__select_gpo(gpo_guid)
                        WizardDialog.ReplaceWidget('rightPane', self.__gpo_tab(gpo_guid))
                        current_page = 'Dumbtab'
                    if str(ret) == 'Scope':
                        WizardDialog.ReplaceWidget('gpo_tabContents', self.__scope_page())
                    elif str(ret) == 'Details':
                        WizardDialog.ReplaceWidget('gpo_tabContents', self.__details_page(gpo_guid))
                    elif str(ret) == 'Settings':
                        WizardDialog.ReplaceWidget('gpo_tabContents', self.__settings_page())
                    elif str(ret) == 'Delegation':
                        WizardDialog.ReplaceWidget('gpo_tabContents', self.__delegation_page())
                    elif str(ret) == 'gpo_status' and self.q:
                        combo_choice = WizardDialog.QueryWidget('gpo_status', 'Value')
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
        WizardDialog.ReplaceWidget('gpo_tabContainer', DumbTab(['Scope', 'Details', 'Settings', 'Delegation'], ReplacePoint(self.__scope_page(), ID='gpo_tabContents'), ID='gpo_tab'))

    def __gpmc_page(self):
        return HBox(
            HWeight(1, self.__forest()),
            HWeight(2, ReplacePoint(Empty(), ID='rightPane')),
            )

