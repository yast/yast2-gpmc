from __future__ import absolute_import, division, print_function, unicode_literals
from defaults import Policies, fetch_inf_value, set_admx_value, get_admx_value, get_admx_configured
from complex import GPConnection, GPOConnection, dn_to_path, parse_gplink
from adcommon.strings import strcmp, strcasecmp
from yast import import_module
import_module('Wizard')
import_module('UI')
from yast import *
import re
from functools import cmp_to_key
from samba.dcerpc import security
from samba.ndr import ndr_unpack
import samba.security
from samba.ntacls import dsacl2fsacl
import os.path
from itertools import chain
from samba.dcerpc import preg
import six
from adcommon.creds import YCreds, switch_domains
from adcommon.ui import CreateMenu, DeleteButtonBox

ENABLE_EXPERIMENTAL = bool(os.getenv("YAST2_GPMC_EXPERIMENTAL"))

selected_gpo = None

class GPME:
    def __init__(self, lp, creds):
        global selected_gpo
        self.conn = GPOConnection(lp, creds, selected_gpo[1]['gPCFileSysPath'][-1])

    def __reset(self):
        UI.SetApplicationTitle('Group Policy Management Editor')
        Wizard.SetContentsButtons('Group Policy Management Editor', self.__gpme_page(), 'Group Policy Management Editor', '', 'Close')
        self.__setup_menus()
        DeleteButtonBox()

    def __setup_menus(self):
        menus = [{'title': '&File', 'id': 'file', 'type': 'Menu'},
                 {'title': 'Exit', 'id': 'abort', 'type': 'MenuEntry', 'parent': 'file'}]
        CreateMenu(menus)

    def Show(self):
        if not self.conn:
            return Symbol('back')
        self.__reset()
        UI.SetFocus('gpme_tree')

        policy = None
        while True:
            ret = UI.UserInput()
            if str(ret) in ['back', 'abort', 'next', 'cancel']:
                ret = 'back'
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
                UI.SetApplicationTitle('%s Properties' % selection)
                UI.OpenDialog(self.__change_setting(values))
                while True:
                    subret = UI.UserInput()
                    if str(subret) == 'ok_change_setting' or str(subret) == 'apply_change_setting':
                        for k in values.keys():
                            if 'configurable' in values[k]['input'] and values[k]['input']['configurable']:
                                configured = UI.QueryWidget('configured_%s' % k, 'Value')
                                if configured or configured == None:
                                    value = UI.QueryWidget('entry_%s' % k, 'Value')
                                else:
                                    value = None
                            else:
                                if values[k]['set'] or values[k]['input']['options']:
                                    value = UI.QueryWidget('entry_%s' % k, 'Value')
                                if values[k]['input']['options']:
                                    value = values[k]['input']['options'][value.strip()]
                            if values[k]['set']:
                                if type(value) is str:
                                    value = value.strip()
                                values[k]['set'](value)
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
                        UI.SetApplicationTitle('Group Policy Management Editor')
                        break
                UI.ReplaceWidget('rightPane', self.__display_policy(policy))
                UI.SetFocus(str(ret))
            elif str(ret) == 'delete_policy':
                selection = UI.QueryWidget(str(ret), 'CurrentItem')
                Policies[policy]['delete'](conf, selection)

        return Symbol(ret)

    def __button_entry(self, k, values, value):
        return TextEntry(Id('entry_%s' % k), Opt('hstretch'), values[k]['title'], value)

    def __label_display(self, k, values, value, detail_desc):
        ret = Label('%s: %s' % (values[k]['title'], values[k]['valstr'](value)))
        if detail_desc:
            ret = MinHeight(20, MinWidth(50, RichText(detail_desc.replace('\n', '<br/>'))))
        return ret

    def __change_values_prompt(self, values):
        items = []
        vertical = True
        reverse = False
        title = None
        ckey = cmp_to_key(lambda a,b : a[-1]['order']-b[-1]['order'])
        for value in sorted(values.items(), key=ckey):
            k = value[0]
            if not value[-1]['input']:
                continue
            if strcmp(value[-1]['input']['type'], 'TextEntry'):
                configurable = Empty()
                configured = value[-1]['get'] != None
                if 'configurable' in value[-1]['input'] and value[-1]['input']['configurable']:
                    configurable = CheckBox(Id('configured_%s' % k), Opt('hstretch'), 'Configured', configured)
                items.append(Top(MinWidth(30, Left(
                    ReplacePoint(Id('text_entry_%s' % k), VBox(
                        configurable,
                        TextEntry(Id('entry_%s' % k), Opt('hstretch'), value[-1]['title'], value[-1]['get'] if value[-1]['get'] else '')
                    )),
                ))))
            elif strcmp(value[-1]['input']['type'], 'ComboBox'):
                combo_options = []
                current = value[-1]['valstr'](value[-1]['get'])
                for sk in value[-1]['input']['options'].keys():
                    combo_options.append(Item(sk, strcmp(current, sk)))
                items.append(Top(MinWidth(30, Left(ComboBox(Id('entry_%s' % k), Opt('hstretch'), value[-1]['title'], combo_options)))))
            elif strcmp(value[-1]['input']['type'], 'Label'):
                if 'description' in value[-1]['input'] and value[-1]['input']['description']:
                    vertical = False
                    reverse = True
                    title = values[k]['valstr'](value[-1]['get'] if value[-1]['get'] else '')
                items.append(Left(
                    ReplacePoint(Id('label_%s' % k), self.__label_display(k, values, value[-1]['get'] if value[-1]['get'] else '', value[-1]['input']['description'] if 'description' in value[-1]['input'] else None)),
                ))
            elif strcmp(value[-1]['input']['type'], 'ButtonEntry'):
                items.append(Top(MinWidth(30, Left(
                    VBox(
                        ReplacePoint(Id('button_entry_%s' % k), self.__button_entry(k, values, value[-1]['get'] if value[-1]['get'] else '')),
                        PushButton(Id('select_entry_%s' % k), 'Select'),
                    )
                ))))
            elif strcmp(value[-1]['input']['type'], 'IntField'):
                configurable = Empty()
                configured = value[-1]['get'] != None
                if 'configurable' in value[-1]['input'] and value[-1]['input']['configurable']:
                    configurable = CheckBox(Id('configured_%s' % k), Opt('hstretch'), 'Configured', configured)
                items.append(Top(MinWidth(30, Left(
                    ReplacePoint(Id('int_field_%s' % k), VBox(
                        configurable,
                        IntField(Id('entry_%s' % k), Opt('hstretch'), value[-1]['title'], 0, 999999999, value[-1]['get'] if value[-1]['get'] else 0)
                    ))
                ))))
            elif strcmp(value[-1]['input']['type'], 'CheckBox'):
                if 'configurable' in value[-1]['input'] and value[-1]['input']['configurable']:
                    disp = value[-1]['valstr'](value[-1]['get'])
                    items.append(Top(Left(
                        ReplacePoint(Id('check_box_%s' % k), RadioButtonGroup(Id('entry_%s' % k), VBox(
                            Left(RadioButton(Id(None), 'Not Configured', strcmp(disp, 'Not configured'))),
                            Left(RadioButton(Id(True), 'Enabled', strcmp(disp, 'Enabled'))),
                            Left(RadioButton(Id(False), 'Disabled', strcmp(disp, 'Disabled')))
                        )))
                    )))
                else:
                    items.append(Top(Left(
                        ReplacePoint(Id('check_box_%s' % k), CheckBox(Id('entry_%s' % k), Opt('hstretch'), value[-1]['title'], bool(value[-1]['get']) if value[-1]['get'] else False))
                    )))
        if reverse:
            items.reverse()
        items = tuple(items)
        if vertical:
            ret = VBox(*items)
        else:
            ret = HBox(*items)
        if title:
            ret = VBox(Left(Heading(title)), ret)
        return ret

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
        if 'delete' in terms.keys():
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

    def __fetch_admin_templates(self):
        templates = []
        items = {}
        def itemizer(ref, items):
            if 'item' in items[ref].keys():
                return
            # First build dependant children
            if len(items[ref]['children']) > 0:
                for child_ref in items[ref]['children']:
                    itemizer(child_ref, items)
            # Next build the Item
            children = [items[cr]['item'] for cr in items[ref]['children']]
            if 'displayName' in items[ref].keys():
                items[ref]['item'] = Item(Id(ref), items[ref]['displayName'], False, children)

        def fetch_attr(obj, attr, strings, presentations):
            val = obj.attrib[attr]
            m = re.match('\$\((\w*).(\w*)\)', val)
            if m and strcmp(m.group(1), 'string'):
                val = strings.find('string[@id="%s"]' % m.group(2)).text
            elif m and strcmp(m.group(1), 'presentation'):
                val = presentations.find('presentation[@id="%s"]' % m.group(2)).text
            return val

        for f in self.conn.list('../PolicyDefinitions/'):
            fname = os.path.join('../PolicyDefinitions/', f['name'])
            fparts = os.path.splitext(fname)
            if strcasecmp(fparts[-1].lower(), '.admx'):
                admx = self.conn.parse(fname)
                dirname = os.path.dirname(fparts[0])
                basename = os.path.basename(fparts[0])
                adml = self.conn.parse('%s/en-US/%s.adml' % (dirname, basename))
                strings = adml.find('resources').find('stringTable')
                presentations = adml.find('resources').find('presentationTable')
                policies = admx.find('policies').findall('policy')
                parents = set([p.find('parentCategory').attrib['ref'] for p in policies])
                categories = admx.find('categories').findall('category')
                for category in categories:
                    disp = fetch_attr(category, 'displayName', strings, presentations)
                    my_ref = category.attrib['name']
                    par_ref = category.find('parentCategory').attrib['ref']

                    if my_ref not in items.keys():
                        items[my_ref] = {}
                        items[my_ref]['children'] = []
                    if par_ref not in items.keys():
                        items[par_ref] = {}
                        items[par_ref]['children'] = [my_ref]
                    else:
                        items[par_ref]['children'].append(my_ref)
                    items[my_ref]['displayName'] = disp
                for ref in items.keys():
                    itemizer(ref, items)
                refs = [items[r]['children'] for r in items.keys() if not 'item' in items[r].keys()]
                refs = chain.from_iterable(refs)
                for r in refs:
                    templates.append(items[r]['item'])

                for parent in parents:
                    Policies[parent] = {}
                    Policies[parent]['file'] = '\\MACHINE\\Registry.pol'
                    Policies[parent]['gpe_extension'] = None
                    Policies[parent]['new'] = None
                    Policies[parent]['add'] = None
                    Policies[parent]['header'] = (lambda : ['Setting', 'Value'])
                    Policies[parent]['values'] = \
                            (lambda conf, reg_key, key, desc, valstr, val_type, _input : {
                                'setting' : {
                                    'order' : 0,
                                    'title' : 'Setting',
                                    'get' : key,
                                    'set' : None,
                                    'valstr' : (lambda v : v),
                                    'input' : {
                                        'type' : 'Label',
                                        'options' : None,
                                        'description' : desc,
                                    },
                                },
                                'value' : {
                                    'order' : 1,
                                    'title' : key,
                                    'get' : get_admx_value(conf, reg_key, key),
                                    'set' : (lambda v : set_admx_value(conf, reg_key, key, v, val_type)),
                                    'valstr' : (lambda v : valstr(v) if get_admx_configured(conf, reg_key, key) else 'Not configured'),
                                    'input' : _input,
                                },
                            } )

                    def policy_generator(conf):
                        values = {}
                        for policy in policies:
                            if policy.find('parentCategory').attrib['ref'] != parent:
                                continue
                            disp = fetch_attr(policy, 'displayName', strings, presentations)
                            desc = fetch_attr(policy, 'explainText', strings, presentations)
                            values[disp] = {}
                            val_type = None
                            elements = policy.find('elements')
                            defined = get_admx_configured(conf, policy.attrib['key'], disp)
                            if elements.find('text') is not None:
                                val_type = 'TextEntry'
                                val_str = (lambda v : v if v else '')
                            elif elements.find('decimal') is not None:
                                val_type = 'IntField'
                                val_str = (lambda v : v)
                            elif elements.find('boolean') is not None:
                                val_type = 'CheckBox'
                                val_str = (lambda v : 'Disabled' if int(v) == 0 else 'Enabled')
                            values[disp]['values'] = Policies[parent]['values'](
                                conf, policy.attrib['key'], disp, desc, val_str, val_type,
                                {
                                    'type' : val_type,
                                    'configurable' : True,
                                    'options' : None,
                                },
                            )
                        return values

                    Policies[parent]['opts'] = policy_generator

        return templates

    def __policy_tree(self):
        global selected_gpo

        admin_templates = self.__fetch_admin_templates()

        policy_items = []
        if ENABLE_EXPERIMENTAL:
            policy_items.append(
                Item('Software Settings', False,
                    [
                        Item(Id('comp_software_install'), 'Software installation', False, []),
                    ]
                )
            )
        os_settings_items = []
        if ENABLE_EXPERIMENTAL:
            os_settings_items.append(
                Item('Scripts', False,
                    [
                        Item(Id('comp_scripts_startup'), 'Startup', False, []),
                        Item(Id('comp_scripts_shutdown'), 'Shutdown', False, []),
                    ]
                )
            )
        os_settings_items.append(
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
            )
        )
        policy_items.append(
            Item('OS Settings', False,
                    os_settings_items
            )
        )

        policy_items.append(
            Item('Administrative Templates', False,
                admin_templates
            )
        )

        computer_config = [
            Item('Policies', False,
                policy_items
            ),
        ]

        if ENABLE_EXPERIMENTAL:
            computer_config.append(
                Item('Preferences', False,
                    [
                        Item('OS Settings', False,
                            [
                                Item(Id('comp_env_var'), 'Environment', False, []),
                            ]
                        ),
                    ]
                )
            )

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
                    Item('Administrative Templates', False,
                        admin_templates
                    ),
                ]
            ),
        ]

        items = [
            Item('Computer Configuration', True,
                computer_config
            ),
        ]
        if ENABLE_EXPERIMENTAL:
            items.append(
                Item('User Configuration', True,
                    user_config
                )
            )

        contents = Tree(Id('gpme_tree'), Opt('notify'), selected_gpo[1]['displayName'][-1],
            items
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
        self.__setup_menus()
        DeleteButtonBox()
        ycred = YCreds(creds)
        def cred_valid():
            try:
                self.q = GPConnection(lp, creds)
                self.gpos = self.q.gpo_list()
                self.realm_dn = self.q.realm_to_dn(self.realm)
                return True
            except Exception as e:
                ycpbuiltins.y2error(str(e))
            return False
        self.cred_valid = cred_valid
        if not self.cred_valid():
            self.got_creds = ycred.Show(self.cred_valid)
        else:
            self.got_creds = True

    def __setup_menus(self, actions=None):
        menus = [{'title': '&File', 'id': 'file', 'type': 'Menu'},
                 {'title': 'Change domain...', 'id': 'change_domain', 'type': 'MenuEntry', 'parent': 'file'},
                 {'title': 'Exit', 'id': 'abort', 'type': 'MenuEntry', 'parent': 'file'}]
        if actions:
            menus.extend(actions)
        CreateMenu(menus)

    def __gpo_menus(self, parent=None):
        menus = [{'title': 'Action', 'id': 'action', 'type': 'Menu'},
                 {'title': 'Edit...', 'id': 'edit_gpo', 'type': 'MenuEntry', 'parent': 'action'}]
        if parent:
            delete_id = 'context_del_link'
        else:
            delete_id = 'context_del_gpo'
        menus.append({'title': 'Delete', 'id': delete_id, 'type': 'MenuEntry', 'parent': 'action'})
        self.__setup_menus(actions=menus)

    def __objs_menus(self, container=None):
        menus = [{'title': 'Action', 'id': 'action', 'type': 'Menu'}]
        if container:
            menus.append({'title': 'Create a GPO in this domain, and Link it here...', 'id': 'context_add_gpo_and_link', 'type': 'MenuEntry', 'parent': 'action'})
        else:
            menus.append({'title': 'New', 'id': 'context_add_gpo', 'type': 'MenuEntry', 'parent': 'action'})
        self.__setup_menus(actions=menus)

    def __find_gpo(self, gpo_guid):
        fgpo = None
        for gpo in self.gpos:
            if strcasecmp(gpo[1]['name'][-1], gpo_guid):
                fgpo = gpo
                break
        return fgpo

    def add_gpo(self, container=None):
        UI.SetApplicationTitle('New GPO')
        UI.OpenDialog(self.__name_gpo())
        sret = UI.UserInput()
        if str(sret) == 'ok_name_gpo':
            gpo_name = UI.QueryWidget('gpo_name_entry', 'Value')
            self.q.create_gpo(gpo_name, container)
        UI.CloseDialog()
        try:
            self.gpos = self.q.gpo_list()
        except:
            self.gpos = []

    def del_gpo(self, displayName):
        UI.SetApplicationTitle('Group Policy Management')
        UI.OpenDialog(self.__request_delete_gpo())
        sret = UI.UserInput()
        if str(sret) == 'delete_gpo':
            self.q.delete_gpo(displayName)
        UI.CloseDialog()
        try:
            self.gpos = self.q.gpo_list()
        except:
            self.gpos = []

    def del_link(self, child, parent):
        UI.SetApplicationTitle('Group Policy Management')
        UI.OpenDialog(self.__request_delete_link())
        sret = UI.UserInput()
        if str(sret) == 'delete_link':
            self.q.delete_link(child, parent)
        UI.CloseDialog()
        try:
            self.gpos = self.q.gpo_list()
        except:
            self.gpos = []

    def __reset(self):
        UI.SetApplicationTitle('Group Policy Management Console')
        Wizard.SetContentsButtons('Group Policy Management Console', self.__gpmc_page(), self.__help(), 'Back', 'Edit GPO')
        self.__setup_menus()
        DeleteButtonBox()

    def Show(self):
        global selected_gpo
        if not self.got_creds:
            return Symbol('abort')
        self.__reset()
        UI.SetFocus('gpmc_tree')

        current_page = 'Domains'
        old_gpo_guid = None
        gpo_guid = None
        while True:
            event = UI.WaitForEvent()
            if 'WidgetID' in event:
                ret = event['WidgetID']
            elif 'ID' in event:
                ret = event['ID']
            else:
                raise Exception('ID not found in response %s' % str(event))
            old_gpo_guid = gpo_guid
            gpo_guid = UI.QueryWidget('gpmc_tree', 'CurrentItem')
            if str(ret) in ['back', 'abort', 'cancel']:
                break
            elif str(ret) == 'next':
                break
            elif str(ret) == 'add_gpo':
                self.add_gpo()
                self.__reset()
                UI.ReplaceWidget('rightPane', self.__container(gpo_guid))
                current_page = 'Realm'
            elif str(ret) == 'del_gpo':
                self.del_gpo(UI.QueryWidget('link_order', 'CurrentItem'))
                self.__reset()
                UI.ReplaceWidget('rightPane', self.__container(gpo_guid))
                current_page = 'Realm'
            elif ret == 'gpmc_tree' and event['EventReason'] == 'ContextMenuActivated':
                if gpo_guid == 'Group Policy Objects':
                    UI.OpenContextMenu(self.__objs_context_menu())
                elif gpo_guid != 'Domains' and self.__find_gpo(gpo_guid):
                    parent = UI.QueryWidget('gpmc_tree', 'CurrentBranch')[-2]
                    if parent != 'Group Policy Objects' and parent != self.realm_dn:
                        UI.OpenContextMenu(self.__gpo_context_menu(parent))
                    else:
                        UI.OpenContextMenu(self.__gpo_context_menu())
                elif gpo_guid != 'Domains':
                    UI.OpenContextMenu(self.__objs_context_menu(gpo_guid, realm=(gpo_guid == self.realm_dn)))
            elif ret == 'edit_gpo':
                selected_gpo = self.__find_gpo(gpo_guid)
                ret = 'next'
                break
            elif ret == 'context_del_gpo':
                selected_gpo = self.__find_gpo(gpo_guid)
                current_page = self.del_gpo(selected_gpo[1]['displayName'][-1])
                self.__reset()
                UI.ReplaceWidget('rightPane', Empty())
                current_page = None
            elif ret == 'context_del_link':
                selected_gpo = self.__find_gpo(gpo_guid)
                parent = UI.QueryWidget('gpmc_tree', 'CurrentBranch')[-2]
                self.del_link(selected_gpo[1]['distinguishedName'][-1], parent)
                self.__reset()
                UI.ReplaceWidget('rightPane', Empty())
                current_page = None
            elif ret == 'context_add_gpo':
                self.add_gpo()
                self.__reset()
                UI.ReplaceWidget('rightPane', Empty())
                current_page = None
            elif ret == 'context_add_gpo_and_link':
                self.add_gpo(gpo_guid)
                self.__reset()
                UI.ReplaceWidget('rightPane', Empty())
                current_page = None
            elif ret == 'change_domain':
                if switch_domains(self.lp, self.creds, self.cred_valid):
                    self.realm = self.lp.get('realm')
                    self.__reset()
            elif UI.HasSpecialWidget('DumbTab'):
                if gpo_guid == 'Domains':
                    if current_page != None:
                        Wizard.DisableNextButton()
                        UI.ReplaceWidget('rightPane', Empty())
                        current_page = None
                elif gpo_guid == self.realm_dn:
                    if current_page != 'Realm':
                        Wizard.DisableNextButton()
                        UI.ReplaceWidget('rightPane', self.__container(gpo_guid))
                        current_page = 'Realm'
                    if ret == 'Linked Group Policy Objects':
                        UI.ReplaceWidget(Id('realm_tabContainer'), self.__container_links(gpo_guid))
                    elif ret == 'Delegation':
                        UI.ReplaceWidget(Id('realm_tabContainer'), self.__realm_delegation())
                    elif ret == 'Group Policy Inheritance':
                        UI.ReplaceWidget(Id('realm_tabContainer'), self.__realm_inheritance())
                    if event['EventReason'] == 'SelectionChanged':
                        self.__objs_menus(gpo_guid)
                elif gpo_guid == 'Group Policy Objects':
                    if current_page != 'Group Policy Objects':
                        Wizard.DisableNextButton()
                        UI.ReplaceWidget('rightPane', Empty())
                        current_page = 'Group Policy Objects'
                    if event['EventReason'] == 'SelectionChanged':
                        self.__objs_menus()
                elif gpo_guid.lower().startswith('ou='):
                    UI.ReplaceWidget('rightPane', self.__container(gpo_guid))
                    current_page = None
                    if event['EventReason'] == 'SelectionChanged':
                        self.__objs_menus(gpo_guid)
                else:
                    parent = UI.QueryWidget('gpmc_tree', 'CurrentBranch')[-2]
                    if event['EventReason'] == 'SelectionChanged':
                        if parent != 'Group Policy Objects' and parent != self.realm_dn:
                            self.__gpo_menus(parent)
                        else:
                            self.__gpo_menus()
                    if current_page != 'Dumbtab' or old_gpo_guid != gpo_guid:
                        Wizard.EnableNextButton()
                        selected_gpo = self.__find_gpo(gpo_guid)
                        UI.ReplaceWidget('rightPane', self.__gpo_tab(gpo_guid))
                        current_page = 'Dumbtab'
                    if str(ret) == 'Scope':
                        UI.ReplaceWidget('gpo_tabContents', self.__scope_page(gpo_guid))
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

    def __gpo_context_menu(self, parent=None):
        if parent:
            delete_id = 'context_del_link'
        else:
            delete_id = 'context_del_gpo'
        return Term('menu', [
            Item(Id('edit_gpo'), 'Edit...'),
            Item(Id(delete_id), 'Delete')
        ])

    def __objs_context_menu(self, container=None, realm=False):
        items = []
        if realm:
            items.append(Item(Id('change_domain'), 'Change Domain...'))
        if container:
            items.append(Item(Id('context_add_gpo_and_link'), 'Create a GPO in this domain, and Link it here...'))
        else:
            items.append(Item(Id('context_add_gpo'), 'New'))
        return Term('menu', items)

    def __name_gpo(self):
        return MinWidth(30, VBox(
            TextEntry(Id('gpo_name_entry'), Opt('hstretch'), 'GPO Name'),
            Right(HBox(
                PushButton(Id('ok_name_gpo'), 'OK'),
                PushButton(Id('cancel_name_gpo'), 'Cancel')
            ))
        ))

    def __request_delete_gpo(self):
        return MinWidth(30, VBox(
            Label('Do you want to delete this GPO and all links to it in this\ndomain? This will not delete links in other domains.'),
            Right(HBox(
                PushButton(Id('delete_gpo'), 'Yes'),
                PushButton(Id('cancel_delete_gpo'), 'No'),
            ))
        ))

    def __request_delete_link(self):
        return MinWidth(30, VBox(
            Label('Do you want to delete this link?\nThis will not delete the GPO itself.'),
            Right(HBox(
                PushButton(Id('delete_link'), 'OK'),
                PushButton(Id('cancel_delete_link'), 'Cancel'),
            ))
        ))

    def __help(self):
        return 'Group Policy Management Console'

    def __scope_page(self, gpo_guid):
        header = Header('Location', 'Enforced', 'Link Enabled', 'Path')
        contents = []
        links = self.q.get_gpo_containers(gpo_guid)
        for link in links:
            if b'domain' in link['objectClass']:
                name = self.realm.lower()
            else:
                name = link['name'][-1]
            gplist = parse_gplink(link['gPLink'][-1])[gpo_guid]
            vals = Item(name, str(gplist['enforced']), str(gplist['enabled']), dn_to_path(self.realm.lower(), link['distinguishedName'][-1]))
            contents.append(vals)
        return VBox(
            Left(Label('Links')),
            Table(Id('scope_links'), header, contents)
        )

    def __ms_time_to_readable(self, timestamp):
        if type(timestamp) is bytes:
            timestamp = timestamp.decode()
        m = re.match('(?P<year>\d\d\d\d)(?P<month>\d\d)(?P<day>\d\d)(?P<hour>\d\d)(?P<minute>\d\d)(?P<second>\d\d)\..*', timestamp)
        if m:
            return '%s/%s/%s %s:%s:%s UTC' % (m.group('month'), m.group('day'), m.group('year'), m.group('hour'), m.group('minute'), m.group('second'))

    def __details_page(self, gpo_guid):
        global selected_gpo
        status_selection = [False, False, False, False]
        if strcmp(selected_gpo[1]['flags'][-1], '0'):
            status_selection[2] = True
        elif strcmp(selected_gpo[1]['flags'][-1], '1'):
            status_selection[3] = True
        elif strcmp(selected_gpo[1]['flags'][-1], '2'):
            status_selection[1] = True
        elif strcmp(selected_gpo[1]['flags'][-1], '3'):
            status_selection[0] = True
        combo_options = [Item('All settings disabled', status_selection[0]), Item('Computer configuration settings disabled', status_selection[1]), Item('Enabled', status_selection[2]), Item('User configuration settings disabled', status_selection[3])]


        msg = self.q.gpo_list(selected_gpo[1]['displayName'][-1], attrs=['nTSecurityDescriptor'])
        if msg:
            ds_sd_ndr = msg[0][1]['nTSecurityDescriptor'][0]
            ds_sd = ndr_unpack(security.descriptor, ds_sd_ndr)
            owner_obj = self.q.user_from_sid(ds_sd.owner_sid)
            owner = owner_obj['sAMAccountName'][-1].decode('utf-8')
        else:
            owner = 'Unknown'

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
                    Left(Label(owner)), VSpacing(),
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
        return Top(HBox(Empty()))

    def __delegation_page(self):
        return Top(HBox(Empty()))

    def __forest(self):
        gp_containers = self.q.get_containers_with_gpos()
        items = []
        for gpo in self.gpos:
            items.append(Item(Id(gpo[1]['name'][-1]), gpo[1]['displayName'][-1]))
        folders = []
        for container in gp_containers:
            if b'domain' in container['objectClass']:
                gplists = parse_gplink(container['gPLink'][-1])
                for gpname in gplists:
                    gpo = self.__find_gpo(gpname)
                    displayName = gpo[1]['displayName'][-1] if gpo else gpname
                    folders.append(Item(Id(gpname), displayName))
            else:
                container_objs = []
                if 'gPLink' in container:
                    gplists = parse_gplink(container['gPLink'][-1])
                else:
                    gplists = []
                for gpname in gplists:
                    gpo = self.__find_gpo(gpname)
                    displayName = gpo[1]['displayName'][-1] if gpo else gpname
                    container_objs.append(Item(Id(gpname), displayName))
                folders.append(Item(Id(container['distinguishedName'][-1]), container['name'][-1], False, container_objs))
        folders.append(Item('Group Policy Objects', False, items))
        forest = [
            Item('Domains', True,
            [
                Item(Id(self.realm_dn), self.realm, True, folders)
            ])
        ]
        contents = Tree(Id('gpmc_tree'), Opt('notify', 'immediate', 'notifyContextMenu'), 'Group Policy Management', forest)
        
        return contents

    def __container(self, dn):
        return VBox(
            Frame(self.realm, DumbTab([
                'Linked Group Policy Objects',
                #'Group Policy Inheritance',
                #'Delegation'
            ], ReplacePoint(Id('realm_tabContainer'), self.__container_links(dn)))),
        )

    def __realm_delegation(self):
        return Top(HBox(Empty()))

    def __realm_inheritance(self):
        return Top(HBox(Empty()))

    def __container_links(self, dn):
        header = Header('Link Order', 'GPO', 'Enforced', 'Link Enabled', 'GPO Status', 'WMI Filter', 'Modified', 'Domain')
        contents = []
        for gpo in self.q.get_gpos_for_container(dn):
            status = ''
            if strcmp(gpo[1]['flags'][-1], '0'):
                status = 'Enabled'
            elif strcmp(gpo[1]['flags'][-1], '1'):
                status = 'User configuration settings disabled'
            elif strcmp(gpo[1]['flags'][-1], '2'):
                status = 'Computer configuration settings disabled'
            elif strcmp(gpo[1]['flags'][-1], '3'):
                status = 'All settings disabled'
            vals = Item('', gpo[1]['displayName'][-1], '', '', status, '', self.__ms_time_to_readable(gpo[1]['whenChanged'][-1]), '')
            contents.append(vals)

        return Table(Id('link_order'), header, contents)

    def __gpo_tab(self, gpo_guid):
        global selected_gpo
        if not selected_gpo:
            return Top(HBox(Empty()))
        gpo_name = selected_gpo[1]['displayName'][-1]
        return Frame(gpo_name, DumbTab(Id('gpo_tab'), [
            'Scope',
            Item('Details', True),
            #'Settings',
            #'Delegation'
        ], ReplacePoint(Id('gpo_tabContents'), self.__details_page(gpo_guid))))

    def __gpmc_page(self):
        return HBox(
            HWeight(1, self.__forest()),
            HWeight(2, ReplacePoint(Id('rightPane'), Empty())),
            )

