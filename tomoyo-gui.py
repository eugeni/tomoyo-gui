#!/usr/bin/python
"""Parses tomoyo"""

import gobject
import gtk
import pango

# localization
import gettext
try:
    gettext.install("msec")
except IOError:
    _ = str

class TomoyoGui(gtk.Window):
    (COLUMN_DOMAIN, COLUMN_STATE, COLUMN_CUSTOM) = range(3)

    def __init__(self, policy, parent=None):
        gtk.Window.__init__(self)
        try:
            self.set_screen(parent.get_screen())
        except AttributeError:
            self.connect('destroy', lambda *w: gtk.main_quit())
        self.set_title(self.__class__.__name__)
        self.set_default_size(640, 480)

        self.policy = policy

        # main vbox
        self.main_vbox = gtk.VBox()
        self.add(self.main_vbox)

        # scrolled window
        sw = gtk.ScrolledWindow()
        sw.set_policy(gtk.POLICY_AUTOMATIC, gtk.POLICY_AUTOMATIC)
        sw.set_shadow_type(gtk.SHADOW_ETCHED_IN)
        self.main_vbox.pack_start(sw)

        # list of options
        lstore = gtk.ListStore(
            gobject.TYPE_STRING,
            gobject.TYPE_STRING,
            gobject.TYPE_INT)

        # treeview
        treeview = gtk.TreeView(lstore)
        treeview.set_rules_hint(True)
        treeview.set_search_column(self.COLUMN_DOMAIN)

        treeview.connect('row-activated', self.show_domain, lstore)

        # configuring columns

        # column for option names
        renderer = gtk.CellRendererText()
        renderer.set_property('width', 400)
        column = gtk.TreeViewColumn(_('Security domain'), renderer, text=self.COLUMN_DOMAIN, weight=self.COLUMN_CUSTOM)
        column.set_sort_column_id(self.COLUMN_DOMAIN)
        column.set_resizable(True)
        column.set_expand(True)
        treeview.append_column(column)

        # column for values
        column = gtk.TreeViewColumn(_('Value'), gtk.CellRendererText(), text=self.COLUMN_STATE, weight=self.COLUMN_CUSTOM)
        column.set_sort_column_id(self.COLUMN_STATE)
        treeview.append_column(column)

        sw.add(treeview)

        # building the list
        for item in self.policy.policy:
            iter = lstore.append()
            lstore.set(iter,
                    self.COLUMN_DOMAIN, item,
                    self.COLUMN_STATE, self.policy.policy_dict[item],
                    self.COLUMN_CUSTOM, pango.WEIGHT_NORMAL
                    )

        # contents
        sw2 = gtk.ScrolledWindow()
        sw2.set_policy(gtk.POLICY_AUTOMATIC, gtk.POLICY_AUTOMATIC)
        sw2.set_shadow_type(gtk.SHADOW_ETCHED_IN)
        frame = gtk.Frame(_("Domain details"))
        self.domain_details = gtk.VBox(False, 5)
        frame.add(self.domain_details)
        sw2.add_with_viewport(frame)
        self.main_vbox.pack_start(sw2)

        # size group
        self.size_group = gtk.SizeGroup(gtk.SIZE_GROUP_HORIZONTAL)


        self.show_all()

    def __add_row(self, table, row, label_text, options):
        label = gtk.Label(label_text)
        label.set_use_underline(True)
        label.set_alignment(0, 1)
        table.attach(label, 0, 1, row, row + 1, gtk.EXPAND | gtk.FILL, 0, 0, 0)

        self.size_group.add_widget(options)
        table.attach(options, 1, 2, row, row + 1, 0, 0, 0, 0)


    def show_domain(self, treeview, path, col, model):
        """Shows details for a domain"""
        iter = model.get_iter(path)
        domain = model.get_value(iter, self.COLUMN_DOMAIN)
        params = self.policy.policy_dict[domain]

        children = self.domain_details.get_children()
        for child in children:
            self.domain_details.remove(child)

        label = gtk.Label(domain)
        label.set_line_wrap(True)
        self.domain_details.pack_start(label, False, False)
        # building details
        table = gtk.Table(2, 2, False)

        # profile
        combobox = gtk.combo_box_new_text()
        combobox.append_text(_("Disabled"))
        combobox.append_text(_("Learning"))
        combobox.append_text(_("Permissive"))
        combobox.append_text(_("Enforcing"))
        combobox.set_active(self.policy.get_profile(domain))
        self.__add_row(table, 1, _("Profile"), combobox)

        self.domain_details.add(table)
        self.domain_details.show_all()


class TomoyoPolicy:
    def __init__(self):
        """Initializes the policy class"""
        # TODO: support system/saved policy
        pass

    def get_profile(self, item):
        """Gets profile status for item"""
        params = self.policy_dict.get(item, None)
        for p,val in params:
            if p == 'use_profile':
                return int(val)
        return 0

    def parse(self):
        """Loads the policy"""
        self.policy = []
        self.policy_dict = {}
        self.policy_tree = []
        with open("/sys/kernel/security/tomoyo/domain_policy") as fd:
            data = fd.readlines()
        for line in data:
            line = line.strip()
            if not line:
                continue
            # parse policy
            if line.find('<kernel>') == 0:
                # it is a security domain
                domain = line
                self.policy.append(domain)
                if domain not in self.policy_dict:
                    self.policy_dict[domain] = []
                items = line.split(" ")
                if len(items) < 1:
                    continue
                self.policy_tree.append(" -> ".join(items[1:]))
            else:
                # an ACL
                command, params = line.split(" ", 1)
                self.policy_dict[domain].append((command, params))




if __name__ == "__main__":
    policy = TomoyoPolicy()
    policy.parse()

    TomoyoGui(policy)
    gtk.main()
