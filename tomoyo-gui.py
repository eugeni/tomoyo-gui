#!/usr/bin/python
"""Parses tomoyo"""

import gobject
import gtk
import pango

import gc

# localization
import gettext
try:
    gettext.install("msec")
except IOError:
    _ = str

class TomoyoGui(gtk.Window):
    (COLUMN_PATH, COLUMN_DOMAIN, COLUMN_WEIGHT) = range(3)
    DOMAINS=[_("Disabled"), _("Learning"), _("Permissive"), _("Enforced")]

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

        # tabs
        self.notebook = gtk.Notebook()
        self.main_vbox.pack_start(self.notebook)

        # building the list of domains and active domains
        all = []
        active = []
        for i in range(len(self.policy.policy)):
            # quick and dirty way to find out if domain is active
            item = self.policy.policy[i]
            path = self.policy.policy_tree[i]
            dom, val = self.policy.policy_dict[item][0]
            if val == "0":
                color = pango.WEIGHT_NORMAL
            else:
                color = pango.WEIGHT_BOLD
                active.append((path, item, color))
            all.append((path, item, color))

        self.notebook.append_page(self.build_list_of_domains(all), gtk.Label(_("All domains")))
        self.notebook.append_page(self.build_list_of_domains(active), gtk.Label(_("Active domains")))

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

    def build_list_of_domains(self, entries):
        """Builds scrollable list of domains"""
        # scrolled window
        sw = gtk.ScrolledWindow()
        sw.set_policy(gtk.POLICY_AUTOMATIC, gtk.POLICY_AUTOMATIC)
        sw.set_shadow_type(gtk.SHADOW_ETCHED_IN)

        # list of options
        lstore = gtk.ListStore(
            gobject.TYPE_STRING,
            gobject.TYPE_STRING,
            gobject.TYPE_INT)

        # treeview
        treeview = gtk.TreeView(lstore)
        treeview.set_rules_hint(True)
        treeview.set_search_column(self.COLUMN_PATH)

        treeview.connect('row-activated', self.show_domain, lstore)

        # configuring columns

        # column for option names
        renderer = gtk.CellRendererText()
        renderer.set_property('width', 400)
        column = gtk.TreeViewColumn(_('Security domain'), renderer, text=self.COLUMN_PATH, weight=self.COLUMN_WEIGHT)
        column.set_sort_column_id(self.COLUMN_PATH)
        column.set_resizable(True)
        column.set_expand(True)
        treeview.append_column(column)

        sw.add(treeview)

        for path, item, color in entries:
            iter = lstore.append()
            lstore.set(iter,
                    self.COLUMN_PATH, path,
                    self.COLUMN_DOMAIN, item,
                    self.COLUMN_WEIGHT, color
                    )
        return sw


    def build_profile(self, profile):
        """Building profile selection combobox"""
        # profile selection options
        cur_profile = gtk.combo_box_new_text()
        for item in self.DOMAINS:
            cur_profile.append_text(item)
        cur_profile.set_active(profile)
        return cur_profile

    def __add_row(self, table, row, label_text, options=None, markup=False):
        label = gtk.Label()
        label.set_use_underline(True)
        label.set_alignment(0, 1)
        if markup:
            label.set_markup(label_text)
        else:
            label.set_text(label_text)
        table.attach(label, 0, 1, row, row + 1, gtk.EXPAND | gtk.FILL, 0, 0, 0)

        if options:
            self.size_group.add_widget(options)
            table.attach(options, 1, 2, row, row + 1, 0, 0, 0, 0)

    def format_acl(self, item):
        """Format acl results"""
        params = self.policy.policy_dict.get(item, None)
        profile = 0
        acl = []
        for p,val in params:
            if p == 'use_profile':
                profile = int(val)
                continue
            acl.append((p, val))
        return profile, acl


    def show_domain(self, treeview, path, col, model):
        """Shows details for a domain"""
        iter = model.get_iter(path)
        domain = model.get_value(iter, self.COLUMN_DOMAIN)
        params = self.policy.policy_dict[domain]

        children = self.domain_details.get_children()
        for child in children:
            self.domain_details.remove(child)
            del child
        # free memory
        gc.collect()

        label = gtk.Label(domain)
        label.set_line_wrap(True)
        self.domain_details.pack_start(label, False, False)

        # get profile description
        profile, acl = self.format_acl(domain)

        # building details
        table = gtk.Table(2, 2, False)

        # profile for domain
        self.__add_row(table, 1, _("Profile"), options=self.build_profile(profile))

        # building ACL
        if len(acl) > 0:
            self.__add_row(table, 2, _("<b>Security settings</b>"), markup=True)
            cur_row = 3
            for acl, item in acl:
                self.__add_row(table, cur_row, item, options=gtk.Label(acl))
                cur_row += 1

        self.domain_details.add(table)
        self.domain_details.show_all()

        print repr(self.policy.policy_dict[domain])


class TomoyoPolicy:
    def __init__(self, policy="system"):
        """Initializes the policy class"""
        # TODO: support system/saved policy
        if policy == "kernel":
            self.location = "/sys/kernel/security/tomoyo/domain_policy"
        else:
            self.location = "/etc/tomoyo/domain_policy.conf"

    def parse(self):
        """Loads the policy"""
        self.policy = []
        self.policy_dict = {}
        self.policy_tree = []
        path = []
        with open(self.location) as fd:
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
                depth = len(items)
                last_depth = len(path) -1
                if depth >= last_depth:
                    del path[depth:]
                curitems = []
                # rebuilt item description
                for i in range(depth):
                    if i > last_depth:
                        path += items[i:]
                        curitems += items[i:]
                        break
                    if items[i] == path[i]:
                        curitems.append("  ")
                        continue
                    curitems.append(items[i])
                    path[i] = items[i]
                curpath = " ".join(curitems)
                self.policy_tree.append(curpath)
            else:
                # an ACL
                command, params = line.split(" ", 1)
                self.policy_dict[domain].append((command, params))

if __name__ == "__main__":
    policy = TomoyoPolicy()
    policy.parse()

    TomoyoGui(policy)
    gtk.main()
