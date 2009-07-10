#!/usr/bin/python
"""Parses tomoyo"""

import gobject
import gtk
import pango

import gc
import os
from stat import *
import datetime

# localization
import gettext
try:
    gettext.install("msec")
except IOError:
    _ = str

class TomoyoGui(gtk.Window):
    (COLUMN_PATH, COLUMN_DOMAIN, COLUMN_WEIGHT, COLUMN_LEVEL) = range(4)
    DOMAINS=[_("Disabled"), _("Learning"), _("Permissive"), _("Enforced")]

    def __init__(self, policy, parent=None):
        """Initializes main window and GUI"""
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

        # toolbar
        toolbar = gtk.Toolbar()
        toolbar.set_style(gtk.TOOLBAR_BOTH)

        toolbar_item = gtk.ToolButton("Refresh")
        toolbar_item.set_stock_id(gtk.STOCK_REFRESH)
        toolbar_item.connect("clicked", lambda *w: self.refresh_domains(self.all_domains, self.active_domains, reload=True))
        toolbar.insert(toolbar_item, -1)

        toolbar_item = gtk.ToolButton("Quit")
        toolbar_item.set_stock_id(gtk.STOCK_QUIT)
        toolbar_item.connect("clicked", lambda *w: gtk.main_quit())
        toolbar.insert(toolbar_item, -1)

        self.main_vbox.pack_start(toolbar, False, False)

        # tabs
        self.notebook = gtk.Notebook()
        self.main_vbox.pack_start(self.notebook)

        # domains
        sw_all, self.all_domains = self.build_list_of_domains()
        sw_active, self.active_domains = self.build_list_of_domains()

        self.refresh_domains(self.all_domains, self.active_domains)

        self.notebook.append_page(sw_all, gtk.Label(_("All domains")))
        self.notebook.append_page(sw_active, gtk.Label(_("Active domains")))

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

        # show default text
        table, cur_row = self.refresh_details(self.domain_details, _("Security Configuration for TOMOYO Linux"))
        self.__add_row(table, cur_row, _("This application allows you to fine-tune the security settings for TOMOYO."))
        cur_row += 1
        self.__add_row(table, cur_row, _("Select a security domain to view and edit its settings."))
        cur_row += 1
        self.__add_row(table, cur_row, _("Alternatively, you may double-click on a security domain to select all subdomains for a domain."))
        cur_row += 1
        self.__add_row(table, cur_row, _("You may also select a group of domains to apply settings to them at once."))
        cur_row += 1
        self.__add_row(table, cur_row, _("Use the toolbar to refresh current policy from the kernel, or save your settings."))
        cur_row += 1
        self.__add_row(table, cur_row, _("Have a nice TOMOYO experience :)"))
        self.show_all()

    def refresh_domains(self, lstore_all, lstore_active, reload=True):
        """Refresh the list of domain entries"""
        # building the list of domains and active domains

        # reload policy from disk?
        if reload:
            self.policy.reload()

        lstore_all.clear()
        lstore_active.clear()

        def add_to_liststore(lstore, path, item, color, level):
            iter = lstore.append()
            lstore.set(iter,
                    self.COLUMN_PATH, path,
                    self.COLUMN_DOMAIN, item,
                    self.COLUMN_WEIGHT, color,
                    self.COLUMN_LEVEL, level)

        for i in range(len(self.policy.policy)):
            # quick and dirty way to find out if domain is active
            item = self.policy.policy[i]
            path, level = self.policy.policy_tree[i]
            dom, val = self.policy.policy_dict[item][0]
            if val == "0":
                color = pango.WEIGHT_NORMAL
            else:
                color = pango.WEIGHT_BOLD
                add_to_liststore(lstore_active, path, item, color, level)
            add_to_liststore(lstore_all, path, item, color, level)

    def build_list_of_domains(self):
        """Builds scrollable list of domains"""
        # scrolled window
        sw = gtk.ScrolledWindow()
        sw.set_policy(gtk.POLICY_AUTOMATIC, gtk.POLICY_AUTOMATIC)
        sw.set_shadow_type(gtk.SHADOW_ETCHED_IN)

        # list of options
        lstore = gtk.ListStore(
            gobject.TYPE_STRING,
            gobject.TYPE_STRING,
            gobject.TYPE_INT,
            gobject.TYPE_INT)

        # treeview
        treeview = gtk.TreeView(lstore)
        treeview.set_rules_hint(True)
        treeview.set_search_column(self.COLUMN_PATH)

        treeview.connect('row-activated', self.expand_domain, lstore)

        # selection
        selection = treeview.get_selection()
        selection.set_mode(gtk.SELECTION_MULTIPLE)
        selection.connect('changed', self.select_domain)

        # configuring columns

        # column for option names
        renderer = gtk.CellRendererText()
        renderer.set_property('width', 400)
        column = gtk.TreeViewColumn(_('Security domain'), renderer, text=self.COLUMN_PATH, weight=self.COLUMN_WEIGHT)
        column.set_resizable(True)
        column.set_expand(True)
        treeview.append_column(column)

        sw.add(treeview)

        # search
        def search_domain(model, column, key, iter, data=None):
            path = model.get_value(iter, self.COLUMN_PATH)
            return path.find(key) < 0
        treeview.set_search_equal_func(func=search_domain)

        return sw, lstore

    def build_profile(self, profile):
        """Building profile selection combobox"""
        # profile selection options
        cur_profile = gtk.combo_box_new_text()
        for item in self.DOMAINS:
            cur_profile.append_text(item)
        cur_profile.set_active(profile)
        return cur_profile

    def __add_row(self, table, row, label_text, options=None, markup=False, wrap=False):
        label = gtk.Label()
        label.set_use_underline(True)
        label.set_alignment(0, 1)
        if wrap:
            label.set_line_wrap(wrap)
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

    def select_domain(self, selection):
        """A domain is selected"""
        model, rows = selection.get_selected_rows()
        if selection.count_selected_rows() == 1:
            # just one item is selected
            iter = model.get_iter(rows[0])
            return self.show_domain(model, iter)
        else:
            domains = []
            for item in rows:
                iter = model.get_iter(item)
                domain = model.get_value(iter, self.COLUMN_DOMAIN)
                domains.append(domain)

            # update title
            self.refresh_details(self.domain_details, domains[0])
            table, cur_row = self.refresh_details(self.domain_details, _("Configure profile for a group"))
            # building details

            # get profile description
            profile, acl = self.format_acl(domains[0])
            self.__add_row(table, cur_row, _("Profile"), options=self.build_profile(profile))
            cur_row += 1

            # building ACL
            if len(domains) > 0:
                self.__add_row(table, cur_row, _("<b>Sub-domains</b>"), markup=True)
                cur_row += 1
                for domain in domains:
                    self.__add_row(table, cur_row, domain)
                    cur_row += 1

            self.domain_details.show_all()

            return

    def refresh_details(self, container, title):
        """Updates description of a domain or group of domains"""
        children = container.get_children()
        for child in children:
            container.remove(child)
            del child
        label = gtk.Label(title)
        label.set_line_wrap(True)
        container.pack_start(label, False, False)

        # building details
        table = gtk.Table(2, 2, False)
        container.add(table)
        start_row = 1
        return table, start_row

    def show_domain(self, model, iter):
        """Shows domain details"""
        domain = model.get_value(iter, self.COLUMN_DOMAIN)
        params = self.policy.policy_dict[domain]

        table, cur_row = self.refresh_details(self.domain_details, _("Configure ACL for %s") % domain)

        # get profile description
        profile, acl = self.format_acl(domain)
        self.__add_row(table, cur_row, _("Profile"), options=self.build_profile(profile))
        cur_row += 1

        # building ACL
        if len(acl) > 0:
            self.__add_row(table, cur_row, _("<b>Security settings</b>"), markup=True)
            cur_row += 1
            for acl, item in acl:
                self.__add_row(table, cur_row, item, options=gtk.Label(acl))
                cur_row += 1

        self.domain_details.show_all()

    def expand_domain(self, treeview, path, col, model):
        """Locates all subdomains for a domain"""
        start_path = path
        iter = model.get_iter(path)
        initial_level = model.get_value(iter, self.COLUMN_LEVEL)
        domains = []
        last_iter = iter
        # detecting all subdomains
        while True:
            iter = model.iter_next(iter)
            if not iter:
                break
            domain = model.get_value(iter, self.COLUMN_DOMAIN)
            cur_level = model.get_value(iter, self.COLUMN_LEVEL)
            domains.append(domain)
            if cur_level <= initial_level:
                break
            last_iter = iter
        end_path = model.get_path(last_iter)

        # update selection
        selection = treeview.get_selection()

        # updating details widget
        selection.select_range(start_path, end_path)

        # show details for the selected domains
        self.select_domain(selection)


class TomoyoPolicy:
    POLICY_LOAD="/usr/sbin/ccs-loadpolicy a"
    POLICY_SAVE="/usr/sbin/ccs-savepolicy a"
    def __init__(self, policy="system", version="tomoyo"):
        """Initializes the policy class.

        If version is "tomoyo", LSM version of tomoyo is used.
        Otherwise, if policy is "ccs", Tomoyo 1.6 policy is used.

        If policy=system, reads policy from /etc/(tomoyo,css)/domain_policy.conf.
        If policy=kernel, policy is read from /sys/kernel/security/tomoyo/domain_policy"""
        self.policy = policy
        self.version = version
        if policy == "kernel":
            self.location = "/sys/kernel/security/tomoyo/domain_policy"
        else:
            self.location = "/etc/%s/domain_policy.conf" % version
        self.save_location = "domain_policy.conf"

    def reload(self):
        """Reloads the policy. If using system policy, current kernel policy is saved first"""
        if self.policy == "system":
            os.system(self.POLICY_SAVE)
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
                curlevel = 0
                # rebuilt item description
                for i in range(depth):
                    if i > last_depth:
                        path += items[i:]
                        curitems += items[i:]
                        break
                    if items[i] == path[i]:
                        curitems.append("  ")
                        curlevel += 1
                        continue
                    curitems.append(items[i])
                    path[i] = items[i]
                curpath = " ".join(curitems)
                self.policy_tree.append((curpath, curlevel))
            else:
                # an ACL
                command, params = line.split(" ", 1)
                self.policy_dict[domain].append((command, params))

    def save(self, reload=True):
        """Saves the policy. If reload=True, the saved policy is loaded into kernel"""
        time = datetime.datetime.now().strftime("%F.%T")
        filename = "domain_policy.%s.conf" % time
        full_filename = "/etc/%s/%s" % (self.version, filename)
        # are we working on a real file or a symbolic link?
        status = os.lstat(self.location)
        if S_ISLNK(status.st_mode):
            # remove old link, new one will be created instead
            os.unlink(self.location)
            os.symlink(filename, self.location)
        else:
            os.rename(self.location, "%s.old" % self.location)
        fd = open(full_filename, "w")
        for item in self.policy:
            print >>fd, "%s\n" % item
            for acl, val in self.policy_dict[item]:
                print >>fd, "%s %s" % (acl, val)
                # compatibility with ccs-savepolicy
                if acl == "use_policy":
                    print >>fd
            print >>fd
        if reload:
            os.system(self.POLICY_LOAD)


if __name__ == "__main__":
    policy = TomoyoPolicy()

    TomoyoGui(policy)
    gtk.main()
