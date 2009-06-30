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

        # scrolled window
        sw = gtk.ScrolledWindow()
        sw.set_policy(gtk.POLICY_AUTOMATIC, gtk.POLICY_AUTOMATIC)
        sw.set_shadow_type(gtk.SHADOW_ETCHED_IN)
        self.add(sw)

        # list of options
        lstore = gtk.ListStore(
            gobject.TYPE_STRING,
            gobject.TYPE_STRING,
            gobject.TYPE_INT)

        # treeview
        treeview = gtk.TreeView(lstore)
        treeview.set_rules_hint(True)
        treeview.set_search_column(self.COLUMN_DOMAIN)

        treeview.connect('row-activated', self.option_changed, lstore)

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


        sw.add(treeview)
        self.show_all()

    def option_changed(self, treeview, path, col, model):
        """Processes an option change"""
        iter = model.get_iter(path)
        domain = model.get_value(iter, self.COLUMN_DOMAIN)
        value = model.get_value(iter, self.COLUMN_STATE)

class TomoyoPolicy:
    def __init__(self):
        """Initializes the policy class"""
        # TODO: support system/saved policy
        pass

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
