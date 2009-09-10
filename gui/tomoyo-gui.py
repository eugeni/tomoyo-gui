#!/usr/bin/python
"""Parses tomoyo"""

import gobject
import gtk
import pango

import gc
import os
from stat import *
import datetime
import getopt
import sys

from threading import Thread
from Queue import Queue
import time

import textwrap

DEBUG=False

# localization
import gettext
try:
    gettext.install("msec")
except IOError:
    _ = str

def multiline_help(help):
    """Helper function to wrap and format multi-line help text"""
    text = []
    for s in help:
        for l in textwrap.wrap(s, 80):
            text.append(l)
        text.append("")
    return text
# help text
HELP_ALL_DOMAINS=multiline_help([_("""This view displays all security domains known to TOMOYO.
Each domain represents the complete application execution chain, from kernel to the last executed application.
To simplify the visualization, subdomains are displayed on separate lines."""),
_("""If you click on a domain, you may change the TOMOYO settings for it, such as the execution policy
(which specifies whether TOMOYO should ignore this domain, learn its actions, preview or enforce the security settings).
By default, all domains are disabled. To start using TOMOYO, select a domain and change its policy to Learning.
Afterwards, use the application normally. TOMOYO will learn from the application actions, such as file accesses, application executions and so on.
""")
])

HELP_ACTIVE_DOMAINS=multiline_help([_("""This view displays all security domains known to TOMOYO which are currently enabled.
For these domains, the TOMOYO policy is either in Learning, Permissive or Enforced mode.
You may use this view to have a quick view on security domains currently active on your system.
""")])

HELP_EXCEPTIONS=multiline_help([_("""This view displays the exceptions known to TOMOYO.
The following kinds of exceptions are supported:"""),
_("""<b>alias</b>: indicates different paths that point to the same file (e.g., symlinks).
This keyword is intended to allow programs that behave differently depending on the name of invocation and that referenced using symbolic links instead of hard links transit domain using the symbolic link's name.
For example, /sbin/pidof is a symbolic link to /sbin/killall5.
In normal case, if /sbin/pidof is executed, the domain is defined as if /sbin/killall5 is executed. By specifying "alias /sbin/killall5 /sbin/pidof", you can run /sbin/pidof in the domain for /sbin/pidof."""),
_("""<b>file_pattern</b>: When file access requests arise in learning mode, the pathnames are automatically patterned according to patterns specified using this keyword.
This keyword is used for only reducing the burden of policy tuning which is needed after the learning mode by making already known pathname patterns as templates."""),
_("""<b>allow_read</b>: Used to grant unconditionally readable permissions to files.
This keyword is intended to reduce size of domain policy by granting read access to library files such as GLIBC and locale files."""),
_("""<b>deny_rewrite</b>: Files whose pathname match the patterns are not permitted to open for writing without append mode or truncate unless the pathnames are explicitly granted using allow_rewrite keyword in domain policy."""),
_("""<b>initialize_domain</b>: allows to initialize domain transition when specific program is executed."""),
_("""<b>no_initialize_domain</b>: prevents a program from initializing a new domain transition."""),
_("""<b>keep_domain</b>: used to prevent domain transition when program is executed from specific domain.
This directive is intended to reduce total number of domains and memory usage by suppressing unneeded domain transitions."""),
_("""<b>no_keep_domain</b>: Use this directive when you want to escape from a domain that is kept by "keep_domain" directive."""),
])

HELP_DEFAULT=multiline_help([_("""
This application allows you to fine-tune the security settings for TOMOYO.
Select a security domain to view and edit its settings.
Alternatively, you may double-click on a security domain to select all subdomains for a domain.
You may also select a group of domains to apply settings to them at once.
Start typing a name of an application to quickly locate it in the list
Use the toolbar to refresh current policy from the kernel, or save your settings.
Have a nice TOMOYO experience :)
""")])

class TomoyoInstaller(Thread):
    # tomoyo policy installer
    def __init__(self, finish_install, installer="/usr/lib/ccs/tomoyo_init_policy.sh"):
        Thread.__init__(self)
        """Initializes policy installer. finish_install is a Queue item that will be filled when job has ended."""
        self.finish_install = finish_install
        self.installer = installer

    def run(self):
        """Installs tomoyo policy"""
        print "Running %s" % self.installer
        try:
            res = os.system(self.installer)
            self.finish_install.put(res)
        except:
            print "Aborted: %s" % sys.exc_value
            self.finish_install.put(-1)

class TomoyoGui:
    (COLUMN_PATH, COLUMN_DOMAIN, COLUMN_WEIGHT, COLUMN_LEVEL) = range(4)
    DOMAINS=[_("Disabled"), _("Learning"), _("Permissive"), _("Enforced")]

    def __init__(self, policy, embed=None, execution_path="/usr/share/tomoyo-mdv"):
        """Initializes main window and GUI"""
        if embed:
            self.window = gtk.Plug(embed)
        else:
            self.window = gtk.Window()
            self.window.set_title(_("Tomoyo GUI"))
            self.window.set_default_size(640, 440)
        self.window.connect('delete-event', lambda *w: gtk.main_quit())

        self.policy = policy
        self.execution_path = execution_path

        # main vbox
        self.main_vbox = gtk.VBox()
        self.window.add(self.main_vbox)

        # toolbar
        toolbar = gtk.Toolbar()
        toolbar.set_style(gtk.TOOLBAR_ICONS)

        toolbar_item = gtk.ToolButton("Refresh")
        toolbar_item.set_stock_id(gtk.STOCK_REFRESH)
        toolbar_item.connect("clicked", lambda *w: self.refresh_domains(self.all_domains, self.active_domains, reload=True))
        toolbar_item.set_tooltip_text(_("Refresh policy"))
        toolbar.insert(toolbar_item, -1)

        toolbar_item = gtk.ToolButton("Save")
        toolbar_item.set_stock_id(gtk.STOCK_SAVE)
        toolbar_item.connect("clicked", lambda *w: self.save_domains())
        toolbar_item.set_tooltip_text(_("Save policy"))
        toolbar.insert(toolbar_item, -1)

        toolbar_item = gtk.ToolButton(label="Save and apply")
        toolbar_item.set_stock_id(gtk.STOCK_APPLY)
        toolbar_item.connect("clicked", lambda *w: self.save_domains(reload=True))
        toolbar_item.set_tooltip_text(_("Save and apply policy"))
        toolbar.insert(toolbar_item, -1)

        toolbar.insert(gtk.SeparatorToolItem(), -1)

        # policy exporting
        self.export_domains = gtk.ToolButton("Export")
        self.export_domains.set_stock_id(gtk.STOCK_SAVE_AS)
        self.export_domains.connect("clicked", self.export_policy)
        self.export_domains.set_tooltip_text(_("Export selected policy"))
        self.export_domains.set_sensitive(False)
        self.selected_domains = None
        toolbar.insert(self.export_domains, -1)

        toolbar.insert(gtk.SeparatorToolItem(), -1)

        toolbar_item = gtk.ToolButton("Quit")
        toolbar_item.set_stock_id(gtk.STOCK_QUIT)
        toolbar_item.connect("clicked", lambda *w: gtk.main_quit())
        toolbar_item.set_tooltip_text(_("Quit without saving"))
        toolbar.insert(toolbar_item, -1)

        self.main_vbox.pack_start(toolbar, False, False)

        # tabs
        self.notebook = gtk.Notebook()
        self.main_vbox.pack_start(self.notebook)
        self.notebook.connect('switch-page', self.show_help_for_page)

        # domains
        sw_all, self.all_domains = self.build_list_of_domains()
        sw_active, self.active_domains = self.build_list_of_domains()

        # help text for switching pages
        self.num_pages = 0
        self.page_help = {}
        self.notebook.append_page(sw_all, gtk.Label(_("All domains")))
        self.add_page_help("All domains")
        self.notebook.append_page(sw_active, gtk.Label(_("Active domains")))
        self.add_page_help("Active domains")

        # contents
        sw2 = gtk.ScrolledWindow()
        sw2.set_policy(gtk.POLICY_AUTOMATIC, gtk.POLICY_AUTOMATIC)
        sw2.set_shadow_type(gtk.SHADOW_ETCHED_IN)
        frame = gtk.Frame(_("Details"))
        self.domain_details = gtk.VBox(False, 5)
        frame.add(self.domain_details)
        sw2.add_with_viewport(frame)
        self.main_vbox.pack_start(sw2)

        # size group
        self.size_group = gtk.SizeGroup(gtk.SIZE_GROUP_HORIZONTAL)

        # show initial help
        self.show_help(0)

        self.window.show_all()

        self.refresh_domains(self.all_domains, self.active_domains)

        # now building exceptions
        sw_exceptions, self.exceptions = self.build_list_of_exceptions()
        self.update_exceptions()
        self.notebook.append_page(sw_exceptions, gtk.Label(_("Exceptions")))
        self.add_page_help("Exceptions")

        # help
        self.notebook.append_page(self.build_help(), gtk.Label(_("Help")))
        self.add_page_help("Help")

    def add_page_help(self, page):
        """Associates tab number with contents"""
        self.page_help[self.num_pages] = page
        self.num_pages += 1

    def export_policy(self, widget):
        """Exports selected domains into a file"""
        if DEBUG:
            print "Exporting %s" % str(self.selected_domains)
        chooser = gtk.FileChooserDialog(title=_("Policy export"),action=gtk.FILE_CHOOSER_ACTION_SAVE,
                      buttons=(gtk.STOCK_CANCEL,gtk.RESPONSE_CANCEL,gtk.STOCK_SAVE,gtk.RESPONSE_OK))
        chooser.set_current_name("policy.conf")
        response = chooser.run()
        if response == gtk.RESPONSE_OK:
            filename = chooser.get_filename()
            self.policy.write_policy(filename, self.selected_domains)
        chooser.destroy()

    def show_help_for_page(self, notebook, page, page_num):
        """Shows help for current page"""
        if page_num in self.page_help:
            self.show_help(page_num)

    def show_help(self, page):
        """Shows initial help text"""
        # show default text
        tab = self.page_help[page]
        if tab == "All domains":
            title = tab
            help = HELP_ALL_DOMAINS
        elif tab == "Active domains":
            title = tab
            help = HELP_ACTIVE_DOMAINS
        elif tab == "Exceptions":
            title = tab
            help = HELP_EXCEPTIONS
        elif tab == "Help":
            # default help text
            title = _("Help for TOMOYO Linux gui")
            help = HELP_DEFAULT
        else:
            # no help, leaving
            return
        if len(help) > 0:
            table, cur_row = self.refresh_details(self.domain_details, title)
            for line in help:
                self.__add_row(table, cur_row, line, markup=True)
                cur_row += 1
        self.domain_details.show_all()

    def save_domains(self, reload=False):
        """Saves and, optionally, reload current policy"""
        ret = self.policy.save(reload)
        if not ret:
            dialog = gtk.MessageDialog(
                    parent=self.window,
                    flags=0,
                    type=gtk.MESSAGE_ERROR,
                    message_format = _("Unable to save TOMOYO policy! Please certify that ccs-tools package is installed and operational."),
                    buttons=gtk.BUTTONS_OK
                    )
            dialog.show_all()
            dialog.run()
            dialog.destroy()


    def refresh_domains(self, lstore_all, lstore_active, reload=True):
        """Refresh the list of domain entries"""
        # building the list of domains and active domains

        # reload policy from disk?
        if reload:
            # show some informative window
            progress = gtk.Window()
            progress.set_title(_("Please wait..."))
            progress.set_transient_for(self.window)
            progress.set_modal(True)
            progress.connect('delete-event', lambda *w: None)

            vbox = gtk.VBox(spacing=10)
            progress.add(vbox)
            vbox.add(gtk.Label("Please wait, loading TOMOYO policy..."))

            # show window
            progress.show_all()
            self.process_events()

            ## reload policy
            ret = self.policy.reload()

            # kill progress window
            progress.destroy()

            if not ret:
                # something went wrong..
                dialog = gtk.MessageDialog(
                        parent=self.window,
                        flags=0,
                        type=gtk.MESSAGE_ERROR,
                        message_format = _("TOMOYO policy not found or not initialized. Do you want to initialize the default TOMOYO policy?"),
                        buttons=gtk.BUTTONS_YES_NO)
                dialog.show_all()
                ret = dialog.run()

                dialog.destroy()
                if ret == gtk.RESPONSE_YES:
                    # installing policy
                    self.install_policy()


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

    def update_exceptions(self):
        """Updates the list of exceptions"""
        def add_to_liststore(lstore, item):
            iter = lstore.append()
            lstore.set(iter,
                    self.COLUMN_PATH, item,
                    )

        for exc in self.exceptions:
            lstore = self.exceptions[exc]
            lstore.clear()
            for item in self.policy.exceptions[exc]:
                add_to_liststore(lstore, item)

    def process_events(self):
        """Process pending gtk events"""
        while gtk.events_pending():
            gtk.main_iteration(False)

    def install_policy(self):
        """Installs tomoyo policy"""
        # progress bar
        progress = gtk.Window()
        progress.set_title(_("Please wait..."))
        progress.set_transient_for(self.window)
        progress.set_modal(True)
        progress.connect('delete-event', lambda *w: None)

        vbox = gtk.VBox(spacing=10)
        progress.add(vbox)
        progressbar = gtk.ProgressBar()
        progressbar.set_text(_("Initializing TOMOYO policy..."))
        vbox.pack_start(progressbar)

        label = gtk.Label(_("Please wait, this might take a few minutes."))
        vbox.pack_start(label)

        # show window
        progress.show_all()

        self.process_events()
        # queue to signal that job is finished
        q = Queue()

        installer = TomoyoInstaller(finish_install=q)
        installer.start()

        while 1:
            self.process_events()
            if not q.empty():
                result = q.get()
                break
            else:
                progressbar.pulse()
                time.sleep(0.5)

        progress.destroy()

        if result == 0:
            text = _("TOMOYO policy was initialized successfully. Please reboot your machine to activate and start using it.")
            type = gtk.MESSAGE_INFO
        else:
            text = _("An error occured while initializing TOMOYO policy. You might have to run /usr/lib/ccs/tomoyo_init_policy.sh manually.")
            type = gtk.MESSAGE_ERROR
        # policy was initialized
        dialog = gtk.MessageDialog(
                parent=self.window,
                flags=0,
                type=type,
                message_format=text,
                buttons=gtk.BUTTONS_OK
                )
        dialog.show_all()
        dialog.run()
        dialog.destroy()
        # leave
        sys.exit(0)


    def build_list_of_exceptions(self):
        """Builds scrollable list of exceptions"""
        # tabs
        exceptions = {}
        vbox = gtk.VBox()
        notebook = gtk.Notebook()
        vbox.pack_start(notebook)

        classes = self.policy.exceptions.keys()
        classes.sort()
        for item in classes:
            sw_exceptions, exceptions_list = self.build_exceptions_for_class(item)
            notebook.append_page(sw_exceptions, gtk.Label(item))
            exceptions[item] = exceptions_list
        vbox.show_all()
        return vbox, exceptions

    def build_help(self):
        """Build help screen"""
        vbox = gtk.VBox()
        vbox.show_all()
        try:
            image = gtk.Image()
            pixbuf = gtk.gdk.pixbuf_new_from_file("%s/%s" % (self.execution_path, "tomoyo.png"))
            image.set_from_pixbuf(pixbuf)
            vbox.pack_start(image)
        except:
            # image not found?
            print >>sys.stderr, "Unable to find tomoyo logo: %s/%s" % (self.execution_path, "tomoyo.png")
        vbox.show_all()
        return vbox

    def build_exceptions_for_class(self, item):
        """Builds list of exceptions of given type"""
        # scrolled window
        sw = gtk.ScrolledWindow()
        sw.set_policy(gtk.POLICY_AUTOMATIC, gtk.POLICY_AUTOMATIC)
        sw.set_shadow_type(gtk.SHADOW_ETCHED_IN)

        # list of options
        lstore = gtk.ListStore(
            gobject.TYPE_STRING,
            )

        # treeview
        treeview = gtk.TreeView(lstore)
        treeview.set_rules_hint(True)
        treeview.set_search_column(self.COLUMN_PATH)

        #treeview.connect('row-activated', self.expand_domain, lstore)

        # selection
        selection = treeview.get_selection()
        selection.set_mode(gtk.SELECTION_MULTIPLE)
        #selection.connect('changed', self.select_domain)

        # configuring columns

        # column for option names
        renderer = gtk.CellRendererText()
        renderer.set_property('width', 400)
        column = gtk.TreeViewColumn(_('Exception'), renderer, text=self.COLUMN_PATH)
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

    def build_profile(self, profile, domains):
        """Building profile selection combobox"""
        # profile selection options
        if DEBUG:
            print domains
        cur_profile = gtk.combo_box_new_text()
        for item in self.DOMAINS:
            cur_profile.append_text(item)
        cur_profile.set_active(profile)
        cur_profile.connect('changed', self.change_profile, domains)
        return cur_profile

    def change_profile(self, cur_profile, domains):
        """Change profile for domains"""
        new_profile = cur_profile.get_active()
        for domain in domains:
            params = self.policy.policy_dict.get(domain)
            for i in range(len(params)):
                p, val = params[i]
                if p == 'use_profile':
                    params[i] = (p, new_profile)
                    break

    def __add_row(self, table, row, label_text, options=None, markup=False, wrap=False, entry=None):
        label = gtk.Label()
        label.set_use_underline(True)
        label.set_alignment(0, 1)
        if wrap:
            label.set_line_wrap(wrap)
        if markup or entry:
            label.set_markup(label_text)
        else:
            label.set_label(label_text)
        label.label_text = label_text
        if entry:
            eventbox = gtk.EventBox()
            eventbox.connect('enter-notify-event', self.show_controls, entry, label)
            eventbox.connect('leave-notify-event', self.hide_controls, entry, label)
            eventbox.connect('button-press-event', self.edit_entry, entry, label)
            eventbox.add(label)
            item = eventbox
        else:
            item = label
        table.attach(item, 0, 1, row, row + 1, gtk.EXPAND | gtk.FILL, 0, 0, 0)

        if options:
            self.size_group.add_widget(options)
            table.attach(options, 1, 2, row, row + 1, 0, 0, 0, 0)

    def show_controls(self, widget, event, entry, label):
        """Showing controls for an entry"""
        label.set_markup("<u>%s</u>" % label.label_text)
        label.get_window().set_cursor(gtk.gdk.Cursor(gtk.gdk.HAND2))


    def hide_controls(self, widget, event, entry, label):
        """Hides controls for an entry"""
        label.set_markup(label.label_text)

    def edit_entry(self, widget, event, entry, label):
        """Hides controls for an entry"""
        # TODO: handle both buttons
        popupMenu = gtk.Menu()
        menuPopup1 = gtk.ImageMenuItem (gtk.STOCK_EDIT)
        menuPopup1.connect('activate', self.edit_acl, entry)
        popupMenu.add(menuPopup1)
        menuPopup2 = gtk.ImageMenuItem (gtk.STOCK_DELETE)
        menuPopup2.connect('activate', self.delete_acl, entry)
        popupMenu.add(menuPopup2)
        popupMenu.show_all()
        popupMenu.popup(None, None, None, 1, 0, entry)

    def edit_acl(self, menuitem, entry):
        """An entry will be changed"""
        domain, pos, item = entry
        if DEBUG:
            print "Editing %s [%s]:" % (domain, item)
        params = self.policy.policy_dict.get(domain)
        acl, path = params[pos]
        dialog = gtk.Dialog(_("Editing ACL"),
                self.window, 0,
                (gtk.STOCK_OK, gtk.RESPONSE_OK,
                gtk.STOCK_CANCEL, gtk.RESPONSE_CANCEL))
        # option title
        label = gtk.Label("Domain: %s" % domain)
        dialog.vbox.pack_start(label)
        dialog.vbox.pack_start(gtk.HSeparator())

        # new acl
        hbox = gtk.HBox(spacing=5)
        label = gtk.Label(_("<b>Path:</b>"))
        label.set_use_markup(True)
        hbox.pack_start(label, False, False)
        entry_path = gtk.Entry()
        entry_path.set_text(item)
        hbox.pack_start(entry_path)
        dialog.vbox.pack_start(hbox)

        hbox = gtk.HBox(spacing=5)
        label = gtk.Label("<b>ACL:</b>")
        label.set_use_markup(True)
        hbox.pack_start(label, False, False)
        entry_acl = gtk.Entry()
        entry_acl.set_text(acl)
        hbox.pack_start(entry_acl)
        dialog.vbox.pack_start(hbox)

        dialog.show_all()
        response = dialog.run()
        if response != gtk.RESPONSE_OK:
            dialog.destroy()
            return

        new_item = entry_path.get_text()
        new_acl = entry_acl.get_text()
        dialog.destroy()

        params[pos] = (new_acl, new_item)
        if DEBUG:
            print "%s -> %s, %s -> %s" % (item, acl, new_item, new_acl)

        # refresh domain data
        self.show_domain_details(domain)

    def delete_acl(self, menuitem, entry):
        """An entry will be deleted"""
        domain, pos, item = entry
        if DEBUG:
            print "Deleting %s [%s]:" % (domain, item)
        params = self.policy.policy_dict.get(domain)
        del params[pos]
        # refresh domain data
        self.show_domain_details(domain)

    def entry_clicked(self, button, entry):
        """An ACL entry was clicked"""
        if DEBUG:
            print "Clicked on %s" % str(entry)

    def format_acl(self, item):
        """Format acl results"""
        # TODO: we could rearrange the list of entries so use_profile comes always first,
        # and include the policy level into the dict as well. This would get rid of
        # policy_tree structure
        params = self.policy.policy_dict.get(item, None)
        profile = 0
        acl = []
        for i in range(len(params)):
            p,val = params[i]
            if p == 'use_profile':
                profile = int(val)
                continue
            acl.append((i, p, val))
        return profile, acl

    def select_domain(self, selection):
        """A domain is selected"""
        self.selected_domains = None
        model, rows = selection.get_selected_rows()
        if selection.count_selected_rows() == 0:
            self.export_domains.set_sensitive(False)
            return
        elif selection.count_selected_rows() == 1:
            # just one item is selected
            self.export_domains.set_sensitive(False)
            iter = model.get_iter(rows[0])
            return self.show_domain(model, iter)
        else:
            self.export_domains.set_sensitive(True)
            domains = []
            for item in rows:
                iter = model.get_iter(item)
                domain = model.get_value(iter, self.COLUMN_DOMAIN)
                domains.append(domain)

            if len(domains) < 1:
                self.show_help(0)
                return
            self.selected_domains = domains
            # update title
            self.refresh_details(self.domain_details, domains[0])
            table, cur_row = self.refresh_details(self.domain_details, _("Configure profile for a group"))
            # building details

            # get profile description
            profile, acl = self.format_acl(domains[0])
            self.__add_row(table, cur_row, _("Profile"), options=self.build_profile(profile, domains))
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
        return self.show_domain_details(domain)

    def show_domain_details(self, domain):
        """Displays domain details"""
        params = self.policy.policy_dict[domain]

        table, cur_row = self.refresh_details(self.domain_details, _("Configure ACL for %s") % domain)

        # get profile description
        profile, acl = self.format_acl(domain)
        self.__add_row(table, cur_row, _("Profile"), options=self.build_profile(profile, [domain]))
        cur_row += 1

        # building ACL
        if len(acl) > 0:
            self.__add_row(table, cur_row, _("<b>Security settings</b>"), markup=True)
            cur_row += 1
            for pos, acl, item in acl:
                self.__add_row(table, cur_row, item, options=gtk.Label(acl), entry = (domain, pos, item))
                cur_row += 1

        self.domain_details.show_all()

    def expand_domain(self, treeview, path, col, model):
        """Locates all subdomains for a domain"""
        start_path = path
        if DEBUG:
            print "Expanding %s" % str(path)
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

        If policy=system, reads policy from /etc/(tomoyo,ccs)/domain_policy.conf.
        If policy=kernel, policy is read from /sys/kernel/security/tomoyo/domain_policy"""
        self.policy = policy
        self.version = version
        if policy == "kernel":
            self.location = "/sys/kernel/security/tomoyo/domain_policy"
            self.exceptions_location = "/sys/kernel/security/tomoyo/exception_policy"
        else:
            self.location = "/etc/%s/domain_policy.conf" % version
            self.exceptions_location = "/etc/%s/exception_policy.conf" % version
        self.save_location = "domain_policy.conf"

    def reload(self):
        """Reloads the policy. If using system policy, current kernel policy is saved first"""
        if self.policy == "system":
            os.system(self.POLICY_SAVE)
        success, self.policy, self.policy_dict, self.policy_tree, self.exceptions = self.read_policy(self.location)
        return success

    def read_policy(self, location):
        """Reads a policy from file"""
        success = True
        try:
            with open(self.location) as fd:
                data = fd.readlines()
        except:
            # unable to open policy file
            print >>sys.stderr, "Unable to open policy file: %s" % self.location
            data = []
            success = False
        # read domains
        domains = []
        domains_dict = {}
        domains_tree = []
        path = []
        for line in data:
            line = line.strip()
            if not line:
                continue
            # parse domains
            if line.find('<kernel>') == 0:
                # it is a security domain
                domain = line
                domains.append(domain)
                if domain not in domains_dict:
                    domains_dict[domain] = []
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
                domains_tree.append((curpath, curlevel))
            else:
                # an ACL
                command, params = line.split(" ", 1)
                domains_dict[domain].append((command, params))
        # read exceptions
        try:
            with open(self.exceptions_location) as fd:
                data = fd.readlines()
        except:
            # unable to open policy file
            print >>sys.stderr, "Unable to open policy file: %s" % self.location
            data = []
            success = False
        exceptions = {}
        # initialize known exception tykes
        for exc in ["file_pattern", "allow_read", "deny_rewrite", "alias", "initialize_domain", "no_initialize_domain", "keep_domain", "no_keep_domain"]:
            exceptions[exc] = []
        for line in data:
            acl, params = line.strip().split(" ", 1)
            if acl not in exceptions:
                exceptions[acl] = []
            exceptions[acl].append(params)
        return success, domains, domains_dict, domains_tree, exceptions

    def save(self, reload=True):
        """Saves the policy. If reload=True, the saved policy is loaded into kernel"""
        time = datetime.datetime.now().strftime("%F.%T")
        filename = "domain_policy.%s.conf" % time
        full_filename = "/etc/%s/%s" % (self.version, filename)
        # are we working on a real file or a symbolic link?
        try:
            status = os.lstat(self.location)
            if S_ISLNK(status.st_mode):
                # remove old link, new one will be created instead
                os.unlink(self.location)
                os.symlink(filename, self.location)
            else:
                os.rename(self.location, "%s.old" % self.location)
            self.write_policy(full_filename, self.policy)
        except:
            print >>sys.stderr, "Unable to save TOMOYO policy: %s" % sys.exc_value[1]
            return False
        if reload:
            os.system(self.POLICY_LOAD)
        return True

    def write_policy(self, filename, entries):
        """Exports specified entries to a file"""
        fd = open(filename, "w")
        for item in entries:
            print >>fd, "%s\n" % item
            for acl, val in self.policy_dict[item]:
                print >>fd, "%s %s" % (acl, val)
                # compatibility with ccs-savepolicy
                if acl == "use_policy":
                    print >>fd
            print >>fd

# {{{ usage
def usage():
    """Prints help message"""
    print """Tomoyo GUI.

Arguments to msecgui:
    -h, --help              displays this helpful message.
    -d, --debug             enable debugging output
    -e, --embedded <XID>    embed in MCC.
"""
# }}}


if __name__ == "__main__":
    PlugWindowID = None

    # parse command line
    try:
        opt, args = getopt.getopt(sys.argv[1:], 'hde:', ['help', 'debug', 'embedded='])
    except getopt.error:
        usage()
        sys.exit(1)
    for o in opt:
        # help
        if o[0] == '-h' or o[0] == '--help':
            usage()
            sys.exit(0)
        # list
        elif o[0] == '-d' or o[0] == '--debug':
            DEBUG=True
        elif o[0] == '-e' or o[0] == '--embedded':
            try:
                PlugWindowID = long(o[1])
            except:
                print >>sys.stderr, "Error: bad master window XID (%s)!" % o[1]
                sys.exit(1)

    policy = TomoyoPolicy()

    gtk.gdk.threads_init()

    gtk.gdk.threads_enter()
    TomoyoGui(policy, embed=PlugWindowID)
    gtk.gdk.threads_leave()
    gtk.main()
