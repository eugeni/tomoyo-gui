PACKAGE = tomoyo-gui
VERSION = 0.02
GITPATH = ssh://git.mandriva.com/git/projects/tomoyo-mdv.git

all: version gui

gui:
	make -C gui

version:
	echo "version='$(VERSION)'" > gui/version.py

clean:
	-find . -name '*.o' -o -name '*.py[oc]' -o -name '*~' | xargs rm -f

install: all
	mkdir -p $(RPM_BUILD_ROOT)/etc/tomoyo/
	mkdir -p $(RPM_BUILD_ROOT)/usr/share/tomoyo-mdv
	mkdir -p $(RPM_BUILD_ROOT)/usr/sbin
	cp gui/*.py* $(RPM_BUILD_ROOT)/usr/share/tomoyo-mdv
	install -m755 gui/tomoyo-gui $(RPM_BUILD_ROOT)/usr/sbin

cleandist:
	rm -rf $(PACKAGE)-$(VERSION) $(PACKAGE)-$(VERSION).tar.bz2

dist: gitdist

gitdist: cleandist
	git archive --prefix $(PACKAGE)-$(VERSION)/ HEAD | bzip2 -9 > $(PACKAGE)-$(VERSION).tar.bz2
