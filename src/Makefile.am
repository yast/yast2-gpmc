# Makefile.am for gpmc/src

yncludedir = ${prefix}/share/YaST2/include/gpmc

clientdir = ${prefix}/share/YaST2/clients
client_DATA =			\
	gpmc.py

#TODO: This must be modified to python can know from where can import!
ynclude_DATA =			\
	wizards.py		\
	dialogs.py		\
	defaults.py		\
	complex.py

gpmc.desktop: org.opensuse.yast.GPMC.desktop.in
	sed -e 's;[@]CLIENTDIR[@];$(clientdir);g' < $(srcdir)/org.opensuse.yast.GPMC.desktop.in > $(srcdir)/org.opensuse.yast.GPMC.desktop

desktopdir = ${prefix}/share/applications/YaST2
desktop_DATA =			\
	org.opensuse.yast.GPMC.desktop

moduledir = ${prefix}/share/YaST2/modules

gpmc.py: gpmc.py.in
	sed -e 's;[@]INCLUDEDIR[@];$(yncludedir);g' < $(srcdir)/gpmc.py.in > $(srcdir)/gpmc.py

dialogs.py: dialogs.py.in
	sed -e 's;[@]ENABLE_EXPERIMENTAL[@];$(experimental);g' < $(srcdir)/dialogs.py.in > $(srcdir)/dialogs.py

# create a symlink for local build, #145327
gpmc:
	ln -sf . $@
ycpchook = gpmc

EXTRA_DIST = $(client_DATA) $(ynclude_DATA) $(module_DATA) $(desktop_DATA)
CLEANFILES = gpmc.py org.opensuse.yast.GPMC.desktop dialogs.py
