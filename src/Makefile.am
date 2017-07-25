# Makefile.am for gpmc/src

yncludedir = ${prefix}/share/YaST2/include/gpmc

clientdir = ${prefix}/share/YaST2/clients
client_DATA =			\
	gpmc.py

#TODO: This must be modified to python can know from where can import!
ynclude_DATA =			\
	wizards.py		\
	dialogs.py		\
	complex.py

desktopdir = ${prefix}/share/applications/YaST2
desktop_DATA =			\
	gpmc.desktop

moduledir = ${prefix}/share/YaST2/modules
module_DATA = Gpmc.py

# create a symlink for local build, #145327
gpmc:
	ln -sf . $@
ycpchook = gpmc

EXTRA_DIST = $(client_DATA) $(ynclude_DATA) $(module_DATA) $(desktop_DATA)
