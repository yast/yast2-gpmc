#
# spec file for package yast2-gpmc
#
# Copyright (c) 2018 SUSE LINUX GmbH, Nuernberg, Germany.
#
# All modifications and additions to the file contributed by third parties
# remain the property of their copyright owners, unless otherwise agreed
# upon. The license for this file, and modifications and additions to the
# file, is the same license as for the pristine package itself (unless the
# license for the pristine package is not an Open Source License, in which
# case the license is the MIT License). An "Open Source License" is a
# license that conforms to the Open Source Definition (Version 1.9)
# published by the Open Source Initiative.

# Please submit bugfixes or comments via http://bugs.opensuse.org/
#


Name:           yast2-gpmc
Version:        1.4.1
Release:        0
Summary:        Group Policy Management Console for YaST
License:        GPL-3.0
Group:          Productivity/Networking/Samba
Url:            http://www.github.com/dmulder/yast2-gpmc
Source:         %{name}-%{version}.tar.bz2
BuildArch:      noarch
Requires:       krb5-client
Requires:       python3-ldap
Requires:       samba-client
Requires:       samba-python3 >= 4.10.0
Requires:       yast2
Requires:       yast2-python3-bindings >= 4.0.0
BuildRequires:  autoconf
BuildRequires:  automake
BuildRequires:  perl-XML-Writer
BuildRequires:  python3
BuildRequires:  update-desktop-files
BuildRequires:  yast2
BuildRequires:  yast2-devtools
BuildRequires:  yast2-testsuite
Provides:       yast-gpmc = %{version}
Obsoletes:      yast-gpmc < %{version}

%description
The Group Policy Management console for YaST provides tools for creating and
modifying Group Policy Objects in Active Directory.

%prep
%setup -q

%build
make -f Makefile.cvs all

CONFIGURE_OPTIONS="\
%if 0%{?is_opensuse}
        --enable-experimental \
%else
        --disable-experimental \
%endif
"
%configure ${CONFIGURE_OPTIONS}
%make_build

%install
%yast_install

%files
%defattr(-,root,root)
%dir %{yast_yncludedir}/gpmc
%{yast_yncludedir}/gpmc/*
%{yast_clientdir}/*.py
%{yast_desktopdir}/gpmc.desktop
%doc %{yast_docdir}
%license COPYING

%changelog
