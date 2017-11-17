#
# spec file for package yast-gpmc
#

Name:       yast-gpmc
Version:    1.0
Release:    1
License:    GPL-3.0
Summary:    Group Policy Management Console for YaST
Url:        http://www.github.com/dmulder/yast-gpmc
Group:      Productivity/Networking/Samba
Source:     %{name}-%{version}.tar.gz
BuildArch:  noarch
Requires:   yast2-python-bindings >= 4.0.0
Requires:   samba-client
Requires:   python-ldap
Requires:   samba-python
Requires:   krb5-client
Requires:   yast2
BuildRequires:  autoconf
BuildRequires:  automake
BuildRequires:  python
BuildRequires:	perl-XML-Writer
BuildRequires:  update-desktop-files
BuildRequires:  yast2
BuildRequires:  yast2-devtools
BuildRequires:  yast2-testsuite

%description
The Group Policy Management console for YaST provides tools for creating and
modifying Group Policy Objects in Active Directory.

%prep
%setup -q

%build
autoreconf -if
%configure --prefix=%{_prefix}
make

%install
make DESTDIR=$RPM_BUILD_ROOT install

%clean
%{__rm} -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
%dir %{_datadir}/YaST2/include/gpmc
%{_datadir}/YaST2/clients/gpmc.py
%{_datadir}/YaST2/include/gpmc/complex.py
%{_datadir}/YaST2/include/gpmc/dialogs.py
%{_datadir}/YaST2/include/gpmc/wizards.py
%{_datadir}/YaST2/include/gpmc/defaults.py
%{_datadir}/applications/YaST2/gpmc.desktop
%dir %{_datadir}/doc/yast2-gpmc
%{_datadir}/doc/yast2-gpmc/COPYING

%changelog
