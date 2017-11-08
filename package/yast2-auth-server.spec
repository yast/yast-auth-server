#
# spec file for package yast2-auth-server
#
# Copyright (c) 2017 SUSE LINUX GmbH, Nuernberg, Germany.
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

Name:           yast2-auth-server
Group:	        System/YaST
Summary:	    A tool for creating identity management server instances
Version:        3.2.0
Release:        0
License:        GPL-2.0+
Source0:        %{name}-%{version}.tar.bz2
Url:            https://github.com/yast/yast-auth-server
BuildArch:      noarch
BuildRequires:  yast2
BuildRequires:  yast2-devtools
BuildRequires:  rubygem(yast-rake)
Requires:       net-tools
Requires:       yast2-ruby-bindings
Requires:       yast2
BuildRoot:      %{_tmppath}/%{name}-%{version}-build

%description
The program assists system administrators to create new directory server and
Kerberos server instances that help to maintain centralised user identity
database for a network.

%prep
%setup -n %{name}-%{version}

%build

%install
rake install DESTDIR="%{buildroot}"

%files
%defattr(-,root,root)
%doc %{yast_docdir}
%{yast_libdir}/
%{yast_desktopdir}/
%{yast_clientdir}/

%changelog
