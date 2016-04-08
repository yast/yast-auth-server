#
# spec file for package yast2-auth-server
#
# Copyright (c) 2014 SUSE LINUX Products GmbH, Nuernberg, Germany.
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
Version:        3.1.16
Release:        0

BuildRoot:      %{_tmppath}/%{name}-%{version}-build
Source0:        %{name}-%{version}.tar.bz2

Group:	System/YaST
License:        GPL-2.0+ and MIT
BuildRequires:	boost-devel gcc-c++ libldapcpp-devel libtool perl-Digest-SHA1 perl-gettext perl-X500-DN pkg-config update-desktop-files yast2 yast2-core-devel yast2-ldap yast2-users
BuildRequires:  yast2-devtools >= 3.1.10
BuildRequires:  cyrus-sasl-devel
Requires:	acl net-tools perl perl-Digest-SHA1 perl-gettext perl-X500-DN yast2 yast2-ca-management yast2-perl-bindings

# users/ldap_dialogs.ycp
Requires:       yast2-users >= 2.22.3
Requires:       yast2-ldap >= 3.1.0

# for Hostname::DefaultDomain
Requires:       yast2 >= 3.1.136
Requires:       yast2-ruby-bindings >= 1.0.0
Requires:       yast2-ldap >= 3.1.2

# Obsolete following packages
Obsoletes:      yast2-kerberos-server < 3.1.2
Obsoletes:      yast2-ldap-server < 3.1.2
Provides:       yast2-kerberos-server = %{version}
Provides:       yast2-ldap-server = %{version}

Summary:	YaST2 - Authentication Server Configuration

%description
Provides basic configuration of an OpenLDAP Server and Kerberos Server
over YaST2 Control Center and during installation.

%prep
%setup -n %{name}-%{version}

%build
%yast_build

%install
%yast_install

rm -f $RPM_BUILD_ROOT/%{yast_plugindir}/libpy2ag_slapdconfig.la
rm -f $RPM_BUILD_ROOT/%{yast_plugindir}/libpy2ag_slapdconfig.so


%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%files
%defattr(-,root,root)
%dir %{yast_yncludedir}/auth-server
%dir %{yast_moduledir}/YaPI
%{yast_yncludedir}/auth-server/*
%{yast_clientdir}/auth-server.rb
%{yast_clientdir}/auth-server_*.rb
%{yast_clientdir}/openldap-mirrormode.rb
%{yast_moduledir}/AuthServer.*
%{yast_moduledir}/LdapDatabase.*
%{yast_moduledir}/YaPI/LdapServer.pm
%{yast_desktopdir}/auth-server.desktop
%{yast_desktopdir}/openldap-mirrormode.desktop
%{yast_plugindir}/libpy2ag_slapdconfig.*
%{yast_schemadir}/autoyast/rnc/auth-server.rnc
%{yast_scrconfdir}/*
%{yast_agentdir}/*
%{yast_ybindir}/ldap-server-ssl-check
%doc %{yast_docdir}
%doc COPYING.MIT
%doc COPYING
