# Sources for ldap-server

module_DATA = \
  modules/Ldap.rb \
  modules/LdapPopup.rb \
  modules/LdapDatabase.rb \
  modules/AuthServer.pm

module1dir = @moduledir@/YaPI
module1_DATA = \
  modules/YaPI/LdapServer.pm

client_DATA = \
  clients/openldap-mirrormode.rb \
  clients/auth-server.rb \
  clients/auth-server_proposal.rb \
  clients/auth-server_auto.rb

yncludedir = @yncludedir@/auth-server
ynclude_DATA = \
  include/auth-server/widgets.rb \
  include/auth-server/wizards.rb \
  include/auth-server/kerberos_advanced.rb \
  include/auth-server/mirrormode-wizard.rb \
  include/auth-server/tree_structure.rb \
  include/auth-server/dialogs.rb \
  include/auth-server/complex.rb \
  include/auth-server/helps.rb

scrconf_DATA = \
  scrconf/cfg_openldap.scr \
  scrconf/ldapserver.scr \
  scrconf/kadmin.scr \
  scrconf/kdc_conf.scr \
  scrconf/krb5_conf.scr

schemafilesdir = $(schemadir)/autoyast/rnc
schemafiles_DATA = \
  autoyast-rnc/ldap-server.rnc

agent_SCRIPTS = \
  servers_non_y2/ag_kadmin \
  servers_non_y2/ag_kerberos

desktop_DATA = \
  desktop/openldap-mirrormode.desktop \
  desktop/auth-server.desktop

EXTRA_DIST = $(module_DATA) $(module1_DATA) $(client_DATA) $(ynclude_DATA) $(scrconf_DATA) $(schemafiles_DATA) $(agent_SCRIPTS) $(desktop_DATA)

include $(top_srcdir)/Makefile.am.common
