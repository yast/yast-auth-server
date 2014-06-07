# encoding: utf-8

# File:	include/ldap-server/helps.ycp
# Package:	Configuration of ldap-server
# Summary:	Help texts of all the dialogs
# Authors:	Andreas Bauer <abauer@suse.de>
#
# $Id$
module Yast
  module AuthServerHelpsInclude
    def initialize_auth_server_helps(include_target)
      textdomain "auth-server"

      # All helps are here
      @HELPS = {
        # The "Startup Configuration node for the main tree widget
        "startup_config"              => _(
          "<h3>Startup Configuration</h3>"
        ) +
          _("<h4>Start LDAP Server</h4>") +
          _(
            "<p>Select <b>Yes</b> if the LDAP server should be started automatically as \n" +
              "part of the boot process. Select <b>No</b> if the LDAP server should not be started. Note:\n" +
              "After selecting <b>No</b>, you cannot change the OpenLDAP configuration.</p>\n"
          ) +
          _("<h4>Protocol Listeners</h4>") +
          _(
            "<p>Enable and disable the various protocol listeners of OpenLDAP.</p>"
          ) +
          _(
            "<p><b>LDAP</b> is the standard LDAP interface on Port 389. TLS/SSL secured communication\nis possible with the StartTLS operation when you have a server certificate configured.</p>"
          ) +
          _(
            "<p><b>LDAPS</b> enables the \"LDAP over SSL (ldaps)\" interface for SSL protected\nconnections on port 636. This only works if you have a server certificate configured (see \"Global Settings\"/\"TLS Settings\").\n"
          ) +
          _(
            "<p><b>LDAPI</b> enables the \"LDAP over IPC\" interface for accessing the\n" +
              "LDAP server via a Unix Domain Socket. Do not disable the LDAPI interface \n" +
              "as YaST uses it to communicate with the server.</p>\n"
          ) +
          _("<h4>Firewall Settings</h4>") +
          _(
            "<p>Select whether SuSEFirewall should allow access on the LDAP-related\nnetwork ports or not.</p>\n"
          ),
        # First part of the Add Database Widget
        "database_basic"              => _(
          "<h3>Basic Database Settings</h3>"
        ) +
          _(
            "<p>Choose the <b>Database</b> from <b>hdb</b> <b>bdb</b> and <b>mdb</b>. <b>Hdb</b> is a\n" +
              "variant of the <b>bdb</b> backend that uses a hierarchical database layout and\n" +
              "supports subtree renames. Otherwise it is identical to <b>bdb</b>. A\n" +
              "<b>hdb</b>-Database needs a larger <b>idlcachesize</b> than a\n" +
              "<b>bdb</b>-Database for a good search performance.\n" +
	      "<b>mdb</b>-Database uses OpenLDAP's Lightning Memory-Mapped DB (LMDB) library to store data.\n" +
	      "It similar to the <b>hdb</b> backend but it is both more space-efficient and more execution-efficient.</p>\n"
          ) +
          _(
            "<p>The <b>Base DN</b> option specifies the name of the root entry \nof the database being created.</p>"
          ) +
          _(
            "<p>The <b>Administrator DN</b> along with a <b>LDAP Administrator Password</b> \n" +
              "specifies a superuser identity for the database, surpassing all ACLs and other \n" +
              "administrative limit restrictions. Checking <b>Append Base DN</b> appends the \n" +
              "<b>Base DN</b> entered above, for example, a base DN of <tt>dc=example,dc=com</tt>\n" +
              "and Administrator DN of <tt>c=Admin</tt> would combine to an effective Administrator DN\n" +
              "of <tt>c=Admin,dc=example,dc=com</tt>.</p> "
          ) +
          _(
            "<p>If this wizard was started during installation, the \n" +
              "<b>LDAP Administrator Password</b> is initially set to the system's root password\n" +
              "entered earlier in the installation process.</p> "
          ) +
          _(
            "<p>To use this database as default for the OpenLDAP client tools \n" +
              "(e.g. ldapsearch), check <b>Use this database as the default for OpenLDAP\n" +
              "clients</b>. This will result in the hostname \"localhost\" and the above \n" +
              "entered <b>Base DN</b> being written to the OpenLDAP client configuration \n" +
              "file <tt>/etc/openldap/ldap.conf</tt>. This checkbox is selected by default\n" +
              "when creating the first database on a server.</p>\n"
          ),
        "database_detail_unsupported" => _(
          "YaST currently does not support this database. You can not \nchange any configuration settings here.\n"
        ),
        "database_detail_config"      => _(
          "<p>To enable or disable plaintext authentication (LDAP Simple Bind)\n" +
            "for the configuration database, click the associated checkbox. Plaintext \n" +
            "authentication to the configuration database will only be allowed when \n" +
            "using sufficiently protected (e.g. SSL/TLS encrypted) connections.</p>\n"
        ) +
          _(
            "<p>To change the administration password for the configuration database, \n" +
              "click <b>Change Password</b>. \n" +
              "A Popup will prompt you to enter the new password and select the \n" +
              "<b>Password Encryption</b>. \n" +
              "The password fields are initially empty even if a password has already been \n" +
              "set in the configuration.</p>\n"
          ),
        "database_detail"             => _("<h3>Edit BDB Database</h3>") +
          _("<p>Change basic settings of BDB and HDB Databases.</p>") +
          _(
            "<p>Enter the complete DN or only the first part and append the base DN automatically\nwith <b>Append Base DN</b>.</p>"
          ) +
          _(
            "<p>To change the password for the administrator account, click <b>Change Password</b>.\n" +
              "A Popup will prompt you to enter the new password and select the <b>Password Encryption</b>.\n" +
              "The password fields are initially empty even if a password has already been set in the configuration.</p>\n"
          ) +
          _(
            "<p>With the <b>Entry Cache</b> and <b>Index Cache (IDL cache)</b> you can adjust\n" +
              "the sizes of OpenLDAP's internal caches. The <b>Entry Cache</b> defines the number of entries\n" +
              "that are kept in OpenLDAP's in-memory entry cache. If it is possible (enough RAM) this number\n" +
              "should be large enough to keep the whole database in memory. The <b>Index Cache (IDL cache)</b> \n" +
              "is used to speed up searches on indexed attributes. In general especially HDB-Databases require a\n" +
              "large IDL cache for good search performance (three times the size of the entry cache as a rule of\n" +
              "thumbs).</p>"
          ),
        "ppolicy_edit"                => _("<h3>Password Policy Settings</h3>") +
          _(
            "<p>To make use of password policies for this database, enable \n<b>Enable Password Policies</b>.</p>"
          ) +
          _(
            "<p>Check <b>Hash Clear Text Passwords</b> to specify that the OpenLDAP server\n" +
              "should encrypt clear text passwords present in add and modify requests before storing them\n" +
              "in the database. Note that this violates the  X.500/LDAP information model, but may be\n" +
              "needed to compensate for LDAP clients that do not use the password modify extended operation \n" +
              "to manage passwords.</p> "
          ) +
          _(
            "<p>If <b>Disclose \"Account Locked\" Status</b> is enabled, users trying to\n" +
              "authenticate to a locked account are notified that their account is\n" +
              "locked. This notification might provide useful information to an\n" +
              "attacker. Sites sensitive to security issues should not enable this\n" +
              "option.</p> \n"
          ) +
          _(
            "<p>Enter the name of the default policy object in <b>Default Policy Object DN</b>.</p>"
          ) +
          _(
            "<p>Create or change the default policy by clicking <b>Edit Policy</b>. You may\n" +
              "be asked to enter the LDAP administrator password afterwards to allow the\n" +
              "Policy Object being read from the server.</p>\n"
          ),
        "index_edit"                  => _("<h3>Index Configuration</h3>") +
          _("<p>Change the indexing options of a hdb of bdb-Database.</p>") +
          _(
            "<p>The table displays a list of attributes which currently have an index defined.</p>"
          ) +
          _(
            "<p>Indexes are used by OpenLDAP to improve search performance on specific\n" +
              "types of searches. Indexes should be configured corresponding to the most\n" +
              "common searches on a database. YaST allows you to setup three different types\n" +
              "of indexes.</p>\n"
          ) +
          _(
            "<p><b>Presence</b>: This index is used for searches with presence filters\n" +
              "(i.e. <tt>(attributeType=*)</tt>). Presence indexes should only be configured\n" +
              "for attributes that occur rarely in the database.</p>\n"
          ) +
          _(
            "<p><b>Equality</b>: This index is used for searches with equality filters \n" +
              "(i.e.(<tt>(attributeType=&lt;exact values&gt;)</tt>). An <b>Equality</b> index\n" +
              "should always be configured with the <tt>objectclass</tt> attribute.</p>\n"
          ) +
          _(
            "<p><b>Substring</b>: This index is used for searches with substring filters\n(i.e. <tt>(attributeType=&lt;substring&gt;*)</tt>)</p>\n"
          ) +
          _(
            "<p>Use <b>Add</b> to define indexing options for a new attribute,\n" +
              "<b>Delete</b> to delete an existing index and <b>Edit</b> to change the\n" +
              "indexing options of an already indexed attribute.</p>\n"
          ) +
          _(
            "<p>Note: Depending on the database size it can take a while until newly added\n" +
              "indexes will get active on a database. After the configuration has been\n" +
              "written to the server, a background task will start to generate the indexing\n" +
              "information for the database.</p>\n"
          ),
        "acl_edit"                    => _(
          "<h3>Access Control Configuration</h3>"
        ) +
          _(
            "<p>This table gives you an overview of all Access Control rules that are\ncurrently configured for the selected database</p>\n"
          ) +
          _(
            "<p>For each rule, you can see which target objects it matches. To see a more\n" +
              "detailed view of a rule or to change one, select the rule in the table and\n" +
              "click <b>Edit</b>.</p>\n"
          ) +
          _(
            "<p>Use <b>Add</b> to create new access control rules and <b>Delete</b> to\ndelete an access control rule.</p>\n"
          ) +
          _(
            "<p>OpenLDAP's access control evaluation stops at the first rule whose target\n" +
              "definition (DN, filter and attributes) matches the entry being\n" +
              "accessed. Therefore you should order the rules according to your needs, using\n" +
              "the <b>Up</b> and <b>Down</b> buttons.</p>\n"
          ),
        "syncprov_edit"               => _(
          "<h3>Replication Provider Settings</h3>"
        ) +
          _(
            "<p>Select the \"<b>Enable ldapsync provider for this database</b>\" checkbox, if you want to \nbe able to replicate the currently selected database to another server.</p>"
          ) +
          _("<h4>Checkpoint Settings</h4>") +
          _(
            "<p>Here you can specify how often the synchronization state indicator (stored\n" +
              "in the \"<i>contextCSN</i>\"-Attribute) is written to the database. It is synced\n" +
              "to the database after the number of write \"<i>Operations</i>\" you specify or\n" +
              "after more than the specified \"<i>Minutes</i>\" have passed since the indicator\n" +
              "has last been written. By default (both values are '0') the state indicator is\n" +
              "only written after a clean shutdown. Writing it more often can result in\n" +
              "a faster startup time after an unclean shutdown but might result in a small\n" +
              "performance hit in environments with many LDAP write operations.</p>\n"
          ) +
          _("<h4>Session log</h4>") +
          _(
            "<p>Configures an in-memory session log for recording information about write operations\n" +
              "made on the database. Specify how many write operation should be recorded in the session log. \n" +
              "Configuring a session log is only useful for \"<i>refreshOnly</i>\" replication. In \n" +
              "such a case it can speed up replication and reduce the load on the master server.</p>"
          ),
        "synccons_edit"               => _(
          "<h3>Replication Consumer Settings</h3>"
        ) +
          _(
            "<p>Select \"<b>This database is a Replication Consumer</b>\" if you want the\ndatabase to be a replica of a database on another server.</p>\n"
          ) +
          _("<h4>Provider</h4>") +
          _(
            "Enter the connection details for the replication connection to the master\n" +
              "server here. Select the protocol to use (<b>ldap</b> or <b>ldaps</b>) and\n" +
              "enter the fully qualified hostname of the master server. It is important to\n" +
              "use the fully qualified hostname to verify the master server's TLS/SSL\n" +
              "certificate. Adjust the port number if the master server is using non-standard\n" +
              "ldap ports.\n"
          ) +
          _("<h4>Replication Type</h4>") +
          _("<p>OpenLDAP supports different modes of replication:</p>") +
          _(
            "<p><b>refreshOnly</b>: The slave server will periodically open a new\n" +
              "connection, trigger a synchronization and close the connection again. The\n" +
              "interval how often this synchronization happens can be configured via the\n" +
              "<b>Replication Interval</b> setting.</p>\n"
          ) +
          _(
            "<p><b>refreshAndPersist</b>: The slave server will open a persistent\n" +
              "connection to the master server for synchronization. Updated entries on the\n" +
              "master server are immediately sent to the slave via this connection.</p>\n"
          ) +
          _("<h4>Authentication</h4>") +
          _(
            "<p>Specify a DN and password which the slave server should use to authenticate against the master.\nThe specified DN needs to have read access to all entries in the replicated database on the master.</p>\n"
          ) +
          _("<h4>Update Referral</h4>") +
          _(
            "<p>As the slave database is readonly, the slave server will answer write\n" +
              "operations with an LDAP referral. \n" +
              "By default, this referral points the client to the master server. You can configure a different update referral here.\n" +
              "This is e.g. useful in a cascaded replication setup where the provider for the\n" +
              "slave server is as slave server too. </p>\n"
          ),
        # Read dialog help
        "read"                        => _(
          "<p><b><big>Initializing LDAP Server Configuration</big></b></p>"
        ) +
          _(
            "<p><b><big>Aborting Initialization:</big></b><br>\nSafely abort the configuration utility by pressing <b>Abort</b> now.</p>"
          ),
        # Write dialog help
        "write"                       => _(
          "<p><b><big>Saving LDAP Server Configuration</big></b></p> \n"
        ) +
          _(
            "<p><b><big>Aborting Saving:</big></b><br>\n" +
              "Abort the save procedure by pressing <b>Abort</b>. An additional dialog\n" +
              "informs you whether it is safe to do so.</p>\n"
          ),
        # Summary dialog help 1/3
        "summary"                     => _(
          "<h3>LDAP Server Configuration Summary</h3>"
        ) +
          _(
            "<p>This dialog provides a short summary about the configuration you have\n" +
              "created. Click <b>Finish</b> to write the configuration and leave the LDAP\n" +
              "Server module.</p>\n"
          ),
        # Configuration Wizard Step 1
        "service_dialog"              => _(
          "<p>With <b>Start LDAP Server Yes or No</b>, start or stop the LDAP server.</p> "
        ) +
          _(
            "<p>If you select <b>Yes</b>, click <b>Next</b> to start the configuration wizard.</p>"
          ) +
          _(
            "<p>If the Firewall is enabled, open the required network ports\nfor OpenLDAP by checking the corresponding checkbox.</p>\n"
          ),
        # Configuration Wizard Step 2
        "server_type"                 => _(
          "<p>Select the type of LDAP server you want to setup. The following scenarios are available:</p>"
        ) +
          _(
            "<p><b>Stand-alone server</b>: Setup a single stand-alone OpenLDAP server with\nno preparations for replication.</p>\n"
          ) +
          _(
            "<p><b>Master server in a replication setup</b>: Create an OpenLDAP setup\nprepared to act as a master server (provider) in a replication setup.</p>\n"
          ) +
          _(
            "<p><b>Replica slave server</b>: Setup an OpenLDAP slave server that replicates all its data,\nincluding configuration, from a master server.</p>"
          ),
        # Configuration Wizard Step 3
        "tls_dialog"                  => _(
          "<h3>TLS Settings</h3>"
        ) +
          _("<h4>Basic Settings</h4>") +
          _(
            "<p>To enable encryption via TLS/SSL, check the <b>Enabled TLS</b>\n" +
              "checkbox. Additionally you need to configure a certificate for the Server \n" +
              "to use.</p>\n"
          ) +
          _(
            "<p>Check <b>Enable LDAP over SSL (ldaps) interface</b>, to enable the server\n" +
              "to accept LDAPS connections on port 636. If not checked, OpenLDAP will only\n" +
              "support TLS encrypted connections through the StartTLS extended operation.</p>\n"
          ) +
          _(
            "<p>If you already have a common server certificate installed using the\n" +
              "corresponding YaST Module, check <b>Use common Server Certificate</b> so that\n" +
              "the OpenLDAP server uses this certificate.</p>\n"
          ) +
          _("<h4>Import Certificate</h4>") +
          _(
            "<p>If you have no common server certificate or you want OpenLDAP to use a\n" +
              "different certificate, enter the file names of the <b>CA Certificate File</b>,\n" +
              "<b>Certificate File</b> and <b>Certificate Key File</b> into the corresponding\n" +
              "textfields.</p>\n"
          ) +
          _(
            "<p>To create a new CA or certificate, launch the CA management module by\nclicking <b>Launch CA Management Module</b>.</p>\n"
          ),
        # Tree Item Dialog "global" 1/1
        "global"                      => _(
          "<p>Below this item, configure some global parameters.</p>"
        ),
        #Tree Item Dialog "schema" 1/
        "schema"                      => _(
          "<p>Add schema files in this dialog. Press <b>Add</b> to open a file dialog in which to choose\n" +
            "a new schema. Note: OpenLDAP (when used with back-config) does currently not support the removal of \n" +
            "Schema Data</p>"
        ),
        # Tree Item Dialog "loglevel"
        "g_loglevel"                  => _(
          "<p>Select the subsystems that should log debugging statements and statistics\nto syslog.</p>"
        ),
        # Tree Item Dialog "allow" 1/1
        "g_allow"                     => _(
          "<p>Select which special features the OpenLDAP Server should allow or disallow:</p>"
        ) +
          _("<h3>Select Allow Flags</h3>") +
          _(
            "<p><b>LDAPv2 Bind Requests</b>: To let the server accept LDAPv2 bind requests.\nNote that OpenLDAP does not truly implement LDAPv2.</p>\n"
          ) +
          _(
            "<p><b>Anonymous Bind when credentials not empty</b>: To allow anonymous bind when \ncredentials are not empty (i.e. password is present but bind DN is not present) </p>"
          ) +
          _(
            "<p><b>Unauthenticated Bind when DN not empty</b>: To allow unauthenticated \n(anonymous) binds when DN is not empty</p>"
          ) +
          _(
            "<p><b>Unauthenticated Update Operations to process</b>: To allow unauthenticated\n" +
              "(anonymous) update operations to be processed. They are still subject to\n" +
              "access controls and other administrative limits.</p>\n"
          ) +
          _("<h3>Select Disallow Flags</h3>") +
          _(
            "<p><b>Disable acceptance of anonymous Bind Requests</b>: The Server will\n" +
              "not accept anonymous bind requests. Note that this does not generally\n" +
              "prohibit anonymous directory access.</p>\n"
          ) +
          _(
            "<p><b>Disable Simple Bind authentication</b>: Completely disable Simple Bind\nauthentication</p>\n"
          ) +
          _(
            "<p><b>Disable forcing session to anonymous status upon StartTLS operation\n" +
              "receipt</b>: The server will no longer force an authenticated connection back\n" +
              "to the anonymous state when receiving the StartTLS operation.</p>\n"
          ) +
          _(
            "<p><b>Disallow the StartTLS operation if authenticated</b>:\n" +
              "The server will not allow the StartTLS operation on already authenticated\n" +
              "connections.</p>\n"
          ),
        # Tree Item Dialog "databases"
        "databases"                   => _(
          "<p>This lists shows all configured databases. The databases with the type\n" +
            "\"frontend\" and \"config\" represent special internal databases. The \"Frontend\"\n" +
            "database is use to configure global access control restrictions and overlays\n" +
            "that apply to all databases. The \"Config\" database holds the configuration of\n" +
            "the LDAP server itself.</p>\n"
        ) +
          # Tree Item Dialog "databases" 2/2
          _("<p>To add a new database, press <b>Add Database...</b>.</p>") +
          _(
            "<p>To delete a database, select a database from the list and press <b>Delete Database...</b>.\nYou cannot delete the \"config\" and \"frontend\" databases.</p>\n"
          ),
        "master_setup_dialog"         => _(
          "<p>Enter a password for the configuration database (\"<i>cn=config</i>\") here. This is required to make\nthe configuration database accessible remotely.</p>"
        ) +
          _(
            "<p>If the server is supposed to participate in a MirrorMode setup, select the \"<b>Prepare for MirrorMode replication</b>\"\ncheckbox. This will ensure that the serverId attribute is generated as needed for MirrorMode replication.</p>\n"
          ),
        "slave_dialog"                => _(
          "<p>To setup a slave server some details need to be queried from the master server. Please enter the master\n" +
            "server's hostname, adjust the protocol (either \"<i>ldap</i>\" or \"<i>ldaps</i>\") and port number as needed and enter the password\n" +
            "for the master's configuration database (\"<i>cn=config</i>\").</p>"
        ),
	########### kerberos
        # Help text: basic settings 1/2
        "kerberos"                            => _(
          "<p>Specify the <big>Realm</big> and the <big>Master Password</big> for your Kerberos server.</p>"
        ) +
          # Help text: basic settings 2/2
          _(
            "<p>Although your Kerberos realm can be any ASCII string, the convention is to use upper-case letters as in your domain name.</p>\n"
          ),
        # advanced item help: database_name
        "adv_database_name"                => _(
          "<p>This string specifies the location of the Kerberos database for this realm.</p>"
        ),
        # advanced item help: acl_file
        "adv_acl_file"                     => _(
          "<p>This string specifies the location of the access control list (ACL) file that kadmin uses to determine the principals' permissions on the database.</p>"
        ),
        # advanced item help: admin_keytab
        "adv_admin_keytab"                 => _(
          "<p>This string specifies the location of the keytab file that kadmin uses to authenticate to the database.</p>"
        ),
        # advanced item help: default_principal_expiration
        "adv_default_principal_expiration" => _(
          "<p>This absolute time specifies the default expiration date of principals created in this realm.</p>"
        ),
        # advanced item help principal_flags 1/13
        "adv_default_principal_flags"      => _(
          "<p>These flags specify the default attributes of the principal created in this realm.</p>"
        ) + "<ul><li><b>" +
          _("Allow postdated") + "</b> " +
          # advanced item help principal_flags 2/13 :Allow postdated
          _(
            "Enabling this flag allows the principal to obtain postdateable tickets."
          ) + "</li>" + "<li><b>" +
          _("Allow forwardable") + "</b> " +
          # advanced item help principal_flags 3/13 :Allow forwardable
          _(
            "Enabling this flag allows the principal to obtain forwardable tickets."
          ) + "</li>" + "<li><b>" +
          _("Allow renewable") + "</b> " +
          # advanced item help principal_flags 4/13 :Allow renewable
          _(
            "Enabling this flag allows the principal to obtain renewable tickets."
          ) + "</li>" + "<li><b>" +
          _("Allow proxiable") + "</b> " +
          # advanced item help principal_flags 5/13 :Allow proxiable
          _("Enabling this flag allows the principal to obtain proxy tickets.") + "</li>" + "<li><b>" +
          _("Enable user-to-user authentication") + "</b> " +
          # advanced item help principal_flags 6/13 :Enable user-to-user authentication
          _(
            "Enabling this flag allows the principal to obtain a session key for another user, permitting user-to-user authentication for this  principal."
          ) + "</li>" + "<li><b>" +
          _("Requires preauth") + "</b> " +
          # advanced item help principal_flags 7/13 :Requires preauth
          _(
            "If this flag is enabled on a client principal, that principal is required to preauthenticate to the KDC before receiving any tickets. If you enable this flag on a service principal, the service tickets for this principal will only be issued to clients with a TGT that has the preauthenticated ticket set."
          ) + "</li>" + "<li><b>" +
          _("Requires hwauth") + "</b> " +
          # advanced item help principal_flags 8/13 :Requires hwauth
          _(
            "If this flag is enabled, the principal is required to preauthenticate using a hardware device before receiving any tickets."
          ) + "</li>" + "<li><b>" +
          _("Allow service") + "</b> " +
          # advanced item help principal_flags 9/13 :Allow service
          _(
            "Enabling this flag allows the KDC to issue service tickets for this principal."
          ) + "</li>" + "<li><b>" +
          _("Allow tgs request") + "</b> " +
          # advanced item help principal_flags 10/13 :Allow tgs request
          _(
            "Enabling this flag allows a principal to obtain tickets based on a ticket-granting-ticket, rather than repeating the authentication process that was used to obtain the TGT."
          ) + "</li>" + "<li><b>" +
          _("Allow tickets") + "</b> " +
          # advanced item help principal_flags 11/13 :Allow tickets
          _(
            "Enabling  this  flag  means  that the KDC will issue tickets for this principal. Disabling this flag essentially deactivates the principal within this realm."
          ) + "</li>" + "<li><b>" +
          _("Need change") + "</b> " +
          # advanced item help principal_flags 12/13 :Needchange
          _("Enabling this flag forces a password change for this principal.") + "</li>" + "<li><b>" +
          _("Password changing service") + "</b> " +
          # advanced item help principal_flags 13/13 :Password changing service
          _(
            "If this flag is enabled, it marks this principal as a password change service.  This should only be used in special cases, for example,  if a  user's  password  has  expired,  the user has to get tickets for that principal to be able to change it without going through the normal password authentication."
          ) + "</li></ul>",
        # advanced item help : dict_file
        "adv_dict_file"                    => _(
          "<p>The string location of the dictionary file containing strings that are not allowed as passwords. If this tag is not set or if there is no policy assigned to the principal, no check will be done.</p>"
        ),
        # advanced item help : kadmind_port
        "adv_kadmind_port"                 => _(
          "<p>This port number specifies the port on which the kadmind daemon listens for this realm.</p>"
        ),
        # advanced item help : kpasswd_port
        "adv_kpasswd_port"                 => _(
          "<p>This port number specifies the port on which the kadmind daemon listens for this realm.</p>"
        ),
        # advanced item help : key_stash_file
        "adv_key_stash_file"               => _(
          "<p>This string specifies the location where the master key has been stored with kdb5_stash.</p>"
        ),
        # advanced item help : kdc_ports
        "adv_kdc_ports"                    => _(
          "<p>This string specifies the list of ports that the KDC listens to for this realm.</p>"
        ),
        # advanced item help : master_key_name
        "adv_master_key_name"              => _(
          "<p>This string specifies the name of the principal associated with the master key. The default value is K/M.</p>"
        ),
        # advanced item help : master_key_type
        "adv_master_key_type"              => _(
          "<p>This key type string represents the master keys key type.</p>"
        ),
        # advanced item help : max_life
        "adv_max_life"                     => _(
          "<p>This delta time specifies the maximum time period that a ticket may be valid for in this realm.</p>"
        ),
        # advanced item help : max_renew_life
        "adv_max_renew_life"               => _(
          "<p>This delta time specifies the maximum time period that a ticket may be renewed for in this realm.</p>"
        ),
        # advanced item help : supported_enctypes
        "adv_supported_enctypes"           => _(
          "<p>A list of key/salt strings that specifies the default key/salt combinations of principals for this realm.</p>"
        ),
        # advanced item help : kdc_supported_enctypes
        "adv_kdc_supported_enctypes"       => _(
          "<p>Specifies the permitted key/salt combinations of principals for this realm.</p>"
        ),
        # advanced item help : reject_bad_transit
        "adv_reject_bad_transit"           => _(
          "<p>Specifies whether or not the list of transited realms for cross-realm tickets should be checked against the transit path computed from the realm names and the [capaths] section of its krb5.conf file</p>"
        ),
        # advanced item help : ldap_conns_per_server
        "adv_ldap_conns_per_server"        => _(
          "<p>This LDAP specific tag indicates the number of connections to be maintained via the LDAP server.</p>"
        ),
        # advanced item help : ldap_service_password_file
        "adv_ldap_service_password_file"   => _(
          "<p>This LDAP-specific tag indicates the file containing the stashed passwords for the objects used for starting the Kerberos servers.</p>"
        ),
        # advanced item help : kdb_subtrees
        "adv_kdb_subtrees"                 => _(
          "<p>Specifies the list of subtrees containing the principals of a realm. The list contains the DNs of the subtree objects separated by colon(:).</p><p>The search scope specifies the scope for searching the principals under the subtree.</p>"
        ),
        # advanced item help : kdb_containerref
        "adv_kdb_containerref"             => _(
          "<p>Specifies the DN of the container object in which the principals of a realm will be created. If the container reference is not configured for a realm, the principals will be created in the realm container.</p>"
        ),
        # advanced item help : kdb_maxtktlife
        "adv_kdb_maxtktlife"               => _(
          "<p>Specifies maximum ticket life for principals in this realm.</p>"
        ),
        # advanced item help : kdb_maxrenewlife
        "adv_kdb_maxrenewlife"             => _(
          "<p>Specifies maximum renewable life of tickets for principals in this realm.</p>"
        )
      } 

      # EOF
    end
  end
end
