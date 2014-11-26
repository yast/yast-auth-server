=head1 NAME

YaPI::LdapServer

=head1 PREFACE

This package is the public Yast2 API to managing a LDAP Server.

=head1 SYNOPSIS

use YaPI::LdapServer

$bool = Init()

 Initializes the API, needs to be called first, before any
 other API call.

\@dbList = ReadDatabaseList()

 Returns a list of configured databases.

$bool = AddDatabase(\%valueMap)

 Creates a new database

$bool = EditDatabase($suffix,\%valueMap)

 Edit the database section with the suffix $suffix.

\%valueMap = ReadDatabase($suffix)

 Read the database section with the suffix $suffix.

\@indexList = ReadIndex($suffix)

 Returns a List of Maps with all index statements for this database

$bool = EditIndex($suffix,\%indexMap)

 Add a new index statement %indexMap to the database section

\@aclList = ReadAcl($suffix)

 Returns a List of Maps with the ACL for this database

$bool = WriteAcl($suffix,\@aclList)

 Replace the existing ACLs of a database

\@list = ReadSchemaList()

 Returns a list of all included schema items

$bool = AddSchema($schemaFile)

 Add an additional Schema item

\@list = ReadAllowList()

 Returns a list of allow statements.

$bool = WriteAllowList(\@list)

 Replaces the complete allow option with the specified list

$loglevel = ReadLoglevel()

 Read the loglevel bitmask.

$bool = AddLoglevel($bit)

 Set the given loglevel bit to 1 in the current bitmask.

$bool = DeleteLoglevel($bit)

 Set the given loglevel bit to 0 in the current bitmask.

$bool = WriteLoglevel($loglevel)

 Replaces the loglevel bitmask.

ModifyService($status)

 Turn on/of the LDAP server runnlevel script

SwitchService($status)

 Start/Stop the LDAP server

$status = ReadService()

 Read out the state of the LDAP server runlevel script

\%valueMap = ReadTLS()

 Return the current TLS settings

$bool = WriteTLS(\%valueMap)

 Write the TLS options in the configuration file.

$bool = CheckCommonServerCertificate()

 Check, if a common server certificate is available.

$bool = ConfigureCommonServerCertificate()

 Configure the LDAP server to use the common server certificate.

$bool = ImportCertificates(\%valueMap)

 Import certificates and configure TLS for the LDAP Server.

$bool = ReadSLPEnabled()

 Read if SLP is enabled in /etc/sysconfig/openldap

$bool = WriteSLPEnabled($bool)

 Activate/Deactivate SLP Registering in /etc/sysconfig/openldap


=head1 DESCRIPTION

=over 2

=cut


package YaPI::LdapServer;

BEGIN {
    push @INC, '/usr/share/YaST2/modules/';
}


use strict;
use vars qw(@ISA);
use YaST::YCP;
use YaPI;
use ycp;
textdomain("auth-server");

use Digest::MD5 qw(md5_hex);
use Digest::SHA1 qw(sha1);
use MIME::Base64;
use X500::DN;

@YaPI::LdapServer::ISA = qw( YaPI );


YaST::YCP::Import ("SCR");
YaST::YCP::Import ("Ldap");
YaST::YCP::Import ("LdapServer");
YaST::YCP::Import ("Service");

our $VERSION="1.2.0";
our @CAPABILITIES = ( 'SLES9' );
our %TYPEINFO;

=item *
C<\$bool = Init()>

Initializes the API, needs to be called first, before any
other API call.

=cut

BEGIN { $TYPEINFO{Init} = ["function", "boolean"]; }
sub Init()
{
    my $self = shift;
    my $rc = SCR->Execute('.ldapserver.init' );
    if ( ! $rc )
    {
        my $err = SCR->Error(".ldapserver");
        $err->{'code'} = "INIT_FAILED";
        return $self->SetError(%{$err});
    }
    return 1;
}

=item *
C<\@dbList = ReadDatabaseList()>

Returns a List of databases. Each element of the list is a hash reference
with the following elements:

 * 'index' : The index of the database. Frontend Database has index -1, 
        config database has index 0 and first "real" database has index 1.

 * 'suffix': The base DN the database is servinng e.g. 'dc=example,dc=com'
 
 * 'type': The database type e.g. 'bdb' or 'config'

EXAMPLE:

 use Data::Dumper;

 my $res = YaPI::LdapServer->ReadDatabaseList();
 if( not defined $res ) {
     # error    
 } else {
     print "OK: \n";
     print STDERR Data::Dumper->Dump([$res])."\n";
 }

=cut

BEGIN { $TYPEINFO{ReadDatabaseList} = ["function", ["list", [ "map", "string", "string"]] ]; }
sub ReadDatabaseList {
    my $self = shift;
    
    my $dbList = SCR->Read('.ldapserver.databases');
    if(! defined $dbList) {
        my $err = SCR->Error(".ldapserver");
        $err->{'code'} = "SCR_READ_FAILED";
        return $self->SetError(%{$err});
    }
    return $dbList;
}

=item *
C<$bool = AddDatabase(\%valueMap)>

Creates a new database section in the configuration file,
start or restart the LDAP Server and add the base object.
If the database exists, nothing is done and undef is returned. 

Supported keys in %valueMap are:
 
 * type: The database type (required)
 
 * suffix: The suffix (required)
 
 * directory: The Directory where the database files are(bdb/ldbm) (required)

 * createdatabasedir: If true the directory for the database will be created (optional; default false)

 * rootdn: The Root DN 
 
 * rootpw: The hashed RootDN Password (requires rootdn)

 * rootpw_clear: The plain Root Password (requires rootdn)

 * cryptmethod: The crypt method; allowed values are (CRYPT, SMD5, SHA, SSHA, PLAIN); default is 'SSHA'
 
 * entrycache: The cachesize (optional; default 10000)
 
 * idlcache: The cachesize (optional; default 10000)
 
 * checkpoint: The bdb checkpoint setting as an array reference (optional; default [1024, 5])

If no rootdn and passwd is set, the base object is not added to the
LDAP server.

EXAMPLE:

 my $hash = {
             database     => 'bdb',
             suffix       => 'dc=example,dc=com',
             rootdn       => "cn=Admin,dc=example,dc=com",
             rootpw_clear => "system",
             cryptmethod  => 'SMD5',
             directory    => "/var/lib/ldap/db1",
            };

 my $res = YaPI::LdapServer->AddDatabase($hash);
 if( not defined $res ) {
     # error
 } else {
     print "OK: \n";
 }

=cut

BEGIN { $TYPEINFO{AddDatabase} = ["function", "boolean", ["map", "string", "any"]]; }
sub AddDatabase {
    my $self = shift;
    my $data = shift;

    my $entrycache    = undef;
    my $idlcache      = undef;
    my $checkpoint    = undef;
    my $addDBHash = {};

    my $cryptMethod = "SSHA";

    y2debug("YaPI::LdapServer.pm AddDatabase: ".Data::Dumper->Dump([$data]));
    ################
    # check database
    ################
    if(!defined $data->{type} || $data->{type} eq "") {
                                          # error message at parameter check
        return $self->SetError(summary => "Missing parameter 'database'",
                               code => "PARAM_CHECK_FAILED");
    }
    if ( !grep( ($_ eq $data->{type}), ("bdb", "hdb") ) ) {
        return $self->SetError(summary => sprintf(
                                   # error at paramter check
                                 __("Database type '%s' is not supported. Allowed are 'bdb' and 'hdb'."),
                                                  $data->{type}),
                               code => "PARAM_CHECK_FAILED");
    }
    $addDBHash->{type} = $data->{type};

    ################
    # check suffix
    ################
    if(!defined $data->{suffix} || $data->{suffix} eq "") {
        return $self->SetError(summary => "Missing parameter 'suffix'",
                               code => "PARAM_CHECK_FAILED");
    }

    my $object = X500::DN->ParseRFC2253($data->{suffix});

    if(! defined $object) {
        # parameter check failed
        return $self->SetError(summary => "Invalid parameter 'suffix'",
                               description => "suffix '$data->{suffix}' is not allowed",
                               code => "PARAM_CHECK_FAILED");
    }

    my @attr = $object->getRDN($object->getRDNs()-1)->getAttributeTypes();
    my $val = $object->getRDN($object->getRDNs()-1)->getAttributeValue($attr[0]);
    
    if(!defined $attr[0] || !defined $val) {
        return $self->SetError(summary => "Can not parse 'suffix'",
                               description => "Parsing error for suffix '".$data->{suffix}."'",
                               code => "PARSE_ERROR");
    }
    my $entry = {};
    
    if( lc($attr[0]) eq "ou") {
        $entry = {
                  "objectClass" => [ "organizationalUnit" ],
                  "ou" => $val,
                 }
    } elsif( lc($attr[0]) eq "o") {
        $entry = {
                  "objectClass" => [ "organization" ],
                  "o" => $val,
                 }
    } elsif( lc($attr[0]) eq "c") {
        if($val !~ /^\w{2}$/) {
                                   # parameter check failed
            return $self->SetError(summary => __("The countryName must be an ISO-3166 country 2-letter code."),
                                   description => "Invalid value for 'c' ($val)",
                                   code => "PARAM_CHECK_FAILED");
        }
        $entry = {
                  "objectClass" => [ "country" ],
                  "c" => $val,
                 }
    } elsif( lc($attr[0]) eq "l") {
        $entry = {
                  "objectClass" => [ "locality" ],
                  "l" => $val,
                 }
    } elsif( lc($attr[0]) eq "st") {
        $entry = {
                  "objectClass" => [ "locality" ],
                  "st" => $val,
                 }
    } elsif( lc($attr[0]) eq "dc") {
        $entry = {
                  "objectClass" => [ "organization", "dcObject" ],
                  "dc" => $val,
                  "o"  => $val,
                 }
    } else {
                               # parameter check failed
        return $self->SetError(summary => __("First part of suffix must be c=, st=, l=, o=, ou= or dc=."),
                               code => "PARAM_CHECK_FAILED");
    }
    $addDBHash->{suffix} = $data->{suffix};
    
    ##############
    # check rootdn
    ##############
    
    if(exists $data->{rootdn}) {
        if(!defined $data->{rootdn} || $data->{rootdn} eq "") {
            # parameter check failed
            return $self->SetError(summary => "Missing parameter 'rootdn'",
                                   code => "PARAM_CHECK_FAILED");
        }
        
        if(! defined X500::DN->ParseRFC2253($data->{rootdn})) {
        # parameter check failed
            return $self->SetError(summary => __("Invalid 'rootdn'."),
                                   description => "rootdn '$data->{rootdn}' is not allowed.",
                                   code => "PARAM_CHECK_FAILED");
        }

        if($data->{suffix} ne substr($data->{rootdn}, 
                                     length($data->{rootdn}) - length($data->{suffix}))) {
            
            # parameter check failed
            return $self->SetError(summary => __("'rootdn' must be below the 'suffix'."),
                                   description => "'$data->{rootdn}' must be below the '$data->{suffix}'",
                                   code => "PARAM_CHECK_FAILED");
        }
        $addDBHash->{rootdn} = $data->{rootdn};
    }
    
    ##############################
    # check passwd and cryptmethod
    ##############################
       
    if(exists $data->{rootpw}) {
        
        if(!exists $addDBHash->{rootdn} || $addDBHash->{rootdn} eq "") {
            # parameter check failed
            return $self->SetError(summary => __("To set a password, you must define 'rootdn'."),
                                   code => "PARAM_CHECK_FAILED");
        }
        
        if( (!defined $data->{rootpw} || $data->{rootpw} eq "") && 
            (!defined $data->{rootpw_clear} || $data->{rootpw_clear} eq "" ) ){
            # parameter check failed
            return $self->SetError(summary => __("Define 'rootpw'."),
                                   code => "PARAM_CHECK_FAILED");
        }

	if( (! defined $data->{rootpw} || $data->{rootpw} eq "") && 
	    ( defined $data->{rootpw_clear} && $data->{rootpw_clear} ne "") ) {

            if(defined $data->{cryptmethod} && $data->{cryptmethod} ne "") {
                $cryptMethod = $data->{cryptmethod};
            }
            if( !grep( ($_ eq $cryptMethod), ("CRYPT", "SMD5", "SHA", "SSHA", "PLAIN") ) ) {
                return $self->SetError(summary => sprintf(
                                                          # parameter check failed
                                                          __("'%s' is an unsupported crypt method."),
                                                          $cryptMethod),
                                       code => "PARAM_CHECK_FAILED");
            }
            my $passwd_string = "";
            
            if( $cryptMethod eq "CRYPT" ) {
                my $salt =  pack("C2",(int(rand 26)+65),(int(rand 26)+65));
                $passwd_string = crypt $data->{rootpw_clear},$salt;
                $passwd_string = "{crypt}".$passwd_string;
            } elsif( $cryptMethod eq "SMD5" ) {
                my $salt =  pack("C5",(int(rand 26)+65),(int(rand 26)+65),(int(rand 26)+65),
                                 (int(rand 26)+65), (int(rand 26)+65));
                my $ctx = new Digest::MD5();
                $ctx->add($data->{rootpw_clear});
                $ctx->add($salt);
                $passwd_string = "{smd5}".encode_base64($ctx->digest.$salt, "");
            } elsif( $cryptMethod eq "SHA"){
                my $digest = sha1($data->{rootpw_clear});
                $passwd_string = "{sha}".encode_base64($digest, "");
            } elsif( $cryptMethod eq "SSHA"){
                my $salt =  pack("C5",(int(rand 26)+65),(int(rand 26)+65),(int(rand 26)+65),
                                 (int(rand 26)+65), (int(rand 26)+65));
                my $digest = sha1($data->{rootpw_clear}.$salt);
                $passwd_string = "{ssha}".encode_base64($digest.$salt, "");
            } else {
                $passwd_string = $data->{rootpw_clear};
            }
            $addDBHash->{rootpw} = $passwd_string;
        } else {
            $addDBHash->{rootpw} = $data->{rootpw};
        }
    }
    
    #################
    # check directory
    #################
    
    if(!defined $data->{directory} || $data->{directory} eq "") {
                               # parameter check failed
        return $self->SetError(summary => __("Define 'directory'."),
                               code => "PARAM_CHECK_FAILED");
    }
    if( ! defined  SCR->Read(".target.dir", $data->{directory})) {
                               # parameter check failed
        if ( defined $data->{createdatabasedir} && $data->{createdatabasedir} == 1 ) {
            my $ret = SCR->Execute(".target.bash", 
                           "mkdir -m 0700 -p ".$data->{directory});
            if( ( $ret ) && ( ! defined  SCR->Read(".target.dir", $data->{directory}) ) ) {
                return $self->SetError(summary => __("Could not create directory."),
                               description => "The 'directory' (".$data->{directory}.") could not be created.",
                               code => "DIR_NOT_CREATED");
            }
        } else {
            return $self->SetError(summary => __("The directory does not exist."),
                               description => "The 'directory' (".$data->{directory}.") does not exist.",
                               code => "DIR_DOES_NOT_EXIST");
        }
    }
    my $owner = SCR->Read('.sysconfig.openldap.OPENLDAP_USER');
    my $group = SCR->Read('.sysconfig.openldap.OPENLDAP_GROUP');
    if ( SCR->Execute(".target.bash", "chown ".$owner.":".$group." ".$data->{directory}) )
    {
        return $self->SetError( summary => _("Could not adjust ownership of database directory."),
                                description => "",
                                code => "DIR_CHOWN_FAILED" );
    }

    $addDBHash->{directory} = $data->{directory};

    ##################
    # check cachesizes
    ##################
    if(defined $data->{entrycache} && $data->{entrycache} ne "") {

        if($data->{entrycache} !~ /^\d+$/) {
            return $self->SetError(summary => __("Invalid cache size value."),
                                   description => "entrycache = '".$data->{entrycache}."'. Must be a integer value",
                                   code => "PARAM_CHECK_FAILED");
        }
        $entrycache = $data->{entrycache};
    }
    if(! exists $data->{entrycache}) {
        # set default if parameter does not exist
        $entrycache = 10000;
    }
    $addDBHash->{entrycache} = YaST::YCP::Integer($entrycache);
    
    if(defined $data->{idlcache} && $data->{idlcache} ne "") {

        if($data->{idlcache} !~ /^\d+$/) {
            return $self->SetError(summary => __("Invalid cache size value."),
                                   description => "idlcache = '".$data->{idlcache}."'. Must be a integer value",
                                   code => "PARAM_CHECK_FAILED");
        }
        $idlcache = $data->{idlcache};
    }
    if(! exists $data->{idlcache}) {
        # set default if parameter does not exist
        $idlcache = 10000;
    }
    $addDBHash->{idlcache} = YaST::YCP::Integer($idlcache);

    
    if( ($data->{type} eq "bdb") && ($data->{type} eq "hdb" ) ){
        ##################
        # check checkpoint
        ##################
        if(defined $data->{checkpoint} && (scalar($data->{checkpoint}) != 2) ) {
            my @cp = @{$data->{checkpoint} };
            if(!defined $cp[0] || !defined $cp[1] ||
               $cp[0] !~ /^\d+$/ || $cp[1] !~ /^\d+$/) {
                return $self->SetError(summary => __("Invalid checkpoint value."),
                                       description => "checkpoint = '".$data->{checkpoint}."'.\n Must be two integer values seperated by space.",
                                       code => "PARAM_CHECK_FAILED");
            }
            $checkpoint = $data->{checkpoint};
        }
        if(! exists $data->{checkpoint}) {
            # set default if parameter does not exist
            $checkpoint = ["1024,  5"];
        }
        $addDBHash->{checkpoint} = [ YaST::YCP::Integer($checkpoint->[0]), YaST::YCP::Integer( $checkpoint->[1] ) ];
    }
#    if ( exists $data->{'overlay'} ){
#        $addDBHash->{'overlay'} = $data->{'overlay'};
#    }

    if(SCR->Read(".target.size", $addDBHash->{directory}."/DB_CONFIG") < 0) {
        my $DB_CONFIG = "set_cachesize 0 15000000 1\n".
                        "set_lg_bsize 2097152\n".
                        "set_lg_regionmax 262144\n".
                        "set_flags DB_LOG_AUTOREMOVE\n";

        if(! SCR->Write(".target.string", $addDBHash->{directory}."/DB_CONFIG", $DB_CONFIG)) {
            return $self->SetError(summary => "Can not create DB_CONFIG file.",
                                   code => "SCR_WRITE_FAILED");
        }
    }

    if ( ! SCR->Write(".ldapserver.database.new.", $addDBHash ) )
    {
        my $err = SCR->Error(".ldapserver");
        $err->{'code'} = "SCR_WRITE_FAILED";
        return $self->SetError(%{$err});
    }

    if(! SCR->Execute(".ldapserver.commitChanges") ) {
        my $err = SCR->Error(".ldapserver");
        $err->{'code'} = "SCR_EXECUTE_FAILED";
        return $self->SetError(%{$err});
    }

    # do not add the base entry, if we have nothing to bind with.
    if((exists $data->{rootdn} && exists $data->{passwd}) && 
       (defined $data->{passwd} && $data->{passwd} ne "") ){
    
        if(! SCR->Execute(".ldap", {"hostname" => 'localhost',
                                    "port"     => 389})) {
            return $self->SetError(summary => "LDAP init failed",
                                   code => "SCR_INIT_FAILED");
        }
        
        my $success = 0;
        my $ldapERR;
        
        for(my $i = 0; $i < 5; $i++) {
            # after the LDAP server is started, it takes some time if
            # a bind is possible. So try it 5 times with a sleep. 
            
            if (! SCR->Execute(".ldap.bind", {"bind_dn" => $data->{'rootdn'},
                                              "bind_pw" => $data->{'passwd'}}) ) {
                $ldapERR = SCR->Read(".ldap.error");
            } else {
                $success = 1;
                last;
            }
            sleep(1);
        }
        
        if(!$success) {
            return $self->SetError(summary => "LDAP bind failed",
                                   code => "SCR_INIT_FAILED",
                                   description => $ldapERR->{'code'}." : ".$ldapERR->{'msg'});
        }
        
        if (! SCR->Write(".ldap.add", { dn => $data->{'suffix'} } , $entry)) {
            my $ldapERR = SCR->Read(".ldap.error");
            return $self->SetError(summary => "Can not add base entry.",
                                   code => "LDAP_ADD_FAILED",
                                   description => $ldapERR->{'code'}." : ".$ldapERR->{'msg'});
        }
        y2debug("base entry added");
    } else {
        y2debug("no base entry added");
    }
    
    return 1;
}

=item *
C<$bool = EditDatabase($suffix,\%valueMap)>

Edit the database section with the suffix B<$suffix> in the configuration file.
Only save parameter are supported. 

You have to restart the LDAP Server with YaPI::LdapServer->SwitchService(1)
to activate these changes. 

Supported keys in %valueMap are:
 
 * rootdn: The Root DN
 
 * rootpw: The Root Password

 * rootpw_clear: The cleartext Root Password
 
 * cryptmethod: The crypt method; allowed values are (CRYPT, SMD5, SHA, SSHA, PLAIN); default is 'SSHA'

If a key is not defined, the option is not changed.
If the key is defined and a value is specified, this value will be set.

If you delete rootdn, rootpw is also deleted.

EXAMPLE:

 my $hash = { suffix      => "dc=example,dc=com",
              rootdn      => "cn=Administrator,dc=example,dc=com",
              rootpw      => "example",
              cryptmethod => "CRYPT"
            };

 my $res = YaPI::LdapServer->EditDatabase($hash);
 if( not defined $res ) {
     # error
 } else {
     print "OK: \n";
 }

=cut

BEGIN { $TYPEINFO{EditDatabase} = ["function", "boolean", "string", ["map", "string", "any"]]; }
sub EditDatabase {
    my $self   = shift;
    my $suffix = shift;
    my $data   = shift;
    my $cryptMethod = undef;
    my $passwd_string = undef;
    my $editHash = {};

    if(!defined $suffix || $suffix eq "") {
        return $self->SetError(summary => "Missing parameter 'suffix'",
                               code => "PARAM_CHECK_FAILED");
    }
    
    if(! defined $data || ref($data) ne "HASH") {
        return $self->SetError(summary => "Missing 'data'",
                               code => "PARAM_CHECK_FAILED");
    }
    y2milestone("YaPI::LdapServer.pm EditDatabase: $suffix: ".Data::Dumper->Dump([$data]));

    # check if database exists and find index
    my $dblist = $self->ReadDatabaseList();
    y2milestone("EditDatabase: ".Data::Dumper->Dump([$dblist]));
    my $index = -2;

    foreach my $db (@{$dblist})
    {
        if ( $db->{'suffix'} eq $suffix)
        {
            $index = $db->{'index'};
        }
    }

    if ( $index <= 0 )
    {
        return $self->SetError(summary => "Database does not exist",
                               code => "DATABASE_NOT_FOUND");
    }

    ###################
    # work on rootdn
    ###################
    if(exists $data->{rootdn} && ! defined $data->{rootdn}) {

        $editHash->{rootdn} = undef;
        $data->{rootpw} = undef;        # delete also passwd

    } elsif(exists $data->{rootdn}) {
        if(! defined X500::DN->ParseRFC2253($data->{rootdn})) {
        # parameter check failed
            return $self->SetError(summary => __("Invalid 'rootdn'."),
                                   description => "rootdn '$data->{rootdn}' is not allowed.",
                                   code => "PARAM_CHECK_FAILED");
        }
        if($suffix ne substr($data->{rootdn}, 
                             length($data->{rootdn}) - length($suffix))) {

            # parameter check failed
            return $self->SetError(summary => __("'rootdn' must be below the 'suffix'."),
                                   description => "'$data->{rootdn}' must be below the '$suffix'",
                                   code => "PARAM_CHECK_FAILED");
        } else {
            $editHash->{rootdn} = $data->{rootdn};
        }
    }

    ###################
    # work on passwd
    ###################
    if(exists $data->{rootpw} && ! defined $data->{rootpw}) {
        $editHash->{rootpw} = undef;
    } elsif ( exists $data->{rootpw} && defined $data->{rootpw} && $data->{rootpw} ne "" ) {
        $editHash->{rootpw} = $data->{rootpw};
    } elsif(exists $data->{rootpw_clear}) {

        if(!defined $data->{rootpw_clear} || $data->{rootpw_clear} eq "") {
                                               # parameter check failed
            return $self->SetError(summary => __("Define 'passwd'."),
                                   code => "PARAM_CHECK_FAILED");
        }
        if(!defined $data->{rootpw_clear} || $data->{rootpw_clear} eq "") {
                                   # parameter check failed
            return $self->SetError(summary => __("Define 'passwd'."),
                                   code => "PARAM_CHECK_FAILED");
        }

        if(defined $data->{cryptmethod} && $data->{cryptmethod} ne "") {
            $cryptMethod = $data->{cryptmethod};
        }
        if( !grep( ($_ eq $cryptMethod), ("CRYPT", "SMD5", "SHA", "SSHA", "PLAIN") ) ) {
            return $self->SetError(summary => sprintf(
                                                      # parameter check failed
                                                      __("'%s' is an unsupported crypt method."),
                                                      $cryptMethod),
                                   code => "PARAM_CHECK_FAILED");
        }

        if( $cryptMethod eq "CRYPT" ) {
            my $salt =  pack("C2",(int(rand 26)+65),(int(rand 26)+65));
            $passwd_string = crypt $data->{rootpw_clear},$salt;
            $passwd_string = "{crypt}".$passwd_string;
        } elsif( $cryptMethod eq "SMD5" ) {
            my $salt =  pack("C5",(int(rand 26)+65),(int(rand 26)+65),(int(rand 26)+65),
                             (int(rand 26)+65), (int(rand 26)+65));
            my $ctx = new Digest::MD5();
            $ctx->add($data->{rootpw_clear});
            $ctx->add($salt);
            $passwd_string = "{smd5}".encode_base64($ctx->digest.$salt, "");
        } elsif( $cryptMethod eq "SHA"){
            my $digest = sha1($data->{rootpw_clear});
            $passwd_string = "{sha}".encode_base64($digest, "");
        } elsif( $cryptMethod eq "SSHA"){
            my $salt =  pack("C5",(int(rand 26)+65),(int(rand 26)+65),(int(rand 26)+65),
                             (int(rand 26)+65), (int(rand 26)+65));
            my $digest = sha1($data->{rootpw_clear}.$salt);
            $passwd_string = "{ssha}".encode_base64($digest.$salt, "");
        } else {
            $passwd_string = $data->{rootpw_clear};
        }
        # set new rootpw
        
        $editHash->{rootpw} = $passwd_string;
    }

    y2debug("YaPI::EditDatabase ". Data::Dumper->Dump([$data]) );
    y2debug("YaPI::EditDatabase edithash: ". Data::Dumper->Dump([$editHash]) );
    if(! SCR->Write(".ldapserver.database.{$index}" , $editHash)) {
        my $err = SCR->Error(".ldapserver");
        $err->{description} = $err->{summary}."\n\n".$err->{description};
        $err->{summary} = __("Database edit failed.");
        $err->{code} = "SCR_WRITE_FAILED";
        return $self->SetError(%{$err});
    }
    if(! SCR->Execute(".ldapserver.commitChanges") ) {
        my $err = SCR->Error(".ldapserver");
        $err->{'code'} = "SCR_EXECUTE_FAILED";
        return $self->SetError(%{$err});
    }

    return 1;
}

=item *
C<\%valueMap = ReadDatabase($suffix)>

Read the database section with the suffix B<$suffix>. 

Returned keys in %valueMap are:
 
 * type: The database type
 
 * suffix: The suffix
 
 * rootdn: The Root DN
 
 * rootpw: The Root Password Hash
 
 * directory: The Directory where the database files are (bdb/hdb)
 
 * entrycache: The size of the entrycache
 
 * idlcache: The size of the idlcache

 * checkpoint: The checkpoint setting (A reference to a list see
   AddDatabase()
 
There can be some more, depending on the database's configuration

EXAMPLE:

 use Data::Dumper;

 my $res = YaPI::LdapServer->ReadDatabase('"dc=example,dc=com"');
 if( not defined $res ) {
     # error
 } else {
     print "OK: \n";
     print STDERR Data::Dumper->Dump([$res])."\n";
 }

=cut

BEGIN { $TYPEINFO{ReadDatabase} = ["function", ["map", "string", "any"], "string"]; }
sub ReadDatabase {
    my $self = shift;
    my $suffix = shift;

    if(! defined $suffix || $suffix eq "") {
                                          # error message at parameter check
        return $self->SetError(summary => __("Missing parameter 'suffix'."),
                               code => "PARAM_CHECK_FAILED");
    }
    # check if database exists and find index
    my $dblist = $self->ReadDatabaseList();
    my $index = -2;
    my $type = "";

    foreach my $db (@{$dblist})
    {
        if ( $db->{'suffix'} eq $suffix)
        {
            $index = $db->{'index'};
            $type = $db->{'type'};
        }
    }

    if ( $index <= 0 )
    {
        return $self->SetError(summary => "Database does not exist",
                               code => "DATABASE_NOT_FOUND");
    }

    my $dbHash = SCR->Read( ".ldapserver.database.{$index}" );
    if(! defined $dbHash) {
        my $err = SCR->Error(".ldapserver");
        $err->{'code'} = "SCR_READ_FAILED";
        return $self->SetError(%{$err});
    }
    $dbHash->{'type'} = $type;
    return $dbHash;
}

=item *
C<\@indexList = ReadIndex($suffix)>

Returns a Map of Maps with all defined indexes for a database. The keys of
the outer Map are LDAP Attribute Type (e.g. 'objectClass'), the keys in the
inner Maps are booleans for the specific type of indexes.

 {
   'objectClass' => {
                      'eq' => 1
                    },
   'cn' => {
             'sub' => 1,
             'pres' => 1,
             'eq' => 1
           }
 }

EXAMPLE:

 use Data::Dumper;

 my $res = YaPI::LdapServer->ReadIndex('"dc=example,dc=com"');
 if( not defined $res ) {
     # error
 } else {
     print "OK: \n";
     print STDERR Data::Dumper->Dump([$res])."\n";
 }

=cut

BEGIN { $TYPEINFO{ReadIndex} = ["function", ["list", ["map", "string", "string"] ], "string"]; }
sub ReadIndex {
    my $self = shift;
    my $suffix = shift;
    y2milestone("YaPI::LdapServer->ReadIndex()");

    if(! defined $suffix || $suffix eq "") {
                                          # error message at parameter check
        return $self->SetError(summary => __("Missing parameter 'suffix'."),
                               code => "PARAM_CHECK_FAILED");
    }
    my $dblist = $self->ReadDatabaseList();
    my $index = -2;

    foreach my $db (@{$dblist})
    {
        if ( $db->{'suffix'} eq $suffix)
        {
            $index = $db->{'index'};
        }
    }
    
    if ( $index <= 0 )
    {
        return $self->SetError(summary => "Database does not exist",
                               code => "DATABASE_NOT_FOUND");
    }

    my $idxList = SCR->Read( ".ldapserver.database.{$index}.indexes" );

    return $idxList;
}

=item *
C<$bool = EditIndex($suffix,\%indexMap)>

Add/or change the indexing of a single AttributeType.

The indexMap has up to four keys

 * 'name', A single AttributeType

 * 'eq', A boolean to indicate whether an equality index should be created 

 * 'sub', A boolean to indicate whether a substring index should be created 

 * 'pres', A boolean to indicate whether a presence index should be created 

EXAMPLE:

 my $newIndex = {
                 'name'  => "uid",
                 'eq' => 1,
                 'pres' => 1,
                 'sub' => 0
                };

 my $res = YaPI::LdapServer->EditIndex("dc=example,dc=com", $newIndex);
 if( not defined $res ) {
     # error
 } else {
     print "OK: \n";
 }

=cut

BEGIN { $TYPEINFO{EditIndex} = ["function", "boolean", "string", [ "map", "string", "any"] ]; }
sub EditIndex {
    my $self = shift;
    my $suffix = shift;
    my $indexHash = shift;
    my $orig_idxArray = undef;
    my @new_idx = ();

    y2milestone("YaPI::LdapServer->EditIndex()");
    if(!defined $suffix || $suffix eq "") {
        return $self->SetError(summary => "Missing parameter 'suffix'",
                               code => "PARAM_CHECK_FAILED");
    }
    if(!defined $indexHash || !defined $indexHash->{name} ) {
        return $self->SetError(summary => "Missing parameter 'index'",
                               code => "PARAM_CHECK_FAILED");
    }
    
    my $dblist = $self->ReadDatabaseList();
    my $index = -2;

    foreach my $db (@{$dblist})
    {
        if ( $db->{'suffix'} eq $suffix)
        {
            $index = $db->{'index'};
        }
    }
    
    if ( $index <= 0 )
    {
        return $self->SetError(summary => "Database does not exist",
                               code => "DATABASE_NOT_FOUND");
    }

    $indexHash->{'pres'} = YaST::YCP::Boolean($indexHash->{'pres'});
    $indexHash->{'eq'} = YaST::YCP::Boolean($indexHash->{'eq'});
    $indexHash->{'sub'} = YaST::YCP::Boolean($indexHash->{'sub'});
    if(! SCR->Write(".ldapserver.database.{$index}.index", $indexHash) ) {
        my $err = SCR->Error(".ldapserver");
        $err->{'code'} = "SCR_WRITE_FAILED";
        return $self->SetError(%{$err});
    }
    if(! SCR->Execute(".ldapserver.commitChanges") ) {
        my $err = SCR->Error(".ldapserver");
        $err->{'code'} = "SCR_EXECUTE_FAILED";
        return $self->SetError(%{$err});
    }
    return 1;
}

=item *
C<\@aclList = ReadAcl($suffix)>

 Read ACLs of a Database

 The return value is a list of maps defining the ACLs. The maps  
 has the following structure:

  {
      'target' => {
              # a Map defining the target objects of this ACL
              # can contain any or multiple keys of the following
              # types
              'attrs'  => [ <list of attributetypes> ],
              'filter' => <LDAP filter string>,
              'dn' => {
                      'style' => <'base' or 'subtree'>
                      'value' => <LDAP DN>
                  }
          },
      'access' => [
              # a list of maps defining the access level of different
              # indentities, each map looks like this:
              'level' => <'none'|'disclose'|'auth'|'compare'|'read'|'write'|'manage'>,
              'type'  => <'self'|'users'|'anoymous'|'*'|'group'|'dn.base'|'dn.subtree'>
              # if type is 'group', 'dn.base', 'dn.subtree':
              'value'    => <a valid LDAP DN>
          ]

  }

=cut
BEGIN { $TYPEINFO{ReadAcl} = ["function", ["list", ["map", "string", "any"] ], "string"]; }
sub ReadAcl {
    my $self = shift;
    my $suffix = shift;

    if(! defined $suffix || $suffix eq "") {
                                          # error message at parameter check
        return $self->SetError(summary => __("Missing parameter 'suffix'."),
                               code => "PARAM_CHECK_FAILED");
    }
    my $dblist = $self->ReadDatabaseList();
    my $index = -2;

    foreach my $db (@{$dblist})
    {
        if ( $db->{'suffix'} eq $suffix)
        {
            $index = $db->{'index'};
        }
    }
    
    if ( $index <= 0 )
    {
        return $self->SetError(summary => "Database does not exist",
                               code => "DATABASE_NOT_FOUND");
    }

    my $aclList = SCR->Read( ".ldapserver.database.{$index}.acl" );
    y2milestone("YAPI acllist: ".Data::Dumper->Dump([$aclList]));

    return $aclList;
}

=item *
C<$bool = WriteAcl($suffix,\@aclList)>

 Update the ACLs of a Database, all exiting ACLs of that Database are overwritten.

 The aclList parameter must have the same structure as documented for the
 ReadAcl function above.

=cut
BEGIN { $TYPEINFO{WriteAcl} = ["function", "boolean", "string", ["list", ["map", "string", "any"] ]]; }
sub WriteAcl {
    my $self = shift;
    my $suffix = shift;
    my $aclList = shift;

    if(! defined $suffix || $suffix eq "") {
                                          # error message at parameter check
        return $self->SetError(summary => __("Missing parameter 'suffix'."),
                               code => "PARAM_CHECK_FAILED");
    }
    my $dblist = $self->ReadDatabaseList();
    my $index = -2;

    foreach my $db (@{$dblist})
    {
        if ( $db->{'suffix'} eq $suffix)
        {
            $index = $db->{'index'};
        }
    }
    
    if ( $index <= 0 )
    {
        return $self->SetError(summary => "Database does not exist",
                               code => "DATABASE_NOT_FOUND");
    }

    if(! SCR->Write( ".ldapserver.database.{$index}.acl", $aclList ) ) {
        my $err = SCR->Error(".ldapserver");
        $err->{'code'} = "SCR_WRITE_FAILED";
        return $self->SetError(%{$err});
    }
    if(! SCR->Execute(".ldapserver.commitChanges") ) {
        my $err = SCR->Error(".ldapserver");
        $err->{'code'} = "SCR_EXECUTE_FAILED";
        return $self->SetError(%{$err});
    }

    return 1;
}

=item *
C<\@list = ReadSchemaList()>

Returns a list of all included schemas items

EXAMPLE:

 use Data::Dumper;

 my $res = YaPI::LdapServer->ReadSchemaList();
 if( not defined $res ) {
     # error
 } else {
     print "OK: \n";
     print STDERR Data::Dumper->Dump([$res])."\n";
 }

=cut

BEGIN { $TYPEINFO{ReadSchemaList} = ["function", ["list", "string"] ]; }
sub ReadSchemaList {
    my $self = shift;

    my $schemaList = SCR->Read( ".ldapserver.schemaList" );
    if(! defined $schemaList) {
        my $err = SCR->Error(".ldapserver");
        $err->{'code'} = "SCR_READ_FAILED";
        $self->SetError(%{$err});
        return undef;
    }
    return $schemaList;
}

=item *
C<$bool = AddSchema($file)>

Adds an additional schema item. $file is the absolute pathname of the file
to add.  It can either be in .schema or LDIF format.

EXAMPLE:

 my $res = YaPI::LdapServer->AddSchema("/etc/openldap/schema/ppolicy.schema");
 if( not defined $res ) {
     # error
 } else {
     print "OK: \n";
 }

=cut

BEGIN { $TYPEINFO{AddSchema} = ["function", "boolean", "string" ]; }
sub AddSchema {
    my $self = shift;
    my $file = shift;

    if(!defined $file || $file eq "" ) {
        return $self->SetError(summary => "File name is missing",
                               code => "PARAM_CHECK_FAILED");
    }
    
    my $ret = 0;

    if ( $file =~ /.schema$/ )
    {
        $ret = SCR->Write(".ldapserver.schema.addFromSchemafile", $file );
    }
    elsif ( $file =~ /.ldif$/ )
    {
        $ret = SCR->Write(".ldapserver.schema.addFromLdif", $file );
    }
    else
    {
        return $self->SetError(summary => "File format not supported",
                               code => "SCHEMA_UNKNOWN_FORMAT");
    }

    if (! $ret ) {
        my $err = SCR->Error(".ldapserver");
        $err->{'code'} = "SCR_EXECUTE_FAILED";
        return $self->SetError(%{$err});
    }
    if(! SCR->Execute(".ldapserver.commitChanges") ) {
        my $err = SCR->Error(".ldapserver");
        $err->{'code'} = "SCR_EXECUTE_FAILED";
        return $self->SetError(%{$err});
    }
    return 1;
}

=item *
C<\@list = ReadAllowList()>

Returns a list of allow statements. 

EXAMPLE:

 use Data::Dumper;

 my $res = YaPI::LdapServer->ReadAllowList();
 if( not defined $res ) {
     # error
 } else {
     print "OK: \n";
     print STDERR Data::Dumper->Dump([$res])."\n";
 }

=cut

BEGIN { $TYPEINFO{ReadAllowList} = ["function", ["list", "string"] ]; }
sub ReadAllowList {
    my $self = shift;
    my @allowList = ();

    my $global = SCR->Read( ".ldapserver.global" );
    if(! defined $global) {
        return $self->SetError(%{SCR->Error(".ldapserver")});
    }
    if(exists $global->{allow} && defined $global->{allow}) {
        
        foreach my $value (split(/\s+/, $global->{allow})) {
            next if( $value eq "");
            $value =~ s/\s+/ /sg;
            $value =~ s/\s+$//;
            next if( $value eq "");
            push @allowList, $value;
        }
    }
    return \@allowList;
}

=item *
C<$bool = WriteAllowList(\@list)>

Replaces the complete allow option with the specified feature list.

You have to restart the LDAP Server with YaPI::LdapServer->SwitchService(1)
to activate these changes. 

EXAMPLE:

 my @list = ( "bind_v2" );

 $res = YaPI::LdapServer->WriteAllowList( \@list );
 if( not defined $res ) {
     # error
 } else {
     print "OK: \n";
 }

=cut

BEGIN { $TYPEINFO{WriteAllowList} = ["function", "boolean", [ "list", "string"] ]; }
sub WriteAllowList {
    my $self = shift;
    my $allowList = shift;

    if(!defined $allowList || ref($allowList) ne "ARRAY") {
        return $self->SetError(summary => "'Allow list' is missing",
                               code => "PARAM_CHECK_FAILED");
    }
    
    if(scalar @$allowList == 0) {
        if(!SCR->Write(".ldapserver.global", { allow => undef })) {
            return $self->SetError(%{SCR->Error(".ldapserver")});
        }
    } else {
        if(!SCR->Write(".ldapserver.global", { allow => join( " ", @$allowList ) })) {
            return $self->SetError(%{SCR->Error(".ldapserver")});
        }
    }
    return 1;
}

=item *
C<$loglevel = ReadLoglevel()>

Read the loglevel bitmask.

EXAMPLE:

 my $res = YaPI::LdapServer->ReadLoglevel();
 if( not defined $res ) {

 } else {
     print "OK: \n";
     print STDERR Data::Dumper->Dump([$res])."\n";
 }

=cut

BEGIN { $TYPEINFO{ReadLoglevel} = ["function", "integer" ]; }
sub ReadLoglevel {
    my $self = shift;
    my $loglevel = 0;

    my $global = SCR->Read( ".ldapserver.global" );
    if(! defined $global) {
        return $self->SetError(%{SCR->Error(".ldapserver")});
    }
    if(exists $global->{loglevel} && defined $global->{loglevel} && $global->{loglevel} ne "" ) {
        
        $loglevel = $global->{loglevel};
        
    }
    return $loglevel;
}

=item *
C<$bool = AddLoglevel($bit)>

Set the given loglevel bit to 1 in the current bitmask.

You have to restart the LDAP Server with YaPI::LdapServer->SwitchService(1)
to activate these changes. 

EXAMPLE:

 my $res = YaPI::LdapServer->AddLoglevel( 0x04 );
 if( not defined $res ) {
     # error
 } else {
     print "OK: \n";
 }

=cut

BEGIN { $TYPEINFO{AddLoglevel} = ["function", "boolean", "integer" ]; }
sub AddLoglevel {
    my $self = shift;
    my $bit  = shift;
 
    if(!defined $bit || $bit !~ /^\d+$/) {
        return $self->SetError(summary => "Wrong parameter 'bit'",
                               code => "PARAM_CHECK_FAILED");
    }
    
    my $loglevel = $self->ReadLoglevel();
    return undef if(!defined $loglevel);
    
    $loglevel = $loglevel | $bit;
    
    my $ret = $self->WriteLoglevel($loglevel);
    return undef if(!defined $loglevel);
    
    return 1;
}

=item *
C<$bool = DeleteLoglevel($bit)>

Set the given loglevel bit to 0 in the current bitmask.

You have to restart the LDAP Server with YaPI::LdapServer->SwitchService(1)
to activate these changes. 

EXAMPLE:

 my $res = YaPI::LdapServer->DeleteLoglevel( 0x04 );
 if( not defined $res ) {

 } else {
     print "OK: \n";
 }

=cut

BEGIN { $TYPEINFO{DeleteLoglevel} = ["function", "boolean", "integer" ]; }
sub DeleteLoglevel {
    my $self = shift;
    my $bit  = shift;
 
    if(!defined $bit || $bit !~ /^\d+$/) {
        return $self->SetError(summary => "Wrong parameter 'bit'",
                               code => "PARAM_CHECK_FAILED");
    }
    
    my $loglevel = $self->ReadLoglevel();
    return undef if(!defined $loglevel);
    
    $loglevel = ( $loglevel & (~ $bit) );
    
    my $ret = $self->WriteLoglevel($loglevel);
    return undef if(!defined $loglevel);
    
    return 1;
}

=item *
C<$bool = WriteLoglevel($loglevel)>

Replaces the loglevel bitmask. 

You have to restart the LDAP Server with YaPI::LdapServer->SwitchService(1)
to activate these changes. 

EXAMPLE:

 my $res = YaPI::LdapServer->WriteLoglevel( 0x06 );
 if( not defined $res ) {

 } else {
     print "OK: \n";
 }

=cut

BEGIN { $TYPEINFO{WriteLoglevel} = ["function", "boolean", "integer" ]; }
sub WriteLoglevel {
    my $self = shift;
    my $loglevel = shift;

    if(!defined $loglevel || $loglevel !~ /^\d+$/) {
        return $self->SetError(summary => "Wrong parameter 'loglevel'",
                               code => "PARAM_CHECK_FAILED");
    }

    if(! SCR->Write(".ldapserver.global", { loglevel => $loglevel } )) {
        return $self->SetError(%{SCR->Error(".ldapserver")});
    }
    return 1;
}

=item *
C<ModifyService($status)>

with this function you can turn on and off the LDAP server
runlevel script.
Turning off means, no LDAP server start at boot time.

EXAMPLE

 ModifyService(0); # turn LDAP server off at boot time
 ModifyService(1); # turn LDAP server on at boot time

=cut

BEGIN { $TYPEINFO{ModifyService} = ["function", "boolean", "boolean" ]; }
sub ModifyService {
    my $self = shift;
    my $enable = shift;

    if( $enable ) {
        Service->Adjust( "slapd", "enable" );
    } else {
        Service->Adjust( "slapd", "disable" );
    }
    return 1;
}

=item *
C<SwitchService($status)>

with this function you can start and stop the LDAP server
service.

EXAMPLE

 SwitchService( 0 ); # turning off the LDAP server service
 SwitchService( 1 ); # turning on the LDAP server service

=cut

sub SwitchService {
    my $self = shift;
    my $enable = shift;
    my $ret = undef;

    if( $enable ) {
        $ret = Service->RunInitScript( "slapd", "restart");
        if(! defined $ret || $ret != 0) {
            return $self->SetError(summary => __("Cannot restart the service."),
                                   description => "LDAP restart failed ($ret)",
                                   code => "SERVICE_RESTART_FAILED");
        }
    } else {
        $ret = Service->RunInitScript( "slapd", "stop" );
        if(! defined $ret || $ret != 0) {
            return $self->SetError(summary => __("Cannot stop the service."),
                                   description => "LDAP stop failed ($ret)",
                                   code => "SERVICE_STOP_FAILED");
        }
    }
    return 1;
}

=item *
C<$status = ReadService()>

with this function you can read out the state of the
LDAP server runlevel script (starting LDAP server at boot time).

EXAMPLE

 print "LDAP is ".( (ReadService())?('on'):('off') )."\n";

=cut
BEGIN { $TYPEINFO{ReadService} = ["function", "boolean"]; }
sub ReadService {
    my $self = shift;
    return Service->Enabled('slapd');
}

=item *
C<\%valueMap = ReadTLS()>

Return the current TLS settings

Supported keys in %valueMap are:
 
 * TLSCipherSuite: cipher suite parameter
 
 * TLSCACertificateFile: Specifies the file that contains certificates for all of the Certificate Authorities that slapd will recognize.

 * TLSCACertificatePath: Specifies  the path of a directory that contains Certificate Authority certificates in separate individual files. Usually only one of this or the TLSCACertificateFile is used.

 * TLSCertificateFile: Specifies the file that contains the slapd server certificate.

 * TLSCertificateKeyFile: Specifies the file that contains the slapd server private key.

 * TLSVerifyClient: Specifies what checks to perform on client certificates in an incoming TLS session.

EXAMPLE:

 use Data::Dumper;

 my $res = YaPI::LdapServer->ReadTLS();
 if( not defined $res ) {
     # error
 } else {
     print "OK: \n";
     print STDERR Data::Dumper->Dump([$res])."\n";
 }

=cut

BEGIN { $TYPEINFO{ReadTLS} = ["function", ["map", "string", "any"]]; }
sub ReadTLS {
    my $self  = shift;
    my $ret   = {};

    my $global = SCR->Read( ".ldapserver.global" );
    if(! defined $global) {
        return $self->SetError(%{SCR->Error(".ldapserver")});
    }
    if(exists $global->{TLSCipherSuite} && defined $global->{TLSCipherSuite}) {
        $ret->{TLSCipherSuite} = $global->{TLSCipherSuite};
    }
    if(exists $global->{TLSCACertificateFile} && defined $global->{TLSCACertificateFile}) {
        $ret->{TLSCACertificateFile} = $global->{TLSCACertificateFile};
    }
    if(exists $global->{TLSCACertificatePath} && defined $global->{TLSCACertificatePath}) {
        $ret->{TLSCACertificatePath} = $global->{TLSCACertificatePath};
    }
    if(exists $global->{TLSCertificateFile} && defined $global->{TLSCertificateFile}) {
        $ret->{TLSCertificateFile} = $global->{TLSCertificateFile};
    }
    if(exists $global->{TLSCertificateKeyFile} && defined $global->{TLSCertificateKeyFile}) {
        $ret->{TLSCertificateKeyFile} = $global->{TLSCertificateKeyFile};
    }
    if(exists $global->{TLSVerifyClient} && defined $global->{TLSVerifyClient}) {
        $ret->{TLSVerifyClient} = $global->{TLSVerifyClient};
    }

    return $ret;
}


=item *
C<$bool = WriteTLS(\%valueMap)>

Edit the TLS options in the configuration file.

You have to restart the LDAP Server with YaPI::LdapServer->SwitchService(1)
to activate these changes. 

Supported keys in %valueMap are:
 
 * TLSCipherSuite: cipher suite parameter
 
 * TLSCACertificateFile: Specifies the file that contains certificates for all of the Certificate Authorities that slapd will recognize.

 * TLSCACertificatePath: Specifies  the path of a directory that contains Certificate Authority certificates in separate individual files. Usually only one of this or the TLSCACertificateFile is used.

 * TLSCertificateFile: Specifies the file that contains the slapd server certificate.

 * TLSCertificateKeyFile: Specifies the file that contains the slapd server private key.

 * TLSVerifyClient: Specifies what checks to perform on client certificates in an incoming TLS session.


If the key is defined, but the value is 'undef' the option will be deleted.
If a key is not defined, the option is not changed.
If the key is defined and a value is specified, this value will be set.

EXAMPLE:

 my $hash = {
             TLSCipherSuite        => "HIGH:MEDIUM:+SSLv2",
             TLSCertificateFile    => "/etc/ssl/server_crt.pem",
             TLSCertificateKeyFile => "/etc/ssl/server_key.pem",
             TLSCACertificateFile  => "/etc/ssl/ca.pem",
             TLSVerifyClient       => "never"
            };

 my $res = YaPI::LdapServer->WriteTLS($hash);
 if( not defined $res ) {
     # error
 } else {
     print "OK: \n";
 }

=cut

BEGIN { $TYPEINFO{WriteTLS} = ["function", "boolean", ["map", "string", "any"]]; }
sub WriteTLS {
    my $self  = shift;
    my $data  = shift;
    my $hash  = {};

    if(exists $data->{TLSCipherSuite}) {
        if(!defined $data->{TLSCipherSuite}) {
            
            $hash->{TLSCipherSuite} = undef;
            
        } else {

            $hash->{TLSCipherSuite} = $data->{TLSCipherSuite};

        }
    }

    if(exists $data->{TLSCACertificateFile}) {

        if(!defined $data->{TLSCACertificateFile}) {
            $hash->{TLSCACertificateFile} = undef;
        } else {
            if(-e  $data->{TLSCACertificateFile}) {
                $hash->{TLSCACertificateFile} = $data->{TLSCACertificateFile};
            } else {
                # error message
                return $self->SetError(summary => __("CA certificate file does not exist."),
                                       code => "PARAM_CHECK_FAILED");
            }
        }
    }
    
    if(exists $data->{TLSCACertificatePath}) {
        if(!defined $data->{TLSCACertificatePath}) {
            
            $hash->{TLSCACertificatePath} = undef;
            
        } else {
            if(-d  $data->{TLSCACertificatePath}) {
                $hash->{TLSCACertificatePath} = $data->{TLSCACertificatePath};
            } else {
                # error message
                return $self->SetError(summary => __("CA certificate path does not exist."),
                                       code => "PARAM_CHECK_FAILED");
            }
        }
    }

    if(exists $data->{TLSCertificateFile}) {
        if(!defined $data->{TLSCertificateFile}) {

            $hash->{TLSCertificateFile} = undef;

        } else {
            if(-e  $data->{TLSCertificateFile}) {
                $hash->{TLSCertificateFile} = $data->{TLSCertificateFile};
            } else {
                # error message
                return $self->SetError(summary => __("Certificate file does not exist."),
                                       code => "PARAM_CHECK_FAILED");
            }
        }
    }


    if(exists $data->{TLSCertificateKeyFile}) {
        if(!defined $data->{TLSCertificateKeyFile}) {

            $hash->{TLSCertificateKeyFile} = undef;

        } else {
            if(-e  $data->{TLSCertificateFile}) {
                $hash->{TLSCertificateKeyFile} = $data->{TLSCertificateKeyFile};
            } else {
                # error message
                return $self->SetError(summary => __("Certificate key file does not exist."),
                                       code => "PARAM_CHECK_FAILED");
            }
        }
    }
    
    if(exists $data->{TLSVerifyClient}) {
        if(!defined $data->{TLSVerifyClient}) {

            $hash->{TLSVerifyClient} = undef;

        } else {
            if( grep( ($_ eq $data->{TLSVerifyClient}), ("never", "allow", "try",
                                                         "demand","hard", "true")))
            {
                $hash->{TLSVerifyClient} = $data->{TLSVerifyClient};
            } else {
                # error message
                return $self->SetError(summary => __("Invalid value for 'TLSVerifyClient'."),
                                       code => "PARAM_CHECK_FAILED");
            }
        }
    }

    if(! SCR->Write(".ldapserver.global", $hash )) {
        my $err = SCR->Error(".ldapserver");
        $err->{description} = $err->{summary}."\n\n".$err->{description};
        $err->{summary} = __("Writing failed.");
        return $self->SetError(%{$err});
    }
    
    return 1;
}

=item *
C<$bool = CheckCommonServerCertificate()>

Check, if a server certificate is available which can be used
for more then one service. Such common certificate is saved at
'/etc/ssl/servercerts/servercert.pem'.

This function returns 'true' if such a certificate is available
and 'false' if not.

EXAMPLE:

 my $res = YaPI::LdapServer->CheckCommonServerCertificate();
 if( not defined $res ) {
     # error
 } else {
     print "Available \n" if($res);
     print "Not Avalable \n" if(!res);
 }

=cut

BEGIN { $TYPEINFO{CheckCommonServerCertificate} = ["function", "boolean"]; }
sub CheckCommonServerCertificate {
    my $self  = shift;

    my $size = SCR->Read(".target.size", '/etc/ssl/servercerts/servercert.pem');
    if ($size <= 0) {
        return 0;
    }
    $size = SCR->Read(".target.size", '/etc/ssl/servercerts/serverkey.pem');
    if ($size <= 0) {
        return 0;
    }
    return 1;
}

=item *
C<$bool = ConfigureCommonServerCertificate()>

Configure the LDAP server to use the common server certificate.

At first this function try to set read permissions for user ldap
on the common private key via filesystem acls. After that it 
modifies the slapd.conf and add/edit the TLS pararamter.

You have to restart the LDAP Server with YaPI::LdapServer->SwitchService(1)
to activate these changes. 

EXAMPLE:

 my $res = YaPI::LdapServer->ConfigureCommonServerCertificate();
 if( not defined $res ) {
     # error
 } else {
     print "OK: \n";
 }

=cut

BEGIN { $TYPEINFO{ConfigureCommonServerCertificate} = ["function", "boolean"]; }
sub ConfigureCommonServerCertificate {
    my $self  = shift;

    my $size = SCR->Read(".target.size", '/etc/ssl/servercerts/servercert.pem');
    if ($size <= 0) {
        return $self->SetError(summary => "Common server certificate not found.",
                               code => "PARAM_CHECK_FAILED");
    }
    $size = SCR->Read(".target.size", '/etc/ssl/servercerts/serverkey.pem');
    if ($size <= 0) {
        return $self->SetError(summary => "Common private key not found.",
                               code => "PARAM_CHECK_FAILED");
    }

    my $tlsHash = $self->ReadTLS();
    return undef if(! defined $tlsHash);

    $tlsHash->{TLSCertificateFile}    = '/etc/ssl/servercerts/servercert.pem';
    $tlsHash->{TLSCertificateKeyFile} = '/etc/ssl/servercerts/serverkey.pem';

    if(SCR->Read(".target.size", '/etc/pki/trust/anchors/YaST-CA.pem') > 0) {
        $tlsHash->{TLSCACertificatePath} = '/etc/ssl/certs/';
        $tlsHash->{TLSCACertificateFile} = undef;
    }
    
    # try to set read acl on the keyfile for user ldap
    my $ret = SCR->Execute(".target.bash", 
                           "/usr/bin/setfacl -m u:ldap:r /etc/ssl/servercerts/serverkey.pem");
    if($ret != 0) {
        return $self->SetError(summary => "Can not set a filesystem acl on the private key",
                               description => "setfacl -m u:ldap:r /etc/ssl/servercerts/serverkey.pem failed.\n".
                               "Do you have filesystem acl support disabled?",
                               code => "SCR_EXECUTE_ERROR");
    }

    # configure TLS
    if(! defined $self->WriteTLS($tlsHash)) {
        return undef;
    }
    
    return 1;
}

=item *
C<$bool = ImportCertificates(\%valueMap)>

Import certificates and configure TLS for the LDAP Server.

The following Keys are possible in %valueMap:

* ServerCertificateFile (required)

* ServerKeyFile (required)

* CACertificatesFile (optional)

The file format must be PEM.

Alternative you can send the PEM data direct via:

* ServerCertificateData (required)

* ServerKeyData (required)

* CACertificatesData (optional)

The return value is 'true' on success and 'undef' on an error.

EXAMPLE:

 my $hash = {
              ServerCertificateFile => '/path/to/the/certificate.pem',
              ServerKeyFile         => '/path/to/the/key.pem',
              CACertificatesFile    => '/path/to/the/CAcertificate.pem',
            }

 my $res = YaPI::LdapServer->ImportCertificates($hash);
 if( not defined $res ) {
     # error
 } else {
     print "OK: \n";
 }

=cut

BEGIN { $TYPEINFO{ImportCertificates} = ["function", "boolean", ["map", "string", "string"]]; }
sub ImportCertificates {
    my $self = shift;
    my $data = shift;
    my $cert = "";
    my $key  = "";
    my $CA   = undef;

    # check ServerCertificateFile/Data
    if(exists $data->{ServerCertificateFile}) {

        if(! defined $data->{ServerCertificateFile} || $data->{ServerCertificateFile} eq "") {
            return $self->SetError(summary => __("Missing 'ServerCertificateFile' parameter."),
                                   code => "PARAM_CHECK_FAILED");
        }

        $cert = SCR->Read(".target.string", $data->{ServerCertificateFile});
        if(not defined $cert || !$cert) {
            return $self->SetError(summary => __("Cannot read certificate file."),
                                   code => "PARAM_CHECK_FAILED");
        }
    } else {
        if(! defined $data->{ServerCertificateData} || $data->{ServerCertificateData} eq "") {
            return $self->SetError(summary => __("Missing 'ServerCertificateData' parameter."),
                                   code => "PARAM_CHECK_FAILED");
        }
        $cert = $data->{ServerCertificateData};
    }

    if($cert !~ /BEGIN CERTIFICATE/ ) {
        return $self->SetError( summary => __("Corrupt PEM data."), code => 'CERT_ERROR' );
    }

    # check ServerKeyFile
    if(exists $data->{ServerKeyFile}) {

        if(! defined $data->{ServerKeyFile} || $data->{ServerKeyFile} eq "") {
            return $self->SetError(summary => __("Missing 'ServerKeyFile' parameter."),
                                   code => "PARAM_CHECK_FAILED");
        }

        $key = SCR->Read(".target.string", $data->{ServerKeyFile});
        if(not defined $key || !$key) {
            return $self->SetError(summary => __("Cannot read key file."),
                                   code => "PARAM_CHECK_FAILED");
        }
    } else {
        if(! defined $data->{ServerKeyData} || $data->{ServerKeyData} eq "") {
            return $self->SetError(summary => __("Missing 'ServerKeyData' parameter."),
                                   code => "PARAM_CHECK_FAILED");
        }
        $key = $data->{ServerKeyData};
    }
    
    if($key !~ /PRIVATE KEY/ ) {
        return $self->SetError( summary => __("Corrupt PEM data."), code => 'CERT_ERROR' );
    }


    if(exists $data->{CACertificatesFile} && 
       defined $data->{CACertificatesFile} && 
       $data->{CACertificatesFile} ne "") 
      {
       
          $CA = SCR->Read(".target.string", $data->{CACertificatesFile});
          if(not defined $CA || !$CA) {
              return $self->SetError(summary => __("Cannot read CA certificate file."),
                                     code => "PARAM_CHECK_FAILED");
          }
          
          if($CA !~ /BEGIN CERTIFICATE/ ) {
              return $self->SetError( summary => __("Corrupt PEM data."), code => 'CERT_ERROR' );
          }
      } elsif(exists $data->{CACertificatesData} && 
              defined $data->{CACertificatesData} && 
              $data->{CACertificatesData} ne "") 
        {
            $CA = $data->{CACertificatesData};
            
            if($CA !~ /BEGIN CERTIFICATE/ ) {
                return $self->SetError( summary => __("Corrupt PEM data."), code => 'CERT_ERROR' );
            }
        }
    

    my $tlsHash = $self->ReadTLS();
    return undef if(! defined $tlsHash);
    
    if(! SCR->Write('.target.string', '/etc/openldap/servercert.pem', $cert)) {
        return $self->SetError(summary => __("Cannot write certificate file."),
                               code => "SCR_WRITE_FAILED");
    }
    $tlsHash->{TLSCertificateFile}    = '/etc/openldap/servercert.pem';

    if(!SCR->Write('.target.string', '/etc/openldap/serverkey.pem', $key)) {
        return $self->SetError(summary => __("Cannot write key file."),
                               code => "SCR_WRITE_FAILED");
    }
    my $ret = SCR->Execute(".target.bash", 
                           "chmod 0600 /etc/openldap/serverkey.pem");
    if($ret != 0) {
        return $self->SetError(summary => "Can not chmod to '/etc/openldap/serverkey.pem'",
                               code => "SCR_EXECUTE_FAILED");
    }
    $ret = SCR->Execute(".target.bash", 
                           "chown ldap.root /etc/openldap/serverkey.pem");
    if($ret != 0) {
        return $self->SetError(summary => "Can not chown to '/etc/openldap/serverkey.pem'",
                               code => "SCR_EXECUTE_FAILED");
    }
    $tlsHash->{TLSCertificateKeyFile} = '/etc/openldap/serverkey.pem';
        
    if(defined $CA) {
        if(!SCR->Write('.target.string', '/etc/openldap/cacert.pem', $CA)) {
            return $self->SetError(summary => __("Cannot write CA certificate file."),
                                   code => "SCR_WRITE_FAILED");
        }
        $tlsHash->{TLSCACertificateFile} = '/etc/openldap/cacert.pem';
    }

    # configure TLS
    if(! defined $self->WriteTLS($tlsHash)) {
        return undef;
    }
}


=item *
C<$bool = ReadSLPEnabled()>

This function reads the OPENLDAP_REGISTER_SLP entry in /etc/sysconfig/openldap.
It returns 'true' if it reads 'yes' and 'false' if it reads 'no'.

EXAMPLE

 print "SLP registering is ".( (ReadSLPEnabled())?('activated'):('deactivated') )."\n";

=cut
BEGIN { $TYPEINFO{ReadSLPEnabled} = ["function", "boolean"]; }
sub ReadSLPEnabled
{
    my $self = shift;
    my $slp_enabled = SCR->Read( ".sysconfig.openldap.OPENLDAP_REGISTER_SLP" );

    if( !$slp_enabled )
    {
        return $self->SetError( summary => "Failed to read .sysconfig.openldap.OPENLDAP_REGISTER_SLP",
                                code    => "SCR_READ_FAILED" );
    }
    
    return 1 if( lc( $slp_enabled ) eq "yes" );
    return 0;
}

=item *
C<$bool = WriteSLPEnabled( $bool )>

This function sets OPENLDAP_REGISTER_SLP in /etc/sysconfig/openldap.
The entry is set to 'yes' if the argument is true or 'no' if the argument is false.

The return value is true on success, undef on error.

EXAMPLE

  WriteSLPEnabled( 1 );

=cut
BEGIN { $TYPEINFO{WriteSLPEnabled} = ["function", "boolean", "boolean"]; }
sub WriteSLPEnabled
{
    my $self = shift;
    my $activate_slp = shift;
    
    my $scr_string = "";
    if( $activate_slp )
    {
        $scr_string = "yes";
    } else 
    {
        $scr_string = "no";
    }

    if( !SCR->Write( ".sysconfig.openldap.OPENLDAP_REGISTER_SLP", $scr_string ) )
    {
        return $self->SetError( summary => "Failed to write .sysconfig.openldap.OPENLDAP_REGISTER_SLP",
                                code    => "SCR_WRITE_FAILED" );
    }
    return 1;
}

1;
