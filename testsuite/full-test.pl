#! /usr/bin/perl -w 

BEGIN {
    push @INC, '/usr/share/YaST2/modules/';
}

use strict;
use YaST::YCP;
use ycp;
use Data::Dumper;
use YaPI::LdapServer;

my $pwd = $ENV{'PWD'};
print "$pwd\n";
exit 1 if (!defined $pwd || $pwd eq "");

my $new_database = 'o=Müller GmbH & Co/KG,c=DE';

sub printError {
    my $err = shift;
    foreach my $k (keys %$err) {
        print STDERR "$k = ".$err->{$k}."\n";
    }
    print STDERR "\n";
    exit 1;
}

sub init_testsetup {

    if( -d "/$pwd/testout") {
        system("rm -r /$pwd/testout");
    }
    mkdir("/$pwd/testout", 0755);
    open(STDERR, ">> /$pwd/testout/YaST2-LdapServer-fulltest-OUTPUT.log");

#    if( -d '/var/lib/ldap/SuSE_Test_DB') {
#        unlink </var/lib/ldap/SuSE_Test_DB/*>;
#        open(SLAPD, "< /etc/openldap/slapd.conf") or die "can not read slapdconf: $!";
#        my @lines = <SLAPD>;
#        close SLAPD;
#        if(grep( ($_ =~ /dc=example,dc=com/), @lines )) {
#            print "Please remove the test DB section from slapd.conf\n";
#            print "and restart the ldapserver.\n";
#            exit 1;
#        }
#    } else {
#        mkdir("/var/lib/ldap/SuSE_Test_DB", 0755);
#    }
}

sub T01_Interface {

    print STDERR "------------------- T01_Interface ---------------------\n";
    print "------------------- T01_Interface ---------------------\n";
    my $res = YaPI::LdapServer->Interface();
    if( not defined $res ) {
        my $msg = YaPI::LdapServer->Error();
        printError($msg);
    } else {
        print "OK:\n";
        print STDERR Data::Dumper->Dump($res)."\n";
    }
}

sub T02_Version {
    print STDERR "------------------- T02_Version ---------------------\n";
    print "------------------- T02_Version ---------------------\n";
    my $res = YaPI::LdapServer->Version();
    if( not defined $res ) {
        my $msg = YaPI::LdapServer->Error();
        printError($msg);
    } else {
        print "OK:\n";
        print STDERR Data::Dumper->Dump([$res])."\n";
    }
}

sub T03_Capabilities {
    print STDERR "------------------- T03_Capabilities ---------------------\n";
    print "------------------- T03_Capabilities ---------------------\n";
    foreach my $cap ("SLES9", "USER") {
        my $res = YaPI::LdapServer->Supports($cap);
        if( not defined $res ) {
            my $msg = YaPI::LdapServer->Error();
            printError($msg);
        } else {
            print "OK: test CAP = $cap\n";
            print STDERR Data::Dumper->Dump([$res])."\n";
        }
    }
}

sub T04_ReadDatabaseList {
    print STDERR "------------------- T04_ReadDatabaseList ---------------------\n";
    print "------------------- T04_ReadDatabaseList ---------------------\n";

    my $res = YaPI::LdapServer->ReadDatabaseList();
    if( not defined $res ) {
        my $msg = YaPI::LdapServer->Error();
        printError($msg);
    } else {
        print "OK: \n";
        print STDERR Data::Dumper->Dump([$res])."\n";
    }
}

sub T05_ReadDatabase {
    print STDERR "------------------- T05_ReadDatabase ---------------------\n";
    print "------------------- T05_ReadDatabase ---------------------\n";

    my $res = YaPI::LdapServer->ReadDatabase($new_database);
    if( not defined $res ) {
        my $msg = YaPI::LdapServer->Error();
        printError($msg);
    } else {
        print "OK: \n";
        print STDERR Data::Dumper->Dump([$res])."\n";
    }
}

sub T06_ReadIndex {
    print STDERR "------------------- T06_ReadIndex ---------------------\n";
    print "------------------- T06_ReadIndex ---------------------\n";

    my $res = YaPI::LdapServer->ReadIndex("dc=site");
    if( not defined $res ) {
        my $msg = YaPI::LdapServer->Error();
        printError($msg);
    } else {
        print "OK: \n";
        print STDERR Data::Dumper->Dump([$res])."\n";
    }
}

sub T07_ReadSchemaList {
    print STDERR "------------------- T07_ReadSchemaList ---------------------\n";
    print "------------------- T07_ReadSchemaList ---------------------\n";

    my $res = YaPI::LdapServer->ReadSchemaList();
    if( not defined $res ) {
        my $msg = YaPI::LdapServer->Error();
        printError($msg);
    } else {
        print "OK: \n";
        print STDERR Data::Dumper->Dump([$res])."\n";
    }
}

sub T08_ReadAllowList {
    print STDERR "------------------- T08_ReadAllowList ---------------------\n";
    print "------------------- T08_ReadAllowList ---------------------\n";

    my $res = YaPI::LdapServer->ReadAllowList();
    if( not defined $res ) {
        my $msg = YaPI::LdapServer->Error();
        printError($msg);
    } else {
        print "OK: \n";
        print STDERR Data::Dumper->Dump([$res])."\n";
    }
}

sub T09_AddDatabase {
    print STDERR "------------------- T09_AddDatabase ---------------------\n";
    print "------------------- T09_AddDatabase ---------------------\n";

    my $hash = {
                type    => 'bdb',
                suffix      => "$new_database",
                rootdn      => 'cn=Admin,'."$new_database",
                rootpw_clear      => "system",
                cryptmethod => 'SMD5',
                directory   => "/var/lib/ldap/SuSE_Test_DB",
                createdatabasedir => 1 
               };

    my $res = YaPI::LdapServer->AddDatabase($hash);
    if( not defined $res ) {
        my $msg = YaPI::LdapServer->Error();
        printError($msg);
    } else {
        print "OK: \n";
        print STDERR Data::Dumper->Dump([$res])."\n";
    }
}

sub T10_EditDatabase {
    print STDERR "------------------- T10_EditDatabase ---------------------\n";
    print "------------------- T10_EditDatabase ---------------------\n";

    my $suffix = "dc=does_not_exists";
    my $hash = {
                rootdn  => 'cn=Administrator,'."$suffix",
               };

    my $res = YaPI::LdapServer->EditDatabase($suffix, $hash);
    if( not defined $res ) {
        my $msg = YaPI::LdapServer->Error();
        print "OK: \n";
        print STDERR Data::Dumper->Dump([$msg])."\n";
    } else {
        print "FAILED: \n";
        printError("This test should return an error");
    }

    $suffix = $new_database;
    $hash = {
                rootdn  => 'cn=Administrator,'."$suffix",
               };

    $res = YaPI::LdapServer->EditDatabase($suffix, $hash);
    if( not defined $res ) {
        my $msg = YaPI::LdapServer->Error();
        printError($msg);
    } else {
        print "OK: \n";
        print STDERR Data::Dumper->Dump([$res])."\n";
    }

    $hash = { 
              rootpw_clear  => "tralla",
              cryptmethod => "CRYPT"
            };

    $res = YaPI::LdapServer->EditDatabase($suffix, $hash);
    if( not defined $res ) {
        my $msg = YaPI::LdapServer->Error();
        printError($msg);
    } else {
        print "OK: \n";
        print STDERR Data::Dumper->Dump([$res])."\n";
    }

#    $hash = { 
#              cachesize  => "20000",
#            };
#
#    $res = YaPI::LdapServer->EditDatabase($suffix, $hash);
#    if( not defined $res ) {
#        my $msg = YaPI::LdapServer->Error();
#        printError($msg);
#    } else {
#        print "OK: \n";
#        print STDERR Data::Dumper->Dump([$res])."\n";
#    }
#
#    $hash = { 
#              checkpoint  => "2048 10",
#            };
#    
#    $res = YaPI::LdapServer->EditDatabase($suffix, $hash);
#    if( not defined $res ) {
#        my $msg = YaPI::LdapServer->Error();
#        printError($msg);
#    } else {
#        print "OK: \n";
#        print STDERR Data::Dumper->Dump([$res])."\n";
#    }
}

sub T11_EditIndex {
    print STDERR "------------------- T11_AddIndex ---------------------\n";
    print "------------------- T11_AddIndex ---------------------\n";

    my $res = YaPI::LdapServer->EditIndex("$new_database", { "name" => "uid", "eq" => 1, "pres" => 0});
    if( not defined $res ) {
        my $msg = YaPI::LdapServer->Error();
        printError($msg);
    } else {
        print "OK: \n";
        print STDERR Data::Dumper->Dump([$res])."\n";
    }
    $res = YaPI::LdapServer->EditIndex("$new_database", { "name" => "cn", "eq" => 1, "pres" => 0});
    if( not defined $res ) {
        my $msg = YaPI::LdapServer->Error();
        printError($msg);
    } else {
        print "OK: \n";
        print STDERR Data::Dumper->Dump([$res])."\n";
    }
}


sub T13_DeleteIndex {
    print STDERR "------------------- T13_DeleteIndex ---------------------\n";
    print "------------------- T13_DeleteIndex ---------------------\n";
    
    my $res = YaPI::LdapServer->DeleteIndex("$new_database", "590775aeaa1fce858a7a214faa21ca07");
    if( not defined $res ) {
        my $msg = YaPI::LdapServer->Error();
        printError($msg);
    } else {
        print "OK: \n";
        print STDERR Data::Dumper->Dump([$res])."\n";
    }
}

sub T15_AddSchema {
    print STDERR "------------------- T15_AddSchema ---------------------\n";
    print "------------------- T15_AddSchema ---------------------\n";

    my $schemas = '/etc/openldap/schema/ppolicy.schema';

    my $res = YaPI::LdapServer->AddSchema($schemas);
    if( not defined $res ) {
        my $msg = YaPI::LdapServer->Error();
        printError($msg);
    } else {
        print "OK: \n";
        print STDERR Data::Dumper->Dump([$res])."\n";
    }
}

sub T16_WriteAllowList {
    print STDERR "------------------- T16_WriteAllowList ---------------------\n";
    print "------------------- T16_WriteAllowList ---------------------\n";
    
    my @list = ();
    
    my $res = YaPI::LdapServer->WriteAllowList( \@list );
    if( not defined $res ) {
        my $msg = YaPI::LdapServer->Error();
        printError($msg);
    } else {
        print "OK: \n";
        print STDERR Data::Dumper->Dump([$res])."\n";
    }

    push @list, "bind_v2";

    $res = YaPI::LdapServer->WriteAllowList( \@list );
    if( not defined $res ) {
        my $msg = YaPI::LdapServer->Error();
        printError($msg);
    } else {
        print "OK: \n";
        print STDERR Data::Dumper->Dump([$res])."\n";
    }
}

sub T17_AddLoglevel {
    print STDERR "------------------- T17_AddLoglevel ---------------------\n";
    print "------------------- T17_AddLoglevel ---------------------\n";

    my $res = YaPI::LdapServer->AddLoglevel( 0x04 );
    if( not defined $res ) {
        my $msg = YaPI::LdapServer->Error();
        printError($msg);
    } else {
        print "OK: \n";
        print STDERR Data::Dumper->Dump([$res])."\n";
    }
}

sub T18_DeleteLoglevel {
    print STDERR "------------------- T18_DeleteLoglevel ---------------------\n";
    print "------------------- T18_DeleteLoglevel ---------------------\n";

    my $res = YaPI::LdapServer->DeleteLoglevel( 0x04 );
    if( not defined $res ) {
        my $msg = YaPI::LdapServer->Error();
        printError($msg);
    } else {
        print "OK: \n";
        print STDERR Data::Dumper->Dump([$res])."\n";
    }

}

sub T19_WriteLoglevel {
    print STDERR "------------------- T19_WriteLoglevel ---------------------\n";
    print "------------------- T19_WriteLoglevel ---------------------\n";

    my $res = YaPI::LdapServer->WriteLoglevel( 0x06 );
    if( not defined $res ) {
        my $msg = YaPI::LdapServer->Error();
        printError($msg);
    } else {
        print "OK: \n";
        print STDERR Data::Dumper->Dump([$res])."\n";
    }
}

sub T20_ReadLoglevel {
    print STDERR "------------------- T20_ReadLoglevel ---------------------\n";
    print "------------------- T20_ReadLoglevel ---------------------\n";

    my $res = YaPI::LdapServer->ReadLoglevel();
    if( not defined $res ) {
        my $msg = YaPI::LdapServer->Error();
        printError($msg);
    } else {
        print "OK: \n";
        print STDERR Data::Dumper->Dump([$res])."\n";
    }
}

sub T21_ReadTLS {
    print STDERR "------------------- T21_ReadTLS ---------------------\n";
    print "------------------- T21_ReadTLS ---------------------\n";

    my $res = YaPI::LdapServer->ReadTLS();
    if( not defined $res ) {
        my $msg = YaPI::LdapServer->Error();
        printError($msg);
    } else {
        print "OK: \n";
        print STDERR Data::Dumper->Dump([$res])."\n";
    }
}

sub T22_WriteTLS {
    print STDERR "------------------- T22_WriteTLS ---------------------\n";
    print "------------------- T22_WriteTLS ---------------------\n";

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
        my $msg = YaPI::LdapServer->Error();
        printError($msg);
    } else {
        print "OK: \n";
        print STDERR Data::Dumper->Dump([$res])."\n";
    }
}

sub T23_ReadIndex2() {
    print STDERR "------------------- T23_ReadIndex2 ---------------------\n";
    print "------------------- T23_ReadIndex2 ---------------------\n";

    my $res = YaPI::LdapServer->ReadIndex($new_database);
    if( not defined $res ) {
        my $msg = YaPI::LdapServer->Error();
        printError($msg);
    } else {
        print "OK: \n";
        print STDERR Data::Dumper->Dump([$res])."\n";
    }
}

sub T35_ReadDatabase2 {
    print STDERR "------------------- T35_ReadDatabase2 ---------------------\n";
    print "------------------- T35_ReadDatabase2 ---------------------\n";

    my $res = YaPI::LdapServer->ReadDatabase("$new_database");
    if( not defined $res ) {
        my $msg = YaPI::LdapServer->Error();
        printError($msg);
    } else {
        print "OK: \n";
        print STDERR Data::Dumper->Dump([$res])."\n";
    }
}

sub T36_ReadIndex2 {
    print STDERR "------------------- T36_ReadIndex2 ---------------------\n";
    print "------------------- T36_ReadIndex2 ---------------------\n";

    my $res = YaPI::LdapServer->ReadIndex("$new_database");
    if( not defined $res ) {
        my $msg = YaPI::LdapServer->Error();
        printError($msg);
    } else {
        print "OK: \n";
        print STDERR Data::Dumper->Dump([$res])."\n";
    }
}

sub T37_CheckCommonServerCertificate {
    print STDERR "------------------- T37_CheckCommonServerCertificate ---------------------\n";
    print "------------------- T37_CheckCommonServerCertificate ---------------------\n";

    my $res = YaPI::LdapServer->CheckCommonServerCertificate();
    if( not defined $res ) {
        my $msg = YaPI::LdapServer->Error();
        printError($msg);
    } else {
        print "OK: \n";
        print STDERR Data::Dumper->Dump([$res])."\n";
    }
}

sub T38_ConfigureCommonServerCertificate {
    print STDERR "------------------- T38_ConfigureCommonServerCertificate ---------------------\n";
    print "------------------- T38_ConfigureCommonServerCertificate ---------------------\n";

    my $res = YaPI::LdapServer->ConfigureCommonServerCertificate();
    if( not defined $res ) {
        my $msg = YaPI::LdapServer->Error();
        printError($msg);
    } else {
        print "OK: \n";
        print STDERR Data::Dumper->Dump([$res])."\n";
    }
}

sub T39_ReadSLPEnabled
{
    print STDERR "------------------- T39_ReadSLPEnabled ---------------------\n";
    print "------------------- T39_ReadSLPEnabled ---------------------\n";

    my $res = YaPI::LdapServer->ReadSLPEnabled();
    if( not defined $res ) {
        my $msg = YaPI::LdapServer->Error();
        printError($msg);
    } else {
        print "OK: \n";
        print STDERR Data::Dumper->Dump([$res])."\n";
    }
}

sub T40_WriteSLPEnabled
{
    print STDERR "------------------- T40_WriteSLPEnabled ---------------------\n";
    print "------------------- T40_WriteSLPEnabled ---------------------\n";

    my $res = YaPI::LdapServer->WriteSLPEnabled( 1 );
    if( not defined $res ) {
        my $msg = YaPI::LdapServer->Error();
        printError($msg);
    } else {
        print "OK: \n";
        print STDERR Data::Dumper->Dump([$res])."\n";
    }
}

init_testsetup();

T39_ReadSLPEnabled();
T40_WriteSLPEnabled();
exit;
#
#T01_Interface();
#T02_Version();
#T03_Capabilities();
T04_ReadDatabaseList();
T06_ReadIndex();
T07_ReadSchemaList();
#T08_ReadAllowList();
#T21_ReadTLS();
#T09_AddDatabase();
T10_EditDatabase();
T05_ReadDatabase();
T11_EditIndex();
T23_ReadIndex2();
#T12_EditIndex();
#T23_ReadIndex2();
#T13_DeleteIndex();
T15_AddSchema();
T07_ReadSchemaList();
#T16_WriteAllowList();
#T17_AddLoglevel();
#T18_DeleteLoglevel();
#T19_WriteLoglevel();
#T20_ReadLoglevel();
#T22_WriteTLS();
#
#T04_ReadDatabaseList();
#T35_ReadDatabase2();
#T36_ReadIndex2();
#T07_ReadSchemaIncludeList();
#T08_ReadAllowList();
#T21_ReadTLS();
#
#T37_CheckCommonServerCertificate();
#T38_ConfigureCommonServerCertificate();
#T21_ReadTLS();
#
#T39_ReadSLPEnabled();
#T40_WriteSLPEnabled();
   
