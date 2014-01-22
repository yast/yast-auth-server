#include "SlapdConfigAgent.h"
#include <LDAPConnection.h>
#include <LDAPException.h>
#include <LdifReader.h>
#include <LdifWriter.h>
#include <LDAPEntry.h>
#include <LDAPUrl.h>
#include <SaslInteraction.h>
#include <algorithm>
#include <exception>
#include <sstream>
#include <fstream>

#define DEFAULT_PORT 389
#define ANSWER	42
#define MAX_LENGTH_ID 5

class SaslExternalHandler : SaslInteractionHandler
{
    public:
        virtual void handleInteractions(const std::list<SaslInteraction*> &cb );
        virtual ~SaslExternalHandler();
    private:
        std::list<SaslInteraction*> cleanupList;

};

void SaslExternalHandler::handleInteractions( const std::list<SaslInteraction *> &cb )
{
    std::list<SaslInteraction*>::const_iterator i;

    for (i = cb.begin(); i != cb.end(); i++ ) {
        cleanupList.push_back(*i);
    }
}

SaslExternalHandler::~SaslExternalHandler()
{
    std::list<SaslInteraction*>::const_iterator i;
    for (i = cleanupList.begin(); i != cleanupList.end(); i++ ) {
        delete(*i);
    }
}

bool caseIgnoreCompare( char c1, char c2)
{
    return toupper(c1) == toupper(c2);
}

static void y2LogCallback( int level, const std::string &msg,
            const char* file=0, const int line=0, const char* function=0)
{
    loglevel_t y2level = LOG_DEBUG;

    if ( level == SLAPD_LOG_INFO )
        y2level = LOG_MILESTONE;
    if ( level == SLAPD_LOG_DEBUG )
        y2level = LOG_DEBUG;
    if ( level == SLAPD_LOG_ERR )
        y2level = LOG_ERROR;
    y2_logger(y2level, "libslapdconfig", file, line, function, "%s", msg.c_str());
}

SlapdConfigAgent::SlapdConfigAgent() : m_lc(0)
{
    y2milestone("SlapdConfigAgent::SlapdConfigAgent");
    OlcConfig::setLogCallback(y2LogCallback);
}

SlapdConfigAgent::~SlapdConfigAgent()
{
    if ( m_lc)
    {
        delete(m_lc);
    }
}

YCPValue SlapdConfigAgent::Read( const YCPPath &path,
                                 const YCPValue &arg,
                                 const YCPValue &opt)
{
    y2milestone("Path %s Length %ld ", path->toString().c_str(),
                                      path->length());
    y2milestone("Component %s ", path->component_str(0).c_str());
    
    try {
        if ( path->length() < 1 ) {
            return YCPNull();
        } 
        else if ( path->component_str(0) == "global" ) 
        {
            y2milestone("Global read");
            return ReadGlobal(path->at(1), arg, opt);
        } 
        else if ( path->component_str(0) == "databases" ) 
        {
            y2milestone("read databases");
            return ReadDatabases(path->at(1), arg, opt);
        }
        else if ( path->component_str(0) == "schemaList" )
        {
            y2milestone("read schemalist");
            return ReadSchemaList(path->at(1), arg, opt);
        }
        else if ( path->component_str(0) == "schema" )
        {
            return ReadSchema( path->at(1), arg, opt );
        }
        else if ( path->component_str(0) == "database" ) 
        {
            y2milestone("read database");
            return ReadDatabase(path->at(1), arg, opt);
        }
        else if ( path->component_str(0) == "configAsLdif" )
        {
            return ConfigToLdif();
        }
    } catch ( std::runtime_error e ) {
        y2error("Error during Read: %s", e.what() );
        lastError->add(YCPString("summary"), YCPString(std::string( e.what() ) ) );
        lastError->add(YCPString("description"), YCPString("") );
        return YCPBoolean(false);
    }
    return YCPNull();
}


YCPBoolean SlapdConfigAgent::Write( const YCPPath &path,
                                  const YCPValue &arg,
                                  const YCPValue &arg2)
{
    y2milestone("Path %s Length %ld ", path->toString().c_str(),
                                      path->length());
    try {
        if ( path->component_str(0) == "global" )
        {
            y2milestone("Global Write");
            return WriteGlobal(path->at(1), arg, arg2);
        }
        else if ( (path->component_str(0) == "database") && (path->length() > 1) )
        {
            y2milestone("Database Write");
            return WriteDatabase(path->at(1), arg, arg2);
        }
        else if ( path->component_str(0) == "schema" )
        {
            y2milestone("Schema Write");
            return WriteSchema(path->at(1), arg, arg2);
        }
        else if ( path->component_str(0) == "sambaACLHack" )
        {
            // FIXME: remove this, when ACL support in WriteDatabase() is implemented
            y2error("Warning: sambaACL is currently not implemented");
            return YCPBoolean(true);
        } else {
            lastError->add(YCPString("summary"), YCPString("Write Failed") );
            std::string msg = "Unsupported SCR path: `.ldapserver.";
                        msg += path->toString().c_str();
                        msg += "`";
            lastError->add(YCPString("description"), YCPString(msg) );
            return YCPNull();
        }
    } catch ( std::runtime_error e ) {
        y2error("Caught exception: %s", e.what());
        lastError->add(YCPString("summary"), YCPString(std::string( e.what() ) ) );
        lastError->add(YCPString("description"), YCPString("") );
        return YCPBoolean(false);
    }
}

YCPMap SlapdConfigAgent::Error( const YCPPath &path )
{
    return lastError;
}

YCPValue SlapdConfigAgent::Execute( const YCPPath &path,
                                    const YCPValue &arg,
                                    const YCPValue &arg2)
{
    y2milestone("Execute Path %s", path->toString().c_str() );
    if ( path->component_str(0) == "init" )
    {
        if ( ! olc.hasConnection() )
        {
            std::string uri = "ldapi:///";
            YCPMap argMap;
            if (! arg.isNull() )
            {
                argMap = arg->asMap();
                YCPMap targetMap(argMap->value(YCPString("target"))->asMap());
                LDAPUrl target;
                target.setScheme( targetMap->value(YCPString("protocol"))->asString()->value_cstr() );
                target.setHost( targetMap->value(YCPString("target"))->asString()->value_cstr() );
                target.setPort( targetMap->value(YCPString("port"))->asInteger()->value() );
                uri = target.getURLString();
            }
            m_lc = new LDAPConnection(uri);
            try {
                if( arg.isNull() )
                {
                    SaslExternalHandler sih;
                    m_lc->saslInteractiveBind("external", 2 /* LDAP_SASL_QUIET */, (SaslInteractionHandler*)&sih);
                }
                else
                {
                    TlsOptions tls = m_lc->getTlsOptions();
                    if ( ! argMap->value(YCPString("cacert")).isNull() )
                    {
                        tls.setOption( TlsOptions::CACERTFILE, argMap->value( YCPString("cacert"))->asString()->value_cstr() );
                    }
                    if ( argMap->value(YCPString("starttls"))->asBoolean()->value() )
                    {
                        m_lc->start_tls();
                    }
                    m_lc->bind("cn=config", std::string( argMap->value(YCPString("configcred"))->asString()->value_cstr() ));
                }
            }
            catch ( LDAPException e)
            {
                std::string errstring = "Error connecting to LDAP Server";
                std::string details = e.getResultMsg() + ": " + e.getServerMsg();
                
                lastError->add(YCPString("summary"),
                        YCPString(errstring) );
                lastError->add(YCPString("description"), YCPString( details ) );
                y2milestone("Error connection to the LDAP Server: %s", details.c_str());
                delete(m_lc);
                m_lc=0;
                return YCPBoolean(false);
            }
            olc = OlcConfig(m_lc);
        }
        databases.clear();
        schema.clear();
        deleteableSchema.clear();
        globals.reset((OlcGlobalConfig*) 0 );
    }
    else if ( path->component_str(0) == "reset" )
    {
        y2milestone("Reseting Agent");
        if (olc.hasConnection())
        {
           // olc.getLdapConnection()->unbind();
        }
        olc = OlcConfig();
        if ( m_lc)
            delete m_lc;
        m_lc=0;
        databases.clear();
        schema.clear();
        deleteableSchema.clear();
        globals.reset((OlcGlobalConfig*) 0 );
    }
    else if ( path->component_str(0) == "initFromLdif" )
    {
        std::istringstream ldifstream(arg->asString()->value_cstr());
        LdifReader ldif(ldifstream);
        while ( ldif.readNextRecord() )
        {   
            LDAPEntry currentEntry = ldif.getEntryRecord();
            y2milestone( "EntryDN: %s", ldif.getEntryRecord().getDN().c_str() );
            StringList oc = currentEntry.getAttributeByName("objectclass")->getValues();
            string ocstring;
            for( StringList::const_iterator i = oc.begin(); i != oc.end(); i++ )
            {
                ocstring += *i;
                ocstring += " ";
            }
            y2milestone( "objectclasses: %s", ocstring.c_str());
            y2milestone( "isDatabase: %i", OlcConfigEntry::isDatabaseEntry(currentEntry) );
            if (OlcConfigEntry::isDatabaseEntry(currentEntry) )
            {
                boost::shared_ptr<OlcDatabase> olce(OlcDatabase::createFromLdapEntry(currentEntry));
                databases.push_back(olce);
            }
            else if (OlcConfigEntry::isGlobalEntry(currentEntry) )
            {
                globals = boost::shared_ptr<OlcGlobalConfig>(new OlcGlobalConfig(currentEntry));
            }
        }
    }
    else if ( path->component_str(0) == "initGlobals" )
    {
        globals = boost::shared_ptr<OlcGlobalConfig>(new OlcGlobalConfig());
        globals->setStringValue("olcPidFile", "/var/run/slapd/slapd.pid");
        globals->setStringValue("olcArgsFile", "/var/run/slapd/slapd.args");
        globals->setStringValue("olcLogLevel", "none");
        globals->setStringValue("olcSizeLimit", "10000");
        globals->setStringValue("olcAuthzRegexp", 
                "gidNumber=0\\+uidNumber=0,cn=peercred,cn=external,cn=auth dn:cn=config");
    }
    else if ( path->component_str(0) == "initSchema" )
    {   
        schemaBase = boost::shared_ptr<OlcSchemaConfig>(new OlcSchemaConfig() );
    }
    else if ( path->component_str(0) == "initDatabases" )
    {
        YCPList dbList = arg->asList();
        databases.clear();
        for ( int i = 0; i < dbList->size(); i++ )
        {
            YCPMap dbMap = dbList->value(i)->asMap();
            std::string dbtype(dbMap->value(YCPString("type"))->asString()->value_cstr());
            y2milestone("Database Type: %s", dbtype.c_str());
            boost::shared_ptr<OlcDatabase> db;
            if ( dbtype == "bdb" || dbtype == "hdb" )
            {
                db = boost::shared_ptr<OlcDatabase>(new OlcBdbDatabase(dbtype) );
            } 
            else
            {
                db = boost::shared_ptr<OlcDatabase>( new OlcDatabase(dbtype.c_str()) );
            }
            db->setIndex(i-1);
            YCPMap::const_iterator j = dbMap.begin();
            for ( ; j != dbMap.end(); j++ )
            {
                y2debug("Key: %s, Valuetype: %s",
                    j->first->asString()->value_cstr(),
                    j->second->valuetype_str() );
                if ( std::string("suffix") == j->first->asString()->value_cstr() )
                {
                    db->setSuffix( j->second->asString()->value_cstr() );
                    continue;
                }
                else if (std::string("rootdn") == j->first->asString()->value_cstr() )
                {
                    db->setRootDn( j->second->asString()->value_cstr() );
                    continue;
                }
                else if (std::string("rootpw") == j->first->asString()->value_cstr() )
                {
                    db->setRootPw( j->second->asString()->value_cstr() );
                    continue;
                }
                if ( dbtype == "bdb" || dbtype == "hdb" )
                {
                    boost::shared_ptr<OlcBdbDatabase> bdb = 
                        boost::dynamic_pointer_cast<OlcBdbDatabase>(db);
                    if (std::string("directory") == j->first->asString()->value_cstr() )
                    {
                        bdb->setDirectory( j->second->asString()->value_cstr() );
                    }
                    else if (std::string("entrycache") == j->first->asString()->value_cstr() )
                    {
                        bdb->setEntryCache( j->second->asInteger()->value() );
                    }
                    else if (std::string("idlcache") == j->first->asString()->value_cstr() )
                    {
                        bdb->setIdlCache( j->second->asInteger()->value() );
                    }
                    else if (std::string("checkpoint") == j->first->asString()->value_cstr() )
                    {
                        YCPList cpList = j->second->asList();
                        bdb->setCheckPoint( cpList->value(0)->asInteger()->value(),
                                cpList->value(1)->asInteger()->value() );
                    }
                }
            }
            databases.push_back(db);
        }
    }
    else if ( path->component_str(0) == "commitChanges" )
    {
        try {
            if ( globals )
                olc.updateEntry( *globals );

            OlcSchemaList::iterator j;
            for ( j = schema.begin(); j != schema.end() ; j++ )
            {
                olc.updateEntry(**j);
            }
            deleteableSchema.clear();
            OlcDatabaseList::iterator i;
            for ( i = databases.begin(); i != databases.end() ; i++ )
            {
                if ( ! (*i)->isDeletedEntry() )
                {
                    olc.updateEntry(**i);
                }
                OlcOverlayList overlays = (*i)->getOverlays();
                OlcOverlayList::iterator k;
                for ( k = overlays.begin(); k != overlays.end(); k++ )
                {
                    y2milestone("Update overlay: %s", (*k)->getDn().c_str() );
                    olc.updateEntry(**k);
                }
                if ( (*i)->isDeletedEntry() )
                {
                    olc.updateEntry(**i);
                }
            }
        } catch ( LDAPException e ) {
            std::string errstring = "Error while committing changes to config database";
            std::string details = e.getResultMsg() + ": " + e.getServerMsg();
            
            lastError->add(YCPString("summary"),
                    YCPString(errstring) );
            lastError->add(YCPString("description"), YCPString( details ) );
            return YCPBoolean(false);
        } catch ( std::runtime_error e ) {
            lastError->add(YCPString("summary"),
                    YCPString("Error while trying to update LDAP Entries") );
            lastError->add(YCPString("description"), 
                    YCPString(std::string( e.what() ) ) );
            return YCPBoolean(false);
        }
    }
    else if ( path->component_str(0) == "dumpConfDb" )
    {
        try {
            StringList attrs;
            attrs.add("*");
            attrs.add("structuralObjectClass");
            attrs.add("entryUUID");
            attrs.add("creatorsName");
            attrs.add("createTimestamp");
            attrs.add("entryCSN");
            attrs.add("modifiersName");
            attrs.add("modifyTimestamp");
            attrs.add("contextCSN");
            LDAPSearchResults *sr = m_lc->search( "cn=config", LDAPConnection::SEARCH_SUB,
                                                  "objectclass=*", attrs );
            std::ostringstream ldifStream;
            LdifWriter ldif(ldifStream);
            while ( LDAPEntry *e = sr->getNext() )
            {
                ldif.writeRecord( *e );
            }
            return YCPString( ldifStream.str() );
        } catch ( LDAPException e ) {
            std::string errstring = "Error while reading remote Database";
            std::string details = e.getResultMsg() + ": " + e.getServerMsg();

            lastError->add(YCPString("summary"),
                    YCPString(errstring) );
            lastError->add(YCPString("description"), YCPString( details ) );
            return YCPBoolean(false);
        } catch ( std::runtime_error e ) {
            lastError->add(YCPString("summary"),
                    YCPString("Error while trying to read remote Database") );
            lastError->add(YCPString("description"), 
                    YCPString(std::string( e.what() ) ) );
            return YCPBoolean(false);
        }
    }
    else if ( path->component_str(0) == "assignServerId" )
    {
        std::string url( arg->asString()->value_cstr() );
        this->assignServerId( url );
    }
    else if ( path->component_str(0) == "waitForBackgroundTasks" )
    {
        bool ret = true;
        try {
            olc.waitForBackgroundTasks();
        } catch ( std::runtime_error e ) {
            ret = false;
        }

        return YCPBoolean(ret);
    }
    else if ( path->component_str(0) == "addRootSaslRegexp" )
    {
        std::string filename = "/etc/openldap/slapd.d/cn=config.ldif";
        std::ifstream ldifFile(filename.c_str());
        try {
            LdifReader ldif(ldifFile);
            if ( ldif.readNextRecord() )
            {
                LDAPEntry entry, oldEntry;
                entry = ldif.getEntryRecord();
                entry.addAttribute(
                    LDAPAttribute( "olcAuthzRegexp", 
                        "gidNumber=0\\+uidNumber=0,cn=peercred,cn=external,cn=auth dn:cn=config")
                    );
                ldifFile.close();
                std::ofstream oldifFile(filename.c_str(), std::ios::out|std::ios::trunc);
                LdifWriter oldif(oldifFile);
                oldif.writeRecord(entry);
                oldifFile.close();
            }
            return YCPBoolean(true);
        } catch ( std::runtime_error e ) {
            lastError->add(YCPString("summary"),
                    YCPString("Error while parsing LDIF file") );
            lastError->add(YCPString("description"), 
                    YCPString(std::string( e.what() ) ) );
            return YCPBoolean(false);
        }
    }
    else if ( path->component_str(0) == "remoteBindCheck" )
    {
        return YCPBoolean(remoteBindCheck(arg));
    }
    else if ( path->component_str(0) == "remoteLdapSyncCheck" )
    {
        return YCPBoolean(remoteSyncCheck(arg));
    }
    return YCPBoolean(true);
}

YCPList SlapdConfigAgent::Dir( const YCPPath &path)
{
    return YCPNull();
}

YCPValue SlapdConfigAgent::otherCommand( const YCPTerm& term)
{
    y2milestone("SlapdConfigAgent::otherCommand -> %s ", term->name().c_str());
    std::string sym = term->name();

    if (sym == "SlapdConfigAgent") {
        /* Your initialization */
        return YCPVoid();
    }

    return YCPNull();

}

YCPValue SlapdConfigAgent::ReadGlobal( const YCPPath &path,
                                    const YCPValue &arg,
                                    const YCPValue &opt)
{
    y2milestone("Path %s Length %ld ", path->toString().c_str(),
                                      path->length());
    y2milestone("Component: %s", path->component_str(0).c_str());
    if ( path->length() == 0 ) 
    {
        return YCPNull();
    } 
    else
    {
        if ( globals == 0 )
        {
            globals = olc.getGlobals();
        }
        if ( path->component_str(0) == "loglevel" )
        {
            y2milestone("Read loglevel");
            YCPList yLevelList;
            const std::vector<std::string> loglevel = globals->getLogLevelString();
            std::vector<std::string>::const_iterator i;
            for ( i = loglevel.begin(); i != loglevel.end(); i++ )
            {
                yLevelList.add(YCPString(*i) );
            }
            return yLevelList;
        }
        if ( path->component_str(0) == "allow" )
        {
            y2milestone("Read allow Features");
            YCPList yFeatureList;
            const std::vector<std::string> loglevel = globals->getAllowFeatures();
            std::vector<std::string>::const_iterator i;
            for ( i = loglevel.begin(); i != loglevel.end(); i++ )
            {
                yFeatureList.add(YCPString(*i) );
            }
            return yFeatureList;
        }
        if ( path->component_str(0) == "disallow" )
        {
            y2milestone("Read allow Features");
            YCPList yFeatureList;
            const std::vector<std::string> loglevel = globals->getDisallowFeatures();
            std::vector<std::string>::const_iterator i;
            for ( i = loglevel.begin(); i != loglevel.end(); i++ )
            {
                yFeatureList.add(YCPString(*i) );
            }
            return yFeatureList;
        }
        if ( path->component_str(0) == "tlsSettings" )
        {
            YCPMap ymap;
            const OlcTlsSettings tls( globals->getTlsSettings() );
            ymap.add(YCPString("crlCheck"), YCPInteger( tls.getCrlCheck() ) );
            ymap.add(YCPString("verifyClient"), YCPInteger( tls.getVerifyClient() ) );
            ymap.add(YCPString("caCertDir"), YCPString( tls.getCaCertDir() ) );
            ymap.add(YCPString("caCertFile"), YCPString( tls.getCaCertFile() ) );
            ymap.add(YCPString("certFile"), YCPString( tls.getCertFile() ) );
            ymap.add(YCPString("certKeyFile"), YCPString( tls.getCertKeyFile() ) );
            ymap.add(YCPString("crlFile"), YCPString( tls.getCrlFile() ) );
            return ymap;
        }
        if ( path->component_str(0) == "serverIds" )
        {
            YCPList resList;
            std::vector<OlcServerId> serverIds = globals->getServerIds();
            for ( std::vector<OlcServerId>::const_iterator i =  serverIds.begin();
                  i != serverIds.end(); i++ )
            {
                YCPMap idMap;
                idMap.add( YCPString("id"), YCPInteger( i->getServerId() ) );
                idMap.add( YCPString("uri"), YCPString( i->getServerUri() ) );
                resList.add( idMap );
            }
            return resList;
        }
    }
    return YCPNull();
}

YCPValue SlapdConfigAgent::ReadDatabases( const YCPPath &path,
                                    const YCPValue &arg,
                                    const YCPValue &opt)
{
    y2milestone("Path %s Length %ld ", path->toString().c_str(),
                                      path->length());
    if ( databases.size() == 0 )
    {
        databases = olc.getDatabases();
    }
    OlcDatabaseList::const_iterator i;
    YCPList dbList;
    for (i = databases.begin(); i != databases.end(); i++ )
    {
        YCPMap ymap;
        if ( (*i)->isDeletedEntry() )
        {
            continue;
        }
        if ( (*i)->getSuffix().empty() && (*i)->getType() == "config" )
        {
            ymap.add( YCPString("suffix"), YCPString("cn=config") );
        }
        else
        {
            ymap.add( YCPString("suffix"), YCPString((*i)->getSuffix()) );
        }
        ymap.add( YCPString("type"), YCPString((*i)->getType()) );
        ymap.add( YCPString("index"), YCPInteger((*i)->getEntryIndex()) );
        dbList.add(ymap);
    }
    return dbList;
}

YCPValue SlapdConfigAgent::ReadDatabase( const YCPPath &path,
                                    const YCPValue &arg,
                                    const YCPValue &opt)
{
    y2milestone("Path %s Length %ld ", path->toString().c_str(),
                                      path->length());
    std::string dbIndexStr = path->component_str(0);
    y2milestone("Component %s ", dbIndexStr.c_str());
    int dbIndex = -2;
    if ( dbIndexStr[0] == '{' )
    {
        std::string::size_type pos = dbIndexStr.find('}');
        std::istringstream indexstr(dbIndexStr.substr(1, pos-1));
        indexstr >> dbIndex;
    } else {
        y2error("Database Index expected, got: %s", dbIndexStr.c_str() );
        return YCPNull();
    }
    if ( dbIndex < -1 )
    {
        y2error("Invalid database index: %d", dbIndex );
        return YCPNull();
    }

    y2milestone("Database to read: %d", dbIndex);
    if ( databases.size() == 0 )
    {
        databases = olc.getDatabases();
    }
    OlcDatabaseList::const_iterator i;
    for ( i = databases.begin(); i != databases.end() ; i++ )
    {
        if ( (*i)->getEntryIndex() == dbIndex ) 
        {
            YCPMap resMap;
            if ( path->length() == 1 )
            {
                std::string dbtype = (*i)->getType();
                std::string suffix = (*i)->getStringValue("olcSuffix");
                y2milestone("suffix %s, dbtype %s\n", suffix.c_str(), dbtype.c_str() );
                if ( dbtype == "config" )
                {
                    // expose the security setting to cn=config only for now
                    std::string secVal = (*i)->getStringValue("olcSecurity");
                    OlcSecurity sec(secVal);
                    if ( (sec.getSsf("ssf") >= 71) && (sec.getSsf("simple_bind") >= 128) )
                    {
                        resMap.add( YCPString("secure_only"), YCPBoolean(true) );
                    }
                    else
                    {
                        resMap.add( YCPString("secure_only"), YCPBoolean(false) );
                    }

                    if ( suffix.empty() )
                    {
                        suffix = "cn=config";
                    }
                }
                resMap.add( YCPString("suffix"), YCPString(suffix) );
                resMap.add( YCPString( "type" ),
                            YCPString( dbtype ) );
                resMap.add( YCPString("rootdn"), 
                            YCPString( (*i)->getStringValue("olcRootDn") ));
                resMap.add( YCPString("rootpw"), 
                            YCPString( (*i)->getStringValue("olcRootPw") ));
                if ( dbtype == "bdb" || dbtype == "hdb" )
                {
                    boost::shared_ptr<OlcBdbDatabase> bdb = 
                        boost::dynamic_pointer_cast<OlcBdbDatabase>(*i);
                    resMap.add( YCPString("directory"), 
                                YCPString( bdb->getStringValue("olcDbDirectory") ));
                    resMap.add( YCPString("entrycache"), 
                                YCPInteger( bdb->getEntryCache() ));
                    resMap.add( YCPString("idlcache"), 
                                YCPInteger( bdb->getIdlCache() ));
                    YCPList checkPoint;
                    int kbytes, min;
                    bdb->getCheckPoint(kbytes, min);
                    checkPoint.add( YCPInteger(kbytes) );
                    checkPoint.add( YCPInteger(min) );
                    resMap.add( YCPString("checkpoint"), checkPoint );
                }
                return resMap;
            } else {
                std::string dbComponent = path->component_str(1);
                y2milestone("Component %s ", dbComponent.c_str());
                if ( dbComponent == "indexes" )
                {
                    boost::shared_ptr<OlcBdbDatabase> bdb = 
                        boost::dynamic_pointer_cast<OlcBdbDatabase>(*i);
                    if ( bdb == 0 )
                    {
                        y2milestone("Database doesn't provide indexing\n");
                    }
                    else
                    {
                        IndexMap idx = bdb->getDatabaseIndexes();
                        IndexMap::const_iterator j = idx.begin();
                        for ( ; j != idx.end(); j++ )
                        {
                            YCPMap ycpIdx;
                            y2debug("indexed Attribute: \"%s\"", j->first.c_str() );
                            std::vector<IndexType>::const_iterator k = j->second.begin();
                            for ( ; k != j->second.end(); k++ )
                            {
                                if ( *k == Eq ){
                                    ycpIdx.add(YCPString("eq"), YCPBoolean(true) );
                                } else if ( *k == Present ){
                                    ycpIdx.add(YCPString("pres"), YCPBoolean(true) );
                                } else if ( *k == Sub ){
                                    ycpIdx.add(YCPString("sub"), YCPBoolean(true) );
                                }
                            }
                            resMap.add( YCPString(j->first), ycpIdx );
                        }
                    }
                    return resMap;
                }
                else if ( dbComponent == "overlays" )
                {
                    OlcOverlayList overlays = (*i)->getOverlays();
                    OlcOverlayList::const_iterator j = overlays.begin();
                    YCPList resList;
                    for (; j != overlays.end(); j++ )
                    {
                        y2milestone("Overlay: %s", (*j)->getType().c_str() );
                        YCPMap overlayMap;
                        overlayMap.add( YCPString("type"), YCPString( (*j)->getType() ) );
                        overlayMap.add( YCPString("index"), YCPInteger( (*j)->getEntryIndex() ) );
                        resList.add(overlayMap);
                    }
                    return resList;
                }
                else if ( dbComponent == "ppolicy" )
                {
                    OlcOverlayList overlays = (*i)->getOverlays();
                    OlcOverlayList::const_iterator j = overlays.begin();
                    for (; j != overlays.end(); j++ )
                    {
                        if ( (*j)->getType() == "ppolicy" && (*j)->getUpdatedDn() != "" )
                        {
                            resMap.add(YCPString("defaultPolicy"), 
                                    YCPString((*j)->getStringValue("olcPpolicyDefault") ) );
                            if ( (*j)->getStringValue("olcPPolicyHashCleartext") == "TRUE" )
                            {
                                resMap.add(YCPString("hashClearText"), YCPBoolean(true) );
                            }
                            else
                            {
                                resMap.add(YCPString("hashClearText"), YCPBoolean(false) );
                            }
                            if ( (*j)->getStringValue("olcPPolicyUseLockout") == "TRUE" )
                            {
                                resMap.add(YCPString("useLockout"), YCPBoolean(true) );
                            }
                            else
                            {
                                resMap.add(YCPString("useLockout"), YCPBoolean(false) );
                            }
                            break;
                        }
                    }
                    return resMap;
                }
                else if ( dbComponent == "syncprov" )
                {
                    OlcOverlayList overlays = (*i)->getOverlays();
                    OlcOverlayList::const_iterator j = overlays.begin();
                    for (; j != overlays.end(); j++ )
                    {
                        if ( (*j)->getType() == "syncprov" && (*j)->getUpdatedDn() != "" )
                        {
                            boost::shared_ptr<OlcSyncProvOl> syncprovOlc = boost::dynamic_pointer_cast<OlcSyncProvOl>(*j);
                            int cp_ops,cp_min;
                            syncprovOlc->getCheckPoint(cp_ops, cp_min);
                            if ( cp_ops || cp_min )
                            {
                                YCPMap cpMap;
                                cpMap.add( YCPString("ops"), YCPInteger(cp_ops) );
                                cpMap.add( YCPString("min"), YCPInteger(cp_min) );
                                resMap.add( YCPString("checkpoint"), cpMap );
                            }
                            int slog;
                            if ( syncprovOlc->getSessionLog(slog) )
                            {
                                resMap.add( YCPString("sessionlog"), YCPInteger(slog) );
                            }
                            // This is just that the map is not empty (e.g. when syncprov is
                            // configured with default values)
                            resMap.add( YCPString("enabled"), YCPBoolean(true) );
                            break;
                        }
                    }
                    return resMap;
                }
                else if ( dbComponent == "acl" )
                {
                    YCPList resList;
                    OlcAccessList aclList;
                    bool parsed = (*i)->getAcl(aclList); 
                    if ( parsed )
                    {
                        OlcAccessList::const_iterator j;
                        for ( j = aclList.begin(); j != aclList.end(); j++ )
                        {
                            YCPMap aclMap;
                            YCPMap targetMap;
                            YCPList accessList;
                            if ( (*j)->matchesAll() )
                            {
                            }
                            else
                            {
                                std::string filter = (*j)->getFilter();
                                if (filter != "" )
                                {
                                    targetMap.add( YCPString("filter"), YCPString(filter) );
                                }
                                std::string attrs = (*j)->getAttributes();
                                if (attrs != "" )
                                {
                                    targetMap.add( YCPString("attrs"), YCPString(attrs) );
                                }
                                std::string dn_type = (*j)->getDnType();
                                if ( dn_type != "" )
                                {
                                    YCPMap dnMap;
                                    std::string dn_value = (*j)->getDnValue();
                                    if (dn_type == "dn.subtree" )
                                    {
                                        dnMap.add(YCPString("style"), YCPString("subtree") );
                                    }
                                    else
                                    {
                                        dnMap.add(YCPString("style"), YCPString("base") );
                                    }
                                    dnMap.add(YCPString("value"), YCPString(dn_value) );
                                    targetMap.add( YCPString("dn"), dnMap );
                                }
                            }
                            aclMap.add( YCPString("target"), targetMap );
                            OlcAclByList byList =(*j)->getAclByList() ;
                            OlcAclByList::const_iterator k;
                            for ( k = byList.begin() ; k != byList.end(); k++ )
                            {
                                YCPMap byMap;
                                byMap.add(YCPString("level"), YCPString( (*k)->getLevel() ) );
                                byMap.add(YCPString("type"), YCPString( (*k)->getType() ) );
                                byMap.add(YCPString("value"), YCPString( (*k)->getValue() ) );
                                byMap.add(YCPString("control"), YCPString( (*k)->getControl() ) );
                                accessList.add(byMap);
                            }
                            aclMap.add( YCPString("access"), accessList ); 
                            resList.add(aclMap);
                        }
                        return resList;
                    }
                    else
                    {
                        return YCPNull();
                    }
                }
                else if ( dbComponent == "limits" )
                {
                    YCPList resList;
                    OlcLimitList limitList;
                    if ( (*i)->getLimits(limitList) )
                    {
                        OlcLimitList::const_iterator j;
                        for ( j = limitList.begin(); j != limitList.end(); j++ )
                        {
                            YCPMap limitMap;
                            YCPList limitVals;
                            pairlist limits = (*j)->getLimits();
                            pairlist::const_iterator k ;
                            for ( k = limits.begin(); k != limits.end(); k++ )
                            {
                                YCPMap valMap;
                                valMap.add(YCPString("type"), YCPString(k->first) );
                                valMap.add(YCPString("value"), YCPString(k->second) );
                                limitVals.add(valMap);
                            }
                            limitMap.add( YCPString("selector"), YCPString( (*j)->getSelector().c_str() ) );
                            limitMap.add( YCPString("limits"), limitVals);
                            resList.add(limitMap);
                        }
                        return resList;
                    }
                    else
                    {
                        return YCPNull();
                    }
                }
                else if ( dbComponent == "syncrepl" )
                {
                    YCPList resList;
                    OlcSyncReplList srl = (*i)->getSyncRepl();
                    OlcSyncReplList::const_iterator sr;
                    for ( sr = srl.begin(); sr != srl.end(); sr++ )
                    {
                        YCPMap resMap;
                        resMap.add( YCPString(OlcSyncRepl::RID), YCPInteger( (*sr)->getRid() ));
                        std::string proto,host;
                        int port;
                        (*sr)->getProviderComponents(proto, host, port);
                        YCPMap providerMap;
                        providerMap.add( YCPString("protocol"), YCPString(proto) );
                        providerMap.add( YCPString("target"), YCPString(host) );
                        providerMap.add( YCPString("port"), YCPInteger(port) );
                        resMap.add( YCPString(OlcSyncRepl::PROVIDER),  providerMap );
                        resMap.add( YCPString(OlcSyncRepl::TYPE), YCPString( (*sr)->getType() ));
                        if ( (*sr)->getStartTls() != OlcSyncRepl::StartTlsNo )
                        {
                            resMap.add( YCPString(OlcSyncRepl::STARTTLS), YCPBoolean( true ));
                        }

                        if ( (*sr)->getType() == "refreshOnly" )
                        {
                            YCPMap intervalMap;
                            int d,h,m,s;
                            (*sr)->getInterval(d, h, m, s);
                            intervalMap.add( YCPString("days"), YCPInteger(d) );
                            intervalMap.add( YCPString("hours"), YCPInteger(h) );
                            intervalMap.add( YCPString("mins"), YCPInteger(m) );
                            intervalMap.add( YCPString("secs"), YCPInteger(s) );
                            resMap.add( YCPString( OlcSyncRepl::INTERVAL ), intervalMap );
                        }

                        resMap.add( YCPString(OlcSyncRepl::BINDDN), YCPString( (*sr)->getBindDn() ));
                        resMap.add( YCPString(OlcSyncRepl::CREDENTIALS), YCPString( (*sr)->getCredentials()));
                        resMap.add( YCPString(OlcSyncRepl::BASE), YCPString( (*sr)->getSearchBase()));
                        resList.add(resMap);
                    }
                    return resList;
                }
                else if ( dbComponent == "updateref" )
                {
                    YCPMap resMap;
                    std::string updateRefAttr( (*i)->getStringValue( "olcUpdateRef" ) );

                    if (! updateRefAttr.empty() )
                    {
                        LDAPUrl updateUrl(updateRefAttr);

                        resMap.add( YCPString("protocol"), YCPString( updateUrl.getScheme() ) );
                        resMap.add( YCPString("target"), YCPString( updateUrl.getHost() ) );
                        resMap.add( YCPString("port"), YCPInteger( updateUrl.getPort() ) );
                    }
                    else
                    {
                        resMap = YCPNull();
                    }
                    return resMap;
                }
                else if ( dbComponent == "mirrormode" )
                {
                    return YCPBoolean((*i)->getMirrorMode());
                }
                else
                {
                    lastError->add(YCPString("summary"), YCPString("Read Failed") );
                    std::string msg = "Unsupported SCR path: `.ldapserver.database.";
                    msg += path->toString().c_str();
                    msg += "`";
                    lastError->add(YCPString("description"), YCPString(msg) );
                }
            }
        }
    }
    return YCPNull();
}

YCPValue SlapdConfigAgent::ReadSchema( const YCPPath &path,
                                    const YCPValue &arg,
                                    const YCPValue &opt)
{
    if ( path->component_str(0) == "attributeTypes" )
    {
        if ( schema.size() == 0 )
        {
            schema = olc.getSchemaNames();
        }
        OlcSchemaList::const_iterator i;
        YCPMap resMap;
        std::map<std::string,std::string> attrNamesMap;
        std::map<std::string,std::string> aliasesMap;

        for (i = schema.begin(); i != schema.end(); i++ )
        {
            y2milestone("Schema: %s", (*i)->getName().c_str() );
            std::vector<LDAPAttrType> types = (*i)->getAttributeTypes();
            std::vector<LDAPAttrType>::const_iterator j;
            for ( j = types.begin(); j != types.end(); j++ )
            {
                YCPMap attrMap;

                // normalize to lowercase for later comparison
                std::string curName = j->getName();
                std::transform(curName.begin(), curName.end(), curName.begin(), ::tolower);
                
                // Handling derived AttributeTypes.
                // Attention! This code assumes that supertypes have been 
                // read prior to their subtypes
                if ( j->getSuperiorOid() != "" ){
                    y2debug("'%s' is a subtype of '%s'",curName.c_str(), j->getSuperiorOid().c_str() );
                    // normalize supertype to lowercase as well
                    std::string supName =  j->getSuperiorOid();
                    std::transform(supName.begin(), supName.end(), supName.begin(), ::tolower);
                    // check if Supertype references an Aliasname
                    std::map<std::string,std::string>::const_iterator pos = aliasesMap.find(supName);
                    if ( pos != aliasesMap.end() )
                    {
                        y2debug("subtype '%s' is an alias for '%s'", supName.c_str(), pos->second.c_str() );
                        supName = pos->second;
                    }
                    // locate Supertype

                    YCPMap supMap = resMap->value(YCPString(attrNamesMap[supName]))->asMap();
                    attrMap.add( YCPString("equality"), supMap->value(YCPString("equality")) );
                    attrMap.add( YCPString("substring"), supMap->value(YCPString("substring")) );
                    attrMap.add( YCPString("presence"), supMap->value(YCPString("presence")) );
                } else {
                    if ( j->getEqualityOid() != "" )
                    {
                        attrMap.add( YCPString("equality"), YCPBoolean( true ) );
                    } else {
                        attrMap.add( YCPString("equality"), YCPBoolean( false ) );
                    }
                    if ( j->getSubstringOid() != "" )
                    {
                        attrMap.add( YCPString("substring"), YCPBoolean( true ) );
                    } else {
                        attrMap.add( YCPString("substring"), YCPBoolean( false ) );
                    }
                    attrMap.add( YCPString("presence"), YCPBoolean( true ) );
                }

                // FIXME: how should "approx" indexing be handled, create 
                //        whitelist based upon syntaxes?
                resMap.add( YCPString( j->getName() ), attrMap );
                attrNamesMap.insert(std::make_pair(curName, j->getName() ) );


                // does the current AttributeType have any addional Names?
                StringList names = j->getNames();
                if ( names.size() > 1 )
                {
                    StringList::const_iterator k = names.begin();
                    k++; // skip first
                    for ( std::string curAlias=*k ; k != names.end(); k++ )
                    {
                        std::transform(curAlias.begin(), curAlias.end(), curAlias.begin(), ::tolower);
                        aliasesMap.insert(std::make_pair(curAlias, curName) );
                    }
                }
            }
        }
        return resMap;
    }
    else if ( path->component_str(0) == "ldif" )
    {
        std::string name = path->component_str(1);
        if ( schema.size() == 0 )
        {
            schema = olc.getSchemaNames();
        }
        OlcSchemaList::const_iterator i;
        YCPMap resMap;
        std::string result = "";
        for (i = schema.begin(); i != schema.end(); i++ )
        {
            if ( (*i)->getName() == name )
            {
                ostringstream oldifstr;
                LdifWriter oldif(oldifstr);
                oldif.writeRecord((*i)->getChangedEntry());
                result = oldifstr.str();
                break;
            }
        }
        return YCPString( result.c_str() );
    }
    else if ( path->component_str(0) == "deletable" )
    {
        YCPList result;
        std::list<std::string>::const_iterator i;
        for (i = deleteableSchema.begin() ; i != deleteableSchema.end(); i++ )
        {
            result.add( YCPString(*i) );
        }
        return result;
    }
    y2milestone("Unsupported Path: %s", path->toString().c_str() );
    return YCPNull();
}

YCPValue SlapdConfigAgent::ReadSchemaList( const YCPPath &path,
                                    const YCPValue &arg,
                                    const YCPValue &opt)
{
    y2milestone("Path %s Length %ld ", path->toString().c_str(),
                                      path->length());
    if ( schema.size() == 0 )
    {
        schema = olc.getSchemaNames();
    }
    OlcSchemaList::const_iterator i;
    YCPList resultList;
    for (i = schema.begin(); i != schema.end(); i++ )
    {
        if (! (*i)->getName().empty() )
        {
            resultList.add( YCPString( (*i)->getName() ) );
        }
    }
    return resultList;
}

YCPBoolean SlapdConfigAgent::WriteGlobal( const YCPPath &path,
                                    const YCPValue &arg,
                                    const YCPValue &arg2)
{
    y2milestone("Path %s Length %ld ", path->toString().c_str(),
                                      path->length());
    y2milestone("Component: %s", path->component_str(0).c_str());
    if ( path->length() == 0 ) {
        return YCPNull();
    } else {
        if ( ! globals )
        {
            throw std::runtime_error("Configuration not initialized." );
        }
        if ( path->component_str(0) == "loglevel" )
        {
            y2milestone("Write loglevel");
            YCPList levels = arg->asList();
            std::list<std::string> levelList;
            for ( int i = 0; i < levels->size(); i++ )
            {
                levelList.push_back( levels->value(i)->asString()->value_cstr() );
            }
            globals->setLogLevel( levelList );
            return YCPBoolean(true);
        }
        if ( path->component_str(0) == "allow" )
        {
            y2milestone("Write allow Features");
            YCPList features = arg->asList();
            std::list<std::string> featureList;
            for ( int i = 0; i < features->size(); i++ )
            {
                featureList.push_back( features->value(i)->asString()->value_cstr() );
            }
            globals->setAllowFeatures( featureList );
            return YCPBoolean(true);
        }
        if ( path->component_str(0) == "disallow" )
        {
            y2milestone("Write disallow Features");
            YCPList features = arg->asList();
            std::list<std::string> featureList;
            for ( int i = 0; i < features->size(); i++ )
            {
                featureList.push_back( features->value(i)->asString()->value_cstr() );
            }
            globals->setDisallowFeatures( featureList );
            return YCPBoolean(true);
        }
        if ( path->component_str(0) == "tlsSettings" )
        {
            y2milestone("Write TLS Settings");
            YCPMap tlsMap = arg->asMap();
            OlcTlsSettings tls( globals->getTlsSettings() );
            YCPMap::const_iterator i= tlsMap.begin();
            for ( ; i != tlsMap.end(); i++ )
            {
                std::string key(i->first->asString()->value_cstr() );
                y2debug("tlsMap Key: %s", key.c_str() );
                if ( key == "caCertDir" )
                {
                    if ( ! i->second.isNull() )
                        tls.setCaCertDir(i->second->asString()->value_cstr() );
                } 
                else if ( key == "caCertFile" )
                {
                    if ( ! i->second.isNull() )
                        tls.setCaCertFile(i->second->asString()->value_cstr() );
                    else
                        tls.setCaCertFile("");
                }
                else if ( key == "certFile" )
                {
                    if ( ! i->second.isNull() )
                        tls.setCertFile(i->second->asString()->value_cstr() );
                    else
                        tls.setCertFile("");
                }
                else if ( key == "certKeyFile" )
                {
                    if ( ! i->second.isNull() )
                        tls.setCertKeyFile(i->second->asString()->value_cstr() );
                    else
                        tls.setCertKeyFile("");
                }
                else if ( key == "crlCheck" )
                {
                }
                else if ( key == "crlFile" )
                {
                    if ( ! i->second.isNull() )
                        tls.setCrlFile (i->second->asString()->value_cstr() );
                    else
                        tls.setCertKeyFile("");

                }
                else if ( key == "verifyClient" )
                {
                }
                else
                {
                }
            }
            globals->setTlsSettings(tls);
            return YCPBoolean(true);
        }
        if ( path->component_str(0) == "serverIds" )
        {
            YCPList ycpServerIds = arg->asList();
            std::vector<OlcServerId> serverids;

            YCPList::const_iterator i;
            for ( i = ycpServerIds.begin(); i != ycpServerIds.end(); i++ )
            {
                YCPMap yServerId = (*i)->asMap();
                serverids.push_back( OlcServerId( yServerId->value( YCPString("id") )->asInteger()->value(),
                                                  yServerId->value( YCPString("uri") )->asString()->value_cstr() ) );
            }
            globals->setServerIds(serverids);
        }

    }
    return YCPBoolean(false);
}

YCPBoolean SlapdConfigAgent::WriteDatabase( const YCPPath &path,
                                    const YCPValue &arg,
                                    const YCPValue &arg2)
{
    y2milestone("Path %s Length %ld ", path->toString().c_str(),
                                      path->length());
    int component = 0;
    bool databaseAdd = false;
    std::string dbIndexStr = path->component_str(component);

    if ( databases.size() == 0 && olc.hasConnection() )
    {
        databases =  olc.getDatabases();
    }
    if ( dbIndexStr == "new" )
    {
        component++;
        databaseAdd = true;
        if ( path->length() > component )
        {
            dbIndexStr = path->component_str(component);
        }
        else
        {
            dbIndexStr = "";
        }
    }
    int dbIndex = -2;
    if ( dbIndexStr[0] == '{' )
    {
        std::string::size_type pos = dbIndexStr.find('}');
        std::istringstream indexstr(dbIndexStr.substr(1, pos-1));
        indexstr >> dbIndex;
    }
    else if (! databaseAdd ) // Add without index is support (append database to the end)
    {
        y2error("Database Index expected, got: %s", dbIndexStr.c_str() );
        return YCPBoolean(false);
    }

    if ( (dbIndex < -1) && (!databaseAdd) )
    {
        y2error("Invalid database index: %d", dbIndex );
        return YCPBoolean(false);
    }

    bool ret = false;
    if ( databaseAdd )
    {
        YCPMap dbMap= arg->asMap();
        y2milestone("creating new Database");
        if ( dbIndex == -2 )
        {
            dbIndex = databases.size()-1; //Database indexes start counting from -1
        }
        else if ( (dbIndex <=0) || (dbIndex > (int)databases.size()-1) ) 
        {
            lastError->add(YCPString("summary"), YCPString("Adding Database Failed") );
            std::string msg = "Invalid Index for new Database";
            lastError->add(YCPString("description"), YCPString(msg) );
            return ret;
        }
        y2milestone("Database will get Index: %d", dbIndex);
        std::string dbtype(dbMap->value(YCPString("type"))->asString()->value_cstr());
        boost::shared_ptr<OlcDatabase> db;
        if ( dbtype == "bdb" || dbtype == "hdb" )
        {
            db = boost::shared_ptr<OlcDatabase>(new OlcBdbDatabase( dbtype ) );
        } 
        else
        {
            db = boost::shared_ptr<OlcDatabase>( new OlcDatabase(dbtype.c_str()) );
        }
        db->setIndex(dbIndex);
        YCPMap::const_iterator j = dbMap.begin();
        for ( ; j != dbMap.end(); j++ )
        {
            y2debug("Key: %s, Valuetype: %s",
                j->first->asString()->value_cstr(),
                j->second->valuetype_str() );
            if ( std::string("suffix") == j->first->asString()->value_cstr() )
            {
                db->setSuffix( j->second->asString()->value_cstr() );
                continue;
            }
            else if (std::string("rootdn") == j->first->asString()->value_cstr() )
            {
                db->setRootDn( j->second->asString()->value_cstr() );
                continue;
            }
            else if (std::string("rootpw") == j->first->asString()->value_cstr() )
            {
                db->setRootPw( j->second->asString()->value_cstr() );
                continue;
            }
            if ( dbtype == "bdb" || dbtype == "hdb" )
            {
                boost::shared_ptr<OlcBdbDatabase> bdb = 
                    boost::dynamic_pointer_cast<OlcBdbDatabase>(db);
                if (std::string("directory") == j->first->asString()->value_cstr() )
                {
                    bdb->setDirectory( j->second->asString()->value_cstr() );
                }
                else if (std::string("entrycache") == j->first->asString()->value_cstr() )
                {
                    bdb->setEntryCache( j->second->asInteger()->value() );
                }
                else if (std::string("idlcache") == j->first->asString()->value_cstr() )
                {
                    bdb->setIdlCache( j->second->asInteger()->value() );
                }
                else if (std::string("checkpoint") == j->first->asString()->value_cstr() )
                {
                    YCPList cpList = j->second->asList();
                    bdb->setCheckPoint( cpList->value(0)->asInteger()->value(),
                            cpList->value(1)->asInteger()->value() );
                }
            }
        }
        // find insert position
        OlcDatabaseList::iterator i,k;
        bool inserted = false;
        for ( i = databases.begin(); i != databases.end() ; i++ )
        {
            if ( (*i)->getEntryIndex() == dbIndex )
            {
                k = databases.insert(i, db ); 
                inserted=true;
            }
        }
        if ( inserted )
        {
            k++;
            // renumber remaining databases
            for( ; k != databases.end(); k++ )
            {
                y2milestone("%s needs to be renumbered", (*k)->getSuffix().c_str() );
                (*k)->setIndex( (*k)->getEntryIndex() + 1, true );

                // update the overlays' DNs accordingly
                OlcOverlayList overlays = (*k)->getOverlays();
                OlcOverlayList::const_iterator l = overlays.begin();
                for (; l != overlays.end(); l++ )
                {
                    (*l)->newParentDn( (*k)->getUpdatedDn() );
                }
            }
        }
        else
        {
            databases.push_back(db);
        }
        ret = true;
    }
    else
    {
        y2milestone("Database to write: %d", dbIndex);
        OlcDatabaseList::const_iterator i;
        bool dbDeleted=false;
        for ( i = databases.begin(); i != databases.end() ; i++ )
        {
            if ( (*i)->getEntryIndex() == dbIndex ) 
            {
                if ( path->length() == 1 )
                {
                    YCPMap dbMap= arg->asMap();
                    if ( dbMap.size() == 0 ) // database delete
                    {
                        (*i)->clearChangedEntry();
                        // delete the overlays' DNs  as well
                        OlcOverlayList overlays = (*i)->getOverlays();
                        OlcOverlayList::const_iterator l = overlays.begin();
                        for (; l != overlays.end(); l++ )
                        {
                            (*l)->clearChangedEntry();
                        }
                        dbDeleted = true;
                    }

                    YCPValue val = dbMap.value( YCPString("rootdn") );
                    if ( ! val.isNull()  && val->isString() )
                    {
                        (*i)->setStringValue( "olcRootDn", val->asString()->value_cstr() );
                    }
                    val = dbMap.value( YCPString("rootpw") );
                    if ( ! val.isNull() && val->isString() )
                    {
                        (*i)->setStringValue( "olcRootPw", val->asString()->value_cstr() );
                    }
                    val = dbMap.value( YCPString("secure_only") );
                    if ( ! val.isNull() && val->isBoolean() )
                    {
                        y2milestone("olcSecurity");
                        std::string secVal = (*i)->getStringValue("olcSecurity");

                        OlcSecurity sec(secVal);
                        if ( val->asBoolean()->value() )
                        {
                            if ( sec.getSsf("ssf") < 71 )
                            {
                                sec.setSsf("ssf", 71);
                            }
                            if ( sec.getSsf("simple_bind") < 128 )
                            {
                                sec.setSsf("simple_bind", 128);
                            }
                        }
                        else
                        {
                            sec.setSsf("ssf", 0);
                            sec.setSsf("simple_bind", 0);
                        }
                        std::string newVal(sec.toSecturityVal());
                        if ( !secVal.empty() || !newVal.empty() )
                        {
                            (*i)->setStringValue("olcSecurity", newVal );
                        }
                    }
                    if ( (*i)->getType() == "bdb" || (*i)->getType() == "hdb" )
                    {
                        boost::shared_ptr<OlcBdbDatabase> bdb = 
                            boost::dynamic_pointer_cast<OlcBdbDatabase>(*i);
                        val = dbMap.value( YCPString("entrycache") );
                        if ( ! val.isNull() && val->isInteger() )
                        {
                            bdb->setEntryCache( val->asInteger()->value() );
                        }
                        val = dbMap.value( YCPString("idlcache") );
                        if ( ! val.isNull() && val->isInteger() )
                        {
                            bdb->setIdlCache( val->asInteger()->value() );
                        }
                        val = dbMap.value( YCPString("checkpoint") );
                        if ( ! val.isNull() && val->isList() )
                        {
                            YCPList cpList = val->asList();
                            bdb->setCheckPoint( cpList->value(0)->asInteger()->value(),
                                    cpList->value(1)->asInteger()->value() );
                        }
                    }
                    ret = true;
                } else {
                    std::string dbComponent = path->component_str(1);
                    y2milestone("Component '%s'", dbComponent.c_str());
                    if ( dbComponent == "index" )
                    {
                        boost::shared_ptr<OlcBdbDatabase> bdb = 
                            boost::dynamic_pointer_cast<OlcBdbDatabase>(*i);
                        if ( bdb == 0 )
                        {
                            y2milestone("Database doesn't provide indexing\n");
                            ret = false;
                        }
                        else
                        {
                            std::vector<IndexType> idx;
                            std::string attr( arg->asMap()->value(YCPString("name"))->asString()->value_cstr() );
                            y2milestone("Edit Index for Attribute: '%s'", attr.c_str() );
                            if ( ! arg->asMap()->value(YCPString("pres")).isNull() && 
                                 arg->asMap()->value(YCPString("pres"))->asBoolean()->value() == true )
                            {
                                idx.push_back(Present);
                            }
                            if ( ! arg->asMap()->value(YCPString("eq")).isNull() &&
                                 arg->asMap()->value(YCPString("eq"))->asBoolean()->value() == true )
                            {
                                idx.push_back(Eq);
                            }
                            if ( ! arg->asMap()->value(YCPString("sub")).isNull() &&
                                 arg->asMap()->value(YCPString("sub"))->asBoolean()->value() == true )
                            {
                                idx.push_back(Sub);
                            }
                            if ( ( idx.empty()) || ( ! bdb->getDatabaseIndex(attr).empty() ) ) {
                                bdb->deleteIndex( attr );
                            }
                            if ( ! idx.empty() ) {
                                bdb->addIndex(attr, idx);
                            }
                            ret = true;
                        }
                    }
                    else if (dbComponent == "ppolicy" )
                    {
                        OlcOverlayList overlays = (*i)->getOverlays();
                        OlcOverlayList::const_iterator j = overlays.begin();
                        for (; j != overlays.end(); j++ )
                        {
                            if ( (*j)->getType() == "ppolicy" )
                            {
                                break;
                            }
                        }
                        YCPMap argMap = arg->asMap();
                        if ( j == overlays.end() && argMap.size() == 0 )
                        {
                            y2milestone("Empty overlay nothing to do");
                        }
                        else 
                        {
                            boost::shared_ptr<OlcOverlay> ppolicyOlc;
                            if ( j == overlays.end() )
                            {
                                y2milestone("New Overlay added");
                                boost::shared_ptr<OlcOverlay> tmp(new OlcOverlay("ppolicy", (*i)->getUpdatedDn(), "olcPPolicyConfig") );
                                ppolicyOlc = tmp;
                                ppolicyOlc->setIndex( overlays.size() );
                                (*i)->addOverlay(ppolicyOlc);
                            }
                            else
                            {
                                y2milestone("Update existing Overlay");
                                ppolicyOlc = *j;
                            }
                            if ( argMap.size() == 0 ){
                                y2milestone("Delete ppolicy overlay");
                                ppolicyOlc->clearChangedEntry();
                            } else {
                                ppolicyOlc->setStringValue("olcPpolicyDefault", 
                                    argMap->value(YCPString("defaultPolicy"))->asString()->value_cstr() );
                                if ( argMap->value(YCPString("useLockout"))->asBoolean()->value() == true )
                                {
                                    ppolicyOlc->setStringValue("olcPpolicyUseLockout", "TRUE");
                                }
                                else
                                {
                                    ppolicyOlc->setStringValue("olcPpolicyUseLockout", "FALSE");
                                }
                                if ( argMap->value(YCPString("hashClearText"))->asBoolean()->value() == true )
                                {
                                    ppolicyOlc->setStringValue("olcPpolicyHashCleartext", "TRUE");
                                }
                                else
                                {
                                    ppolicyOlc->setStringValue("olcPpolicyHashCleartext", "FALSE");
                                }
                            }
                        }
                        ret = true;
                    }
                    else if ( dbComponent == "syncprov" )
                    {
                        OlcOverlayList overlays = (*i)->getOverlays();
                        OlcOverlayList::const_iterator j = overlays.begin();
                        for (; j != overlays.end(); j++ )
                        {
                            if ( (*j)->getType() == "syncprov" )
                            {
                                break;
                            }
                        }
                        YCPMap argMap = arg->asMap();
                        if ( j == overlays.end() && argMap.size() == 0 )
                        {
                            y2milestone("Empty overlay nothing to do");
                        }
                        else
                        {
                            boost::shared_ptr<OlcSyncProvOl> syncprovOlc;
                            if ( j == overlays.end() )
                            {
                                boost::shared_ptr<OlcSyncProvOl> tmp(new OlcSyncProvOl((*i)->getUpdatedDn()) );
                                syncprovOlc = tmp;
                                syncprovOlc->setIndex(0);
                                (*i)->addOverlay(syncprovOlc);
                            }
                            else
                            {
                                syncprovOlc = boost::dynamic_pointer_cast<OlcSyncProvOl>(*j);
                            }
                            if( argMap.size() == 0 )
                            {
                                syncprovOlc->clearChangedEntry();
                            }
                            else
                            {
                                if( ! argMap->value(YCPString("checkpoint")).isNull() )
                                {
                                    YCPMap cpMap = argMap->value(YCPString("checkpoint"))->asMap();
                                    syncprovOlc->setCheckPoint( cpMap->value(YCPString("ops"))->asInteger()->value(),
                                                                cpMap->value(YCPString("min"))->asInteger()->value() );
                                }
                                if( ! argMap->value(YCPString("sessionlog")).isNull() )
                                {
                                    syncprovOlc->setSessionLog( argMap->value(YCPString("sessionlog"))->asInteger()->value() );
                                }
                                else
                                {
                                    syncprovOlc->setStringValue( "olcSpSessionlog", "" );
                                }
                            }
                        }
                        ret = true;
                    }
                    else if ( dbComponent == "acl" )
                    {
                        YCPList argList = arg->asList();
                        OlcAccessList aclList;
                        for ( int j = 0; j < argList->size(); j++ )
                        {
                            boost::shared_ptr<OlcAccess> acl( new OlcAccess() );

                            YCPMap target;
                            // create the "to dn.<scope>=<dn> ...." part of the ACL
                            if (! argList->value(j)->asMap()->value(YCPString("target")).isNull() )
                            {
                                target = argList->value(j)->asMap()->value(YCPString("target"))->asMap();
                            }
                            if (target.size() == 0 )
                            {
                                acl->setFilter("");
                                acl->setAttributes("");
                                acl->setDnType("");
                                acl->setDn("");
                                acl->setMatchAll(true);
                            }
                            else
                            {
                                acl->setMatchAll(false);
                                if (! target->value( YCPString("dn") ).isNull() )
                                {
                                    acl->setDnType(std::string("dn.") +
                                                  target->value(YCPString("dn"))->asMap()->value(YCPString("style"))->asString()->value_cstr() );
                                    acl->setDn( target->value( YCPString("dn") )->asMap()->value( YCPString("value") )->asString()->value_cstr() );
                                }
                                if (! target->value( YCPString("filter") ).isNull() )
                                {
                                    acl->setFilter( target->value( YCPString("filter") )->asString()->value_cstr() );
                                }
                                if (! target->value( YCPString("attrs") ).isNull() )
                                {
                                    acl->setAttributes( target->value( YCPString("attrs") )->asString()->value_cstr() );
                                }
                            }

                            // now the " by <xyz> <read|write>" part
                            YCPList accessList = argList->value(j)->asMap()->value( YCPString("access") )->asList();
                            OlcAclByList byList;
                            for ( int k = 0; k < accessList->size(); k++ )
                            {
                                std::string type( accessList->value(k)->asMap()->value( YCPString("type") )->asString()->value_cstr() );
                                std::string value;
                                if ( type == "dn.subtree" || type == "dn.base" || type == "group" )
                                {
                                    value = accessList->value(k)->asMap()->value( YCPString("value") )->asString()->value_cstr();
                                }
                                std::string level( accessList->value(k)->asMap()->value( YCPString("level") )->asString()->value_cstr() );
                                std::string control( "stop" );
                                YCPValue ctrlVal(accessList->value(k)->asMap()->value( YCPString("control") ) );
                                if ( ! ctrlVal.isNull() )
                                {
                                    control = ctrlVal->asString()->value_cstr() ;
                                }
                                y2debug("level %s, type %s, value %s control %s", 
                                            level.c_str(), type.c_str(), value.c_str(), control.c_str() );
                                boost::shared_ptr<OlcAclBy> by( new OlcAclBy( level, type, value, control ) );
                                byList.push_back( by );
                            }
                            acl->setByList(byList);
                            aclList.push_back(acl);
                        }
                        (*i)->replaceAccessControl(aclList);
                        ret = true;
                    }
                    else if ( dbComponent == "limits" )
                    {
                        YCPList argList = arg->asList();
                        OlcLimitList limitList;
                        for ( int j = 0; j < argList->size(); j++ )
                        {
                            boost::shared_ptr<OlcLimits> limit( new OlcLimits() );
                            YCPMap limitMap = argList->value(j)->asMap();
                            limit->setSelector(limitMap->value(YCPString("selector"))->asString()->value_cstr() );

                            YCPList ycpLimitValues = limitMap->value(YCPString("limits"))->asList();
                            pairlist limitVals;
                            for ( int k=0; k < ycpLimitValues->size(); k++ )
                            {
                                YCPMap valMap = ycpLimitValues->value(k)->asMap();
                                limitVals.push_back( make_pair(valMap->value(YCPString("type"))->asString()->value_cstr(),
                                                               valMap->value(YCPString("value"))->asString()->value_cstr() ) );
                            }
                            limit->setLimits(limitVals);
                            limitList.push_back(limit);
                        }
                        (*i)->replaceLimits(limitList);
                        ret = true;
                    }
                    else if ( dbComponent == "syncrepl" )
                    {
                        if ( path->length() == 3 )
                        {
                            std::string srComp = path->component_str(2);
                            y2milestone("Component '%s'", srComp.c_str());
                            if ( srComp == "add" )
                            {
                                YCPMap argMap = arg->asMap();
                                boost::shared_ptr<OlcSyncRepl> sr( new OlcSyncRepl() );
                                ret = this->ycpMap2SyncRepl( argMap, sr );
                                if ( ret )
                                {
                                    int rid =  this->getNextRid();
                                    y2milestone( "New Rid: %d", rid );
                                    if ( rid )
                                    {
                                        sr->setRid( rid );
                                        (*i)->addSyncRepl(sr);
                                    }
                                }
                            }
                            else if ( srComp == "del" )
                            {
                                LDAPUrl destUrl( std::string( arg->asString()->value_cstr() ) );
                                OlcSyncReplList srl = (*i)->getSyncRepl();
                                OlcSyncReplList::iterator j;
                                for ( j = srl.begin(); j != srl.end(); j++ )
                                {
                                    std::string proto, target;
                                    int port;
                                    (*j)->getProviderComponents( proto, target, port );
                                    if ( proto == destUrl.getScheme() &&
                                         target == destUrl.getHost() &&
                                         port == destUrl.getPort() )
                                    {
                                        srl.erase(j);
                                        break;
                                    }
                                }
                                (*i)->setSyncRepl( srl );
                                ret = true;
                            }
                        }
                        else
                        {
                            // for backwards compatiblity
                            YCPMap argMap = arg->asMap();
                            if ( argMap->size() > 0 )
                            {
                                ret = true;
                                OlcSyncReplList srl = (*i)->getSyncRepl();
                                boost::shared_ptr<OlcSyncRepl> sr;
                                if ( srl.empty() )
                                {
                                    sr = boost::shared_ptr<OlcSyncRepl>(new OlcSyncRepl());
                                    srl.push_back(sr);

                                    // find available rid (rid must be unique accross the server)
                                    OlcDatabaseList::const_iterator k;
                                    int largest_rid=0;
                                    for ( k = databases.begin(); k != databases.end() ; k++ )
                                    {
                                        OlcSyncReplList srl1 = (*k)->getSyncRepl();
                                        if ( srl1.empty() )
                                        {
                                            continue;
                                        }
                                        boost::shared_ptr<OlcSyncRepl> sr1;
                                        int currid = (*srl1.begin())->getRid();
                                        if ( currid > largest_rid )
                                        {
                                            largest_rid=currid;
                                        }
                                    }
                                    sr->setRid(largest_rid+1);
                                }
                                else
                                {
                                    sr = *srl.begin();
                                }
                                ret = this->ycpMap2SyncRepl( argMap, sr );
                                (*i)->setSyncRepl(srl);
                            }
                            else
                            {
                                // clear syncrepl config
                                (*i)->setStringValue("olcSyncRepl", "" );
                                ret = true;
                            }
                        }
                    }
                    else if ( dbComponent == "updateref" )
                    {
                        YCPMap updaterefMap = arg->asMap();
                        if ( updaterefMap.size() > 0 )
                        {
                            LDAPUrl updaterefUrl;
                            updaterefUrl.setScheme( updaterefMap->value(YCPString("protocol"))->asString()->value_cstr() );
                            updaterefUrl.setHost( updaterefMap->value(YCPString("target"))->asString()->value_cstr() );
                            updaterefUrl.setPort( updaterefMap->value(YCPString("port"))->asInteger()->value() );
                            (*i)->setStringValue("olcUpdateRef", updaterefUrl.getURLString() );
                        }
                        else
                        {
                            (*i)->setStringValue("olcUpdateRef", "" );
                        }
                        ret = true;
                    }
                    else if ( dbComponent == "dbconfig" )
                    {
                        YCPList argList = arg->asList();
                        StringList dbConfList;
                        for ( int j = 0; j < argList->size(); j++ )
                        {
                            dbConfList.add( argList->value(j)->asString()->value_cstr() );
                        }
                        (*i)->setStringValues("olcDbConfig", dbConfList );
                        ret = true;
                    }
                    else if ( dbComponent == "mirrormode" )
                    {
                        YCPBoolean argVal = arg->asBoolean();
                        (*i)->setMirrorMode( argVal->value() );
                        ret = true;
                    }
                    else
                    {
                        lastError->add(YCPString("summary"), YCPString("Write Failed") );
                        std::string msg = "Unsupported SCR path: `.ldapserver.database.";
                        msg += path->toString().c_str();
                        msg += "`";
                        lastError->add(YCPString("description"), YCPString(msg) );
                        ret = false;
                    }
                }
                break;
            }
        }
        if ( dbDeleted ) // renumber other dbs
        {
            i++;
            // renumber remaining databases
            for( ; i != databases.end(); i++ )
            {
                y2milestone("%s needs to be renumbered", (*i)->getSuffix().c_str() );
                (*i)->setIndex( (*i)->getEntryIndex() + 1, true );

                // update the overlays' DNs accordingly
                OlcOverlayList overlays = (*i)->getOverlays();
                OlcOverlayList::const_iterator l = overlays.begin();
                for (; l != overlays.end(); l++ )
                {
                    (*l)->newParentDn( (*i)->getUpdatedDn() );
                }
            }
        }
    }

    return YCPBoolean(ret);
}

int getSchemaLine( std::istream &input, std::string &schemaLine)
{
    if ( ! getline(input, schemaLine) )
    {
        return -1;
    }
    while ( input &&
        (input.peek() == ' ' || input.peek() == '\t'))
    {
        std::string cat;
        if (input.peek() == '\t' )
            schemaLine += ' ';
        input.ignore();
        getline(input, cat);
        schemaLine += cat;
    }
    return 0;
}

YCPBoolean SlapdConfigAgent::WriteSchema( const YCPPath &path,
                                    const YCPValue &arg,
                                    const YCPValue &arg2)
{
    y2milestone("Path %s Length %ld ", path->toString().c_str(),
                                      path->length());

    y2milestone("WriteSchema");
    if ( schema.size() == 0 && olc.hasConnection() )
    {
        schema =  olc.getSchemaNames();
    }
    std::string subpath = path->component_str(0);
    if ( subpath == "addFromLdif" )
    {
        std::string filename = arg->asString()->value_cstr();
        y2milestone("adding Ldif File: %s", filename.c_str());
        std::ifstream ldifFile(filename.c_str());
        if ( ! ldifFile )
        {
            lastError->add( YCPString("summary"),
                    YCPString("Error while opening Schema file") );
            lastError->add( YCPString("description"),
                    YCPString("") );
            return YCPBoolean(false);
        }
        try {
            LdifReader ldif(ldifFile);
            if ( ldif.readNextRecord() )
            {
                LDAPEntry entry, oldEntry;
                entry = ldif.getEntryRecord();
                y2milestone("adding <%s> to SchemaList", entry.getDN().c_str() );
                boost::shared_ptr<OlcSchemaConfig> schemaCfg(new OlcSchemaConfig(oldEntry, entry));
                int index = schema.size();
                if ( ! schema.empty() && (*schema.begin())->getName() == "schema" )
                {
                    index--;
                }
                std::string cn = *entry.getAttributeByName("cn")->getValues().begin();
                deleteableSchema.push_back(cn);
                schemaCfg->setIndex( index , true );
                schema.push_back( schemaCfg );
            }
            return YCPBoolean(true);
        } catch ( std::runtime_error e ) {
            std::string errstring = "Error while parsing LDIF file: " + filename;
            lastError->add(YCPString("summary"),
                    YCPString(errstring) );
            lastError->add(YCPString("description"), 
                    YCPString(std::string( e.what() ) ) );
            return YCPBoolean(false);
        }
    } 
    else if ( subpath == "addFromSchemafile" )
    {
        std::string filename = arg->asString()->value_cstr();
        y2milestone("reading Schema from File: %s", filename.c_str());
        // build RDN for new schema entry
        std::string::size_type pos = filename.find_last_of('/');
        std::string rdn = filename.substr(pos+1);
        // does file name end with .schema?
        if ( rdn.size() >= 7 )
        {
            if ( rdn.substr( rdn.size()-7 ) == ".schema" )
            {
                rdn = rdn.substr(0, rdn.size()-7 );
            }
        }
        std::string dn = "cn=";
        dn += rdn;
        dn += ",cn=schema,cn=config";
        y2milestone("RDN will be: %s", dn.c_str());
        
        std::ifstream input(filename.c_str());
        if ( ! input )
        {
            lastError->add( YCPString("summary"),
                    YCPString("Error while opening Schema file") );
            lastError->add( YCPString("description"),
                    YCPString("") );
            return YCPBoolean(false);
        }
        std::string schemaLine;
        LDAPEntry entry(dn), oldEntry;
        entry.addAttribute( LDAPAttribute( "objectClass", "olcSchemaConfig" ) ); 
        entry.addAttribute( LDAPAttribute( "cn", rdn ) ); 

        while ( ! getSchemaLine(input, schemaLine) )
        {
            y2debug("Read schema Line: %s", schemaLine.c_str() );
            // empty or comment?
            if ( schemaLine[0] == '#' || schemaLine.size() == 0 )
            {
                y2debug("Comment or empty" );
                continue;
            }
            std::string::size_type pos=schemaLine.find_last_not_of(" \t\n");
            if (pos != std::string::npos )
                schemaLine.erase(pos+1, std::string::npos );

            // FIXME: should validate Schema syntax here
            std::string oid("objectidentifier");
            std::string at("attributetype");
            std::string oc("objectclasses");
            if ( equal(schemaLine.begin(), schemaLine.begin()+sizeof("objectidentifier")-1, 
                       oid.begin(), caseIgnoreCompare ) )
            {
                pos = schemaLine.find_first_not_of(" \t", sizeof("objectidentifier") );
                schemaLine.erase(0, pos );
                y2debug("objectIdentifier Line <%s>", schemaLine.c_str() );
                entry.addAttribute(LDAPAttribute("olcObjectIdentifier", schemaLine) );
            } 
            else if ( equal(schemaLine.begin(), schemaLine.begin()+sizeof("attributetype")-1, 
                       at.begin(), caseIgnoreCompare ) )
            {
                int pos = schemaLine.find_first_not_of(" \t", sizeof("attributetype") );
                schemaLine.erase(0, pos );
                entry.addAttribute(LDAPAttribute("olcAttributeTypes", schemaLine) );
            }

            else if ( equal(schemaLine.begin(), schemaLine.begin()+sizeof("objectclass")-1, 
                       oc.begin(), caseIgnoreCompare ) )
            {
                int pos = schemaLine.find_first_not_of(" \t", sizeof("objectClass") );
                schemaLine.erase(0, pos );
                entry.addAttribute(LDAPAttribute("olcObjectClasses", schemaLine) );
            }
            else
            {
                lastError->add(YCPString("summary"),
                        YCPString("Error while parsing Schema file") );
                lastError->add(YCPString("description"), YCPString("") );
                return YCPBoolean(false);
            }
        }
        boost::shared_ptr<OlcSchemaConfig> schemaCfg(new OlcSchemaConfig(oldEntry, entry));
        int index = schema.size();
        if ( ! schema.empty() && (*schema.begin())->getName() == "schema" )
        {
            index--;
        }
        std::string cn = *entry.getAttributeByName("cn")->getValues().begin();
        deleteableSchema.push_back(cn);
        schemaCfg->setIndex( index , true );
        schema.push_back( schemaCfg );

        return YCPBoolean(true);
    }
    else if ( subpath == "remove" )
    {
        std::string name = arg->asString()->value_cstr();
        y2milestone("remove Schema Entry: %s", name.c_str());
        std::list<std::string>::iterator j;
        for ( j = deleteableSchema.begin(); j != deleteableSchema.end(); j++ )
        {
            if ( name == *j )
            {
                deleteableSchema.erase(j);
                break;
            }
        }
        if ( j == deleteableSchema.end() )
        {
            y2milestone( "Schema %s is not deleteable", name.c_str() );
            return YCPBoolean(false);
        }
        OlcSchemaList::iterator i;
        for (i = schema.begin(); i != schema.end(); i++ )
        {
            if ( (*i)->getName() == name )
            {
                OlcSchemaList::iterator k;
                for ( k = i; k != schema.end(); k++ )
                {
                    (*k)->setIndex( (*k)->getEntryIndex() - 1, true );
                }
                schema.erase(i);
                break;
            }
        }
        return YCPBoolean(true);
    }
    return YCPBoolean(false);
}

YCPString SlapdConfigAgent::ConfigToLdif() const
{
    y2milestone("ConfigToLdif");
    std::ostringstream ldif;
    if ( ! globals )
    {
        throw std::runtime_error("Configuration not initialized. Can't create LDIF dump." );
    }
    ldif << globals->toLdif() << std::endl;
    if ( schemaBase )
    {
        ldif << schemaBase->toLdif() << std::endl;
        OlcSchemaList::const_iterator j;
        for ( j = schema.begin(); j != schema.end() ; j++ )
        {
            ldif << (*j)->toLdif() << std::endl;
        }
    }
    OlcDatabaseList::const_iterator i = databases.begin();
    for ( ; i != databases.end(); i++ )
    {
        ldif << (*i)->toLdif() << std::endl;
        OlcOverlayList overlays = (*i)->getOverlays();
        OlcOverlayList::iterator k;
        for ( k = overlays.begin(); k != overlays.end(); k++ )
        {
            ldif << (*k)->toLdif() << std::endl;
        }
    }
    return YCPString(ldif.str());
}

static void initLdapParameters( const YCPValue &arg, std::string &targetUrl,
        bool &starttls, std::string &binddn, std::string &bindpw, std::string &basedn);
bool SlapdConfigAgent::remoteBindCheck( const YCPValue &arg )
{
    y2milestone("remoteBindCheck");
    std::string targetUrl, binddn, bindpw, basedn;
    bool starttls;
    initLdapParameters(arg, targetUrl ,starttls, binddn, bindpw, basedn);
    try 
    {
        LDAPConnection c( targetUrl );
        if (starttls)
        {
            startTlsCheck(c);
        }
        bindCheck(c, binddn, bindpw);
    }
    catch( LDAPException e )
    {
        std::string details = e.getResultMsg();
        if (! e.getServerMsg().empty() )
        {
            details += ": ";
            details += e.getServerMsg();
        }
        lastError->add(YCPString("description"), YCPString( details ) );
        y2milestone("Error connecting to the LDAP Server \"%s\". %s: %s", 
                targetUrl.c_str(), 
                lastError->value(YCPString("summary"))->asString()->value_cstr(),
                details.c_str());
        return false;
    }
    return true; 
}

bool SlapdConfigAgent::remoteSyncCheck( const YCPValue &arg )
{
    y2milestone("remoteBindCheck");
    std::string targetUrl, binddn, bindpw, basedn;
    bool starttls;
    initLdapParameters(arg, targetUrl ,starttls, binddn, bindpw, basedn);
    try 
    {
        LDAPConnection c( targetUrl );
        if (starttls)
        {
            startTlsCheck(c);
        }
        bindCheck(c, binddn, bindpw);
        syncCheck(c, basedn );
    }
    catch( LDAPException e )
    {
        std::string details = e.getResultMsg();
        if (! e.getServerMsg().empty() )
        {
            details += ": ";
            details += e.getServerMsg();
        }
        lastError->add(YCPString("description"), YCPString( details ) );
        y2milestone("Error connection to the LDAP Server \"%s\". %s: %s", 
                targetUrl.c_str(), 
                lastError->value(YCPString("summary"))->asString()->value_cstr(),
                details.c_str());
        return false;
    }
    return true; 
}

void initLdapParameters( const YCPValue &arg, 
        std::string &url,
        bool &starttls,
        std::string &binddn,
        std::string &bindpw,
        std::string &basedn)
{
    YCPMap argMap = arg->asMap();
    YCPMap target = argMap->value(YCPString("target"))->asMap();
    LDAPUrl targetUrl;
    targetUrl.setScheme( target->value(YCPString("protocol"))->asString()->value_cstr() );
    targetUrl.setHost( target->value(YCPString("target"))->asString()->value_cstr() );
    targetUrl.setPort( target->value(YCPString("port"))->asInteger()->value() );
    url = targetUrl.getURLString();
    starttls = argMap->value(YCPString("starttls"))->asBoolean()->value();
    binddn = argMap->value(YCPString("binddn"))->asString()->value_cstr();
    bindpw = argMap->value(YCPString("credentials"))->asString()->value_cstr();
    basedn = argMap->value(YCPString("basedn"))->asString()->value_cstr();
}

// FIXME:
// Until the TLS parameters can't be setup correctly with LDAPC++
// the start_tls check might return false positives
// 
void SlapdConfigAgent::startTlsCheck( LDAPConnection &c)
{
    try {
        c.start_tls();
    }
    catch( LDAPException e )
    {
        lastError->add(YCPString("summary"), YCPString("StartTLS operation failed") );
        throw;
    }
}

void SlapdConfigAgent::bindCheck( LDAPConnection &c, const std::string &binddn, const std::string &bindpw)
{
    try {
        c.bind(binddn, bindpw);
    }
    catch( LDAPException e )
    {
        lastError->add(YCPString("summary"), YCPString("LDAP authentication failed") );
        throw;
    }
}

void SlapdConfigAgent::syncCheck( LDAPConnection &c, const std::string &basedn )
{
    try{
        // Simple LDAPSync Request Control (refreshOnly, no cookie)
        const char ctrl[] = { 0x30, 0x03, 0x0a, 0x01, 0x01 };
        std::string ctrlStr(ctrl, sizeof(ctrl) );
        LDAPCtrl syncCtrl( std::string("1.3.6.1.4.1.4203.1.9.1.1"), true, ctrlStr );
        LDAPControlSet cs;
        cs.add(syncCtrl);
        LDAPConstraints searchCons;
        searchCons.setServerControls( &cs );
        c.search(basedn, LDAPConnection::SEARCH_BASE, "(objectclass=*)", 
            StringList(), false, &searchCons );
    }
    catch( LDAPException e )
    {
        lastError->add(YCPString("summary"), YCPString("Initiating the LDAPsync Operation failed") );
        throw;
    }
}

class CompareUri
{
    private:
        const std::string &theUri;

    public:
        CompareUri( const std::string &val ) : theUri(val) {}

        bool operator() ( const OlcServerId &id ) const
        {
            return theUri == id.getServerUri();
        }
};

class CompareId
{
    private:
        int theId;

    public:
        CompareId( int val ) : theId(val) {}

        bool operator() ( const OlcServerId &id ) const
        {
            return theId == id.getServerId();
        }
};

void SlapdConfigAgent::assignServerId( const std::string &uri )
{
    // check if uri has already a Id assigned
    std::vector<OlcServerId> serverIds = globals->getServerIds();

    std::vector<OlcServerId>::const_iterator found;
    found = find_if(serverIds.begin(), serverIds.end(), CompareUri(uri) );
    if ( found != serverIds.end() )
    {
        y2milestone("Found ServerId %s", found->toStringVal().c_str() );
        return;
    }

    for ( int j=1; j < 999; j++ )
    {
        found = find_if(serverIds.begin(), serverIds.end(), CompareId(j) );
        if ( found == serverIds.end() )
        {
            y2milestone( "Free ServerId %d", j);
            globals->addServerId( OlcServerId( j, uri ) );
            return;
        }
    }
}

class CompareRid
{
    private:
        int theRid;

    public:
        CompareRid( int val ) : theRid(val) {}

        bool operator() ( const boost::shared_ptr<OlcSyncRepl> sr ) const
        {
            return theRid == sr->getRid();
        }
};

int SlapdConfigAgent::getNextRid() const
{
    OlcDatabaseList::const_iterator i;
    int rid;
    for ( rid = 1; rid < 999; rid++ )
    {
        bool isFree = true;

        for ( i = databases.begin(); i != databases.end() ; i++ )
        {
            OlcSyncReplList::const_iterator found;
            OlcSyncReplList srl = (*i)->getSyncRepl();
            found = find_if( srl.begin(), srl.end(), CompareRid(rid) );
            if ( found != srl.end() )
            {
                isFree = false;
                break;
            }
        }
        if ( isFree )
        {
            return rid;
        }
    }
    return 0;
}

bool SlapdConfigAgent::ycpMap2SyncRepl( const YCPMap &srMap, boost::shared_ptr<OlcSyncRepl> sr )
{
    bool ret = true;
    YCPMap providerMap = srMap->value(YCPString("provider"))->asMap();
    std::string protocol( providerMap->value(YCPString("protocol"))->asString()->value_cstr() );
    std::string target( providerMap->value(YCPString("target"))->asString()->value_cstr() );
    int port = providerMap->value(YCPString("port"))->asInteger()->value();
    std::string type( srMap->value(YCPString("type"))->asString()->value_cstr() );
    std::string basedn( srMap->value(YCPString("basedn"))->asString()->value_cstr() );
    std::string binddn( srMap->value(YCPString("binddn"))->asString()->value_cstr() );
    std::string cred( srMap->value(YCPString("credentials"))->asString()->value_cstr() );
    bool starttls = false;
    if (! srMap->value(YCPString("starttls")).isNull() )
    {
        starttls = srMap->value(YCPString("starttls"))->asBoolean()->value();
    }

    LDAPUrl prvuri;
    prvuri.setScheme(protocol);
    prvuri.setHost(target);
    if ( ( protocol == "ldap" && port != 389 ) || ( protocol == "ldaps" && port != 636 ) )
    {
        prvuri.setPort(port);
    }

    sr->setType( type );
    sr->setProvider( prvuri );
    sr->setSearchBase( basedn );
    sr->setBindDn( binddn );
    sr->setCredentials( cred );
    // default retry (every 120 seconds)
    sr->setRetryString( "120 +" );
    sr->setTlsReqCert("demand");

    if ( starttls )
    {
        sr->setStartTls( OlcSyncRepl::StartTlsCritical );
    }
    else
    {
        sr->setStartTls( OlcSyncRepl::StartTlsNo );
    }

    if ( type == "refreshOnly" )
    {
        if ( srMap->value(YCPString("interval")).isNull() )
        {
            lastError->add(YCPString("summary"), YCPString("Writing SyncRepl config failed") );
            lastError->add(YCPString("description"), YCPString("\"RefreshOnly needs Interval\"") );
            ret = false;
        }
        else
        {
            YCPMap ivMap =  srMap->value(YCPString("interval"))->asMap();
            int days = ivMap->value(YCPString("days"))->asInteger()->value();
            int hours = ivMap->value(YCPString("hours"))->asInteger()->value();
            int mins = ivMap->value(YCPString("mins"))->asInteger()->value();
            int secs = ivMap->value(YCPString("secs"))->asInteger()->value();

            if ( days == 0 && hours == 0 && mins == 0 && secs == 0 )
            {
                lastError->add(YCPString("summary"), YCPString("Writing SyncRepl config failed") );
                lastError->add(YCPString("description"), YCPString("\"Syncrepl Interval is 00:00:00\"") );
                ret = false;
            }
            else
            {
                sr->setInterval( days, hours, mins, secs );
            }
        }
    }
    return ret;
}
