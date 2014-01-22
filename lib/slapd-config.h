/*
 * slapd-config.h
 *
 * A library for accessing OpenLDAP's configuration backend
 *
 * Author: Ralf Haferkamp <rhafer@suse.de>
 *
 * $Id$
 *
 */

#ifndef BACK_CONFIG_TEST_H
#define BACK_CONFIG_TEST_H
#include <LDAPConnection.h>
#include <LDAPResult.h>
#include <LDAPUrl.h>
#include <string>
#include <iostream>
#include <sstream>
#include <map>
#include <vector>
#include <LDAPEntry.h>
#include <LDAPAttrType.h>
#include <boost/shared_ptr.hpp>

#define SLAPD_LOG_DEBUG 3
#define SLAPD_LOG_INFO  2
#define SLAPD_LOG_ERR   1

typedef void (SlapdConfigLogCallback) (int level, const std::string &msg, 
            const char* file=0, const int line=0, const char* function=0 );

class OlcConfigEntry
{
    public:
        static OlcConfigEntry* createFromLdapEntry( const LDAPEntry& le);
        static bool isDatabaseEntry( const LDAPEntry& le);
        static bool isScheamEntry( const LDAPEntry& le);
        static bool isOverlayEntry( const LDAPEntry& le);
        static bool isGlobalEntry( const LDAPEntry& le);

        inline OlcConfigEntry() : m_dbEntry(), m_dbEntryChanged() {}
        inline OlcConfigEntry(const LDAPEntry& le) : m_dbEntry(le), m_dbEntryChanged(le) {}
        inline OlcConfigEntry(const LDAPEntry& le, const LDAPEntry& le1) 
                    : m_dbEntry(le), m_dbEntryChanged(le1) {}

        inline std::string getDn() const { 
            return m_dbEntry.getDN();
        }
        inline std::string getUpdatedDn() const { 
            return m_dbEntryChanged.getDN();
        }
        inline const LDAPEntry& getChangedEntry() const {
            return m_dbEntryChanged;
        }

        virtual void clearChangedEntry();     
        virtual void resetEntries( const LDAPEntry &le );

        bool isNewEntry() const;
        bool isDeletedEntry() const;

        LDAPModList entryDifftoMod() const;
        
        StringList getStringValues(const std::string &type) const;
        void setStringValues(const std::string &type, const StringList &values);

        // shortcuts for single-valued Attributes
        std::string getStringValue(const std::string &type) const;
        void setStringValue(const std::string &type, const std::string &value);
        void addStringValue(const std::string &type, const std::string &value);

        void addIndexedStringValue( const std::string &type, 
                const std::string &value, int index );

        int getIntValue( const std::string &type ) const;
        void setIntValue( const std::string &type, int value );

        void setIndex( int index, bool origEntry = false );

        int getEntryIndex() const;

        virtual std::string toLdif() const;

    protected:
        virtual void resetMemberAttrs() {};
        virtual void updateEntryDn( bool origEntry = false);
        virtual const std::list<std::string>* getOrderedAttrs() const {
            return &orderedAttrs;
        }

        int entryIndex;
        LDAPEntry m_dbEntry;
        LDAPEntry m_dbEntryChanged;

        static const std::list<std::string> orderedAttrs;
};

enum IndexType {
    Default,
    Present,
    Eq,
    Approx,
    Sub,
    SpecialSubInitial,
    SpecialSubAny,
    SpecialSubFinal,
    SpecialNoLang,
    SpecialNoSubTypes,
};

typedef std::map<std::string, std::vector<IndexType> > IndexMap;

class OlcOverlay : public OlcConfigEntry
{
    public:
        static OlcOverlay* createFromLdapEntry( const LDAPEntry& le);
        OlcOverlay( const LDAPEntry &le );
        OlcOverlay( const std::string &type, const std::string &parent, const std::string &oc="" );
        const std::string getType() const;

        void newParentDn( const std::string &parent );

    protected:
        virtual void resetMemberAttrs();
        virtual void updateEntryDn( bool origEntry = false );
        std::string m_type;
        std::string m_parent;
};

class OlcSyncProvOl : public OlcOverlay
{
    public:
        OlcSyncProvOl( const LDAPEntry &le ) : OlcOverlay( le ) {}
        OlcSyncProvOl( const std::string &parent) : OlcOverlay("syncprov",parent,"olcSyncProvConfig") {}
        void getCheckPoint(int &ops, int &min) const;
        void setCheckPoint(int ops, int min);

        bool getSessionLog(int &slog) const;
        void setSessionLog(int slog);
};

class OlcAclBy
{
    public:
        inline OlcAclBy( const std::string& level,
                  const std::string& type,
                  const std::string& value = "",
                  const std::string& control = "" ) : 
                        m_type(type), m_value(value), m_control(control)
        {
            setLevel(level);
        }

        inline std::string getLevel() const
        {
            return m_level;
        }

        inline std::string getType() const
        {
            return m_type;
        }

        inline std::string getValue() const
        {
            return m_value;
        }
        
        inline std::string getControl() const
        {
            return m_control;
        }

        inline void setLevel( const std::string &level )
        {

            if ( !level.empty() &&
                 level != "none" && level != "disclose" && level != "auth" &&
                 level != "compare" && level != "read" &&
                 level != "write" && level != "manage" )
            {
                throw std::runtime_error( "Unsupported access level <" + level + ">" );
            }
            m_level = level;
        }
        inline void setType( const std::string &type )
        {
            m_type = type;
        }
        inline void setValue( const std::string &value )
        {
            m_value = value;
        }
        inline void setControl( const std::string &value )
        {
            m_control = value;
        }


    private:
        std::string m_level;
        std::string m_type;
        std::string m_value;
        std::string m_control;
};

typedef std::list<boost::shared_ptr<OlcAclBy> > OlcAclByList;
class OlcAccess
{
    public:
        inline OlcAccess() {}

        OlcAccess( const std::string &aclString);
        void setFilter( const std::string& filter );
        void setAttributes( const std::string& attrs );
        void setDnType( const std::string& dnType );
        void setDn( const std::string& dn );
        void setMatchAll( bool matchAll );
        void setByList( const OlcAclByList &bylist);

        std::string getFilter() const;
        std::string getAttributes() const;
        std::string getDnType() const;
        std::string getDnValue() const;
        bool matchesAll() const;
        OlcAclByList getAclByList() const;

        std::string toAclString() const;

    private:
        std::string m_filter;
        std::string m_attributes;
        std::string m_dn_value;
        std::string m_dn_type;
        bool m_all;
        OlcAclByList m_byList;
};

typedef std::list<std::pair<std::string,std::string> > pairlist;
class OlcLimits
{
    public:
        inline OlcLimits() {}

        OlcLimits( const std::string &limitsString);
        void setSelector( const std::string &value );
        void setLimits ( const pairlist&value );
        
        std::string getSelector() const;
        pairlist getLimits() const;

        std::string toLimitsString() const;
    private:
        std::string m_selector;
        pairlist m_limits;
};

class OlcSyncRepl
{
    public:
        enum StartTls {
            StartTlsNo,
            StartTlsYes,
            StartTlsCritical
        };

        OlcSyncRepl( const std::string &syncreplLine="" );
        const static std::string RID;
        const static std::string PROVIDER;
        const static std::string BASE;
        const static std::string TYPE;
        const static std::string BINDMETHOD;
        const static std::string BINDDN;
        const static std::string CREDENTIALS;
        const static std::string INTERVAL;
        const static std::string STARTTLS;
        const static std::string RETRY;
        const static std::string TLS_REQCERT;
        const static std::string TIMEOUT;
        const static std::string NETWORK_TIMEOUT;

        std::string toSyncReplLine() const;

        void setRid( int value );
        void setProvider( const std::string &value );
        void setProvider( const LDAPUrl &value );
        void setType( const std::string &value );
        void setSearchBase( const std::string &value );
        void setBindDn( const std::string &value );
        void setCredentials( const std::string &value );
        void setInterval( int days, int hours, int mins, int secs );
        void setStartTls( StartTls tls );
        void setRetryString( const std::string &value );
        void setTlsReqCert( const std::string &value );
        void setNetworkTimeout( int sec );
        void setTimeout( int sec );

        int getRid() const;
        LDAPUrl getProvider() const;
        void getProviderComponents( std::string &proto, std::string &target, int &port) const;
        std::string getType() const;
        std::string getSearchBase() const;
        std::string getBindDn() const;
        std::string getCredentials() const;
        void getInterval( int &days, int &hours, int &mins, int &secs ) const;
        StartTls getStartTls() const;
        std::string getTlsReqCert() const;
        int getNetworkTimeout() const;
        int getTimeout() const;

    private:
        int rid;
        LDAPUrl provider;
        std::string type;
        std::string searchbase;
        std::string bindmethod;
        std::string binddn;
        std::string credentials;
        std::string retryString;
        std::string tlsReqCert;
        int refreshOnlyDays;
        int refreshOnlyHours;
        int refreshOnlyMins;
        int refreshOnlySecs;
        int networkTimeout;
        int timeout;
        std::vector<std::pair<std::string, std::string> > otherValues;
        StartTls starttls;
};

class OlcSecurity
{
    public:
        OlcSecurity(const std::string &securityVal="");
        std::string toSecturityVal() const;

        int getSsf(const std::string& key) const;
        void setSsf(const std::string& key, int value);

    private:
        std::map<std::string, int> secMap;
};

class OlcServerId
{
    public:
        OlcServerId( const std::string &idVal );
        OlcServerId( int id, const std::string &uri ) : serverId( id ), serverUri( uri ) {}

        std::string toStringVal() const;
        int getServerId() const;
        std::string getServerUri() const;

        void setServerId( int id );
        void setServerUri( const std::string &uri );

    private:
        int serverId;
        std::string serverUri;
};

typedef std::list<boost::shared_ptr<OlcOverlay> > OlcOverlayList;
typedef std::list<boost::shared_ptr<OlcAccess> > OlcAccessList;
typedef std::list<boost::shared_ptr<OlcLimits> > OlcLimitList;
typedef std::list<boost::shared_ptr<OlcSyncRepl> > OlcSyncReplList;

class OlcDatabase : public OlcConfigEntry
{
    public :
        static OlcDatabase* createFromLdapEntry( const LDAPEntry& le );
        
        OlcDatabase( const LDAPEntry &le );
        OlcDatabase( const std::string& type );

        static bool isBdbDatabase( const LDAPEntry& le );
        
        void setSuffix( const std::string &suffix);
        void setRootDn( const std::string &rootdn);
        void setRootPw( const std::string &rootpw);
        void setMirrorMode( bool mm );

        const std::string getSuffix() const;
        const std::string getType() const;
        bool getMirrorMode() const;

        bool getAcl( OlcAccessList& accessList ) const;
        virtual void addAccessControl( const std::string& acl, int index=-1 );
        virtual void replaceAccessControl( const OlcAccessList& acllist );
        
        bool getLimits( OlcLimitList& limitList ) const;
        void replaceLimits( const OlcLimitList& limits );

        OlcSyncReplList getSyncRepl() const;
        void setSyncRepl( const OlcSyncReplList& srl );
        void addSyncRepl( const std::string& value, int index=-1 );
        void addSyncRepl( const boost::shared_ptr<OlcSyncRepl> sr, int index=-1 );

        void addOverlay(boost::shared_ptr<OlcOverlay> overlay);
        OlcOverlayList& getOverlays() ;

    protected:
        virtual void resetMemberAttrs();
        virtual void updateEntryDn( bool origEntry = false );
        virtual const std::list<std::string>* getOrderedAttrs() const {
            return &orderedAttrs;
        }
        std::string m_type;
        OlcOverlayList m_overlays;

        static const std::list<std::string> orderedAttrs;
};

class OlcBdbDatabase : public  OlcDatabase 
{
    public:
        OlcBdbDatabase( const std::string& type = "hdb");
        OlcBdbDatabase( const LDAPEntry& le );
        void setDirectory( const std::string &dir);

        virtual IndexMap getDatabaseIndexes() const;
        virtual std::vector<IndexType> getDatabaseIndex( const std::string &attr ) const;
        virtual void addIndex(const std::string& attr, const std::vector<IndexType>& idx);
        virtual void deleteIndex(const std::string& attr);

        int getEntryCache() const;
        void setEntryCache( int cachesize );

        int getIdlCache() const;
        void setIdlCache( int cachesize );

        void setCheckPoint( int kbytes, int min );
        void getCheckPoint( int &kbytes, int& min) const;
};

class OlcTlsSettings;

class OlcGlobalConfig : public OlcConfigEntry 
{
    public:
        OlcGlobalConfig();
        explicit OlcGlobalConfig( const LDAPEntry &le);

        const std::vector<std::string> getLogLevelString() const;
        void setLogLevel(const std::list<std::string> &level);
        void addLogLevel(std::string level);

        const std::vector<std::string> getAllowFeatures() const;
        void setAllowFeatures( const std::list<std::string> &features );
        const std::vector<std::string> getDisallowFeatures() const;
        void setDisallowFeatures( const std::list<std::string> &features );

        OlcTlsSettings getTlsSettings() const;
        void setTlsSettings( const OlcTlsSettings& tls);

        const std::vector<OlcServerId> getServerIds() const;
        void setServerIds(const std::vector<OlcServerId> &serverIds);
        void addServerId(const OlcServerId &serverId);
};

class OlcSchemaConfig : public OlcConfigEntry
{
    public:
        OlcSchemaConfig();
        OlcSchemaConfig(const LDAPEntry &e);
        OlcSchemaConfig(const LDAPEntry &e1, const LDAPEntry &e2);
        virtual void clearChangedEntry();     
        const std::string& getName() const;
        const std::vector<LDAPAttrType> getAttributeTypes() const;
        static const std::string schemabase;

    protected:
        virtual void updateEntryDn( bool origEntry = false);

    private:
        virtual void resetMemberAttrs();
        std::string m_name;
};

class OlcTlsSettings {
    public :
        OlcTlsSettings( const OlcGlobalConfig &ogc );

        void applySettings( OlcGlobalConfig &ogc ) const;

        int getCrlCheck() const;
        int getVerifyClient() const;
        const std::string& getCaCertDir() const;
        const std::string& getCaCertFile() const;
        const std::string& getCertFile() const;
        const std::string& getCertKeyFile() const;
        const std::string& getCrlFile() const;

        void setCrlCheck();
        void setVerifyClient();
        void setCaCertDir(const std::string& dir);
        void setCaCertFile(const std::string& file);
        void setCertFile(const std::string& file);
        void setCertKeyFile(const std::string& file);
        void setCrlFile(const std::string& file);

    private:
        int m_crlCheck;
        int m_verifyCient;
        std::string m_caCertDir;
        std::string m_caCertFile;
        std::string m_certFile;
        std::string m_certKeyFile;
        std::string m_crlFile;
};

typedef std::list<boost::shared_ptr<OlcDatabase> > OlcDatabaseList;
typedef std::list<boost::shared_ptr<OlcSchemaConfig> > OlcSchemaList;

class OlcConfig {

    public:
        OlcConfig(LDAPConnection *lc=0 );

        bool hasConnection() const;
        inline LDAPConnection* getLdapConnection()
        {
            return m_lc;
        }

        boost::shared_ptr<OlcGlobalConfig> getGlobals();
        OlcDatabaseList getDatabases();
        OlcSchemaList getSchemaNames();

        void setGlobals( OlcGlobalConfig &olcg);
        void updateEntry( OlcConfigEntry &oce );

        void waitForBackgroundTasks();

        static SlapdConfigLogCallback *logCallback;
        static void setLogCallback( SlapdConfigLogCallback *lcb );

    private:
        LDAPConnection *m_lc;
};


#endif /* BACK_CONFIG_TEST_H */
