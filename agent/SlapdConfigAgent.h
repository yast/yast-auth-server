/* SlapdConfigAgent.h
 *
 * Authors: Ralf Haferkamp <rhafer@suse.de>
 *
 * $Id$
 */

#ifndef _SlapdConfigAgent_h
#define _SlapdConfigAgent_h

#include <Y2.h>
#include <scr/SCRAgent.h>
#include <boost/shared_ptr.hpp>
#include "slapd-config.h"
/**
 * @short An interface class between YaST2 and Ldap Agent
 */
class SlapdConfigAgent : public SCRAgent {
    public :
        SlapdConfigAgent();
        virtual ~SlapdConfigAgent();
        virtual YCPValue Read( const YCPPath &path,
                               const YCPValue &arg = YCPNull(),
                               const YCPValue &opt = YCPNull());

        virtual YCPBoolean Write( const YCPPath &path,
                                const YCPValue &arg,
                                const YCPValue &arg2 = YCPNull());

        virtual YCPMap Error( const YCPPath &path );

        virtual YCPValue Execute( const YCPPath &path,
                                  const YCPValue &arg = YCPNull(),
                                  const YCPValue &arg2 = YCPNull());

        virtual YCPList Dir( const YCPPath &path);

        virtual YCPValue otherCommand( const YCPTerm& term);

    protected:
        YCPValue ReadGlobal( const YCPPath &path,
                            const YCPValue &arg = YCPNull(),
                            const YCPValue &opt = YCPNull());

        YCPValue ReadDatabases( const YCPPath &path,
                            const YCPValue &arg = YCPNull(),
                            const YCPValue &opt = YCPNull());

        YCPValue ReadSchemaList( const YCPPath &path,
                            const YCPValue &arg = YCPNull(),
                            const YCPValue &opt = YCPNull());

        YCPValue ReadDatabase( const YCPPath &path,
                             const YCPValue &arg = YCPNull(),
                             const YCPValue &opt = YCPNull());

        YCPValue ReadSchema( const YCPPath &path,
                             const YCPValue &arg = YCPNull(),
                             const YCPValue &opt = YCPNull());
 
        YCPBoolean WriteGlobal( const YCPPath &path,
                             const YCPValue &arg = YCPNull(),
                             const YCPValue &opt = YCPNull());
        YCPBoolean WriteDatabase( const YCPPath &path,
                             const YCPValue &arg = YCPNull(),
                             const YCPValue &opt = YCPNull());
        YCPBoolean WriteSchema( const YCPPath &path,
                             const YCPValue &arg = YCPNull(),
                             const YCPValue &opt = YCPNull());
        YCPString ConfigToLdif() const;
        bool remoteBindCheck( const YCPValue &arg );
        bool remoteSyncCheck( const YCPValue &arg );
        void startTlsCheck( LDAPConnection &c);
        void bindCheck( LDAPConnection &c, 
                        const std::string &binddn, 
                        const std::string &bindpw);
        void syncCheck( LDAPConnection &c,
                        const std::string &basedn );
        void assignServerId( const std::string &uri );
        int getNextRid() const;
        bool ycpMap2SyncRepl( const YCPMap &srMap, boost::shared_ptr<OlcSyncRepl> sr );

    private:
        YCPMap lastError;
        LDAPConnection *m_lc;
        OlcConfig olc;
        OlcDatabaseList databases;
        OlcSchemaList schema;
        std::list<std::string> deleteableSchema; 
        boost::shared_ptr<OlcGlobalConfig> globals;
        boost::shared_ptr<OlcSchemaConfig> schemaBase;
};

#endif /* _SlapdConfigAgent_h */

