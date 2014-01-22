#include <LDAPConnection.h>
#include <stdlib.h>
int main(int argc, char** argv)
{
	if ( argc != 3 )
	{
		std::cerr << "usage: " << argv[0] << " <ldap-uri> <path-to-ca-cert>" << std::endl;
		exit(-1);
	}
	std::string uri(argv[1]);
	setenv("LDAPTLS_REQCERT", "hard", 1);
	setenv("LDAPTLS_CACERT", argv[2], 1);
	try 
	{
		LDAPConnection lc( uri );
		lc.start_tls();
	}
	catch ( LDAPException e )
	{
		std::cerr << e << std::endl;
		exit(-1);
	}
	exit(0);
}
