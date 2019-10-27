#define LDAP_DEPRECATED 1

#include <stdio.h> 
#include <ldap.h> 
 
#define BIND_DN "uid=konstantin,ou=ALL,dc=for_work,dc=com"

#define BIND_PW "hifalutin"
int main(int argc, char **argv) 
{
	// INIT LDAP SESSION 
	LDAP *ld; // specify ldap structure 
	int ldap_default_port, version;	// 389 - default LDAP port

	// server to what I want to connect
	char *ldap_host = "dc.etersoft.ru";

	ldap_default_port = LDAP_PORT;


	// init session with LDAP servers, ldap_init = not open connection to LDAP server 
	if ((ld = ldap_init(ldap_host, ldap_default_port)) == NULL) // error in structure
	{
		perror("Erorr in ldap_init");
		return 1;
	}

	printf("now going on binding to LDAP server: %d", ldap_default_port);
	printf("with DN = %s", BIND_DN);

	// Specify LDAP version 
	version = LDAP_VERSION3;
	ldap_set_option(ld /* LDAP structure for information about connection */, LDAP_OPT_PROTOCOL_VERSION, &version);
	
	
	// SET SESSION PREFERENCES
	// ldap_set_option(ld,DAP_OPT_RECONNECT /* LDAP option */, LDAP_OPT_ON /* for set option */);
	// ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION /* for make use LDAP3 version features */, LDAP_OPT_ON);
	
	// for bind request to LDAP-server, LDAP_SUCCESS return value if all good
	int rc = ldap_simple_bind_s(ld, BIND_DN, BIND_PW);

	if ( rc != LDAP_SUCCESS) 
	{
		fprintf(stderr, "ldap_simple_bind_s: %s\n\n", ldap_err2string(rc) /* for output about the error */);
		return 1;
	}
	else 
	{
		printf("SUCCESSFULL bind");
	}
	
	
	//PERFORMING LDAP operations 
	


	//DISCONNECT FROM THE SERVER 
	//


}


