#define LDAP_DEPRECATED 1

#include <stdio.h> 
#include <ldap.h> 
 
#define BIND_DN "uid=konstantin,ou=ALL,dc=for_work,dc=com"
#define HOSTNAME "localhost" 

int main(int argc, char **argv) 
{
	typedef struct {
		char *mech;
		char *realm;
		char *authcid;
		char *passwd;
		char *authzid;
	} _sasl_ctx;

	// INIT LDAP SESSION 
	LDAP *ld; // specify ldap structure 
	int ldap_default_port, version;	// 389 - default LDAP port

	// server to what I want to connect
	char *ldap_host = "dc.etersoft.ru";

	ldap_default_port = LDAP_PORT;


	// init session with LDAP servers, ldap_init = not open connection to LDAP server 
	if ((ld = ldap_init(ldap_host, ldap_default_port)) == NULL) // error in structure
	{
		perror("ERROR in ldap_init");
		return 1;
	}
	
	_sasl_ctx *ctx;

	ctx = (_sasl_ctx *)ldap_memalloc(sizeof(_sasl_ctx));
	memset(ctx, '\0', sizeof(_sasl_ctx));
	if (ctx->mech == NULL)  ldap_get_option(ld, LDAP_OPT_X_SASL_MECH, &ctx->mech);
	if (ctx->realm == NULL) ldap_get_option(ld, LDAP_OPT_X_SASL_REALM, &ctx->realm);	        
	if (ctx->authcid == NULL)  ldap_get_option(ld, LDAP_OPT_X_SASL_AUTHCID, &ctx->authcid);		 
	if (ctx->authzid == NULL) ldap_get_option(ld, LDAP_OPT_X_SASL_AUTHZID, &ctx->authzid);

	if( ctx->mech == "GSSAPI")
	printf("now going on binding to LDAP server: %s:%d\n", ldap_host, ldap_default_port );
	printf("with DN = %s\n", BIND_DN);
	
	int debug = 256; 
	// Specify LDAP version 
	version = LDAP_VERSION3;
	ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &version);
 	ldap_set_option(ld, LDAP_OPT_DEBUG_LEVEL, &debug); 
	// ldap_set_option(ld,DAP_OPT_RECONNECT /* LDAP option */, LDAP_OPT_ON /* for set option */);
	// ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION /* for make use LDAP3 version features */, LDAP_OPT_ON);
	
	// for bind request to LDAP-server, LDAP_SUCCESS return value if all good
	int rc = ldap_sasl_interactive_bind_s(
			ld,
			NULL,
			ctx->mech,
			NULL,
			NULL,
			LDAP_SASL_QUIET,
			NULL,
			ctx ); 



	if ( rc != LDAP_SUCCESS) 
	{
		fprintf(stderr, "ERROR ldap_simple_bind_s: %s\n\n", ldap_err2string(rc) /* for output about the error */);
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






