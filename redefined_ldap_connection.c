#define LDAP_DEPRECATED 1

struct sasl_conn {
	char *mech;
	char *realm;
	char *authcid;
	char *passwd;
	char *authzid;
} ;

#include <stdio.h> 
#include <ldap.h> 
#include <sasl/sasl.h> 

#define BIND_DN "uid=konstantin,ou=ALL,dc=for_work,dc=com"
#define HOSTNAME "localhost" 



static int _sasl_interact(LDAP *ld, unsigned flags, void *defaults, void *interact)
{
	const char *p;
	return LDAP_SUCCESS;

	sasl_conn_t *ctx = (sasl_conn_t *)defaults;
	
	sasl_interact_t *in = (sasl_interact_t *)interact;
		        
	for ( ; in->id != SASL_CB_LIST_END; in++) {
		p = NULL;
		switch(in->id) {
		case SASL_CB_GETREALM:
			p = ctx->realm;
			break;
		case SASL_CB_AUTHNAME:
			p = ctx->authcid;
			break;
		case SASL_CB_USER:
			p = ctx->authzid;
			break;
		case SASL_CB_PASS:
			p = ctx->passwd;
			break;
		}
		if (p) {
			in->result = p;
			in->len = strlen(p);
		}
	}
	return LDAP_SUCCESS;
}

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
		perror("ERROR in ldap_init");
		return 1;
	}
	
	sasl_conn_t *ctx;
	

	ctx = (sasl_conn_t *)ldap_memalloc(sizeof(sasl_conn_t));
	memset(ctx, '\0', sizeof(sasl_conn_t));
	if (ctx->mech == NULL)  ldap_get_option(ld, LDAP_OPT_X_SASL_MECH, &ctx->mech);
	if (ctx->realm == NULL) ldap_get_option(ld, LDAP_OPT_X_SASL_REALM, &ctx->realm);	        
	if (ctx->authcid == NULL)  ldap_get_option(ld, LDAP_OPT_X_SASL_AUTHCID, &ctx->authcid);		 
	if (ctx->authzid == NULL) ldap_get_option(ld, LDAP_OPT_X_SASL_AUTHZID, &ctx->authzid);

	if (ctx->mech == NULL) ctx->mech = "GSSAPI";
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
			LDAP_SASL_INTERACTIVE,
			_sasl_interact, //_sasl_interact,
			ctx );



	if ( rc != LDAP_SUCCESS) 
	{
		fprintf(stderr, "ERROR ldap_sasl_interactive_bind_s: %s\n\n", ldap_err2string(rc) /* for output about the error */);
		return 1;
	}
	else 
	{
		printf("SUCCESSFULL bind\n");
	}
	
	
	//PERFORMING LDAP operations 



	//DISCONNECT FROM THE SERVER 
	//


}






