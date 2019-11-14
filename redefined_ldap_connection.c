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
#include <stdlib.h> 
#define BIND_DN "cn=users,dc=etersoft,dc=ru"
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
			"GSSAPI",	
			NULL,
			NULL,
			LDAP_SASL_INTERACTIVE,
			_sasl_interact, //_sasl_interact,
			ctx );



	if ( rc != LDAP_SUCCESS) 
	{
		fprintf(stderr, "ERROR ldap_sasl_interactive_bind_s: %s\n", ldap_err2string(rc) /* for output about the error */);

	}
	else 
	{
		printf("SUCCESSFULL bind \n");
	}
	
	LDAPMessage *res, *msg;
	BerElement *ber;
	int num_entries = 0, num_references = 0, global_counter = 0;
	int msg_type, parse_rc;
	char *a, *dn, *matched_msg = NULL, *error_msg = NULL;;
	char **vals;// **referrals;
	LDAPControl **serverctrls;
	

	//PERFORMING LDAP operations 
	rc = ldap_search_ext_s(
			ld,
			"cn=users,dc=etersoft,dc=ru",
			LDAP_SCOPE_SUBTREE,
			"(sAMAccountName=konstantin)",
			NULL,
			0,
			NULL,
			NULL,
			NULL,
			LDAP_NO_LIMIT,
			&res);	

	if (rc != LDAP_SUCCESS)
		fprintf(stderr, "ERROR ldap_search: %s\n", ldap_err2string(rc));
	else {
		printf("SUCCESSFULL SEARCH \n");
		num_entries = ldap_count_entries(ld, res);
		num_references = ldap_count_references(ld, res);
		
		printf("SUCCESSFULL search, number of entries %d, number of references %d \n", num_entries, num_references);

		// ITERATE THROUGH THE RESULTS
		for (msg = ldap_first_message(ld, res); msg != NULL; msg = ldap_next_message(ld, msg)) {
	
			// Determining type of the message
			msg_type = ldap_msgtype(msg);

			switch(msg_type) {
			case LDAP_RES_SEARCH_ENTRY:
				// print DN of the entry
				printf("This is search entry \n");

				 if ((dn = ldap_get_dn(ld, res)) != NULL) {
					printf("dn = %s\n", dn);
					ldap_memfree(dn);
				}
				// Iterate through attributes 

				for ( a = ldap_first_attribute( ld, res, &ber ); a != NULL; a = ldap_next_attribute( ld, res, ber ) ) {
					if ((vals = ldap_get_values(ld, res, a )) != NULL) {
						for (int i = 0; vals[i] != NULL; ++i)
							printf("%s: %s\n", a, vals[i]);
						}
					ldap_value_free(vals);
				}		

				ldap_memfree(a);
				
				break;

			case LDAP_RES_SEARCH_REFERENCE:
					printf("This is reference \n");
					break;

			case LDAP_RES_SEARCH_RESULT: 
				printf("This is search result \n");
				
				parse_rc = ldap_parse_result( ld, msg, &rc, &matched_msg, &error_msg, NULL, &serverctrls, 0 ); 
				
				if (parse_rc != LDAP_SUCCESS) {
					fprintf(stderr, "ERROR ldap_parse_result %s\n", ldap_err2string(parse_rc));
					ldap_unbind(ld);

					return(1);
				}
				/* Check the results of the LDAP search operation. */

				if ( rc != LDAP_SUCCESS ) {
					fprintf( stderr, "ldap_search_ext: %s\n", ldap_err2string( rc ) );
					//:ldap_get_lderrno( ld, &matched_msg, &error_msg );
					
					if ( error_msg != NULL && *error_msg != '\0' ) {
						fprintf( stderr, "%s\n", error_msg );
					}

					if ( matched_msg != NULL && *matched_msg != '\0' ) {
						fprintf( stderr, "Part of the DN that matches an existing entry: %s\n", matched_msg );
					}

				} else {
					printf( "Search completed successfully.\n"

							"Entries found: %d\n"

							"Search references returned: %d\n"

							"Counted to %d while waiting for the search operation.\n",

							num_entries, num_references, global_counter );

				}
				/*
				else {
					printf("SUCCESSFULL search, number of entries %d, number of references%d \n", num_entries, num_references);
				}
				*/
				break;
			default: 
				break;
			}
		
		/* const char* mechlist;
		
		int sasl_check = sasl_listmech(ctx, NULL,"(",",",")",&mechlist,NULL,NULL);		
		
		if (sasl_check != SASL_OK) {
		
			printf("ERROR SASL: %d \n", sasl_errors(sasl_check));
		}
		else {

			printf("Supported mechanisms: %s\n", mechlist);
		}
		*/
	//DISCONNECT FROM THE SERVER 
	//
		}
	}
	const char *mechlist;

	int sasl_check = sasl_listmech(NULL, NULL,"(",",",")",&mechlist,NULL,NULL);

	if (sasl_check != SASL_OK) {

		printf("ERROR SASL: %d\n", sasl_check);
	}
	else {

		printf("Supported mechanisms: %s\n", mechlist);
	}

	const char **list = sasl_global_listmech();
	if(!list) printf("sasl_global_listmech failure");

	printf(" [");
	int flag = 0;
	for(int lup = 0; list[lup]; lup++) {
		if(flag) printf(",");
		else flag++;
		printf("%s",list[lup]);
	}
	printf("]\n");


}






