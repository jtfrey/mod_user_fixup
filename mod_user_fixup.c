
#include "apr.h"
#include "apr_strings.h"
#include "apr_lib.h"            /* for apr_isspace */
#include "apr_base64.h"         /* for apr_base64_decode et al */

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"

#include <ctype.h>

const char    *suffix_to_remove = "@udel.edu";
const size_t  suffix_to_remove_len = 9;

module AP_MODULE_DECLARE_DATA user_fixup_module;

static int fixup_remote_user(request_rec *r)
{
  const char *user, *pw;
  const char *auth_line;
  char *decoded_line;
  int length;

  /* Get the appropriate header */
  auth_line = apr_table_get(r->headers_in, (PROXYREQ_PROXY == r->proxyreq)
                                            ? "Proxy-Authorization"
                                            : "Authorization");

  if (!auth_line) {
    /* No authorization header */
    return DECLINED;
  }
      
  ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
              "Original encoded auth header: %s", auth_line);

  if (strcasecmp(ap_getword(r->pool, &auth_line, ' '), "Basic")) {
    /* We only handle basic auth scheme */
    return DECLINED;
  }

  /* Skip leading spaces. */
  while (apr_isspace(*auth_line)) auth_line++;
  
  /* Decode the line: */
  decoded_line = apr_palloc(r->pool, apr_base64_decode_len(auth_line) + 1);
  length = apr_base64_decode(decoded_line, auth_line);
  /* Null-terminate the string. */
  decoded_line[length] = '\0';

  user = ap_getword_nulls(r->pool, (const char**)&decoded_line, ':');
  pw = decoded_line;
  
  /* Now that we have the username and password, check the username
   * for our suffix we wish to discard:
   */
  length = strlen(user);
  if ( length < suffix_to_remove_len ) {
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
               "Username not long enough: %s", user);
  } else {
    const char    *end_of_suffix = suffix_to_remove + suffix_to_remove_len;
    const char    *end_of_user = user + length;
    int           suffix_len = suffix_to_remove_len;
    
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
              "Username to check: %s", user);
    
    /* Start at the NUL terminator on both strings: */
    while ( suffix_len ) {
      end_of_suffix--, end_of_user--;
      suffix_len--;
      if ( tolower(*end_of_user) != *end_of_suffix ) break;
    }
    if ( ! suffix_len ) {
      /* We matched the suffix, so we should redo the Authorization header
       * with the suffix removed.
       */
      struct iovec    string_bits[3] = {
                          { .iov_base = (void*)user, .iov_len = end_of_user - user },
                          { .iov_base = (void*)":", .iov_len = 1 },
                          { .iov_base = (void*)pw, .iov_len = strlen(pw) }
                        };
      apr_size_t      decoded_line_len;
      char            *new_auth_line;
      
      decoded_line = apr_pstrcatv(r->pool, string_bits, 3, &decoded_line_len);
      ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                 "Altered auth credential: %s", decoded_line);
      
      /* Allocate space for the altered header: */
      length = 5 + 1 + apr_base64_encode_len(decoded_line_len) + 1;
      new_auth_line = apr_palloc(r->pool, length);
      
      /* Copy in the "basic" authorization scheme token: */
      strcpy(new_auth_line, "Basic ");
      
      /* Base64-encode the credential into the new header and NUL-terminate
       * the thing:
       */
      length = apr_base64_encode(new_auth_line + 6, decoded_line, decoded_line_len);
      new_auth_line[6 + length] = '\0';
      
      ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                  "Altered encoded auth header: %s", new_auth_line);
      
      /* Stash back in the request header table */
      apr_table_setn(r->headers_in, (PROXYREQ_PROXY == r->proxyreq)
                                            ? "Proxy-Authorization"
                                            : "Authorization",
                                    new_auth_line
                              );
    }
  }
  
  return DECLINED;
}

static void register_hooks(apr_pool_t *p)
{
    ap_hook_header_parser(fixup_remote_user, NULL, NULL, APR_HOOK_FIRST);
}

module AP_MODULE_DECLARE_DATA user_fixup_module =
{
    STANDARD20_MODULE_STUFF,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    register_hooks              /* register hooks */
};
