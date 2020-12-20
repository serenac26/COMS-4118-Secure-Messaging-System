#include <stdio.h>
#include <openssl/ssl.h>

int main(int mama, char **moo) {
  
  // Refer to:
  // http://h30266.www3.hpe.com/odl/axpos/opsys/vmsos84/BA554_90007/ch04s03.html
  // for more information

  SSL_library_init(); /* load encryption & hash algorithms for SSL */         	
  SSL_load_error_strings(); /* load the error strings for good error reporting */

  // TLSv1_1_server_method is deprecated
  // Can switch back if inconvenient
  const SSL_METHOD *mamamethod = TLS_server_method();
  SSL_CTX *ctx = SSL_CTX_new(mamamethod);
  
  // Only accept the LATEST and GREATEST in TLS
  SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
  SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);
}