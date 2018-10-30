/*
  +----------------------------------------------------------------------+
  | PHP Version 7                                                        |
  +----------------------------------------------------------------------+
  | Copyright (c) 1997-2018 The PHP Group                                |
  +----------------------------------------------------------------------+
  | This source file is subject to version 3.01 of the PHP license,      |
  | that is bundled with this package in the file LICENSE, and is        |
  | available through the world-wide-web at the following url:           |
  | http://www.php.net/license/3_01.txt                                  |
  | If you did not receive a copy of the PHP license and are unable to   |
  | obtain it through the world-wide-web, please send a note to          |
  | license@php.net so we can mail you a copy immediately.               |
  +----------------------------------------------------------------------+
  | Author:                                                              |
  +----------------------------------------------------------------------+
*/

/* $Id$ */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_ini.h"
#include "ext/standard/info.h"
#include "php_sm.h"
#include "zend_smart_str.h"
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/pem.h>

static int le_sm;

static const char* id = "1234567812345678";

static const char* openssl_key_typename = "OpenSSL key";

#define STR_TO_LOWER(s, len)                                \
  do {                                                      \
    char* _s = s;                                           \
    for (int i = 0; i < len; ++i, ++_s) *_s = tolower(*_s); \
  } while (0)

PHP_FUNCTION(sm2_pkey_from_pri) {
  char* pri;
  size_t pri_len;

  int nid;
  BIGNUM* pri_b = NULL;
  EC_POINT* pub_b = NULL;
  EC_KEY* ec_key = NULL;
  EC_GROUP* group;
  EVP_PKEY* pkey = NULL;
  int key_tid;
  int ok = 0;

  if (zend_parse_parameters(ZEND_NUM_ARGS(), "s", &pri, &pri_len) == FAILURE) {
    return;
  }

  nid = OBJ_sn2nid("SM2");
  if (nid == NID_undef) {
    RETVAL_FALSE;
    goto done;
  }

  ec_key = EC_KEY_new_by_curve_name(nid);
  if (ec_key == NULL) {
    RETVAL_FALSE;
    goto done;
  }

  group = (EC_GROUP*)EC_KEY_get0_group(ec_key);
  EC_GROUP_set_asn1_flag(group, OPENSSL_EC_NAMED_CURVE);

  pri_b = BN_new();
  if (!pri_b) {
    RETVAL_FALSE;
    goto done;
  }

  if (!BN_hex2bn(&pri_b, pri) || !EC_KEY_set_private_key(ec_key, pri_b)) {
    RETVAL_FALSE;
    goto done;
  }

  EC_KEY_set_private_key(ec_key, pri_b);

  group = (EC_GROUP*)EC_KEY_get0_group(ec_key);
  pub_b = EC_POINT_new(group);
  if (!EC_POINT_mul(group, pub_b, pri_b, NULL, NULL, NULL)) {
    RETVAL_FALSE;
    goto done;
  }
  if (!EC_KEY_set_public_key(ec_key, pub_b)) {
    RETVAL_FALSE;
    goto done;
  }

  pkey = EVP_PKEY_new();
  if (!EC_KEY_check_key(ec_key) || !EVP_PKEY_assign_EC_KEY(pkey, ec_key)) {
    RETVAL_FALSE;
    goto done;
  }

  key_tid = zend_fetch_list_dtor_id(openssl_key_typename);
  RETURN_RES(zend_register_resource(pkey, key_tid));
  ok = 1;

done:
  if (ok) {
    if (ec_key != NULL) {
      EC_KEY_free(ec_key);
    }
    if (pkey != NULL) {
      EVP_PKEY_free(pkey);
    }
  }
  if (pri_b != NULL) {
    BN_free(pri_b);
  }
  if (pub_b != NULL) {
    EC_POINT_free(pub_b);
  }
  RETURN_FALSE;
}

PHP_FUNCTION(sm2_pkey_from_pub) {
  char* pub;
  size_t pub_len;

  int nid;
  EC_POINT* pub_b = NULL;
  EC_KEY* ec_key = NULL;
  EC_GROUP* group;
  EVP_PKEY* pkey = NULL;
  int key_tid;
  int ok = 0;

  if (zend_parse_parameters(ZEND_NUM_ARGS(), "s", &pub, &pub_len) == FAILURE) {
    return;
  }

  nid = OBJ_sn2nid("SM2");
  if (nid == NID_undef) {
    RETVAL_FALSE;
    goto done;
  }

  ec_key = EC_KEY_new_by_curve_name(nid);
  if (ec_key == NULL) {
    RETVAL_FALSE;
    goto done;
  }

  group = (EC_GROUP*)EC_KEY_get0_group(ec_key);
  EC_GROUP_set_asn1_flag(group, OPENSSL_EC_NAMED_CURVE);

  group = (EC_GROUP*)EC_KEY_get0_group(ec_key);
  pub_b = EC_POINT_hex2point(group, pub, NULL, NULL);
  if (!pub_b || !EC_KEY_set_public_key(ec_key, pub_b)) {
    RETVAL_FALSE;
    goto done;
  }

  pkey = EVP_PKEY_new();
  if (!EC_KEY_check_key(ec_key) || !EVP_PKEY_assign_EC_KEY(pkey, ec_key)) {
    RETVAL_FALSE;
    goto done;
  }

  key_tid = zend_fetch_list_dtor_id(openssl_key_typename);
  RETURN_RES(zend_register_resource(pkey, key_tid));
  ok = 1;

done:
  if (ok) {
    if (ec_key != NULL) {
      EC_KEY_free(ec_key);
    }
    if (pkey != NULL) {
      EVP_PKEY_free(pkey);
    }
  }
  if (pub_b != NULL) {
    EC_POINT_free(pub_b);
  }
  RETURN_FALSE;
}

PHP_FUNCTION(sm2_pkey_get_public) {
  static char* mode_uncompress = "uncompress";
  static char* mode_compress = "compress";
  static char* mode_mix = "mix";

  zval* key;
  char* mode = mode_uncompress;
  size_t mode_len;
  zend_bool hex;

  int key_tid;
  EVP_PKEY* pkey;
  point_conversion_form_t form = POINT_CONVERSION_UNCOMPRESSED;
  EC_KEY* ec;
  EC_POINT* point;
  EC_GROUP* group = NULL;
  char* hr = NULL;
  unsigned char* bin = NULL;
  size_t bin_len;

  if (zend_parse_parameters(ZEND_NUM_ARGS(), "r|sb", &key, &mode, &mode_len,
                            &hex) == FAILURE) {
    return;
  }

  key_tid = zend_fetch_list_dtor_id(openssl_key_typename);
  pkey = (EVP_PKEY*)zend_fetch_resource(Z_RES_P(key), openssl_key_typename,
                                        key_tid);

  if (pkey == NULL) {
    RETVAL_FALSE;
    goto done;
  }

  if (EVP_PKEY_id(pkey) != EVP_PKEY_EC) {
    php_error_docref(NULL, E_WARNING, "must be ec key");
    RETVAL_FALSE;
    goto done;
  }

  if (EC_GROUP_get_curve_name(EC_KEY_get0_group(EVP_PKEY_get0_EC_KEY(pkey))) !=
      OBJ_sn2nid("SM2")) {
    php_error_docref(NULL, E_WARNING, "curve must be sm2");
    RETVAL_FALSE;
    goto done;
  }

  ec = EVP_PKEY_get0_EC_KEY(pkey);
  if (!ec) {
    RETVAL_FALSE;
    goto done;
  }

  point = (EC_POINT*)EC_KEY_get0_public_key(ec);
  group = EC_GROUP_dup(EC_KEY_get0_group(ec));

  if (strcmp(mode, mode_compress) == 0) {
    form = POINT_CONVERSION_COMPRESSED;
  } else if (strcmp(mode, mode_mix) == 0) {
    form = POINT_CONVERSION_HYBRID;
  }

  if (hex) {
    hr = EC_POINT_point2hex(group, point, form, NULL);
    STR_TO_LOWER(hr, strlen(hr));
    RETVAL_STRINGL(hr, strlen(hr));
    goto done;
  }

  bin_len = EC_POINT_point2buf(group, point, form, &bin, NULL);
  RETVAL_STRINGL(bin, bin_len);

done:
  if (group != NULL) {
    EC_GROUP_free(group);
  }
  if (hr != NULL) {
    free(hr);
  }
  if (bin != NULL) {
    free(bin);
  }
}

PHP_FUNCTION(sm2_pkey_get_private) {
  zval* key;
  zend_bool hex;

  int key_tid;
  EVP_PKEY* pkey;
  EC_KEY* ec;
  const BIGNUM* k;
  char* hr = NULL;
  unsigned char* bin = NULL;
  size_t bin_len;

  if (zend_parse_parameters(ZEND_NUM_ARGS(), "r|b", &key, &hex) == FAILURE) {
    return;
  }

  key_tid = zend_fetch_list_dtor_id(openssl_key_typename);
  pkey = (EVP_PKEY*)zend_fetch_resource(Z_RES_P(key), openssl_key_typename,
                                        key_tid);

  if (pkey == NULL) {
    RETVAL_FALSE;
    goto done;
  }

  if (EVP_PKEY_id(pkey) != EVP_PKEY_EC) {
    php_error_docref(NULL, E_WARNING, "must be ec key");
    RETVAL_FALSE;
    goto done;
  }

  if (EC_GROUP_get_curve_name(EC_KEY_get0_group(EVP_PKEY_get0_EC_KEY(pkey))) !=
      OBJ_sn2nid("SM2")) {
    php_error_docref(NULL, E_WARNING, "curve must be sm2");
    RETVAL_FALSE;
    goto done;
  }

  ec = EVP_PKEY_get0_EC_KEY(pkey);
  if (!ec) {
    RETVAL_FALSE;
    goto done;
  }

  k = EC_KEY_get0_private_key(ec);
  if (hex) {
    char* hr = BN_bn2hex(k);
    STR_TO_LOWER(hr, strlen(hr));
    RETVAL_STRINGL(hr, strlen(hr));
    return;
  }

  bin_len = BN_num_bytes(k);
  bin = malloc(sizeof(char) * bin_len);
  if (!bin) {
    RETVAL_FALSE;
    goto done;
  }

  BN_bn2bin(k, bin);
  RETVAL_STRINGL(bin, bin_len);

done:
  if (hr != NULL) {
    free(hr);
  }
  if (bin != NULL) {
    free(bin);
  }
}

int sm2_sign(const char* data, size_t data_len, EVP_PKEY* pkey,
             smart_str* out) {
  EVP_MD_CTX* md_ctx = NULL;
  EVP_PKEY_CTX* pk_ctx = NULL;
  zend_string* sigbuf = NULL;
  size_t siglen;
  unsigned char* sig_buf_p;
  ECDSA_SIG* sig = NULL;
  const BIGNUM* r;
  const BIGNUM* s;
  int ret = 0;

  if (EVP_PKEY_id(pkey) != EVP_PKEY_EC) {
    php_error_docref(NULL, E_WARNING, "must be ec key");
    goto done;
  }

  if (EC_GROUP_get_curve_name(EC_KEY_get0_group(EVP_PKEY_get0_EC_KEY(pkey))) !=
      OBJ_sn2nid("SM2")) {
    php_error_docref(NULL, E_WARNING, "curve must be sm2");
    goto done;
  }

  md_ctx = EVP_MD_CTX_create();
  if (!md_ctx) {
    goto done;
  }

  EVP_PKEY_set_alias_type(pkey, EVP_PKEY_SM2);

  pk_ctx = EVP_PKEY_CTX_new(pkey, NULL);
  if (!pk_ctx) {
    goto done;
  }

  EVP_PKEY_CTX_set1_id(pk_ctx, id, strlen(id));
  EVP_MD_CTX_set_pkey_ctx(md_ctx, pk_ctx);

  if (!EVP_DigestSignInit(md_ctx, NULL, EVP_sm3(), NULL, pkey)) {
    goto done;
  }

  siglen = EVP_PKEY_size(pkey);
  sigbuf = zend_string_alloc(siglen, 0);

  sig_buf_p = ZSTR_VAL(sigbuf);
  if (!EVP_DigestSignUpdate(md_ctx, data, data_len) ||
      !EVP_DigestSignFinal(md_ctx, sig_buf_p, &siglen)) {
    goto done;
  }

  sig = d2i_ECDSA_SIG(NULL, (const unsigned char**)&sig_buf_p, siglen);
  if (!sig) {
    goto done;
  }

  r = ECDSA_SIG_get0_r(sig);
  s = ECDSA_SIG_get0_s(sig);
  smart_str_alloc(out, 0, 0);
  smart_str_appends(out, BN_bn2hex(r));
  smart_str_appends(out, BN_bn2hex(s));
  STR_TO_LOWER(ZSTR_VAL(out->s), ZSTR_LEN(out->s));
  ret = 1;

done:
  if (sigbuf != NULL) {
    zend_string_free(sigbuf);
  }
  if (sig != NULL) {
    ECDSA_SIG_free(sig);
  }
  if (pk_ctx != NULL) {
    EVP_PKEY_CTX_free(pk_ctx);
  }
  if (md_ctx != NULL) {
    EVP_MD_CTX_destroy(md_ctx);
  }
  return ret;
}

PHP_FUNCTION(sm2_sign) {
  const unsigned char* data;
  size_t data_len;
  zval* key;

  int key_tid;
  EVP_PKEY* pkey;
  smart_str sig = {0};
  int sig_ok;

  if (zend_parse_parameters(ZEND_NUM_ARGS(), "sr", &data, &data_len, &key) ==
      FAILURE) {
    return;
  }

  key_tid = zend_fetch_list_dtor_id(openssl_key_typename);
  pkey = (EVP_PKEY*)zend_fetch_resource(Z_RES_P(key), openssl_key_typename,
                                        key_tid);

  if (pkey == NULL) RETURN_FALSE;

  sig_ok = sm2_sign(data, data_len, pkey, &sig);
  if (!sig_ok) {
    RETVAL_FALSE;
  }

  RETVAL_STRINGL(ZSTR_VAL(sig.s), ZSTR_LEN(sig.s));
  smart_str_free(&sig);
}

PHP_FUNCTION(sm2_sign_with_pem) {
  const unsigned char* data;
  size_t data_len;
  const unsigned char* pem;
  size_t pem_len;

  EVP_PKEY* pkey = NULL;
  BIO* bio = NULL;
  smart_str sig = {0};
  int sig_ok;

  if (zend_parse_parameters(ZEND_NUM_ARGS(), "ss", &data, &data_len, &pem,
                            &pem_len) == FAILURE) {
    return;
  }

  bio = BIO_new_mem_buf(pem, pem_len);
  if (!bio) {
    RETVAL_FALSE;
    goto done;
  }

  pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
  if (!pkey) {
    RETVAL_FALSE;
    goto done;
  }

  sig_ok = sm2_sign(data, data_len, pkey, &sig);
  if (!sig_ok) {
    RETVAL_FALSE;
    goto done;
  }

  RETVAL_STRINGL(ZSTR_VAL(sig.s), ZSTR_LEN(sig.s));
  smart_str_free(&sig);

done:
  if (pkey != NULL) {
    EVP_PKEY_free(pkey);
  }
  if (bio != NULL) {
    BIO_free(bio);
  }
}

int sm2_verify(const char* data, size_t data_len, const char* sig,
               size_t sig_len, EVP_PKEY* pkey) {
  char* r_buf = NULL;
  char* s_buf = NULL;
  BIGNUM* r = NULL;
  BIGNUM* s = NULL;
  ECDSA_SIG* sig_i = NULL;
  char* sig_d = NULL;
  size_t sig_d_len;
  EVP_MD_CTX* md_ctx = NULL;
  EVP_PKEY_CTX* pk_ctx = NULL;
  int err;

  char* r_b = malloc(sizeof(char) * 65);
  if (!r_b) {
    err = -1;
    goto done;
  }
  memcpy(r_b, sig, 64);
  r_b[64] = '\0';

  char* s_b = malloc(sizeof(char) * 65);
  if (!s_b) {
    err = -1;
    goto done;
  }
  memcpy(s_b, sig + 64, 64);
  s_b[64] = '\0';

  r = BN_new();
  if (!r) {
    err = -1;
    goto done;
  }
  BN_hex2bn(&r, r_b);

  s = BN_new();
  if (!s) {
    err = -1;
    goto done;
  }
  BN_hex2bn(&s, s_b);

  sig_i = ECDSA_SIG_new();
  if (!sig_i) {
    err = -1;
    goto done;
  }
  ECDSA_SIG_set0(sig_i, r, s);

  sig_d_len = EVP_PKEY_size(pkey);
  sig_d = malloc(sizeof(char) * sig_d_len);
  if (!sig_d) {
    err = -1;
    goto done;
  }

  unsigned char* sig_d_p = sig_d;
  sig_d_len = i2d_ECDSA_SIG(sig_i, &sig_d_p);
  if (!sig_d_len) {
    err = -1;
    goto done;
  }

  EVP_PKEY_set_alias_type(pkey, EVP_PKEY_SM2);

  md_ctx = EVP_MD_CTX_create();
  if (md_ctx == NULL) {
    err = -1;
    goto done;
  }

  pk_ctx = EVP_PKEY_CTX_new(pkey, NULL);
  if (!pk_ctx) {
    err = -1;
    goto done;
  }

  EVP_PKEY_CTX_set1_id(pk_ctx, (const uint8_t*)id, strlen(id));

  EVP_MD_CTX_set_pkey_ctx(md_ctx, pk_ctx);

  if (!EVP_DigestVerifyInit(md_ctx, NULL, EVP_sm3(), NULL, pkey)) {
    err = -1;
    goto done;
  }

  if (!EVP_DigestVerifyUpdate(md_ctx, data, data_len)) {
    err = -1;
    goto done;
  }

  err = EVP_VerifyFinal(md_ctx, sig_d, sig_d_len, pkey);

done:
  if (r_buf != NULL) {
    free(r_buf);
  }
  if (s_buf != NULL) {
    free(s_buf);
  }
  if (sig_i != NULL) {
    ECDSA_SIG_free(sig_i);
  } else {
    if (r != NULL) {
      BN_free(r);
    }
    if (s != NULL) {
      BN_free(s);
    }
  }
  if (sig_d != NULL) {
    free(sig_d);
  }
  if (pk_ctx != NULL) {
    EVP_PKEY_CTX_free(pk_ctx);
  }
  if (md_ctx != NULL) {
    EVP_MD_CTX_destroy(md_ctx);
  }
  return err;
}

PHP_FUNCTION(sm2_verify) {
  const unsigned char* data;
  size_t data_len;
  const unsigned char* sig;
  size_t sig_len;
  zval* key;

  int key_tid;
  EVP_PKEY* pkey;
  int err;

  if (zend_parse_parameters(ZEND_NUM_ARGS(), "ssr", &data, &data_len, &sig,
                            &sig_len, &key) == FAILURE) {
    return;
  }

  key_tid = zend_fetch_list_dtor_id(openssl_key_typename);
  pkey = (EVP_PKEY*)zend_fetch_resource(Z_RES_P(key), openssl_key_typename,
                                        key_tid);

  if (pkey == NULL) RETURN_LONG(-1);

  err = sm2_verify(data, data_len, sig, sig_len, pkey);
  RETURN_LONG(err);
}

PHP_FUNCTION(sm2_verify_with_pem) {
  const unsigned char* data;
  size_t data_len;
  const unsigned char* sig;
  size_t sig_len;
  const unsigned char* pem;
  size_t pem_len;

  BIO* bio = NULL;
  EVP_PKEY* pkey = NULL;
  int err;

  if (zend_parse_parameters(ZEND_NUM_ARGS(), "sss", &data, &data_len, &sig,
                            &sig_len, &pem, &pem_len) == FAILURE) {
    return;
  }

  bio = BIO_new_mem_buf(pem, pem_len);
  if (!bio) {
    RETVAL_LONG(-1);
    goto done;
  }

  pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
  if (!pkey) {
    RETVAL_LONG(-1);
    goto done;
  }

  err = sm2_verify(data, data_len, sig, sig_len, pkey);
  RETVAL_LONG(err);

done:
  if (bio != NULL) {
    BIO_free(bio);
  }
  if (pkey != NULL) {
    EVP_PKEY_free(pkey);
  }
}

PHP_MINIT_FUNCTION(sm) { return SUCCESS; }

PHP_MSHUTDOWN_FUNCTION(sm) { return SUCCESS; }

PHP_RINIT_FUNCTION(sm) {
#if defined(COMPILE_DL_SM) && defined(ZTS)
  ZEND_TSRMLS_CACHE_UPDATE();
#endif
  return SUCCESS;
}

PHP_RSHUTDOWN_FUNCTION(sm) { return SUCCESS; }

PHP_MINFO_FUNCTION(sm) {
  php_info_print_table_start();
  php_info_print_table_header(2, "sm support", "enabled");
  php_info_print_table_end();
}

const zend_function_entry sm_functions[] = {
    //
    PHP_FE(sm2_pkey_from_pri, NULL)
    //
    PHP_FE(sm2_pkey_from_pub, NULL)
    //
    PHP_FE(sm2_pkey_get_public, NULL)
    //
    PHP_FE(sm2_pkey_get_private, NULL)
    //
    PHP_FE(sm2_sign, NULL)
    //
    PHP_FE(sm2_verify, NULL)
    //
    PHP_FE(sm2_sign_with_pem, NULL)
    //
    PHP_FE(sm2_verify_with_pem, NULL)
    //
    PHP_FE_END};

zend_module_entry sm_module_entry = {
    STANDARD_MODULE_HEADER, "sm",
    sm_functions,           PHP_MINIT(sm),
    PHP_MSHUTDOWN(sm),      PHP_RINIT(sm),
    PHP_RSHUTDOWN(sm),      PHP_MINFO(sm),
    PHP_SM_VERSION,         STANDARD_MODULE_PROPERTIES};

#ifdef COMPILE_DL_SM
#ifdef ZTS
ZEND_TSRMLS_CACHE_DEFINE()
#endif
ZEND_GET_MODULE(sm)
#endif
