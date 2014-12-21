/*
 * =====================================================================================
 *
 *       Filename:  credit_holder.h
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  2014年12月14日 13时35分37秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  Guo Ang
 *   Organization:  
 *
 * =====================================================================================
 */

#ifndef __CREDIT_HOLDER_H__
#define __CREDIT_HOLDER_H__

#include <utpm_functions.h>

typedef UINT32 CD_RESULT;

/* ERRORS */
#define CD_SUCCESS 0
#define CD_OUT_OF_BUFFER_LEN 1
#define CD_KEY_NOT_FOUND 2
#define CD_READ_KEY_FAILED 3
#define CD_CREATE_CONTEXT_FAILED 4
#define CD_CREATE_KEY_FAILED 5
#define CD_CERTFILE_NOT_FOUND 6
#define CD_CERT_NOT_VALID 7
#define CD_KEYFILE_NOT_FOUND 8
#define CD_UNMARSHAL_FAILED 9
#define CD_LOAD_KEY_FAILED 10
#define CD_UNBIND_KEYS_FAILED 11
#define CD_CLOSE_CONTEXT_FAILED 12
#define CD_INSERT_KEY_FAILED 13

/* limits */
#include <limits.h>
#define CD_DESC_MAX 256
#define CD_KEY_LEN_MAX 2048

typedef struct _CD_cert {
    char *username;
    char *role;
    int security_level;
    BYTE *signature;
} CD_cert;

/* 即将外部保存的密钥存入keyring */
CD_RESULT CD_loadKeys();

/* 将credit_holder使用的RSA密钥load进UKEY */
CD_RESULT CD_loadRootKey(UTPM_KEY_HANDLE *);
/* 解密用户证书相应的密钥并存入keyring */
CD_RESULT CD_unbindAndInsertKeys(UTPM_KEY_HANDLE *, CD_cert *);
/* 将密钥存入keyring */
CD_RESULT CD_insertKey(char *desc, void *buf, size_t len);
CD_RESULT CD_insertUserKey(char *username, void *buf, size_t len);
CD_RESULT CD_insertRoleKey(char *role, void *buf, size_t len);
CD_RESULT CD_insertSLKey(int security_level, void *buf, size_t len);

/* 使用UKEY生成一个新的密钥,
 * 只有root可以调用,
 * 密钥存放到CD_keyFile
CD_RESULT CD_createKey(char *desc);
CD_RESULT CD_createUserKey(char *username);
CD_RESULT CD_createRoleKey(char *role);
 * */

/* 从keyring中读取密钥 */
CD_RESULT CD_getKey(char *desc, char *buffer, size_t *len);
/* 从keyring中读取用户密钥 */
CD_RESULT CD_getUserKey(char *username, char *buffer, size_t *len);
/* 从keyring中读取角色密钥 */
CD_RESULT CD_getRoleKey(char *role, char *buffer, size_t *len);
/* 从keyring中读取安全等级密钥 */
CD_RESULT CD_getSLKey(int security_level, char *buffer, size_t *len);

/* 读取用户证书 */
CD_RESULT CD_readCert(CD_cert *cert, char *path);
/* 验证用户证书 */
CD_RESULT CD_verifyCert(CD_cert *cert);
/* free用户证书 */
CD_RESULT CD_freeCert(CD_cert *cert);

#endif
