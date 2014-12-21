/*
 * =====================================================================================
 *
 *       Filename:  credit_holder.c
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  2014年12月19日 14时44分25秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *   Organization:  
 *
 * =====================================================================================
 */
#include <stdlib.h>
#include <keyutils.h>
#include "credit_holder.h"
#include <tpm_structures.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#include <string.h>

char CD_keyPath[] = "/etc/tcel_leon/credit_holder/keys/";
char CD_certPath[] = "/etc/tcel_leon/cert/";
char CD_rootKey[] = "/etc/tcel_leon/credit_holder/credit_holder.key";

CD_RESULT CD_getKey(char *desc, char *buffer, size_t *len) {
    size_t buffer_len = *len;
    if (buffer_len <=0)
        return CD_OUT_OF_BUFFER_LEN;
    
    key_serial_t keyID = request_key("user", desc, NULL, 0);
    if (keyID == -1)
        return CD_KEY_NOT_FOUND;

    long readLen = keyctl_read(keyID, buffer, *len);
    if (readLen > *len)
        return CD_OUT_OF_BUFFER_LEN;
    if (readLen == -1)
        return CD_READ_KEY_FAILED;

    *len = readLen;

    return CD_SUCCESS;
}

CD_RESULT CD_getUserKey(char *username, char *buffer, size_t *len) {
    char keyDesc[CD_DESC_MAX];
    sprintf(keyDesc, "CD_userKey_%s", username);
    return CD_getKey(keyDesc, buffer, len);
}

CD_RESULT CD_getRoleKey(char *role, char *buffer, size_t *len) {
    char keyDesc[CD_DESC_MAX];
    sprintf(keyDesc, "CD_roleKey_%s", role);
    return CD_getKey(keyDesc, buffer, len);
}

CD_RESULT CD_getSLKey(int security_level, char *buffer, size_t *len) {
    char keyDesc[CD_DESC_MAX];
    sprintf(keyDesc, "CD_SLKey_%d", security_level);
    return CD_getKey(keyDesc, buffer, len);
}

/*
CD_RESULT CD_createKey(char *desc) {
    if (create_tpm_context() != UTPM_SUCCESS)
        return CD_CREATE_CONTEXT_FAILED;

    UTPM_KEY wrappedKey;
    UTPM_KEY_USAGE keyUsage = TPM_KEY_BIND;
    UTPM_SECRET keyAuth = {0x04, 0x05, 0x06};
    UTPM_KEY_HANDLE parentHandle = TPM_KH_SRK;
    UTPM_SECRET parentAuth = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};

    if (create_wrap_key(parentHandle, parentAuth, keyUsage, 
                keyAuth, &wrappedKey) != UTPM_SUCCESS)
        return CD_CREATE_KEY_FAILED;

}  */

CD_RESULT CD_loadKeys() {
    CD_RESULT res;
    struct passwd *userInfo;
    userInfo = getpwuid(getuid());

    /* 1. read cert */
    CD_cert cert;
    char fileName[PATH_MAX];
    sprintf(fileName, "%s%s.cert", CD_certPath, userInfo->pw_name);
    res = CD_readCert(&cert, fileName);
    if (res != CD_SUCCESS)
        return res;

    /* 2. verify cert */
    /* FIXME */
    res = CD_verifyCert(&cert);
    if (res != CD_SUCCESS)
        return res;

    /* 3. load keys use ukey*/
    /* 3.0 create ukey context */
    if (utpm_create_context() != UTPM_SUCCESS)
        return CD_CREATE_CONTEXT_FAILED;
    /* 3.1 load credit_holder key into ukey */
    UTPM_KEY_HANDLE rootKeyHandle;
    res = CD_loadRootKey(&rootKeyHandle);
    if (res != CD_SUCCESS)
        return res;
    
    /* 3.2 unbind keys && insert keys into keyring */ 
    res = CD_unbindAndInsertKeys(&rootKeyHandle, &cert);
    if (res != CD_SUCCESS)
        return res;

    /* 3.3 close ukey context */
    if (utpm_close_context() != UTPM_SUCCESS)
        return CD_CLOSE_CONTEXT_FAILED;

    /* 4. free cert */
    res = CD_freeCert(&cert);
    if (res != CD_SUCCESS)
        return res;
}

CD_RESULT CD_unbindAndInsertKeys(UTPM_KEY_HANDLE *handle, CD_cert *cert) {
    UTPM_RESULT res;
    UTPM_SECRET auth = {0x01, 0x02};
    char filename[PATH_MAX];
    BYTE inBuffer[CD_KEY_LEN_MAX], outBuffer[CD_KEY_LEN_MAX];
    size_t inLen, outLen;
    /* user key */
    memset(filename, 0, sizeof(filename));
    sprintf(filename, "%suser/%s", CD_keyPath, cert->username);
    FILE *fp = fopen(filename, "rb");
    inLen = fread(inBuffer, sizeof(BYTE), CD_KEY_LEN_MAX, fp);
    fclose(fp);
    res = utpm_unbind_data(*handle, auth, inLen, inBuffer, &outLen, outBuffer);
    if (res != UTPM_SUCCESS)
        return CD_UNBIND_KEYS_FAILED;

    res = CD_insertUserKey(cert->username, outBuffer, outLen);
    if (res != CD_SUCCESS)
        return res;

    /* role key */
    memset(filename, 0, sizeof(filename));
    sprintf(filename, "%srole/%s", CD_keyPath, cert->role);
    fp = fopen(filename, "rb");
    inLen = fread(inBuffer, sizeof(BYTE), CD_KEY_LEN_MAX, fp);
    fclose(fp);
    res = utpm_unbind_data(*handle, auth, inLen, inBuffer, &outLen, outBuffer);
    if (res != UTPM_SUCCESS)
        return CD_UNBIND_KEYS_FAILED;

    res = CD_insertRoleKey(cert->role, outBuffer, outLen);
    if (res != CD_SUCCESS)
        return res;

    /* security_level key */
    memset(filename, 0, sizeof(filename));
    sprintf(filename, "%ssecurity_level/%d", CD_keyPath, cert->security_level);
    fp = fopen(filename, "rb");
    inLen = fread(inBuffer, sizeof(BYTE), CD_KEY_LEN_MAX, fp);
    fclose(fp);
    res = utpm_unbind_data(*handle, auth, inLen, inBuffer, &outLen, outBuffer);
    if (res != UTPM_SUCCESS)
        return CD_UNBIND_KEYS_FAILED;

    res = CD_insertSLKey(cert->security_level, outBuffer, outLen);
    if (res != CD_SUCCESS)
        return res;

    /* success */
    return CD_SUCCESS;
}

CD_RESULT CD_insertKey(char *desc, void *buf, size_t len) {
    if (add_key("user", desc, buf, len, KEY_SPEC_USER_KEYRING) == -1)
        return CD_INSERT_KEY_FAILED;
    return CD_SUCCESS;
}

CD_RESULT CD_insertUserKey(char *username, void *buf, size_t len) {
    char desc[CD_DESC_MAX];
    sprintf(desc, "CD_userKey_%s", username);
    return CD_insertKey(desc, buf, len);
}

CD_RESULT CD_insertRoleKey(char *role, void *buf, size_t len) {
    char desc[CD_DESC_MAX];
    sprintf(desc, "CD_roleKey_%s", role);
    return CD_insertKey(desc, buf, len);
}

CD_RESULT CD_insertSLKey(int security_level, void *buf, size_t len) {
    char desc[CD_DESC_MAX];
    sprintf(desc, "CD_SLKey_%d", security_level);
    return CD_insertKey(desc, buf, len);
}

CD_RESULT CD_loadRootKey(UTPM_KEY_HANDLE *rootKeyHandle) {
    UTPM_RESULT res;
    UTPM_KEY rootKey;
    /* 3.1.1 read data from file */
    BYTE *buffer = (BYTE *)malloc(CD_KEY_LEN_MAX);
    BYTE *tail = buffer;
    size_t bufLen = CD_KEY_LEN_MAX;
    FILE *fp = fopen(CD_rootKey, "rb");
    if (fp == NULL)
        return CD_KEYFILE_NOT_FOUND;
    fread(buffer, sizeof(BYTE), CD_KEY_LEN_MAX, fp);
    res = tpm_unmarshal_TPM_KEY(&tail, &bufLen, &rootKey);
    if (res != UTPM_SUCCESS)
        return CD_UNMARSHAL_FAILED;
    free(buffer);
    fclose(fp);
    
    /* 3.1.2 load key into ukey */
    res = flush_all();
    if (res != UTPM_SUCCESS)
        return CD_LOAD_KEY_FAILED;
    UTPM_KEY_HANDLE parentHandle = UTPM_KH_SRK;
    UTPM_SECRET parentAuth = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
    res = load_key(parentHandle, parentAuth, &rootKey, rootKeyHandle);
    if (res != UTPM_SUCCESS)
        return CD_LOAD_KEY_FAILED;

    return CD_SUCCESS;
}

CD_RESULT CD_readCert(CD_cert *cert, char *path) {
    FILE *fp = fopen(path, "r");
    if (fp == NULL)
        return CD_CERTFILE_NOT_FOUND;

    char *buf = NULL;
    size_t bufLen;
    ssize_t lineLen = getline(&buf, &bufLen, fp);
    if (strncmp(buf, "name:", 5) == 0) {
        cert->username = (char *)malloc(lineLen - 5);
        memset(cert->username, 0, lineLen - 5);
        strncpy(cert->username, buf + 5, lineLen - 5 - 1);
    }
    free(buf);
    
    buf = NULL;
    lineLen = getline(&buf, &bufLen, fp);
    if (strncmp(buf, "role:", 5) == 0) {
        cert->role = (char *)malloc(lineLen - 5);
        memset(cert->role, 0, lineLen - 5);
        strncpy(cert->role, buf + 5, lineLen - 5 - 1);
    }
    free(buf);

    buf = NULL;
    lineLen = getline(&buf, &bufLen, fp);
    if (strncmp(buf, "security_level:", 15) == 0) {
        cert->security_level = atoi(buf + 15);
    }
    free(buf);
    
    buf = NULL;
    lineLen = getline(&buf, &bufLen, fp);
    if (strncmp(buf, "signature:", 10) == 0) {
        cert->signature = (BYTE *)malloc(lineLen - 10);
        memset(cert->signature, 0, lineLen - 10);
        memncpy(cert->signature, buf + 10, buf - 10 - 1);
    }
    free(buf);

    return CD_SUCCESS;
}


CD_RESULT CD_verifyCert(CD_cert *cert) {
    return CD_SUCCESS;
}

CD_RESULT CD_freeCert(CD_cert *cert) {
    if (cert == NULL)
        return CD_CERT_NOT_VALID;
    free(cert->username);
    free(cert->role);
    free(cert->signature);
    return CD_SUCCESS;
}

