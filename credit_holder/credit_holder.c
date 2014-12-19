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

char CD_keyFile[] = "/etc/tcel_leon/credit_holder/keys";
char CD_certPath[] = "/etc/tcel_leon/cert/";

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
    char keyDesc[DESC_MAX];
    sprintf(keyDesc, "CD_userKey_%s", username);

    return CD_getKey(keyDesc, buffer, len);
}

CD_RESULT CD_getRoleKey(char *role, char *buffer, size_t *len) {
    char keyDesc[DESC_MAX];
    sprintf(keyDesc, "CD_roleKey_%s", role);

    return CD_getKey(keyDesc, buffer, len);
}

/*
CD_RESULT CD_createKey(char *desc) {
    if (create_tpm_context() != TPM_SUCCESS)
        return CD_CREATE_CONTEXT_FAILED;

    TPM_KEY wrappedKey;
    TPM_KEY_USAGE keyUsage = TPM_KEY_BIND;
    TPM_SECRET keyAuth = {0x04, 0x05, 0x06};
    TPM_KEY_HANDLE parentHandle = TPM_KH_SRK;
    TPM_SECRET parentAuth = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};

    if (create_wrap_key(parentHandle, parentAuth, keyUsage, 
                keyAuth, &wrappedKey) != TPM_SUCCESS)
        return CD_CREATE_KEY_FAILED;

}  */

CD_RESULT CD_loadKeys() {
    CD_RESULT res;
    struct passwd *userInfo;
    userInfo = getpwuid(getuid());

    /* read cert */
    struct CD_cert cert;
    char fileName[PATH_MAX];
    sprintf(fileName, "%s%s.cert", CD_certPath, userInfo->pw_name);
    res = CD_readCert(&cert, fileName);
    if (res != CD_SUCCESS)
        return res;

    /* verify cert */
    /* FIXME */
    res = CD_verifyCert(&cert);
    if (res != CD_SUCCESS)
        return res;

    /* load keys */
        /* load credit_holder key into ukey */
        /* unbind keys */ 
        /* insert keys into keyring */

    /* free cert */
    res = CD_freeCert(&cert);
    if (res != CD_SUCCESS)
        return res;
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
