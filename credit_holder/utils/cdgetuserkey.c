/*
 * =====================================================================================
 *
 *       Filename:  cdgetuserkey.c
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  2014年12月21日 16时48分56秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *   Organization:  
 *
 * =====================================================================================
 */

#include <credit_holder.h>
#include <stdio.h>
#include <unistd.h>
#include <pwd.h>
#include <sys/types.h>

int main() {
    CD_RESULT res;
    char buf[CD_KEY_LEN_MAX];
    size_t len;
    struct passwd *pw = getpwuid(getuid());
    res = CD_getUserKey(pw->pw_name, buf, &len);
    buf[len] = '\0';
    if (res == CD_SUCCESS)
        printf ("%s\n", buf);
    return res;
}
