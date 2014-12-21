/*
 * =====================================================================================
 *
 *       Filename:  cdgetrolekey.c
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  2014年12月21日 16时53分34秒
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

int main(int argc, char **argv) {
    if (argc != 2) {
        printf ( "Wrong arguments.\n" );
        return -1;
    }
    CD_RESULT res;
    char buf[CD_KEY_LEN_MAX];
    size_t len;
    res = CD_getRoleKey(argv[1], buf, &len);
    buf[len] = '\0';
    if (res == CD_SUCCESS)
        printf ("%s\n", buf);
    return res;
}
