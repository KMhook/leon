/*
 * =====================================================================================
 *
 *       Filename:  cdcreateuserkey.c
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  2014年12月21日 18时41分50秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *   Organization:  
 *
 * =====================================================================================
 */
#include <stdlib.h>
#include <stdio.h>
#include <credit_holder.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc != 3) {
        printf ( "Wrong arguments.\n" );
        return -1;
    }

    CD_RESULT res;
    res = CD_createUserKey(argv[1], argv[2], strlen(argv[2]));
    if (res == CD_SUCCESS)
        printf("create complete.\n");
    return res;
}
