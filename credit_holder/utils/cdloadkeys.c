/*
 * =====================================================================================
 *
 *       Filename:  cdloadkey.c
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  2014年12月21日 16时43分14秒
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

int main() {
    CD_RESULT res;
    res = CD_loadKeys();
    if (res == CD_SUCCESS)
        printf ( "Load keys complete.\n" );
    return res;
}
