/*
 * =====================================================================================
 *
 *       Filename:  test.c
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  2014年12月21日 14时12分27秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *   Organization:  
 *
 * =====================================================================================
 */
#include <stdlib.h>
#include <credit_holder.h>
#include <stdio.h>

int main() {
    CD_RESULT res;
    res = CD_loadKeys();
    printf("%d\n", res);
    return res;
}
