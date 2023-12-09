/*
###########################################################################################################
+++*****************************************************************************************************+++
___________Client Application (client.c) - Simple Documentation____________________________________________    
   
*/

#include <stdio.h>

#define CHECK(condition, error_id, message)\
    if ((condition))             \
    {                            \
        perror(message);         \
        exit(error_id);          \
    }                            \

int main(){

    return 0;
}