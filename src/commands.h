#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>

#ifndef commands
#define commands

bool l_ls()
{
    return true;
}
bool l_cp()
{
    return true;
}
bool l_mv()
{
    return true;
}
bool l_touch()
{
    return true;
}
bool l_rm()
{
    return true;
}
bool l_mkdir(const char * path, mode_t mode)
{
    if (mkdir(path, mode) == 0) 
        return true;
    else 
    {
        return -1;
    }
    return true;
}
bool l_rmdir()
{
    return true;
}
bool l_echo()
{
    return true;
}
bool l_ps()
{
    return true;
}
bool l_grep(){
    return true;
}

#endif