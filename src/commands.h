#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <time.h>

#ifndef commands
#define commands

bool listFiles(const char *path, char * server_answer);

bool l_ls(const char * path, char * server_answer)
{
    return listFiles(path, server_answer);
}
bool l_cd(char * current_path, const char * new_path)
{
    if(!strcmp(new_path, ".."))
    {
        for(int i = strlen(current_path) - 1; i >= 0; i--)
            if(current_path[i] == '/')
            {
                if(i + 1< strlen(current_path))
                    current_path[i + 1] = '\0';
                return true;
            } 
    }
    else
    {
        strcat(current_path, "/");
        strcat(current_path, new_path);
    }

    return true;
}
bool l_mv()
{
    return true;
}
bool l_touch(const char * path)
{
    FILE *file = fopen(path, "w");
    if (file != NULL) {
        fclose(file);
        return true;
    } else {
        return false;
    }
}
bool l_rm(const char * path)
{
    if (remove(path) == 0) {
        return true;
    } else {
        return false;
    }
}
bool l_mkdir(const char * path, mode_t mode)
{
    if (mkdir(path, mode) == 0) 
        return true;
    else 
    {
        return false;
    }
}
bool l_rmdir(const char * path)
{
    if (rmdir(path) == 0) {
        return true;
    } else {
        return false;
    }
}
bool l_echo()
{
    return true;
}
bool l_ps()
{
    return true;
}


bool listFiles(const char *path, char * server_answer) {
    DIR *dir;
    struct dirent *entry;

    if ((dir = opendir(path)) == NULL) {
        perror("opendir");
        return false;
    }

    while ((entry = readdir(dir)) != NULL) {
        char filePath[512]; 
        snprintf(filePath, sizeof(filePath), "%s/%s", path, entry->d_name);

        if (entry->d_type == DT_REG) {
            // Regular file
            strcat(server_answer, "\nFile: ");
            strcat(server_answer, entry->d_name);
            // printf("File: %s\n", entry->d_name);
        } else if (entry->d_type == DT_DIR && strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
            // Directory (excluding "." and "..")
            strcat(server_answer, "\nDirectory: ");
            strcat(server_answer, entry->d_name);
            // printf("Directory: %s\n", entry->d_name);
            // listFiles(filePath, server_answer); // Recursive call to list files in the subdirectory
        }
    }

    closedir(dir);
    return true;
}

#endif