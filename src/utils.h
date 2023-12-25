#ifndef utils
#define utils

#define LOCAL_HOST              "127.0.0.1"
#define PORT                    2048

#define COMMAND_BUFF_SIZE       4096
#define ANSWER_BUFF_SIZE        4096

#define CHECK(condition, message)\
    if ((condition))             \
    {                            \
        perror(message);         \
        exit(-1);                \
    }                            \

#define DB_CHECK(condition, message)                      \
    if (!(condition))                                     \
    {                                                     \
        fprintf(stderr, "database error: %s\n", message); \
        sqlite3_close(db);                                \
        exit(-1);                               \
    }


struct user_credentials {
    char username[32];
    char password[32];
};

char working_dir[1024];

#endif