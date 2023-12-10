#ifndef utils
#define utils

#define LOCAL_HOST              "127.0.0.1"
#define PORT                    2048

#define COMMAND_BUFF_SIZE       1024
#define ANSWER_BUFF_SIZE        4096

#define CHECK(condition, message)\
    if ((condition))             \
    {                            \
        perror(message);         \
        exit(-1);                \
    }                            \

#endif