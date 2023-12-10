/*
###########################################################################################################
+++*****************************************************************************************************+++
___________Server Application (server.c) - Simple Documentation____________________________________________    
   
*/

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <pthread.h>
#include "utils.h"

#define MAX_CLIENTS 64

int server_descriptor;

char encrypted_user_command[COMMAND_BUFF_SIZE];
char user_command[COMMAND_BUFF_SIZE];
// char server_answer[ANSWER_BUFF_SIZE];
// char encrypted_server_answer[ANSWER_BUFF_SIZE];

struct thread_data {
	int id;
	int client_descriptor;
};

int configure_server(struct sockaddr_in *server);
static void *treat_client(void *arg);
const char *decrypt_client_command(const char* encrypted_command);
void read_encrypted_command();
void send_answer_to_client();

int main(){

    struct sockaddr_in server;
    struct sockaddr_in client;

    pthread_t threads[MAX_CLIENTS];
    int thread_cnt = 0;
    server_descriptor = configure_server(&server);

    CHECK(-1 == listen(server_descriptor, 5), "[server]:error at binding()!\n")

    while(1)
    {
        int client_descriptor;
        struct thread_data* thread;
        int length = sizeof(client);

        CHECK(0 > (client_descriptor = accept(server_descriptor, (struct sockaddr*) &client, &length)), "[server]:error at accept()")

        thread = (struct thread_data*)malloc(sizeof(struct thread_data));
        thread->id = thread_cnt;
        thread->client_descriptor = client_descriptor;

        pthread_create(&threads[thread->id], NULL, &treat_client, thread);
    }

    return 0;
}

int configure_server(struct sockaddr_in *server) 
{
	int server_descriptor;

    CHECK(-1 == (server_descriptor = socket(AF_INET, SOCK_STREAM, 0)), "[server]:error at socket()!\n")

    //add reuse option
    int on = 1;
    setsockopt(server_descriptor, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

    bzero(server, sizeof(*server));
    
    server->sin_family = AF_INET;
    server->sin_addr.s_addr = htonl(INADDR_ANY);
    server->sin_port = htons(PORT);

    //bind 
    CHECK(-1 == bind(server_descriptor, (struct sockaddr*) server, sizeof(struct sockaddr)), "[server]:error at bind()!\n")

	return server_descriptor;
}

const char *decrypt_client_command(const char* encrypted_command)
{
    return encrypted_command;
}

void read_encrypted_command(int client_descriptor)
{
    bzero(encrypted_user_command, sizeof(encrypted_user_command));
    //read command len
    int len = 0;
    CHECK(0 >= read(client_descriptor, &len, sizeof(len)), "[thread]:error at read()!\n")
    //read encrypted command
    CHECK(0 >= read(client_descriptor, &encrypted_user_command, len), "[thread]:error at read()!\n")
}

void send_answer_to_client(int client_descriptor, const char * answer)
{
    int len = strlen(answer);
    CHECK(0 >= write(client_descriptor, &len, sizeof(int)), "[thread]:error at write()!\n")
    CHECK(0 >= write(client_descriptor, answer, len), "[thread]:error at write()!\n")
}

static void *treat_client(void *arg)
{
    struct thread_data threadL;
    threadL = *((struct thread_data *)arg);
    pthread_detach(pthread_self());

    while(1)
    {
       
        read_encrypted_command(threadL.client_descriptor);
        printf("%s", encrypted_user_command);
        fflush(stdout);

        send_answer_to_client(threadL.client_descriptor, "[OK]");
        // CHECK(0 >= write(threadL.client_descriptor, "got message", 11), "[thread]:error at write()!\n")

        //check if client wants to leave
        if(strcmp(encrypted_user_command, "quit\n") == 0)
        {
            close(threadL.client_descriptor);
            return(NULL);
        }
    }
}