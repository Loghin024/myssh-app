/*
###########################################################################################################
+++*****************************************************************************************************+++
___________Client Application (client.c) - Simple Documentation____________________________________________    
   
*/

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <string.h> 
#include "utils.h"

int socket_descriptor;

char user_command[COMMAND_BUFF_SIZE];
char server_answer[ANSWER_BUFF_SIZE];
char encrypted_server_answer[ANSWER_BUFF_SIZE];

int configure_socket(struct sockaddr_in *server);
const char* encrypt_command(const char* command);
const char* decrypt_server_answer(const char* answer);
void send_command_to_server();
void receive_answer_from_server();

int main(){

    struct sockaddr_in server;
    socket_descriptor = configure_socket(&server);

    CHECK(-1 == connect(socket_descriptor, (struct sockaddr *) &server, sizeof(struct sockaddr)), "[client]:error at connect()\n")

    //receiving commands from user until he decided to quit
    while(1)
    {
        CHECK(printf("-->") < 0, "[client]:error at printf()!\n")
        CHECK(fflush(stdout) != 0, "[client]:Error at fflush\n")
        
        bzero(user_command, sizeof(user_command));
        CHECK(-1 == read(0, user_command, COMMAND_BUFF_SIZE), "[client]:error at read()!\n")

        send_command_to_server();
        // //encrypt command
        // const char* encrypted_command = encrypt_command(user_command);
        // //send encrypted command
        // CHECK(-1 == write(socket_descriptor, encrypt_command, sizeof(encrypt_command)), "[client]:error at sending encrypted command to server!\n")

        // //read encrypted server answer
        // CHECK(-1 == read(socket_descriptor, encrypted_server_answer, ANSWER_BUFF_SIZE), "[client]:Error at receiving message from server!")

        // //decrypt 
        // strcpy(server_answer, (encrypted_server_answer));
        receive_answer_from_server();

        //display answer
        CHECK(printf("%s\n", server_answer) < 0, "[client]:error at printf()!\n")
        CHECK(fflush(stdout) != 0, "[client]:Error at fflush\n")

        //check if user wanted to quit
        if(strcmp(user_command, "quit\n") == 0)
        {
            CHECK(printf("Left my ssh!\n") < 0, "[client]:error at printf()!\n")
            CHECK(fflush(stdout) != 0, "[client]:Error at fflush\n")
            break;
        }

    }

    return 0;
}

int configure_socket(struct sockaddr_in *server)
{
    int socket_descriptor;
    CHECK(-1 == (socket_descriptor = socket(AF_INET, SOCK_STREAM, 0)), "[client]:error at socket()!\n")
    
    server->sin_family = AF_INET;
    server->sin_addr.s_addr = inet_addr(LOCAL_HOST);
    server->sin_port = htons(PORT);

    return socket_descriptor;
}

const char *encrypt_command(const char *command)
{
    return command;
}

const char *decrypt_server_answer(const char *command)
{
    return command;
}

void send_command_to_server()
{   
    //encrypt command
    const char* encrypted_command = encrypt_command(user_command);
    //send len of the message
    int len = strlen(encrypted_command);
    CHECK(-1 == write(socket_descriptor, &len, sizeof(len)), "[client]:error at sending encrypted command lenght to server!\n")
    //send encrypted command
    CHECK(-1 == write(socket_descriptor, encrypted_command, len), "[client]:error at sending encrypted command to server!\n")
}

void receive_answer_from_server()
{
    //read encrypted server answer
    int len = 0;
    bzero(encrypted_server_answer, sizeof(encrypted_server_answer));
    //read answer length
    CHECK(-1 == read(socket_descriptor, &len, sizeof(int)), "[client]:Error at receiving message from server!\n")
    printf("%d\n", len);
    CHECK(-1 == read(socket_descriptor, &encrypted_server_answer, len), "[client]:Error at receiving message from server!\n")

    //decrypt 
    bzero(server_answer, sizeof(server_answer));
    strcpy(server_answer, (encrypted_server_answer));
}