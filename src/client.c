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
#include <stdbool.h>
#include "utils.h"

int socket_descriptor;

char user_command[COMMAND_BUFF_SIZE];
char server_answer[ANSWER_BUFF_SIZE];
char encrypted_server_answer[ANSWER_BUFF_SIZE];

bool is_logged = false;

int configure_socket(struct sockaddr_in *server);
const char* encrypt_command(const char* command);
const char* decrypt_server_answer(const char* answer);

void send_command_to_server();
void receive_answer_from_server();

void fill_login_form();
void fill_signup_form();

int main(){

    struct sockaddr_in server;
    socket_descriptor = configure_socket(&server);

    CHECK(-1 == connect(socket_descriptor, (struct sockaddr *) &server, sizeof(struct sockaddr)), "[client]:error at connect()\n")
    CHECK(printf("---------->WELCOME TO MY SSH<----------\n") < 0, "[client]:error at printf()!\n")
    CHECK(printf("Available commands:\n1.login(if you already have an account)\n2.sign-up(to register an account)\n3.quit(to leave terminal interface)\n") < 0, "[client]:error at printf()!\n")
    CHECK(fflush(stdout) != 0, "[client]:Error at fflush\n")

    //receiving commands from user until he decided to quit
    while(1)
    {
        CHECK(printf("-->") < 0, "[client]:error at printf()!\n")
        CHECK(fflush(stdout) != 0, "[client]:Error at fflush\n")
        
        bzero(user_command, sizeof(user_command));
        CHECK(-1 == read(0, user_command, COMMAND_BUFF_SIZE), "[client]:error at read()!\n")

        if(strcmp(user_command, "\n") == 0)
            continue;

        if (strcmp("login\n", user_command) == 0)
            fill_login_form();
        else if(strcmp("sign-up\n", user_command) == 0)
            fill_signup_form();

        send_command_to_server();
        receive_answer_from_server();

        //display answer

        if(!strcmp(server_answer, "login finished with result: succes!\n"))
            is_logged = true;

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
    CHECK(-1 == read(socket_descriptor, &encrypted_server_answer, len), "[client]:Error at receiving message from server!\n")

    //decrypt 
    bzero(server_answer, sizeof(server_answer));
    strcpy(server_answer, decrypt_server_answer(encrypted_server_answer));
}

void fill_login_form()
{
    if(is_logged)
    {
        CHECK(printf("You are already logged in!") < 0, "[client]:error at printf()!\n")
        CHECK(fflush(stdout) != 0, "[client]:Error at fflush!\n")
        return;
    }
    char username[32];
    char *password = NULL;
    
    //get entered username
    CHECK(printf("USERNAME:") < 0, "[client]:error at printf()!\n")
    CHECK(fflush(stdout) != 0, "[client]:Error at fflush!\n")
    CHECK(scanf("%s", username) < 0, "[client]:Error at scanf()!\n")

    //get entered passworkd
    password = getpass("PASSWORD:");

    //validate
    if(strlen(username) > 32 || strlen(password) > 32)
    {
        CHECK(printf("Username and password can have maximum 32 characters") < 0, "[client]:error at printf()!\n")
        CHECK(fflush(stdout) != 0, "[client]:Error at fflush!\n")
        bzero(user_command, sizeof(user_command));
        return;
    }
    user_command[strlen(user_command) - 1] = ' ';
    strcat(user_command, username);
    strcat(user_command, " ");
    strcat(user_command, password);
}

void fill_signup_form()
{
    char username[32];
    char *password = NULL;
    
    //get entered username
    CHECK(printf("USERNAME:") < 0, "[client]:error at printf()!\n")
    CHECK(fflush(stdout) != 0, "[client]:Error at fflush!\n")
    CHECK(scanf("%s", username) < 0, "[client]:Error at scanf()!\n")

    //get entered passworkd
    password = getpass("PASSWORD:");

    //validate
    if(strlen(username) > 32 || strlen(password) > 32)
    {
        CHECK(printf("Username and password can have maximum 32 characters") < 0, "[client]:error at printf()!\n")
        CHECK(fflush(stdout) != 0, "[client]:Error at fflush!\n")
        bzero(user_command, sizeof(user_command));
        return;
    }
    user_command[strlen(user_command) - 1] = ' ';
    strcat(user_command, username);
    strcat(user_command, " ");
    strcat(user_command, password);
}