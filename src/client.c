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
#include "encryption.h"
#include "utils.h"

int socket_descriptor;

char user_command[COMMAND_BUFF_SIZE];
unsigned char encrypted_user_command[COMMAND_BUFF_SIZE];
char server_answer[ANSWER_BUFF_SIZE];
unsigned char encrypted_server_answer[ANSWER_BUFF_SIZE];

bool is_logged = false;

void receive_server_public_key(RSA **rsa_public_key);
void send_client_public_key(RSA *rsa_public_key);
int configure_socket(struct sockaddr_in *server);
void send_command_to_server();
void receive_answer_from_server();
void fill_login_form();
void fill_signup_form();

int main(){

     // Generate key pair
    generate_keypair(&rsa_keypair_client[0], 2048);

    struct sockaddr_in server;
    socket_descriptor = configure_socket(&server);

    CHECK(-1 == connect(socket_descriptor, (struct sockaddr *) &server, sizeof(struct sockaddr)), "[client]:error at connect()\n")
    CHECK(printf("---------->WELCOME TO MY SSH<----------\n") < 0, "[client]:error at printf()!\n")
    CHECK(printf("Available commands:\n1.login(if you already have an account)\n2.sign-up(to register an account)\n3.quit(to leave terminal interface)\n") < 0, "[client]:error at printf()!\n")
    CHECK(fflush(stdout) != 0, "[client]:Error at fflush\n")

    //server-client public key exchange
    send_client_public_key(rsa_keypair_client[0]);
    receive_server_public_key(&rsa_keypair_server);

    //receiving commands from user until he decides to quit
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

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
void send_command_to_server()
{   
    //encrypt command
    bzero(plain_text, sizeof(plain_text));
    memcpy(plain_text, user_command, COMMAND_BUFF_SIZE);
    rsa_encrypt(plain_text, strlen((char *)plain_text), rsa_keypair_server, encrypted_user_command);
    //send len of the message
    int len = RSA_size(rsa_keypair_server);
    CHECK(-1 == write(socket_descriptor, &len, sizeof(len)), "[client]:error at sending encrypted command lenght to server!\n")
    //send encrypted command
    CHECK(-1 == write(socket_descriptor, encrypted_user_command, len), "[client]:error at sending encrypted command to server!\n")
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
    bzero(plain_text, sizeof(plain_text));
    bzero(server_answer, sizeof(server_answer));
    rsa_decrypt(encrypted_server_answer, RSA_size(rsa_keypair_client[0]), rsa_keypair_client[0], plain_text);
    memcpy(server_answer, plain_text, ANSWER_BUFF_SIZE);
}

#pragma GCC diagnostic pop

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


#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
void  receive_server_public_key(RSA **rsa_public_key) {
    // Placeholder for receiving the modulus and exponent strings from the server
    char modulus_hex[1024];
    char exponent_hex[1024];

    // Receive modulus and exponent 
    int len = 0;
    CHECK(-1 == read(socket_descriptor, &len, sizeof(int)), "[client]:Error at receiving message from server!\n")
    CHECK(-1 == read(socket_descriptor, &modulus_hex, len), "[client]:Error at receiving message from server!\n")

    CHECK(-1 == read(socket_descriptor, &len, sizeof(int)), "[client]:Error at receiving message from server!\n")
    CHECK(-1 == read(socket_descriptor, &exponent_hex, len), "[client]:Error at receiving message from server!\n")

    // Convert the modulus and exponent strings back to BIGNUM objects
    BIGNUM *modulus = BN_new();
    BIGNUM *exponent = BN_new();
    BN_hex2bn(&modulus, modulus_hex);
    BN_hex2bn(&exponent, exponent_hex);

    // Create an RSA object with the received modulus and exponent
    RSA *rsa_key = RSA_new();
    RSA_set0_key(rsa_key, modulus, exponent, NULL);

    // Set the RSA key to the output parameter
    *rsa_public_key = rsa_key;
}

void send_client_public_key(RSA *rsa_public_key)
{
     // Check if the RSA object is valid
    if (rsa_keypair_client[0] == NULL) {
        // Handle error
        return;
    }

    // Get the public key components (modulus and public exponent)
    const BIGNUM *modulus = NULL;
    const BIGNUM *exponent = NULL;
    RSA_get0_key(rsa_keypair_client[0], &modulus, &exponent, NULL);

    // Convert the components to hexadecimal strings for transmission
    char *modulus_hex = BN_bn2hex(modulus);
    char *exponent_hex = BN_bn2hex(exponent);

    // Send modulus_hex and exponent_hex to the server
    int len_modulus_hex = strlen(modulus_hex);
    CHECK(0 >= write(socket_descriptor, &len_modulus_hex, sizeof(int)), "[client]:error at sending public key(modulus hex) length")
    CHECK(0 >= write(socket_descriptor, modulus_hex, len_modulus_hex), "[client]:error at sending public key(modulus hex)")
    
    int len_exponent_hex = strlen(exponent_hex);
    CHECK(0 >= write(socket_descriptor, &len_exponent_hex, sizeof(int)), "[client]:error at sending public key(exponent hex) length")
    CHECK(0 >= write(socket_descriptor, exponent_hex, len_exponent_hex), "[client]:error at sending public key(exponent hex)")

    // Free the memory allocated for the hexadecimal strings
    OPENSSL_free(modulus_hex);
    OPENSSL_free(exponent_hex);
}
#pragma GCC diagnostic pop