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
#include <sqlite3.h>
#include <stdbool.h>
#include "commands.h"
#include "encryption.h"
#include "utils.h"

#define MAX_CLIENTS 64
#define MAX_ARGS 64

int server_descriptor;

unsigned char encrypted_user_command[COMMAND_BUFF_SIZE];
char user_command[COMMAND_BUFF_SIZE];
char server_answer[ANSWER_BUFF_SIZE];
unsigned char encrypted_server_answer[ANSWER_BUFF_SIZE];

int args_counter[MAX_CLIENTS];
struct argument
{
    char value[128];
}user_args[MAX_CLIENTS][MAX_ARGS];

struct thread_data {
	int id;
	int client_descriptor;
    bool is_logged;
    char working_dir[1024];
};


void send_server_public_key(RSA *rsa_keypair, int client_descriptor);
void receive_client_public_key(RSA **rsa_keypair, int client_descriptor);

int configure_server(struct sockaddr_in *server);
static void *treat_client(void *arg);
const char *decrypt_client_command(const char* encrypted_command);
bool read_encrypted_command();
bool send_answer_to_client();

bool iterate_through_tokens();
bool handle_redirection();
bool handle_command_chaining();

int parse_user_command();
void get_user_args();
bool execute_user_command(int command_id, struct thread_data * threadL);

int sign_up(struct thread_data *threadL);
int login(struct thread_data *threadL);

//helpers
int verify_username(char*username);
int insert_user_db(struct user_credentials *new_user);
int check_credentials(struct user_credentials *user);

int main(){

    // Generate key pair
    generate_keypair(&rsa_keypair_server, 2048);

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

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
bool read_encrypted_command(int client_descriptor)
{
    bzero(encrypted_user_command, sizeof(encrypted_user_command));
    bzero(user_command, sizeof(user_command));
    //read command len
    int len = 0;
    if(0 >= read(client_descriptor, &len, sizeof(len)))
    {
        perror("[thread]:error at read()!\n");
        return false;
    }
    //read encrypted command
    if(read(client_descriptor, &encrypted_user_command, len) <= 0)
    {
        perror("[thread]:error at read()!\n");
        return false;
    }
    
    bzero(plain_text, sizeof(plain_text));
    rsa_decrypt(encrypted_user_command, RSA_size(rsa_keypair_server), rsa_keypair_server, plain_text);
    memcpy(user_command, plain_text, COMMAND_BUFF_SIZE);
    return true;
}

bool send_answer_to_client(int client_descriptor, const char * answer)
{
    //encrypt command
    bzero(plain_text, sizeof(plain_text));
    strcpy((char *)plain_text, answer);
    // memcpy(plain_text, answer, ANSWER_BUFF_SIZE);
    rsa_encrypt(plain_text, strlen((char *)plain_text), rsa_keypair_client, encrypted_server_answer);
    
    int len = RSA_size(rsa_keypair_client);
    if(0 >= write(client_descriptor, &len, sizeof(int)))
    {
        perror("[thread]:error at write()!\n");
        return false;
    }
    if(0 >= write(client_descriptor, encrypted_server_answer, len))
    {
        perror("[thread]:error at write()!\n");
        return false;
    }
    return true;
}

#pragma GCC diagnostic pop

static void *treat_client(void *arg)
{
    struct thread_data threadL;
    threadL = *((struct thread_data *)arg);
    threadL.is_logged = false;
    pthread_detach(pthread_self());

    receive_client_public_key(&rsa_keypair_client, threadL.client_descriptor);
    send_server_public_key(rsa_keypair_server, threadL.client_descriptor);

    while(1)
    {
       
        bool result = read_encrypted_command(threadL.client_descriptor);
        if(!result) ;
        
        char *command_name = strtok(user_command, " \n");
        if(*command_name == '\0')
        {
            close(threadL.client_descriptor);
            return(NULL);
        }
        int command_id = parse_user_command(command_name);
        get_user_args(threadL.id);

        //check if client wants to leave
        if(strcmp(user_command, "quit") == 0)
        {
            send_answer_to_client(threadL.client_descriptor, "Connection with server finished with succes!\n");
            close(threadL.client_descriptor);
            return(NULL);
        }
        
        result = execute_user_command(command_id, &threadL);
        if(!result)continue;
    }
}

void get_user_args(int client_id)
{

    char *token = strtok(NULL, " \n");
    args_counter[client_id] = 0;
    while(token)
    {   
        strcpy(user_args[client_id][args_counter[client_id]++].value, token);
        token = strtok(NULL, " \n");
    }
}

int parse_user_command(const char * command_name)
{
    if(!strcmp("sign-up", command_name))
    {
        return 1;
    }
    else if(!strcmp("login", command_name))
    {
        return 2;
    }
    else if(!strcmp("ls", command_name))
    {
        return 3;
    }
    else if(!strcmp("cd", command_name))
    {
        return 4;
    }
    else if(!strcmp("mv", command_name))
    {
        return 5;
    }
    else if(!strcmp("touch", command_name))
    {
        return 6;
    }
    else if(!strcmp("rm", command_name))
    {
        return 7;
    }
    else if(!strcmp("mkdir", command_name))
    {
        return 8;
    }
    else if(!strcmp("rmdir", command_name))
    {
        return 9;
    }
    else if(!strcmp("echo", command_name))
    {
        return 10;
    }
    else if(!strcmp("pwd", command_name))
    {
        return 11;
    }
    else if(!strcmp("help", command_name))
    {
        return 12;
    }
    else 
        return -1;
}

int sign_up(struct thread_data *threadL)
{
    struct user_credentials new_user;

    strcpy(new_user.username, user_args[threadL->id][0].value);
    strcpy(new_user.password, user_args[threadL->id][1].value);
    
    int result = verify_username(new_user.username);

    if(result == 0)
    {
        bzero(server_answer, sizeof(server_answer));
        strcat(server_answer, "Username: ");
        strcat(server_answer, new_user.username);
        strcat(server_answer, " already exists!\n");
        return -1;
    }
    
    result = insert_user_db(&new_user);
    strcpy(threadL->working_dir, "../user_space/");
    strcat(threadL->working_dir, new_user.username);
    CHECK(0 != mkdir(threadL->working_dir, 0777), "[thread]:error at creating user space!\n");
    return result;
}

int login(struct thread_data *threadL)
{
    struct user_credentials new_user;

    strcpy(new_user.username, user_args[threadL->id][0].value);
    strcpy(new_user.password, user_args[threadL->id][1].value);
    
    int result = check_credentials(&new_user);

    if(result != 0)
    {
        bzero(server_answer, sizeof(server_answer));
        strcat(server_answer, "Username or password are incorect!");
        return -1;
    }

    strcpy(threadL->working_dir, "../user_space/");
    strcat(threadL->working_dir, new_user.username);
    
    return result;
}

bool execute_user_command(int command_id, struct thread_data * threadL)
{
    if(command_id == -1)
    {
        return send_answer_to_client(threadL->client_descriptor, "Entered command wasn't recognized!\n");
    }
    else if(command_id == 1)
    {
        int result = sign_up(threadL);
        if(result == -1)
        {
            strcat(server_answer, "\nsign-up finished with result: failure!\n");
            return send_answer_to_client(threadL->client_descriptor, server_answer);
        }
        else
            return send_answer_to_client(threadL->client_descriptor, "You have succesfully signed up!\n");
    }
    else if(command_id == 2)
    {
        if (threadL->is_logged)
            return send_answer_to_client(threadL->client_descriptor, "You are already logged in!\n");

        int result = login(threadL);

        if(result == -1)
        {
            strcat(server_answer, "\nlogin finished with result: failure!\n");
            return send_answer_to_client(threadL->client_descriptor, server_answer);
        }
        else
        {
            threadL->is_logged = true;
            return send_answer_to_client(threadL->client_descriptor, "login finished with result: succes!\nEnter help to display available commands!\n");
        }

    }
    else if(command_id == 3)
    {
        if (!threadL->is_logged)
            return send_answer_to_client(threadL->client_descriptor, "You aren't logged in!\n");

        if(args_counter[threadL->id] != 0)
            return send_answer_to_client(threadL->client_descriptor, "Usage: ls\n");

        bzero(server_answer, sizeof(server_answer));
        int result = l_ls(threadL->working_dir, server_answer);
       

        if(!result)
        {
            strcat(server_answer, "\nls finished with result: failure!\n");
            return send_answer_to_client(threadL->client_descriptor, server_answer);
        }
        else
        {
            if(server_answer == NULL)
                strcat(server_answer, "No files or directory!\n");
            return send_answer_to_client(threadL->client_descriptor, server_answer);
        }
    }
    else if(command_id == 4)
    {
        if (!threadL->is_logged)
            return send_answer_to_client(threadL->client_descriptor, "You aren't logged in!\n");

        if(args_counter[threadL->id] != 1)
            return send_answer_to_client(threadL->client_descriptor, "Usage: cd path");

        int result = l_cd(threadL->working_dir, user_args[0]->value);

        if(!result)
        {
            strcat(server_answer, "\ncd finished with result: failure!\n");
            return send_answer_to_client(threadL->client_descriptor, server_answer);
        }
        else
            return send_answer_to_client(threadL->client_descriptor, "cp finished with result: succes!\n");
    }
    else if(command_id == 5)
    {
        if (!threadL->is_logged)
            return send_answer_to_client(threadL->client_descriptor, "You aren't logged in!\n");

        int result = l_mv();

        if(!result)
        {
            strcat(server_answer, "\nmv finished with result: failure!\n");
            return send_answer_to_client(threadL->client_descriptor, server_answer);
        }
        else
            return send_answer_to_client(threadL->client_descriptor, "mv finished with result: succes!\n");
    }
    else if(command_id == 6)
    {
        if (!threadL->is_logged)
            return send_answer_to_client(threadL->client_descriptor, "You aren't logged in!\n");

        if(args_counter[threadL->id] != 1)
            return send_answer_to_client(threadL->client_descriptor, "Usage: touch file_name");
        
        char path[1024];
        strcpy(path, threadL->working_dir);
        strcat(path, "/");
        strcat(path, user_args[0]->value);

        int result = l_touch(path);

        if(!result)
        {
            strcat(server_answer, "\ntouch finished with result: failure!\n");
            return send_answer_to_client(threadL->client_descriptor, server_answer);
        }
        else
            return send_answer_to_client(threadL->client_descriptor, "touch finished with result: succes!\n");
    }
    else if(command_id == 7)
    {
        if (!threadL->is_logged)
            return send_answer_to_client(threadL->client_descriptor, "You aren't logged in!\n");

        if(args_counter[threadL->id] != 1)
            return send_answer_to_client(threadL->client_descriptor, "Usage: rm file_name");
        
        char path[1024];
        strcpy(path, threadL->working_dir);
        strcat(path, "/");
        strcat(path, user_args[0]->value);

        int result = l_rm(path);

        if(!result)
        {
            strcat(server_answer, "\nrm finished with result: failure!\n");
            return send_answer_to_client(threadL->client_descriptor, server_answer);
        }
        else
            return send_answer_to_client(threadL->client_descriptor, "rm finished with result: succes!\n");
    }
    else if(command_id == 8)
    {
        if (!threadL->is_logged)
            return send_answer_to_client(threadL->client_descriptor, "You aren't logged in!\n");

        if(args_counter[threadL->id] != 1)
        {
            return send_answer_to_client(threadL->client_descriptor, "Usage: mkdir directory_name");
        }
        char path[1024];
        strcpy(path, threadL->working_dir);
        strcat(path, "/");
        strcat(path, user_args[0]->value);
        int result = l_mkdir(path, 0777);

        if(!result)
        {
            strcat(server_answer, "\nmkdir finished with result: failure!\n");
            return send_answer_to_client(threadL->client_descriptor, server_answer);
        }
        else
            return send_answer_to_client(threadL->client_descriptor, "mkdir finished with result: succes!\n");
    }
    else if(command_id == 9)
    {
        if (!threadL->is_logged)
            return send_answer_to_client(threadL->client_descriptor, "You aren't logged in!\n");

        if(args_counter[threadL->id] != 1)
        {
            return send_answer_to_client(threadL->client_descriptor, "Usage: rmdir directory_name");
        }

        char path[1024];
        strcpy(path, threadL->working_dir);
        strcat(path, "/");
        strcat(path, user_args[0]->value);
        int result = l_rmdir(path);

        if(!result)
        {
            strcat(server_answer, "\nrmdir finished with result: failure!\n");
            return send_answer_to_client(threadL->client_descriptor, server_answer);
        }
        else
            return send_answer_to_client(threadL->client_descriptor, "rmdir finished with result: succes!\n");
    }
    else if(command_id == 10)
    {
        if (!threadL->is_logged)
            return send_answer_to_client(threadL->client_descriptor, "You aren't logged in!\n");

        for(int i=0; i<args_counter[threadL->id]; i++)
        {
            strcat(server_answer, user_args[threadL->id][i].value);
            strcat(server_answer, " ");
        }
        return send_answer_to_client(threadL->client_descriptor, server_answer);
    }
    else if(command_id == 11)
    {
        if (!threadL->is_logged)
            return send_answer_to_client(threadL->client_descriptor, "You aren't logged in!\n");

        send_answer_to_client(threadL->client_descriptor, threadL->working_dir);
    }
    else if(command_id == 12)
    {
        if (!threadL->is_logged)
            return send_answer_to_client(threadL->client_descriptor, "You aren't logged in!\n");

        return send_answer_to_client(threadL->client_descriptor, "Available commands:\n1. pwd\n2. cd\n3. ls\n4. mkdir\n5. rmdir\n6. touch\n7. rm");
    }
    return false;
}

int verify_username(char * username)
{
    sqlite3 *db;
	sqlite3_stmt *stmt;

	int rc = sqlite3_open("credentials.db", &db);
    DB_CHECK(!rc, sqlite3_errmsg(db));

    char *createTableSQL = "CREATE TABLE IF NOT EXISTS Users ("
                           "ID INTEGER PRIMARY KEY AUTOINCREMENT,"
                           "Username TEXT NOT NULL,"
                           "Password TEXT NOT NULL);";

    rc = sqlite3_exec(db, createTableSQL, NULL, NULL, NULL);

    char get_usernames[1024];
	snprintf(get_usernames, sizeof(get_usernames), 
    "SELECT * FROM Users WHERE Username = \'%s\'", username);

	printf("[thread]:Database Query On Username Field: %s\n", get_usernames);
    fflush(stdout);
	rc = sqlite3_prepare_v2(db, get_usernames, -1, &stmt, NULL);
	DB_CHECK(!rc, sqlite3_errmsg(db));

	rc = sqlite3_step(stmt);
	short return_flag = (rc == SQLITE_DONE);

	sqlite3_finalize(stmt);
	sqlite3_close(db);

	return return_flag;
}

int check_credentials(struct user_credentials *user)
{
    sqlite3 *db;
	sqlite3_stmt *stmt;

	int rc = sqlite3_open("credentials.db", &db);
    DB_CHECK(!rc, sqlite3_errmsg(db));

    char *createTableSQL = "CREATE TABLE IF NOT EXISTS Users ("
                           "ID INTEGER PRIMARY KEY AUTOINCREMENT,"
                           "Username TEXT NOT NULL,"
                           "Password TEXT NOT NULL);";

    rc = sqlite3_exec(db, createTableSQL, NULL, NULL, NULL);

    char get_usernames[1024];
	snprintf(get_usernames, sizeof(get_usernames), 
    "SELECT * FROM Users WHERE Username = \'%s\' AND Password = \'%s\'", user->username, user->password);

	printf("[thread]:Database Query On Username Field: %s\n", get_usernames);
    fflush(stdout);
	rc = sqlite3_prepare_v2(db, get_usernames, -1, &stmt, NULL);
	DB_CHECK(!rc, sqlite3_errmsg(db));

	rc = sqlite3_step(stmt);
	short return_flag = (rc == SQLITE_DONE);

	sqlite3_finalize(stmt);
	sqlite3_close(db);

	return return_flag;
}

int insert_user_db(struct user_credentials *new_user) 
{
	sqlite3 *db;

	int rc = sqlite3_open("credentials.db", &db);
	DB_CHECK(!rc, sqlite3_errmsg(db));

	char insert_user_query[1024];
	
	snprintf(insert_user_query, 1024, 
				"INSERT INTO Users (Username, Password) "
				"VALUES(\'%s\', \'%s\')", new_user->username, new_user->password
			);
	
	printf("Database insertion command: %s\n", insert_user_query);
	
	rc = sqlite3_exec(db, insert_user_query, NULL, NULL, NULL);

	if(rc != SQLITE_OK) {
        strncpy(server_answer, sqlite3_errmsg(db), ANSWER_BUFF_SIZE);
		return -1;
	}
	else
        return 1;

	sqlite3_close(db);
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
void send_server_public_key(RSA *rsa_keypair, int client_descriptor) {

    // Check if the RSA object is valid
    if (rsa_keypair == NULL) {
        // Handle error
        return;
    }

    // Get the public key components (modulus and public exponent)
    const BIGNUM *modulus = NULL;
    const BIGNUM *exponent = NULL;
    RSA_get0_key(rsa_keypair, &modulus, &exponent, NULL);

    // Convert the components to hexadecimal strings for transmission
    char *modulus_hex = BN_bn2hex(modulus);
    char *exponent_hex = BN_bn2hex(exponent);

    // Send modulus_hex and exponent_hex to the client
    int len_modulus_hex = strlen(modulus_hex);
    CHECK(0 >= write(client_descriptor, &len_modulus_hex, sizeof(int)), "[thread]:error at sending public key(modulus hex) length")
    CHECK(0 >= write(client_descriptor, modulus_hex, len_modulus_hex), "[thread]:error at sending public key(modulus hex)")
    
    int len_exponent_hex = strlen(exponent_hex);
    CHECK(0 >= write(client_descriptor, &len_exponent_hex, sizeof(int)), "[thread]:error at sending public key(exponent hex) length")
    CHECK(0 >= write(client_descriptor, exponent_hex, len_exponent_hex), "[thread]:error at sending public key(exponent hex)")

    // Free the memory allocated for the hexadecimal strings
    OPENSSL_free(modulus_hex);
    OPENSSL_free(exponent_hex);
}

void  receive_client_public_key(RSA **rsa_public_key, int client_descriptor) {
    // Placeholder for receiving the modulus and exponent strings from the server
    char modulus_hex[1024];
    char exponent_hex[1024];

    // Receive modulus and exponent 
    int len = 0;
    CHECK(-1 == read(client_descriptor, &len, sizeof(int)), "[thread]:Error at receiving modulus(client public key) length!\n")
    CHECK(-1 == read(client_descriptor, &modulus_hex, len), "[thread]:Error at receiving modulus(client public key)!\n")

    CHECK(-1 == read(client_descriptor, &len, sizeof(int)), "[thread]:Error at receiving exponent(client public key) length!\n")
    CHECK(-1 == read(client_descriptor, &exponent_hex, len), "[thread]:Error at receiving expoent(client public key)!\n")

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
#pragma GCC diagnostic pop