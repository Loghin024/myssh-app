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
#include "utils.h"

#define MAX_CLIENTS 64

int server_descriptor;

char encrypted_user_command[COMMAND_BUFF_SIZE];
char user_command[COMMAND_BUFF_SIZE];
char server_answer[ANSWER_BUFF_SIZE];
// char encrypted_server_answer[ANSWER_BUFF_SIZE];

struct thread_data {
	int id;
	int client_descriptor;
    bool is_logged;
};

int configure_server(struct sockaddr_in *server);
static void *treat_client(void *arg);
const char *decrypt_client_command(const char* encrypted_command);
bool read_encrypted_command();
bool send_answer_to_client();

bool iterate_through_tokens();
bool handle_redirection();
bool handle_command_chaining();

int parse_user_command();
bool execute_user_command(int command_id, struct thread_data * threadL);

int sign_up();

//helpers
int verify_username(char*username);
int insert_user_db(struct user_credentials *new_user);
int check_credentials(struct user_credentials *user);

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

bool read_encrypted_command(int client_descriptor)
{
    bzero(encrypted_user_command, sizeof(encrypted_user_command));
    //read command len
    int len = 0;
    // CHECK(0 >= read(client_descriptor, &len, sizeof(len)), "[thread]:error at read()!\n")
    if(0 >= read(client_descriptor, &len, sizeof(len)))
    {
        perror("[thread]:error at read()!\n");
        return false;
    }
    //read encrypted command
    // CHECK(0 >= read(client_descriptor, &encrypted_user_command, len), "[thread]:error at read()!\n")
    if(read(client_descriptor, &encrypted_user_command, len) <= 0)
    {
        perror("[thread]:error at read()!\n");
        return false;
    }
    return true;
}

bool send_answer_to_client(int client_descriptor, const char * answer)
{
    int len = strlen(answer);
    if(0 >= write(client_descriptor, &len, sizeof(int)))
    {
        perror("[thread]:error at write()!\n");
        return false;
    }
    if(0 >= write(client_descriptor, answer, len))
    {
        perror("[thread]:error at write()!\n");
        return false;
    }
    return true;
}

static void *treat_client(void *arg)
{
    struct thread_data threadL;
    threadL = *((struct thread_data *)arg);
    threadL.is_logged = false;
    pthread_detach(pthread_self());

    while(1)
    {
       
        bool result = read_encrypted_command(threadL.client_descriptor);
        if(!result) ;

        strcpy(user_command, decrypt_client_command(encrypted_user_command));
        
        char *command_name = strtok(user_command, " \n");
        int command_id = parse_user_command(command_name);
        
        result = execute_user_command(command_id, &threadL);
        if(!result)continue;

        //check if client wants to leave
        if(strcmp(user_command, "quit\n") == 0)
        {
            close(threadL.client_descriptor);
            return(NULL);
        }
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
    else if(!strcmp("cp", command_name))
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
    else if(!strcmp("ps", command_name))
    {
        return 11;
    }
    else if(!strcmp("grep", command_name))
    {
        return 12;
    }
    else 
        return -1;
}

int sign_up()
{
    char *token;
    struct user_credentials new_user;

    token = strtok(NULL, " ");
    strcpy(new_user.username, token);
    token = strtok(NULL, " ");
    strcpy(new_user.password, token);
    
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

    return result;
}

int login()
{
    char *token;
    struct user_credentials new_user;

    token = strtok(NULL, " ");
    strcpy(new_user.username, token);
    token = strtok(NULL, " ");
    strcpy(new_user.password, token);
    
    int result = verify_username(new_user.username);

    if(result != 0)
    {
        bzero(server_answer, sizeof(server_answer));
        strcat(server_answer, "Username: ");
        strcat(server_answer, new_user.username);
        strcat(server_answer, " doesn't exists!\n");
        return -1;
    }

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
        int result = sign_up();
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

        int result = login();

        if(result == -1)
        {
            strcat(server_answer, "\nlogin finished with result: failure!\n");
            return send_answer_to_client(threadL->client_descriptor, server_answer);
        }
        else
        {
            threadL->is_logged = true;
            return send_answer_to_client(threadL->client_descriptor, "login finished with result: succes!\n");
        }

    }
    else if(command_id == 3)
    {
        if (!threadL->is_logged)
            return send_answer_to_client(threadL->client_descriptor, "You aren't logged in!\n");

        int result = l_ls();

        if(!result)
        {
            strcat(server_answer, "\nls finished with result: failure!\n");
            return send_answer_to_client(threadL->client_descriptor, server_answer);
        }
        else
            return send_answer_to_client(threadL->client_descriptor, "ls finished with result: succes!\n");
    }
    else if(command_id == 4)
    {
        if (!threadL->is_logged)
            return send_answer_to_client(threadL->client_descriptor, "You aren't logged in!\n");

        int result = l_cp();

        if(!result)
        {
            strcat(server_answer, "\ncp finished with result: failure!\n");
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

        int result = l_touch();

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

        int result = l_rm();

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

        int result = l_mkdir();

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

        int result = l_rmdir();

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

        int result = l_echo();

        if(!result)
        {
            strcat(server_answer, "\necho finished with result: failure!\n");
            return send_answer_to_client(threadL->client_descriptor, server_answer);
        }
        else
            return send_answer_to_client(threadL->client_descriptor, "echo finished with result: succes!\n");
    }
    else if(command_id == 11)
    {
        if (!threadL->is_logged)
            return send_answer_to_client(threadL->client_descriptor, "You aren't logged in!\n");

        int result = l_ps();

        if(!result)
        {
            strcat(server_answer, "\nps finished with result: failure!\n");
            return send_answer_to_client(threadL->client_descriptor, server_answer);
        }
        else
            return send_answer_to_client(threadL->client_descriptor, "ps finished with result: succes!\n");
    }
    else if(command_id == 12)
    {
        if (!threadL->is_logged)
            return send_answer_to_client(threadL->client_descriptor, "You aren't logged in!\n");

        int result = l_grep();

        if(!result)
        {
            strcat(server_answer, "\ngrep finished with result: failure!\n");
            return send_answer_to_client(threadL->client_descriptor, server_answer);
        }
        else
            return send_answer_to_client(threadL->client_descriptor, "grep finished with result: succes!\n");
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
	snprintf(get_usernames, sizeof(get_usernames), "SELECT * FROM Users WHERE Username = \'%s\'", username);

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
