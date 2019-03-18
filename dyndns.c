/***************************************************************************
 *                                  _   _ ____  _
 *  Project                      ___            ___          
 * |   \ _  _ _ _ |   \ _ _  ___
 * |  |) | || | ' \| |) | ' \(_-<
 * |___/ \_, |_||_|___/|_||_/__/
  *      |__/                   
 * Copyright (C) 2019, Anas Zakaria, <anas.zakaria@gmail.com>
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://dyndns.life/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/


#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <stdbool.h>
#include <unistd.h>
#include <syslog.h>
#include <curl/curl.h>

#define DYN_SERVER_INSTALL		"dyndns.life/api/install"
#define DYN_SERVER_UPDATE		"dyndns.life/api/update"
#define DYN_SERVER_UPDATE_CURL		"dyndns.life/api/update_curl"
#define DYN_CLIENT_IP		"https://dyndns.life/api/ip"
#define DYN_CONF_FILE		"/usr/local/etc/dyndns.conf"

struct MemoryStruct {
  char *memory;
  size_t size;
  
};


struct host_token {
	char hostname[60];
	char token[30];
};
struct fetch_token {
	char token[24];
};

struct host_token initialize(void);
struct fetch_token get(void);
#define OPTCHARS		"Cc:Fc:Uc:vc"

#define SUCCESS                  20
#define UPDATE_OK         "UPDATE_OK"
#define WRONG_TOKEN    "WRONG_TOKEN"
#define FAILED                  90


#define VERSION			"2.1"
#define SIZE 1000

#define LINELEN 	        256

char	*program		=	NULL;
int	prompt_for_executable	=	1;
int	log2syslog		= 	0;
int	needs_conf 		=	0;
char data[100];
char * token_session;
char linko[16384];
void	process_options(int argc, char *argv[]);

void removeStringTrailingNewline(char *str) {
  if (str == NULL)
    return;
  int length = strlen(str);
  if (str[length-1] == '\n')
    str[length-1]  = '\0';
}
void trimLeading(char * str)
{
    int index, i;

    index = 0;

    /* Find last index of whitespace character */
    while(str[index] == ' ' || str[index] == '\t' || str[index] == '\n')
    {
        index++;
    }


    if(index != 0)
    {
        /* Shit all trailing characters to its left */
        i = 0;
        while(str[i + index] != '\0')
        {
            str[i] = str[i + index];
            i++;
        }
        str[i] = '\0'; // Make sure that string is NULL terminated
    }
}
//check if substring present in string : returns 1 is. 0 is not
int is_substr(char *str, char *sub)
{
  int num_matches = 0;
  int sub_size = 0;
  // If there are as many matches as there are characters in sub, then a substring exists.
  while (*sub != '\0') {
    sub_size++;
    sub++;
  }

  sub = sub - sub_size;  // Reset pointer to original place.
  while (*str != '\0') {
    while (*sub == *str && *sub != '\0') {
      num_matches++;
      sub++;
      str++;
    }
    if (num_matches == sub_size) {
      return 1;
    }
    num_matches = 0;  // Reset counter to 0 whenever a difference is found. 
    str++;
  }
  return 0;
}

//delete carriage return from string
void enleve_enter(char from, char to, char *str)
{
    int i = 0;
    int len = strlen(str)+1;

    for(i=0; i<len; i++)
    {
        if(str[i] == from)
        {
            str[i] = to;
        }
    }
}
//error handling
int handle_conn_error(char *error_code){
	if (is_substr(error_code, "UNKNOWN_ACCOUNT") == 1) {
  syslog(LOG_INFO, "It seems that the username/password incorrect");
		return FAILED;
} 
else {
return SUCCESS;
}
return 99;
}

int handle_update_error(char *error_code){
	if (is_substr(error_code, "WRONG_TOKEN") == 40) {
  syslog(LOG_INFO, "It seems that the token is wrong");
		return FAILED;
} 
else {
return SUCCESS;
}
return 30;
}
char* base64Encoder(char input_str[], int len_str) { 
	// Character set of base64 encoding scheme 
	char char_set[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"; 
	
	// Resultant string 
	char *res_str = (char *) malloc(SIZE * sizeof(char)); 
	
	int index, no_of_bits = 0, padding = 0, val = 0, count = 0, temp; 
	int i, j, k = 0; 
	
	// Loop takes 3 characters at a time from 
	// input_str and stores it in val 
	for (i = 0; i < len_str; i += 3) 
		{ 
			val = 0, count = 0, no_of_bits = 0; 

			for (j = i; j < len_str && j <= i + 2; j++) 
			{ 
				// binary data of input_str is stored in val 
				val = val << 8; 
				
				// (A + 0 = A) stores character in val 
				val = val | input_str[j]; 
				
				// calculates how many time loop 
				// ran if "MEN" -> 3 otherwise "ON" -> 2 
				count++; 
			
			} 

			no_of_bits = count * 8; 

			// calculates how many "=" to append after res_str. 
			padding = no_of_bits % 3; 

			// extracts all bits from val (6 at a time) 
			// and find the value of each block 
			while (no_of_bits != 0) 
			{ 
				// retrieve the value of each block 
				if (no_of_bits >= 6) 
				{ 
					temp = no_of_bits - 6; 
					
					// binary of 63 is (111111) f 
					index = (val >> temp) & 63; 
					no_of_bits -= 6;		 
				} 
				else
				{ 
					temp = 6 - no_of_bits; 
					
					// append zeros to right if bits are less than 6 
					index = (val << temp) & 63; 
					no_of_bits = 0; 
				} 
				res_str[k++] = char_set[index]; 
			} 
	} 

	// padding is done here 
	for (i = 1; i <= padding; i++) 
	{ 
		res_str[k++] = '='; 
	} 

	res_str[k] = '\0'; 

	return res_str; 
	free(res_str);

} 
char *create_login_pass_b64(char *username,char *password){

char * input_str;
input_str = malloc(sizeof(char)*100);
strcpy(input_str,"username=");
strcat(input_str,username);
strcat(input_str,"&pass=");
strcat(input_str,password);

return base64Encoder(input_str, strlen(input_str)); 
free(input_str);
}

char *str_after(char *mots){

const char separator = ':';
char * const after_column = strchr(mots, separator);
return after_column+1 ;

}

char *create_token_ip_b64(char *token,char *ip){

char * input_str;
input_str = malloc(sizeof(char)*100);
strcpy(input_str,"token=");
strcat(input_str,token);
strcat(input_str,"&ip=");
strcat(input_str,ip);
return base64Encoder(input_str, strlen(input_str)); 
free(input_str);
}


void Usage2(){	fprintf(stderr,  "\nUSAGE: %s ", program);
	fprintf(stderr,  "[ -C [ -F][ -Y][ -U #min]\n\t");
	fprintf(stderr,  "[ -u username][ -p password][ -x progname]]\n\t");
	fprintf(stderr,  "[ -c file]");
	fprintf(stderr, "Options: -C               create configuration data\n");
        fprintf(stderr, "Options: -U               update hostname's IP using config file /usr/local/etc/dyndns.conf /\n");
	fprintf(stderr, "         -h               help (this text)\n");
        fprintf(stderr, "         -v               version\n");
}
//void create_conf(char *filename){
void create_conf(int argc, char *argv[]){
	FILE *out_file = fopen(argv[2], "w"); 
	if (out_file == NULL) 
            {   
              printf("Error! Could not open file\n"); 
              exit(-1); 
            } 
	fprintf(out_file,  "TOKEN: %s\n", token_session); 
	free(token_session);
	fclose (out_file);
}
int WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp){
  size_t realsize = size * nmemb;
  struct MemoryStruct *mem = (struct MemoryStruct *)userp;

  char *ptr = realloc(mem->memory, mem->size + realsize + 1);
  if(ptr == NULL) {
    /* out of memory! */
    printf("not enough memory (realloc returned NULL)\n");
    return 0;
  }

  mem->memory = ptr;
  memcpy(&(mem->memory[mem->size]), contents, realsize);
  mem->size += realsize;
  mem->memory[mem->size] = 0;

  return realsize;
}
char *request_dyn(char *username,char *password,char *commando){
  CURL *curl_handle;
  CURLcode res;
 struct MemoryStruct chunk;
 
char * pass_str;
pass_str = malloc(sizeof(char)*100);
strcpy(pass_str,create_login_pass_b64(username,password));

char * pass_com;
pass_com = malloc(sizeof(char)*100);
strcpy(pass_com,commando);

  chunk.memory = malloc(1);  /* will be grown as needed by the realloc above */
  chunk.size = 0;    /* no data at this point */

  curl_global_init(CURL_GLOBAL_ALL);

  /* init the curl session */
  curl_handle = curl_easy_init();

/* URL: */
 sprintf(linko, "https://%s/%s", pass_com,pass_str); 
free(pass_str);
free(pass_com);
curl_easy_setopt(curl_handle, CURLOPT_URL, linko);

  /* send all data to this function  */
  curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);

  /* we pass our 'chunk' struct to the callback function */
  curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)&chunk);

  /* some servers don't like requests that are made without a user-agent
     field, so we provide one */
  curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, "libcurl-agent/1.0");

  /* get it! */
  res = curl_easy_perform(curl_handle);

  /* check for errors */
  if(res != CURLE_OK) {
    fprintf(stderr, "Connection failed: %s\n",
            curl_easy_strerror(res));
  }
  else {
    /*
     * Now, our chunk.memory points to a memory block that is chunk.size
     * bytes big and contains the remote file.
     *
     * Do something nice with it!
     */
	 memset(data, '\0', sizeof(data));
	 strcpy(data, chunk.memory);
     //printf("%s",data);
    //printf("%lu bytes retrieved\n", (unsigned long)chunk.size);
  }

  /* cleanup curl stuff */
  curl_easy_cleanup(curl_handle);

  free(chunk.memory);

  /* we're done with libcurl, so clean it up */
  curl_global_cleanup();

  return data;
//return linko;
}

char *update_dyn(char *token,char *ip){
  CURL *curl_handle;
  CURLcode res;
 struct MemoryStruct chunk;
 
char * pass_str;
pass_str = malloc(sizeof(char)*100);
strcpy(pass_str,create_token_ip_b64(token,ip));

  chunk.memory = malloc(1);  /* will be grown as needed by the realloc above */
  chunk.size = 0;    /* no data at this point */

  curl_global_init(CURL_GLOBAL_ALL);

  /* init the curl session */
  curl_handle = curl_easy_init();

/* URL: */
 sprintf(linko, "https://%s/%s", DYN_SERVER_UPDATE,pass_str); 
 
free(pass_str);

curl_easy_setopt(curl_handle, CURLOPT_URL, linko);
curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)&chunk);
curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, "libcurl-agent/1.0");
 res = curl_easy_perform(curl_handle);
  if(res != CURLE_OK) {
    fprintf(stderr, "Connection failed: %s\n",
            curl_easy_strerror(res));
  }
  else {
	 memset(data, '\0', sizeof(data));
	 strcpy(data, chunk.memory);
  }
  curl_easy_cleanup(curl_handle);
  free(chunk.memory);
  curl_global_cleanup();

  return data; 

  //return linko;//addded for test
}

char *curl_req(){
  CURL *curl_handle;
  CURLcode res;
 struct MemoryStruct chunk;

  chunk.memory = malloc(1);  /* will be grown as needed by the realloc above */
  chunk.size = 0;    /* no data at this point */

  curl_global_init(CURL_GLOBAL_ALL);

  /* init the curl session */
  curl_handle = curl_easy_init();

/* URL: */
 sprintf(linko, DYN_CLIENT_IP); 
curl_easy_setopt(curl_handle, CURLOPT_URL, linko);

  /* send all data to this function  */
  curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);

  /* we pass our 'chunk' struct to the callback function */
  curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)&chunk);

  /* some servers don't like requests that are made without a user-agent
     field, so we provide one */
  curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, "libcurl-agent/1.0");

  /* get it! */
  res = curl_easy_perform(curl_handle);

  /* check for errors */
  if(res != CURLE_OK) {
    fprintf(stderr, "Connection failed: %s\n",
            curl_easy_strerror(res));
  }
  else {
	 memset(data, '\0', sizeof(data));
	 strcpy(data, chunk.memory);
  }
  curl_easy_cleanup(curl_handle);

  free(chunk.memory);
  curl_global_cleanup();

  return data;
//return linko;
}

struct host_token initialize(void)
{

FILE *file  = fopen( DYN_CONF_FILE, "r");
    char line[256];
	struct host_token ht;
           fgets(line, sizeof(line), file) ;
       if (is_substr(line, "TOKEN:") == 1){
					strcpy(ht.token,str_after(line));
			};
             fgets(line, sizeof(line), file) ;
		if (is_substr(line, "Hostname: ") == 1){
				strcpy(ht.hostname ,str_after(line));
			};
    fclose(file);
	return ht;
}

struct fetch_token get(void)
{

FILE *file  = fopen( DYN_CONF_FILE, "r");
    char line[256];
	struct fetch_token ht;
           fgets(line, sizeof(line), file) ;
       if (is_substr(line, "TOKEN:") == 1){
					strcpy(ht.token,str_after(line));
			};
    fclose(file);
	return ht;
}



void process_options(int argc, char *argv[]){
	extern  int     optind, opterr;
	extern  char    *optarg;
	int     c;
	char * val_return;
	char userr[60];
    char passw[60];
	struct fetch_token stdArr;
	char answer;
	while ((c = getopt(argc, argv, OPTCHARS)) != EOF)	{
		switch (c) {
		case 'C':
		
	printf("Enter your username :");	
	fgets(userr, sizeof(userr), stdin);
	enleve_enter('\n',' ',userr);//remove new line from userr
	printf("Enter your password :");	
	fgets(passw, sizeof(passw), stdin);
	enleve_enter('\n',' ',passw);
			//get token
			val_return = malloc(sizeof(char)*100);
			strcpy(val_return,request_dyn(userr,passw,DYN_SERVER_INSTALL));
			
			enleve_enter('\n',' ',val_return);
			printf("%d", handle_conn_error(val_return));
            
			if (handle_conn_error(val_return)==20)
			{
				token_session = malloc(sizeof(char)*100);
				strcpy(token_session,val_return);
			create_conf(2, argv);
			printf("%s","...installation successfull. Please add your hostname to dyndns.conf file\n" );
				printf("\nDo you want to lauch execution in the background? y/n: \n");
				scanf(" %c", &answer);
				while (answer == 'y'){
				system("(crontab -l ; echo '10 * * * * dyndns -U') 2>&1 | grep -v 'no crontab' | sort | uniq | crontab -");
				printf("\n Crontab updated.\n");
					break;
				
				}
			}
			else if (handle_conn_error(val_return)==90)
			{	printf("%s","...installation not successfull. Please check your username / password combination\n" );
			}else printf("%s","...installation not successfull!!\n" );
			
			free(val_return);
			break;
		case 'U':
			stdArr = get();	
			trimLeading(stdArr.token);
			val_return = malloc(sizeof(char)*100);
			strcpy(val_return,update_dyn(stdArr.token,curl_req()));
            
			if (handle_update_error(val_return)==30)
			{
				printf("%s","hostname update successfull.\n" );
			}
			else if (handle_update_error(val_return)==40)
			{	printf("%s","hostname update failed.\n" );
			};
			free(val_return);
			break;
		case 'h':
			Usage2();
			exit(0);
		case 'v':
                        fprintf(stderr, VERSION"\n");;
                        exit(0);


		default:
			Usage2();
			exit(0);
		}
	}

	return;
}
char *get_token(char *username, char *password,char *serveur){
	
char input_str[] = "username="; 
	int len_str; 
	// calculates length of string 
	len_str = sizeof(input_str) / sizeof(input_str[0]); 
	// to exclude '\0' character 
	len_str -= 1; 
printf("Encoded string is : %s\n", base64Encoder(input_str, len_str)); 
	
	return username;

}

int main(int argc, char *argv[])
{


process_options(argc, argv);


}

