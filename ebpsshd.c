/* 

ebpsshd.c compile:

gcc -g -Wall -Wstrict-prototypes -O0 -o ebpsshd `pkg-config --cflags --libs glib-2.0` -I/home/jeetu/utils/libssh/libssh-project/include ebpsshd.c -L/home/jeetu/utils/libssh/libssh-project/build/src -lssh -L/home/jeetu/utils/libssh/libssh-project/build/src/threads -lssh_threads -lgthread-2.0

*/


#include <libssh/libssh.h>
#include <libssh/server.h>
#include <libssh/callbacks.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <glib.h>
#include <stdlib.h>
#include <errno.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <fcntl.h>
#include "key.h" //jeetu - temporary hardcoded key

#ifndef KEYS_FOLDER
#ifdef _WIN32
#define KEYS_FOLDER
#else
#define KEYS_FOLDER "/home/jeetu/tmp/" //jeetu - temporary
#define AUTHORIZED_KEYS "/home/jeetu/tmp/authorized_keys"
#endif
#endif

#define MAX_X11_AUTH_PROTO_STR_SZ 18
#define MAX_X11_AUTH_COOKIE_STR_SZ 50

//jeetu - all hardcoded defines; should probably figure out how these values came to be in the orig openssh code
#define MAX_DISPLAYS 1000
#define NI_MAXSERV 32
#define NUM_SOCKS 10
#define SSH_LISTEN_BACKLOG 128


static int copy_chan_to_fd(ssh_session session,
                                           ssh_channel channel,
                                           void *data,
                                           uint32_t len,
                                           int is_stderr,
                                           void *userdata);

static void chan_close(ssh_session session, ssh_channel channel, void *userdata);
static int copy_fd_to_chan(socket_t fd, int revents, void *userdata);


typedef struct x11_session_struct
       {
       char *x11_auth_cookie;
       char *x11_auth_protocol;
       int screen_number;
       int single_connection;
       unsigned int display_number;
       } x11_session;

typedef struct x11_conn_struct
       {
       ssh_session session;
       int client_sock;
       } x11data;
       

int authenticate_user(ssh_session session);
int pubkey_auth(char *pk64);
int server_loop(ssh_session session);
int session_x11_req(ssh_session session,ssh_message message,x11_session* x11session,int *socket);
int session_setup_x11fwd(ssh_session session,x11_session* x11session,int *socket);
int x11_create_display_inet(ssh_session session,unsigned int *display_numberp, int *sockets);
int wait_for_something(ssh_session session,int socket);
static gpointer server_thread(gpointer session_data);
int exec_command(const char *command,x11_session* x11session);
//static gpointer exec_command(gpointer data);
static gpointer process_x11_channel_events_thread(gpointer x11conndata);

ssh_channel chan=0;
ssh_session *session;
x11data **x11conndata;


/* Return Values:
 * 0 - Success
 * 1 - ssh_bind_listen failed - error listening to socket
 * 2 - ssh_bind_accept failed - error accepting a connection
 * 3 - ssh_handle_key_change failed 
 * 4 - authenticate_user failed
 */
int main(int argc, char **argv)
{    
    ssh_bind sshbind;
    int auth=0;
    int r;
    int port = 2000;
    int verbosity = SSH_LOG_PACKET;
    int session_count = 0;

    g_thread_init(NULL);

    ssh_threads_set_callbacks(ssh_threads_get_pthread());
    if(ssh_init() == -1)
      {
      printf("\nError initializing ssh: ssh_init() failed");
      exit(1);
      }

    sshbind=ssh_bind_new();
    session = (ssh_session *) ssh_new();

    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDPORT,&port);
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_DSAKEY, KEYS_FOLDER "ssh_host_dsa_key");
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_RSAKEY, KEYS_FOLDER "ssh_host_rsa_key");

    if(ssh_bind_listen(sshbind)<0)
      {
      printf("Error listening to socket: %s\n",ssh_get_error(sshbind));
      return 1;
      }   
 
    while(1)
         {
         session[session_count]=ssh_new();
         ssh_options_getopt(session[session_count],&argc,argv);
         r=ssh_bind_accept(sshbind,session[session_count]);
         if(r==SSH_ERROR)
           {
           printf("error accepting a connection : %s\n",ssh_get_error(sshbind));
           return 2;
           }
         ssh_options_set(session[session_count], SSH_OPTIONS_LOG_VERBOSITY, &verbosity );
         if(ssh_handle_key_exchange(session[session_count]))
           {
           printf("ssh_handle_key_exchange: %s\n",ssh_get_error(session[session_count]));
           return 3;
           }
      
         /* public key authentication */
         auth = authenticate_user(session[session_count]);
         if(!auth)
           {
           printf("auth error: %s\n",ssh_get_error(session[session_count]));
           ssh_disconnect(session[session_count]);
           return 4;
           }
         g_thread_create(server_thread,session[session_count],FALSE,NULL);
         session_count++;
         }
  
  
    ssh_bind_free(sshbind);
    ssh_finalize();
  
    return 0;
}

/* returns 1 for OK, 0 for KO */
int authenticate_user(ssh_session session) 
{
    ssh_message message;
    ssh_string pubkey = NULL;
    char *pk64 = NULL;
    int signature_state = SSH_PUBLICKEY_STATE_NONE;

    do 
     {
     message = ssh_message_get(session);
     if(!message) 
       return 0;

     switch(ssh_message_type(message)) 
           {
           case SSH_REQUEST_AUTH:
                switch(ssh_message_subtype(message)) 
                      {
                      case SSH_AUTH_METHOD_PUBLICKEY:
                           pubkey = publickey_to_string(ssh_message_auth_publickey(message));
			   pk64 = g_base64_encode((const guchar *)ssh_string_to_char(pubkey), ssh_string_len(pubkey));
			   signature_state = ssh_message_auth_publickey_state(message);
                           if(signature_state == SSH_PUBLICKEY_STATE_NONE) 
			     {
                             /* no signature */
                             ssh_message_auth_reply_pk_ok_simple(message);
                             break;
                             } 
                           else if(signature_state != SSH_PUBLICKEY_STATE_VALID) 
                             {
                             /* will be rejected later */
                             } 
                           else 
                             {
                             /* signature is good at that point */
                             if(pubkey_auth(pk64)) 
                               {
                               /* user is allowed */
                               ssh_message_auth_reply_success(message, 0);
                               ssh_message_free(message);
                               return 1;
                               }
                             }
                           /* the following is not necessary if we want only pubkey auth */
                           ssh_message_auth_set_methods(message,SSH_AUTH_METHOD_PUBLICKEY);
                           /* reject authentication */
                           ssh_message_reply_default(message);
                           break;
                      case SSH_AUTH_METHOD_PASSWORD:
                        /* handle password auth if needed */
                      default:
                           ssh_message_auth_set_methods(message,SSH_AUTH_METHOD_PUBLICKEY);
                           ssh_message_reply_default(message);
                      }
                break;
           default:
                ssh_message_reply_default(message);
           }
     ssh_message_free(message);
     }while(1);
    
    return 0;
}

int pubkey_auth(char* pk64)
{
    char header[100],key[300],footer[100];
    int ret = 0;
    FILE *fp;

    fp = fopen(AUTHORIZED_KEYS,"r");
    if(fp == NULL)
      {
      fprintf(stderr,"\nCould not open authorized_keys file %s\n",AUTHORIZED_KEYS);
      return 0;
      }

    while(fgetc(fp) != EOF)
         {
         header[0] = '\0';
         key[0] = '\0';
         footer[0] = '\0';
         fscanf(fp,"%s %s %s\n",header,key,footer);
         printf("\nkey = %s\n",key);
         if(strcmp(pk64,key) == 0)
           {
           ret = 1;
           break;
           }
         }

    fclose(fp);
    return ret;
}


static gpointer server_thread(gpointer session_data)
{
    ssh_message message;
    int message_subtype = 0;
    int message_type = 0;
    int ret = 0;
    ssh_session session = (ssh_session) session_data;
    x11_session x11session;
    int socket;

    do 
     {
     message=ssh_message_get(session);
     if(message)
       {
       message_type = ssh_message_type(message);
       message_subtype = ssh_message_subtype(message);

       switch(message_type)
             {		
	     case SSH_REQUEST_CHANNEL_OPEN:
                  if(message_subtype == SSH_CHANNEL_SESSION)
                    {
		    printf("\nSSH_CHANNEL_SESSION");
                    chan=ssh_message_channel_request_open_reply_accept(message);
                    }
		  break;
	     case SSH_REQUEST_CHANNEL:
		  printf("\nSSH_REQUEST_CHANNEL subtype = %d",message_subtype);
		  if(message_subtype == SSH_CHANNEL_REQUEST_X11)
		    {
		    printf("\nSSH_CHANNEL_REQUEST_X11");
		    if(session_x11_req(session,message,&x11session,&socket) != 1)
                      {
                      printf("\nsession_x11_req error");
                      ssh_message_reply_default(message);
                      ssh_disconnect(session);
                      return NULL;
                      }
                    else
		      ssh_message_channel_request_reply_success(message);
		    }
		  if(message_subtype == SSH_CHANNEL_REQUEST_ENV)
		    {		   
		    printf("\nSSH_CHANNEL_REQUEST_ENV");
		    ssh_message_channel_request_reply_success(message);
		    }
		  if(message_subtype == SSH_CHANNEL_REQUEST_EXEC)
		    {
		    printf("\nSSH_CHANNEL_REQUEST_EXEC command = %s\n",ssh_message_channel_request_command(message));
                    ret = exec_command(ssh_message_channel_request_command(message),&x11session);
                    if(ret == 0)
                      {
                      printf("\nserver_loop: unable to exec command\n");
                      }
                    ssh_message_channel_request_reply_success(message);		
                    wait_for_something(session,socket);
                    ssh_disconnect(session);
		    return NULL; /* Aris's hack */   
		    }
		  break;		    
	     default:
                  ssh_message_reply_default(message);
	     }
       ssh_message_free(message);
       }
     } while(1);

     return NULL;
}


int session_x11_req(ssh_session session,ssh_message message,x11_session* x11session,int *socket)
{
    int ret = 1;
    FILE* fpxauth;
    char xauth_path[] = "/usr/bin/xauth";
    char strxauth_exec[200]; //jeetu - buffer size sufficient?; xauth path name may be larger; ideally not fixed

    x11session->x11_auth_protocol = NULL;
    x11session->x11_auth_cookie = NULL;

    x11session->x11_auth_protocol = malloc(MAX_X11_AUTH_PROTO_STR_SZ+2);
    strncpy(x11session->x11_auth_protocol,ssh_message_channel_request_x11_auth_protocol(message),MAX_X11_AUTH_PROTO_STR_SZ+1);
    x11session->x11_auth_protocol[MAX_X11_AUTH_PROTO_STR_SZ] = '\0';
    if(strncmp(x11session->x11_auth_protocol,"MIT-MAGIC-COOKIE-1",MAX_X11_AUTH_PROTO_STR_SZ+1) == 0)
      { 
      x11session->x11_auth_cookie = malloc(MAX_X11_AUTH_COOKIE_STR_SZ+2);
      strncpy(x11session->x11_auth_cookie,ssh_message_channel_request_x11_auth_cookie(message),MAX_X11_AUTH_COOKIE_STR_SZ+1);
      x11session->x11_auth_cookie[MAX_X11_AUTH_COOKIE_STR_SZ] = '\0';
      x11session->screen_number = ssh_message_channel_request_x11_screen_number(message);
      x11session->single_connection = ssh_message_channel_request_x11_single_connection(message);
      }
    else
      return 0;

    ret = session_setup_x11fwd(session,x11session,socket);
    if(ret == 0)
      {
      printf("\nsession_setup_x11fwd failed");
      return 0;
      }

    printf("\nx11_auth_protocol=%s\nx11_auth_cookie=%s\nscreen_number = %d\nsingle_connection =  %d\ndisplay_number = %d\n",x11session->x11_auth_protocol,x11session->x11_auth_cookie,x11session->screen_number,x11session->single_connection,x11session->display_number);

    snprintf(strxauth_exec,199,"%s remove :%d",xauth_path,x11session->display_number);
    printf("\nstrxauth_exec = %s",strxauth_exec);

    fpxauth = popen(strxauth_exec,"r");
    if(fpxauth == NULL)
      return 0;
    pclose(fpxauth);

    strxauth_exec[0] = '\0';
    snprintf(strxauth_exec,199,"%s add unix:%d %s %s",xauth_path,x11session->display_number,x11session->x11_auth_protocol,x11session->x11_auth_cookie);
    printf("\nstrxauth_exec = %s",strxauth_exec);

    fpxauth = popen(strxauth_exec,"r");
    if(fpxauth == NULL)
      return 0;
    pclose(fpxauth);

    return ret;
}



int session_setup_x11fwd(ssh_session session,x11_session* x11session,int *socket)
{
    int ret = 1;

    ret = x11_create_display_inet(session,&x11session->display_number,socket);
    if(ret == 0)
      {
      printf("\nx11_create_display_inet failed");
      return 0;
      }

    return ret;
}

int x11_create_display_inet(ssh_session session,unsigned int *display_numberp, int *sockets)
{
    int ret = 1;
    int display_num = 0,sock = 0,num_socks = 0;
    unsigned int port = 0;
    struct addrinfo hints, *ai, *aitop;
    char strport[NI_MAXSERV];
    int gaierr,n,socks[NUM_SOCKS];
    static int x11_display_offset = 10; //jeetu - temporarily hardcoded here

    printf("\nx11_create_display_inet: x11_display_offset = %d\n",x11_display_offset);    
    for(display_num = x11_display_offset; display_num < MAX_DISPLAYS; display_num++)
       {
       port = 6000 + display_num;
       hints.ai_family = AF_INET;
       hints.ai_flags = AI_NUMERICSERV | AI_PASSIVE;
       hints.ai_socktype = SOCK_STREAM;
       hints.ai_protocol = 0;
       snprintf(strport, sizeof strport, "%d", port);
       if((gaierr = getaddrinfo(NULL, strport, &hints, &aitop)) != 0)
	 {
         printf("\ngetaddrinfo: %s",gai_strerror(gaierr));
         return 0;
         }

       for(ai = aitop; ai; ai = ai->ai_next)
          {
	  if(ai->ai_family != AF_INET && ai->ai_family != AF_INET6)
	    continue;
          sock = socket(ai->ai_family, ai->ai_socktype,ai->ai_protocol);
	  if(sock < 0)
            {
	    if((errno != EINVAL) && (errno != EAFNOSUPPORT))
              {
	      printf("\nsocket error: %s", strerror(errno));
	      freeaddrinfo(aitop);
	      return 0;
	      }
            else
              {
	      printf("\nx11_create_display_inet: Socket family %d not supported",ai->ai_family);
	      continue;
              }
            }
//          if(ai->ai_family == AF_INET6)
//	    sock_set_v6only(sock);
//	  if(x11_use_localhost)
//	    channel_set_reuseaddr(sock);
	  if(bind(sock, ai->ai_addr, ai->ai_addrlen) < 0)
            {
	    printf("bind port %d: %s", port, strerror(errno));
            close(sock);
            for(n = 0; n < num_socks; n++) 
               {
	       close(socks[n]);
	       }
            num_socks = 0;
            break;
            }
          socks[num_socks++] = sock;
	  if(num_socks == NUM_SOCKS)
	    break;
          }
       freeaddrinfo(aitop);
       if(num_socks > 0)
	 break;
       }    

    if(display_num >= MAX_DISPLAYS) 
      {
      printf("\nFailed to allocate internet-domain X11 display socket.");
      return 0;
      }
 
    /* Start listening for connections on the socket. */
    for(n = 0; n < num_socks; n++) 
       {
       sock = socks[n];
       *(sockets+n) = sock;
       if(listen(sock, SSH_LISTEN_BACKLOG) < 0) 
         {
	 printf("\nlisten: %s", strerror(errno));
	 close(sock);
	 return 0;
	 }
       }

    *display_numberp = display_num;
    x11_display_offset++;
    return ret;
}

/*
int wait_for_something(ssh_session session,int socket)
{
    fd_set infds, testfds;
    struct timeval tv = { 15, 0 };
    int maxfds = 0;
    int nready;
    int client_sock, cli_len;
    struct sockaddr_in cli_addr;
    ssh_event event;
    short events;
    ssh_channel chan_x11=0;

    struct ssh_channel_callbacks_struct cb = 
	{
    	.channel_data_function = copy_chan_to_fd,
    	.channel_eof_function = chan_close,
    	.channel_close_function = chan_close,
	.userdata = NULL 
	};
    
    FD_ZERO(&infds);
    FD_SET(socket, &infds);
    printf("\nwait_for_something: socket = %d\n",socket);
    maxfds = socket;    

    testfds = infds;
    printf("\nwait_for_something: before select\n");
    tv.tv_sec = 15;
    nready = select(maxfds + 1, &testfds, NULL, NULL, &tv);
    if(nready == -1)
      {
      printf("\nselect error: %s\n",strerror(errno));
      }
    if(nready > 0)
      {
      printf("\nwait_for_something: nready > 0");
      if(FD_ISSET(socket, &testfds))
        {
        printf("\nFD_ISSET\n");
        cli_len = sizeof (cli_addr);
	bzero((char *) &cli_addr, sizeof (cli_addr));	
	client_sock = accept(socket, (struct sockaddr *) &cli_addr, (socklen_t *) &cli_len);
        printf("\nclient_sock = %d",client_sock);
        chan_x11 = ssh_channel_new(session);
        if(ssh_channel_open_x11(chan_x11,"127.0.0.1",client_sock) == SSH_ERROR)
          {
          printf("ssh_channel_open_x11 error : %s\n",ssh_get_error(chan_x11));
          return 0;
          }
        else
          printf("\nssh_channel_open_x11\n");

        cb.userdata = &client_sock;
        ssh_callbacks_init(&cb);
        ssh_set_channel_callbacks(chan_x11, &cb);
	events = POLLIN | POLLPRI | POLLERR | POLLHUP | POLLNVAL;
        event = ssh_event_new();
        if(event == NULL) 
          {
          printf("Couldn't get a event\n");
          return 0;
          }
        else
          printf("\nevent != NULL");

        if(ssh_event_add_fd(event, client_sock, events, copy_fd_to_chan, chan_x11) != SSH_OK) 
          {
          printf("Couldn't add an fd to the event\n");
	  return 0;
          }
        else
          printf("\nAdded fd to event");

        if(ssh_event_add_session(event, session) != SSH_OK) 
          {
          printf("Couldn't add the session to the event\n");
          return 0;
          }
        else
          printf("\nadded the session to the event\n");
  
        do {
           ssh_event_dopoll(event, 1000);
           } while(!ssh_channel_is_closed(chan_x11));
        printf("\nssh_channel_open_x11: channel closed\n");
//             ssh_event_remove_fd(event, client_sock);
//             ssh_event_remove_session(event, data->session);
//             ssh_event_free(event);
        }
      }
    printf("\nexiting wait_for_something\n");
    return 1;
}
*/

static int copy_fd_to_chan(socket_t fd, int revents, void *userdata) 
{
    ssh_channel chan = (ssh_channel)userdata;
    char buf[2048];
    int sz = 0;
    buf[0] = '\0';    

    if(!chan) {
        close(fd);
        return -1;
    }
    if(revents & POLLIN) {
        sz = read(fd, buf, 2048);        
        if(sz == 0)
          {
          ssh_channel_close(chan);
          close(fd);
          sz = -1;
          }
        if(sz > 0) {
            ssh_channel_write(chan, buf, sz);
        }
    }
    if(revents & POLLHUP) {
        ssh_channel_close(chan);
        sz = -1;
    }
    return sz;
}


static int copy_chan_to_fd(ssh_session session,
                                           ssh_channel channel,
                                           void *data,
                                           uint32_t len,
                                           int is_stderr,
                                           void *userdata) 
{
    int fd = *(int*)userdata;
    int sz;
    (void)session;
    (void)channel;
    (void)is_stderr;

    sz = write(fd, data, len);

    return sz;
}

static void chan_close(ssh_session session, ssh_channel channel, void *userdata) 
{
    int fd = *(int*)userdata;
    (void)session;
    (void)channel;

    close(fd);
}


int exec_command(const char *command,x11_session* x11session)
//static gpointer exec_command(gpointer data)
{
    FILE *fpcmd;
    char str_exec[256]; //jeetu - buffer size sufficient?; command name may be larger; ideally not fixed
//    char *env[256] = {"DISPLAY=:10",NULL};
//    char *argv[256] = {"/bin/sh","-c","xcalc",NULL};

    str_exec[0] = '\0';
//    snprintf(str_exec,199,"%s -display :%d",command,x11session->display_number);
    snprintf(str_exec,256,"/bin/sh -c \"export DISPLAY=:%d;%s\"",x11session->display_number,command);
    fpcmd = popen(str_exec,"r");
    if(fpcmd == NULL)
      return 0;
//    execve("/bin/sh",argv,env);    

    return 1;
//    return NULL;
}


int wait_for_something(ssh_session session,int socket)
{
    fd_set infds, testfds;
    struct timeval tv = { 15, 0 };
    int maxfds = 0;
    int nready;
    int x11datacount = 0;
    int client_sock,cli_len;
    struct sockaddr_in cli_addr;

    x11conndata = malloc(sizeof(x11data)); //jeetu - memory to be freed

    while(1)
         {
         FD_ZERO(&infds);
         FD_SET(socket, &infds);
         printf("\nwait_for_something: socket = %d\n",socket);
         maxfds = socket;    

         testfds = infds;
         printf("\nwait_for_something: before select\n");
         tv.tv_sec = 15;
         nready = select(maxfds + 1, &testfds, NULL, NULL, &tv);
         if(nready == -1)
           {
           printf("\nselect error: %s\n",strerror(errno));
           }
         if(nready > 0)
           {
           printf("\nwait_for_something: nready > 0");
           if(FD_ISSET(socket, &testfds))
             {
             printf("\nFD_ISSET\n");
             x11conndata[x11datacount] = malloc(sizeof(x11data));
             cli_len = sizeof (cli_addr);
	     bzero((char *) &cli_addr, sizeof (cli_addr));	
	     client_sock = accept(socket, (struct sockaddr *) &cli_addr, (socklen_t *) &cli_len);
             printf("\nclient_sock = %d",client_sock);
             x11conndata[x11datacount]->session = session;
             x11conndata[x11datacount]->client_sock = client_sock;
             g_thread_create(process_x11_channel_events_thread,x11conndata[x11datacount],FALSE,NULL);
             x11datacount++;
             }
           }
         }
    printf("\nexiting wait_for_something\n");
    return 1;
}


static gpointer process_x11_channel_events_thread(gpointer x11conndata)
{
    ssh_event event;
    short events;
    ssh_channel chan_x11=0;
    int client_sock;
    x11data *data = (x11data *) x11conndata;

    struct ssh_channel_callbacks_struct cb = 
	{
    	.channel_data_function = copy_chan_to_fd,
    	.channel_eof_function = chan_close,
    	.channel_close_function = chan_close,
	.userdata = NULL 
	};

    client_sock = data->client_sock;
    chan_x11 = ssh_channel_new(data->session);
    if(ssh_channel_open_x11(chan_x11,"127.0.0.1",client_sock) == SSH_ERROR)
      {
      printf("ssh_channel_open_x11 error : %s\n",ssh_get_error(chan_x11));
      return NULL;
      }
    else
      printf("\nssh_channel_open_x11\n");

    cb.userdata = &client_sock;
    ssh_callbacks_init(&cb);
    ssh_set_channel_callbacks(chan_x11, &cb);
    events = POLLIN | POLLPRI | POLLERR | POLLHUP | POLLNVAL;
    event = ssh_event_new();
    if(event == NULL) 
      {
      printf("Couldn't get a event\n");
      return NULL;
      }
    else
      printf("\nevent != NULL");

    if(ssh_event_add_fd(event, client_sock, events, copy_fd_to_chan, chan_x11) != SSH_OK) 
      {
      printf("Couldn't add an fd to the event\n");
      return NULL;
      }
    else
      printf("\nAdded fd to event");

    if(ssh_event_add_session(event, data->session) != SSH_OK) 
      {
      printf("Couldn't add the session to the event\n");
      return NULL;
      }
    else
      printf("\nadded the session to the event\n");
 
    do {
       ssh_event_dopoll(event, 1000);
       } while(!ssh_channel_is_closed(chan_x11));
    printf("\nssh_channel_open_x11: channel closed\n");
//             ssh_event_remove_fd(event, client_sock);
//             ssh_event_remove_session(event, data->session);
//             ssh_event_free(event);

    return NULL;
}
