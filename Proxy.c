/*
 * COMP 321 Project 6: Web Proxy
 *
 * This program implements a multithreaded HTTP proxy.
 * 
 * We were granted a one-day extension by Dr. Johnson.
 * Davyd Fridman df21
 * Yuliia Suprun ys70
 */ 

#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include "csapp.h"
#include <signal.h>
#include <unistd.h>
#include <pthread.h>


#define NTHREAD 15
#define SBUFSIZE 16

typedef struct {
    struct args *buf; /* Buffer array */
    int n; /* Maximum number of slots */
    int front; /* buf[(front+1)%n] is first item */
    int rear; /* buf[rear%n] is last item */
    pthread_mutex_t mutex; /* Protects accesses to buf */
    int slots; /* Counts available slots */
    int items; /* Counts available items */
} sbuf_t;

struct args {
    int connfd;
    struct sockaddr_storage *clientaddr;
};

// Counter of total number of requests.
static int req_cnt = 0;
static FILE* logfile;
static sbuf_t sbuf; /* Shared buffer of connected descriptors */
pthread_mutex_t mutex;
pthread_cond_t ready_insert;
pthread_cond_t ready_remove;

static void client_error(int fd, const char *cause, int err_num, const char *short_msg, const char *long_msg);
static char *create_log_entry(const struct sockaddr_in *sockaddr,
            const char *uri, int size);
static int  parse_uri(const char *uri, char **hostnamep, char **portp,
            char **pathnamep);
static char* process_request(int connfd, struct sockaddr_in *clientaddr, char *forward_msg);
static int read_requesthdrs(rio_t *rp, char *buf, char* forward, char* version);
static int call_server(int connfd, char* forward_msg, char* uri);
static int process_response(rio_t *rio, char *buf, int* last_read);
static void* run_thread(void* args);
static void sbuf_init(sbuf_t *sp, int n);
static void sbuf_deinit(sbuf_t *sp);
static void sbuf_insert(sbuf_t *sp, struct args item);
static struct args sbuf_remove(sbuf_t *sp);

static void	sigint_handler(int signum);


/* 
 * Requires:
 *   argc - number of arguments passed to proxy.
 *   argv - array of string arguments.
 *
 * Effects:
 *   Runs proxy program.
 */
int
main(int argc, char **argv)
{

    pthread_t tid[NTHREAD];
    struct sigaction action;
    int listenfd, connfd;
    struct sockaddr_storage clientaddr; 
    socklen_t clientlen;
    /* Check the arguments. */
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <port number>\n", argv[0]);
        // I changed exit(0) to exit(1)
        exit(1);
    }
    // Open logfile.
    logfile = fopen("proxy.log", "a");
    // Let's start with the echo server.
    listenfd = Open_listenfd(argv[1]);

    // Igonre signal SIGPIPE.
    Signal(SIGPIPE, SIG_IGN);
    // Set SIGINT and SIGTERM signal handlers to close the log file when the server is terminated.
	action.sa_handler = sigint_handler;
	action.sa_flags = SA_RESTART;
	sigemptyset(&action.sa_mask);
	if (sigaction(SIGINT, &action, NULL) < 0)
		unix_error("sigaction error");

    action.sa_handler = sigint_handler;
	action.sa_flags = SA_RESTART;
	sigemptyset(&action.sa_mask);
	if (sigaction(SIGTERM, &action, NULL) < 0)
		unix_error("sigaction error");
    
    // Initializations for conccurency.
    Pthread_mutex_init(&mutex, NULL);
    pthread_cond_init(&ready_remove, NULL);
	pthread_cond_init(&ready_insert, NULL);
    sbuf_init(&sbuf, SBUFSIZE);

	for (int i = 0; i < NTHREAD; i++) {
        int* small_int = Malloc(sizeof(int));
        *small_int = i;
		Pthread_create(&tid[i], NULL, run_thread, small_int);//we pass args into a buffer
	}
    while(1) {
        clientlen = sizeof(clientaddr);
        connfd = Accept(listenfd, (struct sockaddr *)&clientaddr, &clientlen);
        struct args t_args;
        t_args.connfd = connfd;
        t_args.clientaddr = &clientaddr;
        sbuf_insert(&sbuf, t_args);
    }
    /* Return success. */
    return (0);
}

static void* run_thread(void* args) {
    // To prevent "unused parameters" warning.
    (void)args;
    Pthread_detach(pthread_self());
    while(1) {
        char client_hostname[MAXLINE], client_port[MAXLINE], forward_msg[MAXBUF];
        struct args arguments = sbuf_remove(&sbuf);
        int connfd = arguments.connfd;
        struct sockaddr_storage *clientaddr = arguments.clientaddr;
        socklen_t clientlen = sizeof(*clientaddr);
        int rc;
        if ((rc = getnameinfo((struct sockaddr *)clientaddr, clientlen, client_hostname, MAXLINE, client_port, MAXLINE, 0)) != 0) {
            fprintf(stderr, "getnameinfo error: %s\n", gai_strerror(rc));
            Close(connfd);
        }
        //Now we have a client whose request we need to forward to the end server.
        char* uri;
        if ((uri = process_request(connfd, (struct sockaddr_in *)clientaddr, forward_msg))== NULL) {
            //if there was na error with the request, then we want to close the fd and wait
            //for the next request.
            Close(connfd);
            continue;
        }
        int size = call_server(connfd, forward_msg, uri);
        if (size < 0) {
            // If there was an error with the server call, then we want to close the fd and wait for the next request.
            //Also, we don't want to log requests that are not met by the end server.
            Close(connfd);
            continue;
        }
        char *log_entry = create_log_entry((struct sockaddr_in *)clientaddr, uri, size);
        char log_out[MAXBUF]; 
        sprintf(log_out, "%s\n", log_entry);
        fwrite(log_out, strlen(log_entry)+1, 1, logfile);
        free(uri);
        free(log_entry);
        fflush(logfile);
        Close(connfd); 
        pthread_mutex_lock(&mutex);
        req_cnt++;
        pthread_mutex_unlock(&mutex);
        return NULL;
    }
}
/*
 * Requires:
 *   args - optional arguments parameter(may be used for debugging).
 * Effects:
 *   For each thread, accepts request from a client, forwards it to the
 *   server, and returns a response from the server to the client.
 */
static int call_server(int connfd, char* forward_msg, char* uri) {
    char buf[MAXBUF], req_out[MAXLINE];
    char *hostname, *port, *pathname;
    parse_uri(uri, &hostname, &port, &pathname);
    rio_t rio;
    // Now act as a client.
    int clientfd = Open_clientfd(hostname, port);
    rio_readinitb(&rio, clientfd);
    rio_writen(clientfd, forward_msg, strlen(forward_msg));//Send the request to the end server.

    int total_size = 0;
    int last_read = 1;
    int size;
    int count = 1;
    //allocate enough mmeory for MAXBUF chars and \0
    char *res_buf = Malloc(sizeof(char) * MAXBUF + 1);
    
    while(last_read > 0) {//We still have something left to read
        //MAXBUF is 8192. We need to split large requests into multiple small ones.
        //allocate enough mmeory for count*MAXBUF chars and \0
        res_buf = realloc(res_buf, count*MAXBUF + 1);//extend the resulting buffer to output
        //Set the next MAXBUF + 1 bytes to \0.
        memset(res_buf+(count-1)*MAXBUF, '\0', MAXBUF + 1);//set the memory before concatenation
        //all the calls to process responss
        count++;
        size = process_response(&rio, buf, &last_read);
        if (size < 0) {
            return (-1);
        }
        total_size+=size;
        sprintf(req_out, "Request %i: Forwarded %i bytes from end server to client\n", req_cnt, size);
        rio_writen(STDOUT_FILENO, req_out, strlen(req_out));
        strcat(res_buf, buf);
        //There are 2 options, learn the size in advance, or grow the resulting string bufferr dynamically.
    }
    char res_req_out[count*MAXBUF + 1];//used for format
    sprintf(res_req_out, "%s", res_buf);
    rio_writen(connfd, res_req_out, strlen(res_req_out));//print the actual return from the server
    free(hostname);
    free(port);
    free(pathname);
    Close(clientfd);
    return total_size;
}

/* Requires:
 *   rio - a valid buffer.
 *   buf - a valid string.
 *   last_read - a valid int pointer (indicates if there is anything left to
 *   read).
 * Effects:
 *   Helper function to process_response that helps with getting the response.
 */
static int process_response(rio_t *rio, char *buf, int* last_read) {
    /* 1. Read request line and headers. */
    int size = 0;
    int err = 0;
    char line[MAXLINE];
    
    //add 1 char for the terminating null
    memset(buf, '\0', MAXBUF + 1);
    memset(line, '\0', MAXBUF);
    while(size < 8192 && (err = rio_readnb(rio, line, MAXBUF)) > 0) {
        size += err;
        strcat(buf, line);
    }
    
    *last_read = err;
    return size;
}
/*
 * Requires: 
 *   connfd - a valid socket file descriptor.
 *   forward_msg - a valid pointer to char.
 *   clientaddr - a valid sockaddr_in struct.
 * Effects:
 *   Processes the request made by the client to the proxy.
 */
static char* process_request(int connfd, struct sockaddr_in *clientaddr, char *forward_msg) 
{
    //process one request and close the socketfd
    // We need to figure out what to do with long request lines. 
    char line[MAXLINE + 1], buf[MAXBUF], forward_hdrs[MAXBUF], method[MAXLINE], version[MAXLINE];
    rio_t rio;


    /* 1. Read request line and headers. */

    char *req_line = Malloc(sizeof(char)*MAXLINE + 1); //allocate for the first line
    memset(req_line, '\0', sizeof(char)*MAXLINE + 1);
    rio_readinitb(&rio, connfd);
    // Read request line into buffer.
    memset(line, '\0', MAXLINE);
    int count = 1;
    while (rio_readlineb(&rio, line, MAXLINE) > 0) {
        req_line = realloc(req_line, (count) * MAXLINE);
        memset(req_line, '\0', MAXLINE + 1);
        strcat(req_line, line);
        if(strstr(line, "\r\n")) 
            break;
        memset(line, '\0', MAXLINE);
    }
    char* uri = Malloc(strlen(req_line) + 1);//uri can't be bigger than the reqline
    //set method to some intial value in case its not get, so we can print a proper message
    // Check if the first line starts with GET.
    memset(uri, '\0', strlen(req_line) + 1);
    sscanf(req_line, "%s %s %s", method, uri, version);
    if (strcasecmp(method, "GET")) {
        client_error(connfd, method, 501, "Not implemented", "Client requested an unsupported method:");
        return NULL;
    }

    if(strcmp(version, "HTTP/1.1") && strcmp(version, "HTTP/1.0")) {
        client_error(connfd, version, 505, "HTTP Version Not Supported", "Received request that is neither HTTP/1.0 nor HTTP/1.1");
        return NULL;
    }

    // Read the headers into buffer.
    int err = read_requesthdrs(&rio, buf, forward_hdrs, version);
    if (err == -1)
        return NULL;

    /* 2. Print the request info. */
    char req_out[MAXBUF];
    char addr[INET_ADDRSTRLEN];

    // Can we use a wrapper function here?
    Inet_ntop(AF_INET, &(clientaddr->sin_addr), addr, INET_ADDRSTRLEN);

    sprintf(req_out, "Request %i: Received request from %s:\n%s%s*** End of Request ***\n", req_cnt, addr, req_line, buf);

    rio_writen(STDOUT_FILENO, req_out, strlen(req_out));
    if (err == 1) {
        char msg_out[MAXBUF];
        // For every header print the message.
        // We need to add more stripping output.

        sprintf(msg_out, "Request %i: Stripping \"Connection\" header\n", req_cnt);

        rio_writen(STDOUT_FILENO, msg_out, strlen(msg_out));
    }

    /* 3. Print the forward info. */
    // First, we have to take only the suffic of URI.
    char *p = strstr(uri, "/");
    char *suf_uri = p + 1;
    count = 0;
    while ((p = strstr(suf_uri, "/")) != NULL) {
        suf_uri = p + 1;
        count++;
    }
    // If this is a default directory, the suffic is absent.
    if (count < 2) {
        suf_uri = "";
    }
    /* Fill in the message that will be forward to the server. */
    sprintf(forward_msg, "%s /%s %s\r\n%s", method, suf_uri, version, forward_hdrs);

    char forward_out[MAXBUF];
    sprintf(forward_out, "Request %i: Forwarding request to end server:\n%s*** End of Request ***\n", req_cnt, forward_msg);
    free(req_line);
    rio_writen(STDOUT_FILENO, forward_out, strlen(forward_out));


    return uri;
}

/*
 * Requires: 
 *   rp - a valid pointer to rio buffer.
 *   forward - a valid pointer to char.
 *   version - a valid string.
 * Effects:
 *   Parse the headers and determine if header-stripping is required.
 */
static int read_requesthdrs(rio_t *rp, char *buf, char* forward, char* version)
{
    int err = 0;
    int alive = 0;
    char line[MAXLINE];

    err = rio_readlineb(rp, line, MAXLINE);
    memset(buf, '\0', MAXBUF);
    memset(forward, '\0', MAXBUF);
    while((strcmp(line, "\r\n")) && (err != -1)) {
        // Our proxy doesn't support persisten connections. Skip the corresponding header.
         if ((strstr(line, "Keep-Alive") == NULL) && (strstr(line, "keep-alive") == NULL)) {
            strcat(forward, line);
        } else {
            alive = 1;
        }
        strcat(buf, line);
        err = rio_readlineb(rp, line, MAXLINE);
    }

    if (!strcmp(version, "HTTP/1.1")) {
        strcat(forward, "Connection: close\r\n");
    }
    if (err != -1) {
        // Add "\r\n"
        strcat(buf, line);
        strcat(forward, line);
    } 
    if ((alive == 1) && (err != -1)) {
        err = 1;
    }
    return err;
}



/*
 * Requires:
 *   The parameter "uri" must point to a properly NUL-terminated string.
 *
 * Effects:
 *   Given a URI from an HTTP proxy GET request (i.e., a URL), extract the
 *   host name, port, and path name.  Create strings containing the host name,
 *   port, and path name, and return them through the parameters "hostnamep",
 *   "portp", "pathnamep", respectively.  (The caller must free the memory
 *   storing these strings.)  Return -1 if there are any problems and 0
 *   otherwise.
 */
static int
parse_uri(const char *uri, char **hostnamep, char **portp, char **pathnamep)
{
    const char *pathname_begin, *port_begin, *port_end;
    //URI is not URL
    if (strncasecmp(uri, "http://", 7) != 0)
        return (-1);

    /* Extract the host name. */
    const char *host_begin = uri + 7;
    const char *host_end = strpbrk(host_begin, ":/ \r\n");
    if (host_end == NULL)
        host_end = host_begin + strlen(host_begin);
    int len = host_end - host_begin;
    char *hostname = Malloc(len + 1);
    strncpy(hostname, host_begin, len);
    hostname[len] = '\0';
    *hostnamep = hostname;

    /* Look for a port number.  If none is found, use port 80. */
    if (*host_end == ':') {
        port_begin = host_end + 1;
        port_end = strpbrk(port_begin, "/ \r\n");
        if (port_end == NULL)
            port_end = port_begin + strlen(port_begin);
        len = port_end - port_begin;
    } else {
        port_begin = "80";
        port_end = host_end;
        len = 2;
    }
    char *port = Malloc(len + 1);
    strncpy(port, port_begin, len);
    port[len] = '\0';
    *portp = port;

    /* Extract the path. */
    if (*port_end == '/') {
        pathname_begin = port_end;
        const char *pathname_end = strpbrk(pathname_begin, " \r\n");
        if (pathname_end == NULL)
            pathname_end = pathname_begin + strlen(pathname_begin);
        len = pathname_end - pathname_begin;
    } else {
        pathname_begin = "/";
        len = 1;
    }
    char *pathname = Malloc(len + 1);
    strncpy(pathname, pathname_begin, len);
    pathname[len] = '\0';
    *pathnamep = pathname;

    return (0);
}

/*
 * Requires:
 *   The parameter "sockaddr" must point to a valid sockaddr_in structure.  The
 *   parameter "uri" must point to a properly NUL-terminated string.
 *
 * Effects:
 *   Returns a string containing a properly formatted log entry.  This log
 *   entry is based upon the socket address of the requesting client
 *   ("sockaddr"), the URI from the request ("uri"), and the size in bytes of
 *   the response from the server ("size").
 */
static char *
create_log_entry(const struct sockaddr_in *sockaddr, const char *uri, int size)
{
    struct tm result;

    /*
     * Create a large enough array of characters to store a log entry.
     * Although the length of the URI can exceed MAXLINE, the combined
     * lengths of the other fields and separators cannot.
     */
    const size_t log_maxlen = MAXLINE + strlen(uri);
    char *const log_str = Malloc(log_maxlen + 1);

    /* Get a formatted time string. */
    time_t now = time(NULL);
    int log_strlen = strftime(log_str, MAXLINE, "%a %d %b %Y %H:%M:%S %Z: ",
        localtime_r(&now, &result));

    /*
     * Convert the IP address in network byte order to dotted decimal
     * form.
     */
    Inet_ntop(AF_INET, &sockaddr->sin_addr, &log_str[log_strlen],
        INET_ADDRSTRLEN);
    log_strlen += strlen(&log_str[log_strlen]);

    /*
     * Assert that the time and IP address fields occupy less than half of
     * the space that is reserved for the non-URI fields.
     */
    assert(log_strlen < MAXLINE / 2);

    /*
     * Add the URI and response size onto the end of the log entry.
     */
    snprintf(&log_str[log_strlen], log_maxlen - log_strlen, " %s %d", uri,
        size);

    return (log_str);
}

/*
 * Requires:
 *   The parameter "fd" must be an open socket that is connected to the client.
 *   The parameters "cause", "short_msg", and "long_msg" must point to properly 
 *   NUL-terminated strings that describe the reason why the HTTP transaction
 *   failed.  The string "short_msg" may not exceed 32 characters in length,
 *   and the string "long_msg" may not exceed 80 characters in length.
 *
 * Effects:
 *   Constructs an HTML page describing the reason why the HTTP transaction
 *   failed, and writes an HTTP/1.0 response containing that page as the
 *   content.  The cause appearing in the HTML page is truncated if the
 *   string "cause" exceeds 2048 characters in length.
 */
static void
client_error(int fd, const char *cause, int err_num, const char *short_msg,
    const char *long_msg)
{
    char body[MAXBUF], headers[MAXBUF], truncated_cause[2049];

    assert(strlen(short_msg) <= 32);
    assert(strlen(long_msg) <= 80);
    /* Ensure that "body" is much larger than "truncated_cause". */
    assert(sizeof(truncated_cause) < MAXBUF / 2);

    /*
     * Create a truncated "cause" string so that the response body will not
     * exceed MAXBUF.
     */
    strncpy(truncated_cause, cause, sizeof(truncated_cause) - 1);
    truncated_cause[sizeof(truncated_cause) - 1] = '\0';

    /* Build the HTTP response body. */
    snprintf(body, MAXBUF,
        "<html><title>Proxy Error</title><body bgcolor=""ffffff"">\r\n"
        "%d: %s\r\n"
        "<p>%s: %s\r\n"
        "<hr><em>The COMP 321 Web proxy</em>\r\n",
        err_num, short_msg, long_msg, truncated_cause);

    /* Build the HTTP response headers. */
    snprintf(headers, MAXBUF,
        "HTTP/1.0 %d %s\r\n"
        "Content-type: text/html\r\n"
        "Content-length: %d\r\n"
        "\r\n",
        err_num, short_msg, (int)strlen(body));

    /* Write the HTTP response. */
    if (rio_writen(fd, headers, strlen(headers)) != -1)
        rio_writen(fd, body, strlen(body));
}

/* Requires:
 *   sp - valid pointer to the buffer sbuf_t.
 *   n - size of the buffer.
 * Effects:
 *   Intialize the buffer sp.
 */
static void sbuf_init(sbuf_t *sp, int n)
{
    sp->buf = Calloc(n, sizeof(struct args));
    sp->n = n; /* Buffer holds max of n items */
    sp->front = 0;
    sp->rear = 0; /* Empty buffer iff front == rear */
    Pthread_mutex_init(&sp->mutex, NULL); /* mutex for locking */
    sp->slots = n; /* Initially, buf has n empty slots */
    sp->items = 0; /* Initially, buf has zero data items */
}

/* Requires:
 *   sp - valid pointer to the buffer sbuf_t.
 * Effects:
 *   Deintialize the buffer sp.
 */
static void sbuf_deinit(sbuf_t *sp)
{
    free(sp->buf);
    Pthread_mutex_destroy(&sp->mutex);
    
}

/* Requires:
 *  sp - valid pointer to the buffer sbuf_t.
 *  item - a valid struct args to add.
 * Effects:
 *   Insert an item to the buffer sp.
 */
static void sbuf_insert(sbuf_t *sp, struct args item)
{
    pthread_mutex_lock(&sp->mutex); /* Lock the buffer */
    while(sp->slots == 0) {
        pthread_cond_wait(&ready_insert, &sp->mutex);
     } /* Wait for available slot */
    sp->buf[(++sp->rear)%(sp->n)] = item; /* Insert the item */
    sp->items++;
    sp->slots--;
    pthread_cond_signal(&ready_remove);/* Announce available item */
    pthread_mutex_unlock(&sp->mutex); /* Unlock the buffer */
}

/* Requires:
 *  sp - valid pointer to the buffer sbuf_t.
 * Effects:
 *   Remove and return the first item from the buffer sp.
 */
static struct args sbuf_remove(sbuf_t *sp)
{
    struct args item;
    pthread_mutex_lock(&sp->mutex); /* Lock the buffer */
    while(sp->items == 0) {
        pthread_cond_wait(&ready_remove, &sp->mutex);
    }
    item = sp->buf[(++sp->front)%(sp->n)]; /* Remove the item */
    sp->slots++;
    sp->items--;
    pthread_cond_signal(&ready_insert);/* Announce available slot */
    pthread_mutex_unlock(&sp->mutex);  /*Unlock buffer*/
    return item;
}

/*
 * Handles the termination of the proxy.
 */
static void	sigint_handler(int signum) {
    (void)signum;
    fclose(logfile);//close the file when the server terminates
    sbuf_deinit(&sbuf);
    Pthread_cond_destroy(&ready_remove);
    Pthread_cond_destroy(&ready_insert);
    pthread_mutex_destroy(&mutex);
    exit(0);
}

// Prevent "unused function" and "unused variable" warnings.
static const void *dummy_ref[] = { client_error, create_log_entry, dummy_ref,
    parse_uri };