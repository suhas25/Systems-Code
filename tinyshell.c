/*
 * COMP 321 Project 4: Shell
 *
 * This program implements a tiny shell with job control.
 *
 * Davyd Fridman(df21)
 * Yulia Suprun(ys70) 
 */

#include <sys/types.h>
#include <sys/wait.h>

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// You may assume that these constants are large enough.
#define MAXLINE      1024   // max line size
#define MAXARGS       128   // max args on a command line
#define MAXJOBS        16   // max jobs at any point in time
#define MAXJID   (1 << 16)  // max job ID

// The job states are:
#define UNDEF 0 // undefined
#define FG 1    // running in foreground
#define BG 2    // running in background
#define ST 3    // stopped

/*
 * The job state transitions and enabling actions are:
 *     FG -> ST  : ctrl-z
 *     ST -> FG  : fg command
 *     ST -> BG  : bg command
 *     BG -> FG  : fg command
 * At most one job can be in the FG state.
 */

struct Job {
	pid_t pid;              // job PID
	int jid;                // job ID [1, 2, ...]
	int state;              // UNDEF, FG, BG, or ST
	char cmdline[MAXLINE];  // command line
};
typedef volatile struct Job *JobP;

/*
 * Define the jobs list using the "volatile" qualifier because it is accessed
 * by a signal handler (as well as the main program).
 */
static volatile struct Job jobs[MAXJOBS];
static int nextjid = 1;            // next job ID to allocate

extern char **environ;             // defined by libc

static char prompt[] = "tsh> ";    // command line prompt (DO NOT CHANGE)
static bool verbose = false;       // If true, print additional output.	  
static char** init_paths; //global array for storing path directories. 
static int num_paths = 0;		 //store number of entries in the init_paths array.

/*
 * The following array can be used to map a signal number to its name.
 * This mapping is valid for x86(-64)/Linux systems, such as CLEAR.
 * The mapping for other versions of Unix, such as FreeBSD, Mac OS X, or
 * Solaris, differ!
 */
static const char *const signame[NSIG] = {
	"Signal 0",
	"HUP",				/* SIGHUP */
	"INT",				/* SIGINT */
	"QUIT",				/* SIGQUIT */
	"ILL",				/* SIGILL */
	"TRAP",				/* SIGTRAP */
	"ABRT",				/* SIGABRT */
	"BUS",				/* SIGBUS */
	"FPE",				/* SIGFPE */
	"KILL",				/* SIGKILL */
	"USR1",				/* SIGUSR1 */
	"SEGV",				/* SIGSEGV */
	"USR2",				/* SIGUSR2 */
	"PIPE",				/* SIGPIPE */
	"ALRM",				/* SIGALRM */
	"TERM",				/* SIGTERM */
	"STKFLT",			/* SIGSTKFLT */
	"CHLD",				/* SIGCHLD */
	"CONT",				/* SIGCONT */
	"STOP",				/* SIGSTOP */
	"TSTP",				/* SIGTSTP */
	"TTIN",				/* SIGTTIN */
	"TTOU",				/* SIGTTOU */
	"URG",				/* SIGURG */
	"XCPU",				/* SIGXCPU */
	"XFSZ",				/* SIGXFSZ */
	"VTALRM",			/* SIGVTALRM */
	"PROF",				/* SIGPROF */
	"WINCH",			/* SIGWINCH */
	"IO",				/* SIGIO */
	"PWR",				/* SIGPWR */
	"Signal 31"
};

// You must implement the following functions:

static int	builtin_cmd(char **argv);
static void	do_bgfg(char **argv);
static void	eval(const char *cmdline);
static void	initpath(const char *pathstr);
static void	waitfg(pid_t pid);


static pid_t	get_id(char *str_id);
static bool 	is_directory(char** argv);
static void     print_process(JobP process);

static void	sigchld_handler(int signum);
static void	sigint_handler(int signum);
static void	sigtstp_handler(int signum);

// We are providing the following functions to you:

static int	parseline(const char *cmdline, char **argv); 

static void	sigquit_handler(int signum);

static int	addjob(JobP jobs, pid_t pid, int state, const char *cmdline);
static void	clearjob(JobP job);
static int	deletejob(JobP jobs, pid_t pid); 
static pid_t	fgpid(JobP jobs);
static JobP	getjobjid(JobP jobs, int jid); 
static JobP	getjobpid(JobP jobs, pid_t pid);
static void	initjobs(JobP jobs);
static void	listjobs(JobP jobs);
static int	maxjid(JobP jobs); 
static int	pid2jid(pid_t pid); 

static void	app_error(const char *msg);
static void	unix_error(const char *msg);
static void	usage(void);
static pid_t 	Fork(void);
static void 	*Malloc(size_t size);

static void	Sio_error(const char s[]);
static ssize_t	Sio_putl(long v);
static ssize_t	Sio_puts(const char s[]);
static void	sio_error(const char s[]);
static void	sio_ltoa(long v, char s[], int b);
static ssize_t	sio_putl(long v);
static ssize_t	sio_puts(const char s[]);
static void	sio_reverse(char s[]);
static size_t	sio_strlen(const char s[]);

/*
 * Entry point to the tsh program.
 * 
 * Requires:
 *   "argc" - the number of arguments passed through
 *   command line. 
 *   "argv" - a valid array of strings (arguments).
 *
 * Effects:
 *   Parses the the command line, emits prompt and starts
 *   the tsh by calling eval function with the command line
 *   input to tsh.
 */
int
main(int argc, char **argv) 
{
	struct sigaction action;
	int c;
	char cmdline[MAXLINE];
	char *path = NULL;
	(void)path;
	bool emit_prompt = true;	// Emit a prompt by default.

	/*
	 * Redirect stderr to stdout (so that driver will get all output
	 * on the pipe connected to stdout).
	 */
	dup2(1, 2);

	// Parse the command line.
	while ((c = getopt(argc, argv, "hvp")) != -1) {
		switch (c) {
		case 'h':             // Print a help message.
			usage();
			break;
		case 'v':             // Emit additional diagnostic info.
			verbose = true;
			break;
		case 'p':             // Don't print a prompt.
			// This is handy for automatic testing.
			emit_prompt = false;
			break;
		default:
			usage();
		}
	}

	/*
	 * Install sigint_handler() as the handler for SIGINT (ctrl-c).  SET
	 * action.sa_mask TO REFLECT THE SYNCHRONIZATION REQUIRED BY YOUR
	 * IMPLEMENTATION OF sigint_handler().//change mask. Use mask to block
	 * other signals that may interfere with the data structures. Rule G3
	 */
	action.sa_handler = sigint_handler;
	action.sa_flags = SA_RESTART;
	sigemptyset(&action.sa_mask);
	//Add the proper signals to the blocking set.
	if (sigaction(SIGINT, &action, NULL) < 0)
		unix_error("sigaction error");

	/*
	 * Install sigtstp_handler() as the handler for SIGTSTP (ctrl-z).  SET
	 * action.sa_mask TO REFLECT THE SYNCHRONIZATION REQUIRED BY YOUR
	 * IMPLEMENTATION OF sigtstp_handler().
	 */
	action.sa_handler = sigtstp_handler;
	action.sa_flags = SA_RESTART;
	sigemptyset(&action.sa_mask);
	//Add the proper signals to the blocking set.
	
	if (sigaction(SIGTSTP, &action, NULL) < 0)
		unix_error("sigaction error");

	/*
	 * Install sigchld_handler() as the handler for SIGCHLD (terminated or
	 * stopped child).  SET action.sa_mask TO REFLECT THE SYNCHRONIZATION
	 * REQUIRED BY YOUR IMPLEMENTATION OF sigchld_handler().
	 */
	action.sa_handler = sigchld_handler;
	action.sa_flags = SA_RESTART;
	sigemptyset(&action.sa_mask);
	//Add the proper signals to the blocking set.
	//We do not need to block child handler because it's automatically blocked.

	if (sigaction(SIGCHLD, &action, NULL) < 0)
		unix_error("sigaction error");

	/*
	 * Install sigquit_handler() as the handler for SIGQUIT.  This handler
	 * provides a clean way for the test harness to terminate the shell.
	 * Preemption of the processor by the other signal handlers during
	 * sigquit_handler() does no harm, so action.sa_mask is set to empty.
	 */
	action.sa_handler = sigquit_handler;
	action.sa_flags = SA_RESTART;
	sigemptyset(&action.sa_mask);
	if (sigaction(SIGQUIT, &action, NULL) < 0)
		unix_error("sigaction error");

	// Initialize the search path.
	path = getenv("PATH");
	initpath(path);

	// Initialize the jobs list.
	initjobs(jobs);

	// Execute the shell's read/eval loop.
	while (true) {

		// Read the command line.
		if (emit_prompt) {
			printf("%s", prompt);
			fflush(stdout);
		}
		if (fgets(cmdline, MAXLINE, stdin) == NULL && ferror(stdin))
			app_error("fgets error");
		if (feof(stdin)) // End of file (ctrl-d)
			exit(0);

		// Evaluate the command line.
		eval(cmdline);
		fflush(stdout);
	}

	// Control never reaches here.
	assert(false);
}
  
/*
 * Requires:
 *   Nothing.
 *
 * Effects:
 *   Handles the possible error, occured when the fork() is called.
 *   Returns the process ID of the child if called by parent or 0 if
 *   called by child.
 */
static pid_t 
Fork(void)
{
	pid_t pid;
	if ((pid = fork()) < 0)
		app_error("Failed to create a new process!");
	return pid;
}

/*
 * Requires:
 *   Nothing.
 *
 * Effects:
 *   Handles the possible error, occured when the malloc() is called.
 *   Returns the pointer to the allocated memory.
 */
void *Malloc(size_t size) 
{
    void *p;

    if ((p  = malloc(size)) == NULL)
	app_error("Malloc error");
    return p;
}
/* 
 * eval - Evaluate the command line that the user has just typed in.
 * 
 * If the user has requested a built-in command (quit, jobs, bg or fg)
 * then execute it immediately.  Otherwise, fork a child process and
 * run the job in the context of the child.  If the job is running in
 * the foreground, wait for it to terminate and then return.  Note:
 * each child process must have a unique process group ID so that our
 * background children don't receive SIGINT (SIGTSTP) from the kernel
 * when we type ctrl-c (ctrl-z) at the keyboard.  
 *
 * Requires:
 *   "cmdline" a valid string enetered into the shell. 
 *
 * Effects:
 *   Attempts an execution of a shell command specified in the "command line".
 *   If the command is a built-in command, then it's executed in the context of the
 *   current process. Otherwise, a new process is created and the execution
 *   of the command is attempted in the context of that process.   
 */
static void
eval(const char *cmdline) 
{

	char *argv[MAXARGS];
	int bg;
	pid_t pid;

	sigset_t mask_one, prev_one;
        // Initialize the mask containing the SIGCHLD signal.
	sigemptyset(&mask_one);
	sigaddset(&mask_one, SIGCHLD);
	// Parse the command line.
	bg = parseline(cmdline, argv);
        // Check if the command line has any arguments.
	if (argv[0] == NULL)
		return;
	// Check whether thefirst arg is a built_in command line.
	if (!builtin_cmd(argv)) {
                // Block the SIGCHLD signal.
		sigprocmask(SIG_BLOCK, &mask_one, &prev_one);
                // Create a child process.
		if ((pid = Fork()) == 0) {
                        // Unlock the SIGCHLD signal.
			sigprocmask(SIG_SETMASK, &prev_one, NULL);
                        // Make the child's group ID different from 
                        // shell's pid.
			setpgid(0, 0);
                        // Check whether the first arg is executable file.
			if (is_directory(argv) || init_paths == NULL) {
				// Executes the executable file.
                                // Use the provided arguments.
				if(execve(argv[0], argv, environ) < 0) {
					printf("%s: Command not found.\n", argv[0]);
					// If the error occured, we exit
                                        // the child process.
					exit(0);
				}
			} else {
				
				char* complete_path;
				for (int i = 0; i < num_paths; i++) {
					// If the executable is in the current directory.
					if (strlen(init_paths[i]) == 0) { 
						execve(argv[0], argv, environ);
						continue;
					} else if (init_paths[i][strlen(init_paths[i]) - 1] == '/') { 
					// When the executable is in the current directory.
						complete_path = Malloc(sizeof(char)*(strlen(argv[0])+ strlen(init_paths[i]) + 1));
						strcpy(complete_path, init_paths[i]);
					} else {
						complete_path = Malloc(sizeof(char)*(strlen(argv[0])+ strlen(init_paths[i]) + 2));
						strcpy(complete_path, init_paths[i]);
						strcat(complete_path, "/");
					}
					strcat(complete_path, argv[0]);
					// Malloc is erased.
					execve(complete_path, argv, environ);
					free(complete_path);
				}
				printf("%s: Command not found.\n", argv[0]);
				// Passed the whole loop.
				exit(0);
				// We exit the child process.
			}
		}

		if (!bg) {//let's add job
			addjob(jobs, pid, FG, cmdline);
			sigprocmask(SIG_SETMASK, &prev_one, NULL);
			//use waitfg
			waitfg(pid);
		}
		else {
			addjob(jobs, pid, BG, cmdline);
			print_process(getjobpid(jobs, pid));
			sigprocmask(SIG_SETMASK, &prev_one, NULL);
			
		}
	}

	return;
}

/* 
 * parseline - Parse the command line and build the argv array.
 *
 * Requires:
 *   "cmdline" is a NUL ('\0') terminated string with a trailing
 *   '\n' character.  "cmdline" must contain less than MAXARGS
 *   arguments.
 *
 * Effects:
 *   Builds "argv" array from space delimited arguments on the command line.
 *   The final element of "argv" is set to NULL.  Characters enclosed in
 *   single quotes are treated as a single argument.  Returns true if
 *   the user has requested a BG job and false if the user has requested
 *   a FG job.
 */
static int
parseline(const char *cmdline, char **argv) 
{
	int argc;                   // number of args
	int bg;                     // background job?
	static char array[MAXLINE]; // local copy of command line
	char *buf = array;          // ptr that traverses command line
	char *delim;                // points to first space delimiter

	strcpy(buf, cmdline);

	// Replace trailing '\n' with space.
	buf[strlen(buf) - 1] = ' ';

	// Ignore leading spaces.
	while (*buf != '\0' && *buf == ' ')
		buf++;

	// Build the argv list.
	argc = 0;
	if (*buf == '\'') {
		buf++;
		delim = strchr(buf, '\'');
	} else
		delim = strchr(buf, ' ');
	while (delim != NULL) {
		argv[argc++] = buf;
		*delim = '\0';
		buf = delim + 1;
		while (*buf != '\0' && *buf == ' ')	// Ignore spaces.
			buf++;
		if (*buf == '\'') {
			buf++;
			delim = strchr(buf, '\'');
		} else
			delim = strchr(buf, ' ');
	}
	argv[argc] = NULL;

	// Ignore blank line.
	if (argc == 0)
		return (1);

	// Should the job run in the background?
	if ((bg = (*argv[argc - 1] == '&')) != 0)
		argv[--argc] = NULL;

	return (bg);
}

/*
 * is_directory - Check if the first argument is a directory.
 * 
 * Requires:
 *   argv - a valid array of strings.
 * Effects:
 *  Returns 1 if the first element of argv contains a "/" 
 *  (i.e. a directory). Otherwise, returns 0. 
 */
static bool 
is_directory(char **argv) {
	char symb;
	// Check whether the string contains '/' character.
	for (int i = 0; (symb =  argv[0][i]) != '\0'; i++) {
		if(symb == '/') {
			return true;
		}
	}
	return false;
}

/* 
 * builtin_cmd - If the user has typed a built-in command then execute
 *  it immediately.  
 *
 * Requires:
 *   argv - a valid array of strings.
 *
 * Effects:
 *   If the the first argument is a bultin command, attempts the execution
 *   of the command with the subsequent arguments and returns 1. Otherwise,
 *   returns 0.
 */
static int
builtin_cmd(char **argv) 
{
	// Check if the command is quit.
	if (!strcmp(argv[0], "quit"))
		exit(0);
	// Check if the command is jobs.
	else if (!strcmp(argv[0], "jobs")) {
		listjobs(jobs);
		return (1);
	}
	// Check if the command is bg or fg.
	else if (!strcmp(argv[0], "bg") || !strcmp(argv[0], "fg")) {
		do_bgfg(argv);
		return (1);
	}
	else if (!strcmp(argv[0], "&")) 
		return (1);

	return (0);     // This is not a built-in command.
}

/* 
 * do_bgfg - Execute the built-in bg and fg commands.
 *
 * Requires:
 *   If bg is callled, then change a 
 *
 * Effects:
 *   If job/process exists, then continues the job/process in the background(bg)
 *   foreground (fg).
*
 */
static void
do_bgfg(char **argv) 
{
	// Get the jid or pid, 0 if error occured.
	pid_t pid = get_id(argv[1]);
	// Let's get all the background job ids
	if (argv[1] == NULL ) {
		printf("%s command requires PID or %%jobid argument\n", argv[0]);
		return;
	} else if (pid <= 0 && argv[1][0] != '0' && argv[1][0] != '%') {
		printf("%s: argument must be a PID or %%jobid\n", argv[0]);
		return;
	} else {
		JobP process = NULL;
		if (argv[1][0] == '%') {
			// Check if jid is in the jobs array.
			if((process = getjobjid(jobs, pid)) == NULL) {
				printf("%s: No such job\n", argv[1]);
				return;
			}
		
			// For every process in the job, run in background.
		} else {
			if((process = getjobpid(jobs, pid)) == NULL) {
				printf("(%i): No such process\n", pid);
				return;
			}
		}

		// Check if bg or fg.
		if(!strcmp(argv[0], "bg")) {
			process->state = BG;
			kill(-process->pid, SIGCONT);
			print_process(process);
		}
		else {
			process->state = FG;
			kill(-process->pid, SIGCONT);
			waitfg(process->pid);
		}		
	}
} 
	
	

/*
 * Prints process info in the specified format.
 *
 */
static void
print_process(JobP process){
	printf("[%d] (%d) %s",process->jid, process->pid, process->cmdline);
}

/*
 * Returns the pid or jid. If the input is invalid, returns -1.
 *
 */
static pid_t
get_id(char *str_id)
{
	// Get the id of the process.
	int id;
	if (str_id == NULL)
		return 0;
	else if (str_id[0] == '%')
		// Atoi returns 0 if not digits.
		id = atoi(&str_id[1]);
	else
		id = atoi(str_id);
	return id;
}

/* 
 * waitfg - Block until process pid is no longer the foreground process.
 *
 * Requires:
 *   "pid" is a valid pointer to the foreground process. 
 *
 * Effects:
 *   Waits for the foreground job to complete through while accepting signals.
 */
static void
waitfg(pid_t pid)
{
	sigset_t mask, prev;
	sigemptyset(&mask);
	// Define all the signals that should be blocked while we are waiting.
	// Deal with errors. print error.
	sigaddset(&mask, SIGCHLD);
	// Block the signals.
	sigprocmask(SIG_BLOCK, &mask, &prev);

	JobP job = getjobpid(jobs, pid);
	// Why do we keep checking job->pid == pid?
	while(job->pid == pid && job->state == FG) {
		//For a moment, unblock the signals.
		sigsuspend(&prev);
	}
	//Return to the mask before the call to waitfg.
	sigprocmask(SIG_SETMASK, &prev, NULL);
}

/* 
 * initpath - Perform all necessary initialization of the search path,
 *  which may be simply saving the path.
 *
 * Requires:
 *   "pathstr" is a valid search path.
 *
 * Effects:
 *   Build an array of directory strings from pathstr.
 */
static void
initpath(const char *pathstr)
{

	//We need to prepare PATH for the use of the eval
	
	//colon inside

	//get the number of search paths
	int count = 0; 
	for (unsigned int i = 0; i < strlen(pathstr); i++){
		if (pathstr[i]==':')
			count++;
	}
	init_paths = Malloc((count + 1)* sizeof(char*));
	num_paths = count + 1; 

	char* pathstr_copy = strdup(pathstr); 
	char* str_dir;
	//use strchr 
	for (int i = 0; (str_dir = strsep(&pathstr_copy,":")) != NULL; i++)
		init_paths[i] = str_dir;
}

/*
 * The signal handlers follow.
 */

/* 
 * sigchld_handler - The kernel sends a SIGCHLD to the shell whenever
 *  a child job terminates (becomes a zombie), or stops because it
 *  received a SIGSTOP or SIGTSTP signal.  The handler reaps all
 *  available zombie children, but doesn't wait for any other
 *  currently running children to terminate.  
 *
 * Requires:
 *   "signum" - number of the signal caught by the handler.
 *
 * Effects:
 *   Catches and handles a SIGCHLD signal depending
 *   on the cause of the signal (i.e. exit, SIGTSTP,
 *   or signal).
 *   
 */
static void
sigchld_handler(int signum)
{
	(void)signum;
	int status;
	pid_t pid;

	// Separate processes using WUNTRACED and WHOANG and puase?
	//We need to take care of all possible signals
	while((pid = waitpid(-1, &status, WNOHANG|WUNTRACED)) > 0){//keep reaping children when there are children to reap
		if(WIFEXITED(status)) {
			deletejob(jobs, pid);//delete if exited
		}
		else if(WIFSIGNALED(status)) {//react to signal
			Sio_puts("Job [");
			Sio_putl(pid2jid(pid));
			Sio_puts("] (");
			Sio_putl(pid);
			Sio_puts(") terminated by signal SIG");
			Sio_puts(signame[WTERMSIG(status)]);
			Sio_puts("\n");
			deletejob(jobs, pid);
		} else if (WIFSTOPPED(status)) {//stopped
			JobP proc = getjobpid(jobs, pid);
			proc->state = ST;
			Sio_puts("Job [");
			Sio_putl(pid2jid(pid));
			Sio_puts("] (");
			Sio_putl(pid);
			Sio_puts(") stopped by signal SIG");
			Sio_puts(signame[WSTOPSIG(status)]);
			Sio_puts("\n");
		}
	}
	return;
}

/* 
 * sigint_handler - The kernel sends a SIGINT to the shell whenever the
 *  user types ctrl-c at the keyboard.  Catch it and send it along
 *  to the foreground job.  
 *
 * Requires:
 *   "signum" - number of the signal caught by the handler.
 *
 * Effects:
 *   Catches and handles SIGTSTP signal by sending
 *   SIGINT to the foreground job.
 */
static void
sigint_handler(int signum)
{
	(void)signum;
	pid_t pid; //foreground jib pid
	//Sio_puts("I'm inside sinit\n");
	if((pid = fgpid(jobs)) == 0) {//if foreground is 0
		return;
	}//how do we delete the child? Does it goes to the handler?
	kill(-pid, SIGINT);
}

/*
 * sigtstp_handler - The kernel sends a SIGTSTP to the shell whenever
 *  the user types ctrl-z at the keyboard.  Catch it and suspend the
 *  foreground job by sending it a SIGTSTP.  
 *
 * Requires:
 *   "signum" - number of the signal caught by the handler.
 *
 * Effects:
 *   Catches and handles SIGTSTP signal by sending
 *   SIGTSTP to the foreground job.
 */
static void
sigtstp_handler(int signum)
{
	(void)signum;
	// Prevent an "unused parameter" warning.
	pid_t pid; //foreground jib pid
	if((pid = fgpid(jobs)) == 0) {//if foreground is 0 it's either because it. Can we call 
		return;
	}
	kill(-pid, SIGTSTP);
}

/*
 * sigquit_handler - The driver program can gracefully terminate the
 *  child shell by sending it a SIGQUIT signal.
 *
 * Requires:
 *   "signum" is SIGQUIT.
 *
 * Effects:
 *   Terminates the program.
 */
static void
sigquit_handler(int signum)
{

	// Prevent an "unused parameter" warning.
	(void)signum;
	Sio_puts("Terminating after receipt of SIGQUIT signal\n");
	_exit(1);
}

/*
 * This comment marks the end of the signal handlers.
 */

/*
 * The following helper routines manipulate the jobs list.
 */

/*
 * Requires:
 *   "job" points to a job structure.
 *
 * Effects:
 *   Clears the fields in the referenced job structure.
 */
static void
clearjob(JobP job)
{

	job->pid = 0;
	job->jid = 0;
	job->state = UNDEF;
	job->cmdline[0] = '\0';
}

/*
 * Requires:
 *   "jobs" points to an array of MAXJOBS job structures.
 *
 * Effects:
 *   Initializes the jobs list to an empty state.
 */
static void
initjobs(JobP jobs)
{
	int i;

	for (i = 0; i < MAXJOBS; i++)
		clearjob(&jobs[i]);
}

/*
 * Requires:
 *   "jobs" points to an array of MAXJOBS job structures.
 *
 * Effects:
 *   Returns the largest allocated job ID.
 */
static int
maxjid(JobP jobs) 
{
	int i, max = 0;

	for (i = 0; i < MAXJOBS; i++)
		if (jobs[i].jid > max)
			max = jobs[i].jid;
	return (max);
}

/*
 * Requires:
 *   "jobs" points to an array of MAXJOBS job structures, and "cmdline" is
 *   a properly terminated string.
 *
 * Effects: 
 *   Adds a job to the jobs list. 
 */
static int
addjob(JobP jobs, pid_t pid, int state, const char *cmdline)
{
	int i;
    
	if (pid < 1)
		return (0);
	for (i = 0; i < MAXJOBS; i++) {
		if (jobs[i].pid == 0) {
			jobs[i].pid = pid;
			jobs[i].state = state;
			jobs[i].jid = nextjid++;
			if (nextjid > MAXJOBS)
				nextjid = 1;
			// Remove the "volatile" qualifier using a cast.
			strcpy((char *)jobs[i].cmdline, cmdline);
			if (verbose) {
				printf("Added job [%d] %d %s\n", jobs[i].jid,
				    (int)jobs[i].pid, jobs[i].cmdline);
			}
			return (1);
		}
	}
	printf("Tried to create too many jobs\n");
	return (0);
}

/*
 * Requires:
 *   "jobs" points to an array of MAXJOBS job structures.
 *
 * Effects:
 *   Deletes a job from the jobs list whose PID equals "pid".
 */
static int
deletejob(JobP jobs, pid_t pid) 
{
	int i;

	if (pid < 1)
		return (0);
	for (i = 0; i < MAXJOBS; i++) {
		if (jobs[i].pid == pid) {
			clearjob(&jobs[i]);
			nextjid = maxjid(jobs) + 1;
			return (1);
		}
	}
	return (0);
}

/*
 * Requires:
 *   "jobs" points to an array of MAXJOBS job structures.
 *
 * Effects:
 *   Returns the PID of the current foreground job or 0 if no foreground
 *   job exists.
 */
static pid_t
fgpid(JobP jobs)
{
	int i;

	for (i = 0; i < MAXJOBS; i++)
		if (jobs[i].state == FG)
			return (jobs[i].pid);
	return (0);
}

/*
 * Requires:
 *   "jobs" points to an array of MAXJOBS job structures.
 *
 * Effects:
 *   Returns a pointer to the job structure with process ID "pid" or NULL if
 *   no such job exists.
 */
static JobP
getjobpid(JobP jobs, pid_t pid)
{
	int i;

	if (pid < 1)
		return (NULL);
	for (i = 0; i < MAXJOBS; i++)
		if (jobs[i].pid == pid)
			return (&jobs[i]);
	return (NULL);
}

/*
 * Requires:
 *   "jobs" points to an array of MAXJOBS job structures.
 *
 * Effects:
 *   Returns a pointer to the job structure with job ID "jid" or NULL if no
 *   such job exists.
 */
static JobP
getjobjid(JobP jobs, int jid) 
{
	int i;

	if (jid < 1)
		return (NULL);
	for (i = 0; i < MAXJOBS; i++)
		if (jobs[i].jid == jid)
			return (&jobs[i]);
	return (NULL);
}

/*
 * Requires:
 *   Nothing.
 *
 * Effects:
 *   Returns the job ID for the job with process ID "pid" or 0 if no such
 *   job exists.
 */
static int
pid2jid(pid_t pid) 
{
	int i;

	if (pid < 1)
		return (0);
	for (i = 0; i < MAXJOBS; i++)
		if (jobs[i].pid == pid)
			return (jobs[i].jid);
	return (0);
}

/*
 * Requires:
 *   "jobs" points to an array of MAXJOBS job structures.
 *
 * Effects:
 *   Prints the jobs list.
 */
static void
listjobs(JobP jobs) 
{
	int i;

	for (i = 0; i < MAXJOBS; i++) {
		if (jobs[i].pid != 0) {
			printf("[%d] (%d) ", jobs[i].jid, (int)jobs[i].pid);
			switch (jobs[i].state) {
			case BG: 
				printf("Running ");
				break;
			case FG: 
				printf("Foreground ");
				break;
			case ST: 
				printf("Stopped ");
				break;
			default:
				printf("listjobs: Internal error: "
				    "job[%d].state=%d ", i, jobs[i].state);
			}
			printf("%s", jobs[i].cmdline);
		}
	}
}

/*
 * This comment marks the end of the jobs list helper routines.
 */

/*
 * Other helper routines follow.
 */

/*
 * Requires:
 *   Nothing.
 *
 * Effects:
 *   Prints a help message.
 */
static void
usage(void) 
{

	printf("Usage: shell [-hvp]\n");
	printf("   -h   print this message\n");
	printf("   -v   print additional diagnostic information\n");
	printf("   -p   do not emit a command prompt\n");
	exit(1);
}

/*
 * Requires:
 *   "msg" is a properly terminated string.
 *
 * Effects:
 *   Prints a Unix-style error message and terminates the program.
 */
static void
unix_error(const char *msg)
{

	fprintf(stdout, "%s: %s\n", msg, strerror(errno));
	exit(1);
}

/*
 * Requires:
 *   "msg" is a properly terminated string.
 *
 * Effects:
 *   Prints "msg" and terminates the program.
 */
static void
app_error(const char *msg)
{

	fprintf(stdout, "%s\n", msg);
	exit(1);
}

/*
 * Requires:
 *   The character array "s" is sufficiently large to store the ASCII
 *   representation of the long "v" in base "b".
 *
 * Effects:
 *   Converts a long "v" to a base "b" string, storing that string in the
 *   character array "s" (from K&R).  This function can be safely called by
 *   a signal handler.
 */
static void
sio_ltoa(long v, char s[], int b)
{
	int c, i = 0;

	do
		s[i++] = (c = v % b) < 10 ? c + '0' : c - 10 + 'a';
	while ((v /= b) > 0);
	s[i] = '\0';
	sio_reverse(s);
}

/*
 * Requires:
 *   "s" is a properly terminated string.
 *
 * Effects:
 *   Reverses a string (from K&R).  This function can be safely called by a
 *   signal handler.
 */
static void
sio_reverse(char s[])
{
	int c, i, j;

	for (i = 0, j = sio_strlen(s) - 1; i < j; i++, j--) {
		c = s[i];
		s[i] = s[j];
		s[j] = c;
	}
}

/*
 * Requires:
 *   "s" is a properly terminated string.
 *
 * Effects:
 *   Computes and returns the length of the string "s".  This function can be
 *   safely called by a signal handler.
 */
static size_t
sio_strlen(const char s[])
{
	size_t i = 0;

	while (s[i] != '\0')
		i++;
	return (i);
}

/*
 * Requires:
 *   None.
 *
 * Effects:
 *   Prints the long "v" to stdout using only functions that can be safely
 *   called by a signal handler, and returns either the number of characters
 *   printed or -1 if the long could not be printed.
 */
static ssize_t
sio_putl(long v)
{
	char s[128];
    
	sio_ltoa(v, s, 10);
	return (sio_puts(s));
}

/*
 * Requires:
 *   "s" is a properly terminated string.
 *
 * Effects:
 *   Prints the string "s" to stdout using only functions that can be safely
 *   called by a signal handler, and returns either the number of characters
 *   printed or -1 if the string could not be printed.
 */
static ssize_t
sio_puts(const char s[])
{

	return (write(STDOUT_FILENO, s, sio_strlen(s)));
}

/*
 * Requires:
 *   "s" is a properly terminated string.
 *
 * Effects:
 *   Prints the string "s" to stdout using only functions that can be safely
 *   called by a signal handler, and exits the program.
 */
static void
sio_error(const char s[])
{

	sio_puts(s);
	_exit(1);
}

/*
 * Requires:
 *   None.
 *
 * Effects:
 *   Prints the long "v" to stdout using only functions that can be safely
 *   called by a signal handler.  Either returns the number of characters
 *   printed or exits if the long could not be printed.
 */
static ssize_t
Sio_putl(long v)
{
	ssize_t n;
  
	if ((n = sio_putl(v)) < 0)
		sio_error("Sio_putl error");
	return (n);
}

/*
 * Requires:
 *   "s" is a properly terminated string.
 *
 * Effects:
 *   Prints the string "s" to stdout using only functions that can be safely
 *   called by a signal handler.  Either returns the number of characters
 *   printed or exits if the string could not be printed.
 */
static ssize_t
Sio_puts(const char s[])
{
	ssize_t n;
  
	if ((n = sio_puts(s)) < 0)
		sio_error("Sio_puts error");
	return (n);
}

/*
 * Requires:
 *   "s" is a properly terminated string.
 *
 * Effects:
 *   Prints the string "s" to stdout using only functions that can be safely
 *   called by a signal handler, and exits the program.
 */
static void
Sio_error(const char s[])
{

	sio_error(s);
}

// Prevent "unused function" and "unused variable" warnings.
static const void *dummy_ref[] = { Sio_error, Sio_putl, addjob, builtin_cmd,
    deletejob, do_bgfg, dummy_ref, fgpid, getjobjid, getjobpid, listjobs,
    parseline, pid2jid, signame, waitfg };