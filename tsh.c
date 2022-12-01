/* 
 * tsh - A tiny shell program with job control
 * 
 * <Put your name and login ID here>
 * wxh 123456
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>
#include <sys/stat.h>
#include <dirent.h>

/* Misc manifest constants */
#define MAXLINE    1024   /* max line size */
#define MAXARGS     128   /* max args on a command line */
#define MAXJOBS      16   /* max jobs at any point in time */
#define MAXJID    1<<16   /* max job ID */

/* Job states */
#define UNDEF 0 /* undefined */
#define FG 1    /* running in foreground */
#define BG 2    /* running in background */
#define ST 3    /* stopped */
#define SsB 4    /* sleeping && session leader in background */
#define SsF 5    /* sleeping && session leader in foreground */


/* 
 * Jobs states: FG (foreground), BG (background), ST (stopped)
 * Job state transitions and enabling actions:
 *     FG -> ST  : ctrl-z
 *     ST -> FG  : fg command
 *     ST -> BG  : bg command
 *     BG -> FG  : fg command
 * At most 1 job can be in the FG state.
 */

/* Global variables */
extern char **environ;      /* defined in libc */
char prompt[] = "tsh> ";    /* command line prompt (DO NOT CHANGE) */
int verbose = 0;            /* if true, print additional output */
int nextjid = 0;            /* next job ID to allocate */
char sbuf[MAXLINE];         /* for composing sprintf messages */
char * username;            /* The name of the user currently logged into the shell */
struct job_t {              /* The job struct */
    pid_t pid;              /* job PID */
    int jid;                /* job ID [1, 2, ...] */
    int state;              /* UNDEF, BG, FG, or ST */
    char cmdline[MAXLINE];  /* command line */
};
struct job_t jobs[MAXJOBS]; /* The job list */
/* End global variables */


/* Function prototypes */

/* Here are the functions that you will implement */
void eval(char *cmdline);
int builtin_cmd(char **argv);
void do_bgfg(char **argv);
void waitfg(pid_t pid);

void sigchld_handler(int sig);
void sigtstp_handler(int sig);
void sigint_handler(int sig);

/* Here are helper routines that we've provided for you */
int parseline(const char *cmdline, char **argv); 
void sigquit_handler(int sig);

void clearjob(struct job_t *job);
void initjobs(struct job_t *jobs);
int maxjid(struct job_t *jobs); 
int addjob(struct job_t *jobs, pid_t pid, int state, char *cmdline);
int deletejob(struct job_t *jobs, pid_t pid); 
pid_t fgpid(struct job_t *jobs);
struct job_t *getjobpid(struct job_t *jobs, pid_t pid);
struct job_t *getjobjid(struct job_t *jobs, int jid); 
int pid2jid(pid_t pid); 
void listjobs(struct job_t *jobs);
char * login();
void usage(void);
void unix_error(char *msg);
void app_error(char *msg);
typedef void handler_t(int);
handler_t *Signal(int signum, handler_t *handler);


/* Here are the function define by myself*/
int convertRecord(char * recordLine, char* record[]);
void adduser(char **argv);
void savecmd(char *cmdline);
void addentry(char * name, pid_t pid, int state);
void deleteentry(pid_t pid); 
void update(pid_t pid, int old, int new);
void logout(struct job_t *jobs);
void history();
int rerun_N(char *command);
void update_shell_status(int state);
int countlines();
int remove_directory(const char *path);


/*
 * main - The shell's main routine 
 */
int main(int argc, char **argv) 
{
    char c;
    char cmdline[MAXLINE];
    int emit_prompt = 1; /* emit prompt (default) */

    /* Redirect stderr to stdout (so that driver will get all output
     * on the pipe connected to stdout) */
    dup2(1, 2);

    /* Parse the command line */
    while ((c = getopt(argc, argv, "hvp")) != EOF) {
        switch (c) {
        case 'h':             /* print help message */
            usage();
	    break;
        case 'v':             /* emit additional diagnostic info */
            verbose = 1;
	    break;
        case 'p':             /* don't print a prompt */
            emit_prompt = 0;  /* handy for automatic testing */
	    break;
	default:
            usage();
	}
    }

    /* Install the signal handlers */

    /* These are the ones you will need to implement */
    Signal(SIGINT,  sigint_handler);   /* ctrl-c */
    Signal(SIGTSTP, sigtstp_handler);  /* ctrl-z */
    Signal(SIGCHLD, sigchld_handler);  /* Terminated or stopped child */

    /* This one provides a clean way to kill the shell */
    Signal(SIGQUIT, sigquit_handler); /* ctrl-\*/

    /* Initialize the job list */
    initjobs(jobs); 

    /* Have a user log into the shell */
    username = login();
    if (username == NULL) {
        return 0;
    }
    int index = 0;
    /* Execute the shell's read/eval loop */
    addentry("shell", getpid(), SsF);
    addjob(jobs, getpid(), BG, "shell\n");
    while (1) {

        /* Read command line */
        if (emit_prompt) {
            printf("%s", prompt);
            fflush(stdout);
        }
        if ((fgets(cmdline, MAXLINE, stdin) == NULL) && ferror(stdin))
            app_error("fgets error");
        if (feof(stdin)) { /* End of file (ctrl-d) */
            fflush(stdout);
            /* Delete all jobs and file under proc folder */
            for (int i = 0; i < MAXJOBS; i++) {
                if(jobs[i].pid != 0) {
                    deleteentry(jobs[i].pid);
                }
            }
            exit(0);
        }
        /* Evaluate the command line */
        eval(cmdline);
        fflush(stdout);
        fflush(stdout);
    } 

    exit(0); /* control never reaches here */
}


/*************************
 * My own defined function
 *************************/

/*
 * login - Performs user authentication for the shell
 * This function returns a string of the username that is logged in
 */
char * login() {
    while (1) {
        /* Read username */
        char *name = (char *) malloc(sizeof(char) * 40);  
        printf("username: ");
        fgets(name, sizeof(name), stdin);
        name[strcspn(name, "\n")] = 0;  // remove the "/n"
        if (strcmp(name, "quit") == 0) {
             return NULL;
        }

        /* Read password */
        char password[40];
        printf("password: ");
        fgets(password, sizeof(password), stdin);   // remove the "/n"
        password[strcspn(password, "\n")] = 0;

        char * line = NULL;
        size_t len = 0;
        ssize_t read;

        /* Open passwd file */
        FILE *fp = fopen("etc/passwd", "r");
        if (fp == NULL){
            printf("file open failed!\n");
            exit(EXIT_FAILURE);
        }
        /* Read passwd file line by line */
        int find = 0;
        while((read = getline(&line, &len, fp)) != -1) {
            char *recordValues[30];
            char recordString[100];
            strcpy(recordString, line);
            convertRecord(recordString, recordValues);
         
            if (strcmp(recordValues[0], name) == 0) {   /* Find the username*/
                if (strcmp(recordValues[1], password) == 0) { /* password is correct*/
                    return name;
                }
                
            } 
        }
        fclose(fp);
        if (line)
            free(line);
        
        printf("User Authentication failed. Please try again.\n");
    }
    
}

/*
 * adduser -  Creates a new user for the shell
 *  This function can only be done if the root user is logged in.
*/
void adduser(char **argv) {
    
    if (strcmp(username, "root") != 0) {    /* If it's not root user*/
        printf("root privileges required to run adduser.\n");
        return;
    }

    if (argv[1] == NULL) {  /* Missing new_username */
        printf("%s command requires a new username\n", argv[0]);
        return;
    } else if (argv[2] == NULL) {   /* Missing new_password */
        printf("%s command requires a new password\n", argv[0]);
        return;
    }
    
    /* Crate a new home directory */
    char new_directory[40];
    strcpy(new_directory, "home/");
    strcat(new_directory, argv[1]);
    struct stat st = {0};
    if (stat(new_directory, &st) == -1) { /* If user not exists, create*/
        mkdir(new_directory, 0700);
    } else {    /*if user already existed*/
        printf("User already exists!\n");
        return;
    }
    
    /* Create .tsh_history file */
    strcat(new_directory, "/.tsh_history");
    fclose(fopen(new_directory, "a"));

    /* Create an entry for the new user inside the etc/passwd file */
    FILE *fp = fopen("etc/passwd", "a");
    fprintf(fp, "%s:%s:/home/%s\n", argv[1], argv[2], argv[1]);
    fclose(fp);


    
}

/* 
 * convertRecord - Parse through a reacord 
 * This function return the length of the record array
*/
int convertRecord(char * recordLine, char* record[]) {
  int count = 0;
  char * token = strtok(recordLine, ":");
  while (token != NULL) {
      record[count++] = token;
      token = strtok(NULL, ":");
  }
  return count;
}

/*
 * savecmd -  Save command line to the history file (i.e., .tsh_history).
 * Specification: In this program, I used this function to save every command line,
 * whether it can be found or not
*/
void savecmd(char *cmdline) {
    /* ignore the !N command */
    if (cmdline[0] == '!') {
        return;
    }

    /* path of history file */
    char hist_file[40];
    strcpy(hist_file, "home/");
    strcat(hist_file, username);
    strcat(hist_file, "/.tsh_history");
    

    if (countlines() >= 10) {
        char delete_cmd[80];
        sprintf(delete_cmd, "sed -i '1d' %s", hist_file);
        system(delete_cmd);
    }

    /* Open and append newline to history file */
    FILE *fp = fopen(hist_file, "a");
    if (fp == NULL) {
        printf("Cannot open %s's history file\n", username);
        exit(-1);
    }
    fprintf(fp, "%s", cmdline);
    fclose(fp);

}

/*
 * addentry - Add an entry in the proc directory. And create status file
*/
void addentry(char * name, pid_t pid, int state) {
    if (pid < 1)
        return;

    /* Create new PID entry */
    char new_entry[40];
    sprintf(new_entry, "proc/%d", pid);
    struct stat st = {0};
    if (stat(new_entry, &st) == -1) { /* If PID entry not exists, create*/
        mkdir(new_entry, 0700);
    } 

    /* Create status file */
    strcat(new_entry, "/status");
    FILE *fp = fopen(new_entry, "a");
    if (fp == NULL) {
        printf("Cannot create %d status file", pid);
        exit(-1);
    }

    fprintf(fp, "Name: %s\n", name);
    
    fprintf(fp, "Pid: %d\n", pid);
    if (strcmp(name, "shell") == 0) {
        fprintf(fp, "PPID: %d\n", getppid());
    } else {
        fprintf(fp, "PPID: %d\n", getpid());
    }
    
    fprintf(fp, "PGID: %d\n", getpgid(pid));
    fprintf(fp, "SID: %d\n", getpid());
    if (state == FG) {
        fprintf(fp, "STAT: R+\n");
    } else if (state == BG) {
        fprintf(fp, "STAT: R\n");
    } else if (state == SsF) {
        fprintf(fp, "STAT: Ss+\n");
    } else if (state == SsB) {
        fprintf(fp, "STAT: Ss\n");
    } else {
        printf("Unkown state");
    }
    fprintf(fp, "Username: %s\n", username);

    fclose(fp);
}

/*
 * deleteentry - delete an entry in the proc directory.
*/
void deleteentry(pid_t pid) {
    if (pid < 1)
        return;
    char entry[40];
    sprintf(entry, "proc/%d", pid);
    kill(-pid, SIGINT);
    remove_directory(entry);
}

/* 
 * update - update the STAT field in status file
*/
void update(pid_t pid, int old, int new) {
    char new_state[10];
    char old_state[10];
    
    /* shell status file path*/
    char shell_status_file[40];
    sprintf(shell_status_file, "proc/%d/status", getpid());
    /* remove shell status file command */
    char shell_rm_cmd[80];
    sprintf(shell_rm_cmd, "rm %s", shell_status_file);

    if (new == BG) {
        strcpy(new_state, "STAT: R");
    } else if (new == FG) { 
        strcpy(new_state, "STAT: R+"); 
        update_shell_status(SsB);
    } else if (new == ST) {
        strcpy(new_state, "STAT: T");
    }

    if (old == BG) {
        strcpy(old_state, "STAT: R");
    } else if (old == FG) {
        strcpy(old_state, "STAT: R+"); 
        update_shell_status(SsF);
    } else if (old == ST) {
        strcpy(old_state, "STAT: T");
    }

    /* update the status file */
    char status_file[40];
    sprintf(status_file, "proc/%d/status", pid);

    char sed_cmd[80], rm_cmd[80], mv_cmd[80];
    sprintf(sed_cmd, "sed 's/%s/%s/' %s > temp", old_state, new_state, status_file);
    sprintf(rm_cmd, "rm %s", status_file);
    sprintf(mv_cmd, "mv temp %s", status_file);
    
    system(sed_cmd);
    system(rm_cmd);
    system(mv_cmd);
    
    return;

}

/*
 * logout - logs out the user from the shell and then terminates the shell 
*/
void logout(struct job_t *jobs) {

    for (int i = 0; i < MAXJOBS; i++) {
        if (jobs[i].state == ST) {
            printf("There are suspended jobs.\n");
            return ;
        } else {
            deleteentry(jobs[i].pid);
        }
    }
    exit(0);
}

/*
 * history -  shows the last 10 commands ran by the user, each numbered on a separate line. 
 * If there are less than 10 commands, then show all of them.
*/
void history() {
    /* history file path */
    char hist_file[40];
    sprintf(hist_file, "home/%s/.tsh_history", username);

    /* Try open history file */
    FILE *fp = fopen(hist_file, "r");
    if (fp == NULL) {
        printf("Cannot open %s's history file\n", username);
        exit(-1);
    }

    char *line = NULL;
    long int len = 0;
    int index = 0;
    while (getline(&line, &len, fp) != -1) {
        index++;
        printf("%d %s", index, line);
    }
    
    fclose(fp);
}

/*   
 * rerun_N - reruns the N command from the user’s history list.
 * The format of command argument is "!N",  where N is a line number from the history command.
*/
int rerun_N(char *command) {
    int n = atoi(&command[1]);
    if (n < 1 || n > countlines()) {
        printf("Line number is invalid\n");
        return 0;
    } else {
        /* history file path */
        char hist_file[40];
        sprintf(hist_file, "home/%s/.tsh_history", username);

        /* Try open history file */
        FILE *fp = fopen(hist_file, "r");
        if (fp == NULL) {
            printf("Cannot open %s's history file\n", username);
            exit(-1);
        }

        char *line = NULL;
        long int len = 0;
        int index = 0;
        while (getline(&line, &len, fp) != -1) {
            index++;
            if (index == n) {   /* find the Nth command line */
                eval(line);
            }
            
        }
        fclose(fp);
        return 1;
    }
    
}


void update_shell_status(int state) {
    /* shell status file path*/
    char shell_status_file[40];
    sprintf(shell_status_file, "proc/%d/status", getpid());

    /* remove shell status file */
    char shell_rm_cmd[80];
    sprintf(shell_rm_cmd, "rm %s", shell_status_file);
    system(shell_rm_cmd);

    /* Create new shell status file*/
    addentry("shell", getpid(), state); 

}

int countlines() {
    /* path of history file */
    char hist_file[40];
    sprintf(hist_file, "home/%s/.tsh_history", username);

    /* Open and read history file */
    FILE *fp = fopen(hist_file, "r");
    if (fp == NULL) {
        printf("Cannot open %s's history file to caculate lines number\n", username);
        exit(-1);
    }

    int ch = 0;
    int lines = 0;
    while (!feof(fp)) {
        ch = fgetc(fp);
        if (ch == '\n') {
            lines++;
        }
    }
    fclose(fp);

    return lines;
}

// reference: https://stackoverflow.com/questions/2256945/removing-a-non-empty-directory-programmatically-in-c-or-c
int remove_directory(const char *path) {
   DIR *d = opendir(path);
   size_t path_len = strlen(path);
   int r = -1;

   if (d) {
      struct dirent *p;

      r = 0;
      while (!r && (p=readdir(d))) {
          int r2 = -1;
          char *buf;
          size_t len;

          /* Skip the names "." and ".." as we don't want to recurse on them. */
          if (!strcmp(p->d_name, ".") || !strcmp(p->d_name, ".."))
             continue;

          len = path_len + strlen(p->d_name) + 2; 
          buf = malloc(len);

          if (buf) {
             struct stat statbuf;

             snprintf(buf, len, "%s/%s", path, p->d_name);
             if (!stat(buf, &statbuf)) {
                if (S_ISDIR(statbuf.st_mode))
                   r2 = remove_directory(buf);
                else
                   r2 = unlink(buf);
             }
             free(buf);
          }
          r = r2;
      }
      closedir(d);
   }

   if (!r)
      r = rmdir(path);

   return r;
}

/*****************************
 * End my own defined function
 *****************************/


/* 
 * eval - Evaluate the command line that the user has just typed in
 * 
 * If the user has requested a built-in command (quit, jobs, bg or fg)
 * then execute it immediately. Otherwise, fork a child process and
 * run the job in the context of the child. If the job is running in
 * the foreground, wait for it to terminate and then return.  Note:
 * each child process must have a unique process group ID so that our
 * background children don't receive SIGINT (SIGTSTP) from the kernel
 * when we type ctrl-c (ctrl-z) at the keyboard.  
*/
void eval(char *cmdline) 
{   
    char *argv[MAXARGS];    /* Argument list execve() */
    char buf[MAXLINE];      /* Holds modified command line */   
    int bg;                 /* Should the job run in bg or fg */
    pid_t pid;              /* Process id */


    sigset_t mask_all, mask_one, prev_one;  

    sigfillset(&mask_all);
    sigemptyset(&mask_one);
    sigaddset(&mask_one, SIGCHLD);
    signal(SIGCHLD, sigchld_handler);


    strcpy(buf, cmdline);
    bg = parseline(buf, argv);
    if (argv[0] == NULL) {
        return; /* Ignore empty lines */
    }

    

    if (!builtin_cmd(argv)) {
        sigprocmask(SIG_BLOCK, &mask_one, &prev_one);   /* Block SIGCHLD */

        if ((pid = fork()) == 0) {  /* Child runs user job */
            if (setpgid(0, 0) < 0) {   /* Puts the child in a new process group */
                unix_error("setpgid error");
            }
            sigprocmask(SIG_SETMASK, &prev_one, NULL); /* Unblock SIGCHLD */

            if (execve(argv[0], argv, environ) < 0) {   // why "test", why "t *" is different with "t &"
                printf("%s: Command not found.\n", argv[0]);
                exit(0);
            }
        }

        /* Parent waits for foreground job to terminate */
        if (!bg) {
            sigprocmask(SIG_BLOCK, &mask_all, NULL); /* Parent process */
            addjob(jobs, pid, FG, cmdline );
            addentry(argv[0], pid, FG);
            update_shell_status(SsB);   // Update shell STAT to Ss
            sigprocmask(SIG_SETMASK, &prev_one, NULL);  /* Unblock SIGCHLD */

            int status;
            waitfg(pid);

        } else {
            sigprocmask(SIG_BLOCK, &mask_all, NULL); /* Parent process */
            addjob(jobs, pid, BG, cmdline );
            addentry(argv[0], pid, BG);
            sigprocmask(SIG_SETMASK, &prev_one, NULL);  /* Unblock SIGCHLD */
        }
    }   

    /* Save command line */
    savecmd(cmdline);
    return;
}

/* 
 * parseline - Parse the command line and build the argv array.
 * 
 * Characters enclosed in single quotes are treated as a single
 * argument.  Return true if the user has requested a BG job, false if
 * the user has requested a FG job.  
 */
int parseline(const char *cmdline, char **argv) 
{
    static char array[MAXLINE]; /* holds local copy of command line */
    char *buf = array;          /* ptr that traverses command line */
    char *delim;                /* points to first space delimiter */
    int argc;                   /* number of args */
    int bg;                     /* background job? */

    strcpy(buf, cmdline);
    buf[strlen(buf)-1] = ' ';  /* replace trailing '\n' with space */
    while (*buf && (*buf == ' ')) /* ignore leading spaces */
	buf++;

    /* Build the argv list */
    argc = 0;
    if (*buf == '\'') {
	buf++;
	delim = strchr(buf, '\'');
    }
    else {
	delim = strchr(buf, ' ');
    }

    while (delim) {
	argv[argc++] = buf;
	*delim = '\0';
	buf = delim + 1;
	while (*buf && (*buf == ' ')) /* ignore spaces */
	       buf++;

	if (*buf == '\'') {
	    buf++;
	    delim = strchr(buf, '\'');
	}
	else {
	    delim = strchr(buf, ' ');
	}
    }
    argv[argc] = NULL;
    
    if (argc == 0)  /* ignore blank line */
	return 1;

    /* should the job run in the background? */
    if ((bg = (*argv[argc-1] == '&')) != 0) {
	argv[--argc] = NULL;
    }
    return bg;
}

/* 
 * builtin_cmd - If the user has typed a built-in command then execute
 *    it immediately.  
 */
int builtin_cmd(char **argv) 
{   
    if (strcmp(argv[0], "quit") == 0){          /* quit command */
        /* clear the jobs */
        for (int i = 0; i < MAXJOBS; i++) {
            deleteentry(jobs[i].pid);
        }
        exit(0);
    } else if (strcmp(argv[0], "logout") == 0) {
        logout(jobs);
        return 1;
    } else if (strcmp(argv[0], "history") == 0) {
        history();
        return 1;
    } else if (strcmp(argv[0], "jobs") == 0) {  /* jobs command */
        listjobs(jobs);
        return 1;
    } else if (argv[0][0] == '!') { /* !N command */
        rerun_N(argv[0]);
        return 1;
        
    } else if (strcmp(argv[0], "bg") == 0) {    /* bg command */
        do_bgfg(argv);
        return 1;
    } else if (strcmp(argv[0], "fg") == 0) {    /* fg command */
        do_bgfg(argv);
        return 1;
    } else if (strcmp(argv[0], "adduser") == 0) {   /* adduser command */
        adduser(argv);
        return 1;
    }
        
    return 0;     /* not a builtin command */
}

/* 
 * do_bgfg - Execute the builtin bg and fg commands
 */
void do_bgfg(char **argv) 
{
    if (argv[1] == NULL) {  /* Missing pid or jid */
        printf("%s command requires a PID or %%jobid argument\n", argv[0]); 
        return;
    }

    if (!isdigit(argv[1][0]) && argv[1][0] != '%') {            /* If the second argument is invlid */
        printf("%s: argument must be a PID or %%jobid\n", argv[0]);
        return;
    }
    struct job_t *job;
    if (argv[1][0] == '%') {    /* JID */
        job =  getjobjid(jobs, atoi(&argv[1][1]));  // Get job by jid
        if (job == NULL) {  /* If job doesn't exist */
            printf("%s: No such job\n", argv[1]);
            return;
        }

    } else {    /* PID */
        job =  getjobpid(jobs, (pid_t) atoi(argv[1]));      //Get job by pid 
        if (job == NULL) {  /* If job doesn't exist */
            printf("%s: No such process\n", argv[1]);
            return;
        }
    }

    if (strcmp(argv[0], "bg") == 0) {   /* If it's background command*/
        update(job->pid, job->state, BG);
        job->state = BG;    
        printf("[%d] (%d) %s", job->jid, job->pid, job->cmdline);
        kill(-(job->pid), SIGCONT);
    } else {    /* If it's foreground command */
        update(job->pid, job->state, FG);
        update_shell_status(SsB);
        job->state = FG;
        kill(-(job->pid), SIGCONT);
        waitfg(job->pid);
    }

    return;
}

/* 
 * waitfg - Block until process pid is no longer the foreground process
 */
void waitfg(pid_t pid)
{
    while(1) {
        if (pid != fgpid(jobs)) {
            break;
        } else {
            sleep(0.2);
        }
        
    } 
  return;
}




/*****************
 * Signal handlers
 *****************/

/* 
 * sigchld_handler - The kernel sends a SIGCHLD to the shell whenever
 *     a child job terminates (becomes a zombie), or stops because it
 *     received a SIGSTOP or SIGTSTP signal. The handler reaps all
 *     available zombie children, but doesn't wait for any other
 *     currently running children to terminate.  
 */
void sigchld_handler(int sig) 
{   int olderrno = errno;   /* store old errno */
    int status; /* used to trace pid's status */
    sigset_t mask_all, prev_all;    
    pid_t pid;
    // printf("begin child handler\n");
    sigfillset(&mask_all);

    while ((pid = waitpid(-1, &status, WNOHANG | WUNTRACED)) > 0) {  /* Reap child */ 
        // printf("pid = %d\n", pid);

        sigprocmask(SIG_BLOCK, &mask_all, &prev_all);

         /* If the job was foreground */
        if (getjobpid(jobs, pid)->state == FG) {  
                update_shell_status(SsF);   
        }
        
        int jid = pid2jid(pid);
        if (WIFEXITED(status)) {    /* If the child terminated normally */
            
            deletejob(jobs, pid);   /* Delete the child from the job list */
            deleteentry(pid);
        } else if (WIFSTOPPED(status)) {    /* If the child is stopped */
            update(pid, getjobpid(jobs, pid)->state, ST);
            getjobpid(jobs, pid)->state = ST;
            printf("Job [%d] (%d) Stopped by signal %d\n", jid, pid, WSTOPSIG(status));

        } else if (WIFSIGNALED(status)) {   /* Child is terminated by catched signal */
            printf("Job [%d] (%d) terminated by signal %d\n", jid, pid, WTERMSIG(status));
            deletejob(jobs, pid);
            deleteentry(pid);
        }

        sigprocmask(SIG_SETMASK, &prev_all, NULL);  /* Unblock SIGCHLD */
    }
    // printf("end child handler");
    // if (errno != ECHILD)
    //     sio_error("waitpid error");
    errno = olderrno;

    return;
}

/* 
 * sigint_handler - The kernel sends a SIGINT to the shell whenver the
 *    user types ctrl-c at the keyboard.  Catch it and send it along
 *    to the foreground job.  
 */
void sigint_handler(int sig) 
{   
    pid_t pid = fgpid(jobs);
    if (pid != 0) {
        kill(-pid, sig); 
        deletejob(jobs,pid);
        deleteentry(pid);
        printf("sigint_handler: Job [%d] and its entire foreground jobs with same process group are killed\n", (int)pid);
    }
    
    return;
}

/*
 * sigtstp_handler - The kernel sends a SIGTSTP to the shell whenever
 *     the user types ctrl-z at the keyboard. Catch it and suspend the
 *     foreground job by sending it a SIGTSTP.  
 */
void sigtstp_handler(int sig) 
{   
    pid_t pid = fgpid(jobs);
    if (pid != 0) {
        kill(-pid, sig); // signals to the entire foreground process group
        printf("sigtstp_handler: Job [%d] and its entire foreground jobs with same process group are stoped\n", (int)pid);
    }
    return;
}

/*********************
 * End signal handlers
 *********************/

/***********************************************
 * Helper routines that manipulate the job list
 **********************************************/

/* clearjob - Clear the entries in a job struct */
void clearjob(struct job_t *job) {
    job->pid = 0;
    job->jid = 0;
    job->state = UNDEF;
    job->cmdline[0] = '\0';
}

/* initjobs - Initialize the job list */
void initjobs(struct job_t *jobs) {
    int i;

    for (i = 0; i < MAXJOBS; i++)
	clearjob(&jobs[i]);
}

/* maxjid - Returns largest allocated job ID */
int maxjid(struct job_t *jobs) 
{
    int i, max=0;

    for (i = 0; i < MAXJOBS; i++)
	if (jobs[i].jid > max)
	    max = jobs[i].jid;
    return max;
}

/* addjob - Add a job to the job list */
int addjob(struct job_t *jobs, pid_t pid, int state, char *cmdline) 
{
    int i;
    
    if (pid < 1)
	return 0;

    for (i = 0; i < MAXJOBS; i++) {
	if (jobs[i].pid == 0) {
	    jobs[i].pid = pid;
	    jobs[i].state = state;
	    jobs[i].jid = nextjid++;
	    if (nextjid > MAXJOBS)
		nextjid = 1;
	    strcpy(jobs[i].cmdline, cmdline);
  	    if(verbose){
	        printf("Added job [%d] %d %s\n", jobs[i].jid, jobs[i].pid, jobs[i].cmdline);
            }
            return 1;
	}
    }
    printf("Tried to create too many jobs\n");
    return 0;
}

/* deletejob - Delete a job whose PID=pid from the job list */
int deletejob(struct job_t *jobs, pid_t pid) 
{
    int i;

    if (pid < 1)
	return 0;

    for (i = 0; i < MAXJOBS; i++) {
	if (jobs[i].pid == pid) {
	    clearjob(&jobs[i]);
	    nextjid = maxjid(jobs)+1;
	    return 1;
	}
    }
    return 0;
}

/* fgpid - Return PID of current foreground job, 0 if no such job */
pid_t fgpid(struct job_t *jobs) {
    int i;

    for (i = 0; i < MAXJOBS; i++)
	if (jobs[i].state == FG)
	    return jobs[i].pid;
    return 0;
}

/* getjobpid  - Find a job (by PID) on the job list */
struct job_t *getjobpid(struct job_t *jobs, pid_t pid) {
    int i;

    if (pid < 1)
	return NULL;
    for (i = 0; i < MAXJOBS; i++)
	if (jobs[i].pid == pid)
	    return &jobs[i];
    return NULL;
}

/* getjobjid  - Find a job (by JID) on the job list */
struct job_t *getjobjid(struct job_t *jobs, int jid) 
{
    int i;

    if (jid < 1)
	return NULL;
    for (i = 0; i < MAXJOBS; i++)
	if (jobs[i].jid == jid)
	    return &jobs[i];
    return NULL;
}

/* pid2jid - Map process ID to job ID */
int pid2jid(pid_t pid) 
{
    int i;

    if (pid < 1)
	return 0;
    for (i = 0; i < MAXJOBS; i++)
	if (jobs[i].pid == pid) {
            return jobs[i].jid;
        }
    return 0;
}

/* listjobs - Print the job list */
void listjobs(struct job_t *jobs) 
{
    int i;
    
    for (i = 0; i < MAXJOBS; i++) {
	if (jobs[i].jid != 0) {
	    printf("[%d] (%d) ", jobs[i].jid, jobs[i].pid);
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
		    printf("listjobs: Internal error: job[%d].state=%d ", 
			   i, jobs[i].state);
	    }
	    printf("%s", jobs[i].cmdline);
	}
    }
}
/******************************
 * end job list helper routines
 ******************************/


/***********************
 * Other helper routines
 ***********************/

/*
 * usage - print a help message
 */
void usage(void) 
{
    printf("Usage: shell [-hvp]\n");
    printf("   -h   print this message\n");
    printf("   -v   print additional diagnostic information\n");
    printf("   -p   do not emit a command prompt\n");
    exit(1);
}

/*
 * unix_error - unix-style error routine
 */
void unix_error(char *msg)
{
    fprintf(stdout, "%s: %s\n", msg, strerror(errno));
    exit(1);
}

/*
 * app_error - application-style error routine
 */
void app_error(char *msg)
{
    fprintf(stdout, "%s\n", msg);
    exit(1);
}

/*
 * Signal - wrapper for the sigaction function
 */
handler_t *Signal(int signum, handler_t *handler) 
{
    struct sigaction action, old_action;

    action.sa_handler = handler;  
    sigemptyset(&action.sa_mask); /* block sigs of type being handled */
    action.sa_flags = SA_RESTART; /* restart syscalls if possible */

    if (sigaction(signum, &action, &old_action) < 0)
	unix_error("Signal error");
    return (old_action.sa_handler);
}

/*
 * sigquit_handler - The driver program can gracefully terminate the
 *    child shell by sending it a SIGQUIT signal.
 */
void sigquit_handler(int sig) 
{   /* clear all jobs */
    for (int i = 0; i < MAXJOBS; i++) {
        deleteentry(jobs[i].pid);
    }
    printf("Terminating after receipt of SIGQUIT signal\n");
    exit(1);
}



