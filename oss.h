#ifndef MASTER_H
#define MASTER_H

#include <unistd.h>

#define MAX_USERS 18
//number of resources in system
#define RN	20
#define RMAX 10

#define BOUND_B 30

#define FTOK_SEM_PATH "/tmp"
#define FTOK_SEM_KEY 6776

enum res_req_op { GET=0, RETURN, RETURN_ALL};
enum res_req_status {GRANT=0, BLOCK, PENDING, DENIED};

struct res_req {
	int id;								//descriptor
	int qty;							//quantity
	enum res_req_op 	type;	//get or return|return all
};

struct vclock {
  unsigned int sec;
	unsigned int ns;
};

//helper functions for virtual clock
#define VCLOCK_COPY(x,y) x.sec = y.sec; x.ns = y.ns;
#define VCLOCK_AVE(x,count) x.sec /= count; x.ns /= count;

enum status_type { READY=1, IOBLK, TERMINATE, DECISON_COUNT};
enum vclock_type { TOTAL_CPU=0, TOTAL_SYSTEM, BURST_TIME, FORK_TIME, BLOCKED_TIME, READY_TIME, VCLOCK_COUNT};

// entry in the process control table
struct process {
	int	pid;
	int id;
	enum status_type state;

	struct vclock	vclk[VCLOCK_COUNT];

  int allocation[RN];	//currently used
	int need[RN];				//max used

	struct res_req req;
	enum res_req_status res;
};

//The variables shared between master and palin processes
struct shared {
	struct vclock vclk;
	int term_flag;
	struct process procs[MAX_USERS];
  int available[RN];		//available resources
	int sysres[RN];		//max available resources
};

//shared memory constants
#define FTOK_Q_PATH "/tmp"
#define FTOK_SHM_PATH "/tmp"
#define FTOK_Q_KEY 6776
#define FTOK_SHM_KEY 7667

struct msgbuf {
	long mtype;
	pid_t from;
	int id;	//process index requesting resource
};

union semun {
               int              val;    /* Value for SETVAL */
               struct semid_ds *buf;    /* Buffer for IPC_STAT, IPC_SET */
               unsigned short  *array;  /* Array for GETALL, SETALL */
               struct seminfo  *__buf;  /* Buffer for IPC_INFO
                                           (Linux-specific) */
           };

#define MSG_SIZE sizeof(pid_t) + sizeof(int)

#endif
