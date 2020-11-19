#include <time.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/msg.h>
#include <sys/sem.h>
#include <sys/wait.h>

#include "oss.h"
#include "blockedq.h"

//maximum time to run
#define MAX_RUNTIME 5
//maximum children to create
#define MAX_CHILDREN 40

enum stat_times {TURN_TIME=0, WAIT_TIME, SLEEP_TIME};
enum res_stats {RGRANTED=0, RBLOCKED, RDENIED, TOTAL_GET, TOTAL_RETURN, DEADLOCK_AVOIDED};

//Our program options
static unsigned int arg_c = 5;
static char * arg_l = NULL;
static unsigned int arg_t = MAX_RUNTIME;
static unsigned int arg_verbose = 0;

static unsigned int C = 0;
static int shmid = -1, msgid = -1, semid = -1;    //shared memory and msg queue ids
static unsigned int interrupted = 0;

static FILE * output = NULL;
static unsigned int ln = 0; //output line counter
static struct shared * shmp = NULL; //pointer to shared memory

static struct blockedq bq;        //blocked queue

static unsigned int pcb_bitmap = 0;

static struct vclock vclk_stat[3];
static unsigned int res_stats[6];
static unsigned int counter_GET[RN];			//statistics for grants per descriptor

static int mysemop(const int op){
  static struct sembuf sops;

  sops.sem_num = 0;
  sops.sem_flg = 0;
	sops.sem_op  = op;

  while(semop(semid, &sops, 1) != 0) {
    if(errno != EINTR){
  	  perror("semop");
  	  return -1;
    }
	}
  return 0;
};

//Send a message to user process. Buffer must be filled!
static int send_msg(struct msgbuf *m)
{
	m->from = getpid();	//mark who is sending the message
	if(msgsnd(msgid, m, MSG_SIZE, 0) == -1){
		perror("msgsnd");
		return -1;
	}
  return 0;
}

static int get_msg(struct msgbuf *m, const int flags)
{
  //this must be non-blocking
	if(msgrcv(msgid, (void*)m, MSG_SIZE, getpid(), flags) == -1){
    if(errno != ENOMSG){
		    perror("msgrcv");
    }
		return -1;
	}
	return 0;
}

//Called when we receive a signal
static void sign_handler(const int sig)
{
  interrupted = 1;
	++ln;fprintf(output, "[%u:%u] Signal %i received\n", shmp->vclk.sec, shmp->vclk.ns, sig);
}

static void master_wait(const pid_t pid){
  int status;
  if(waitpid(pid, &status, WNOHANG) > 0){

    if (WIFEXITED(status)) {  //if process exited

      ++ln;fprintf(output,"OSS: Child %u terminated with %i at %u:%u\n",
        pid, WEXITSTATUS(status), shmp->vclk.sec, shmp->vclk.ns);

    }else if(WIFSIGNALED(status)){  //if process was signalled
      ++ln;fprintf(output,"OSS: Child %u killed with signal %d at system time at %u:%u\n",
        pid, WTERMSIG(status), shmp->vclk.sec, shmp->vclk.ns);
    }
  }
}

//return 0 or 1 bot bit n from pcb bitmap
static int bit_status(const int n){
  return ((pcb_bitmap & (1 << n)) >> n);
}

//find first available pcb
static int unused_pcb(){
	int i;
  for(i=0; i < MAX_USERS; i++){
  	if(bit_status(i) == 0){
			pcb_bitmap ^= (1 << i);	//raise the bit
      return i;
    }
  }
  return -1;
}

//mark a pcb as unused
static void pcb_release(struct process * procs, const unsigned int pcb_index){
  int i;

  //remove proc from blocked q
  for(i=0; i < blockedq_size(&bq); i++){
    if(bq.queue[i] == pcb_index){
      blockedq_deq(&bq, i);
    }
  }

  master_wait(shmp->procs[pcb_index].pid);

  pcb_bitmap ^= (1 << pcb_index); //switch bit
  bzero(&shmp->procs[pcb_index], sizeof(struct process));
}


static struct process * pcb_get(){
	const int i = unused_pcb();
	if(i == -1){
		return NULL;
	}

  //clear previous process statistics
	bzero(&shmp->procs[i], sizeof(struct process));

  shmp->procs[i].id	= C;
  shmp->procs[i].state = READY;
	return &shmp->procs[i];
}

//Create a child process
static pid_t master_fork(const char *prog)
{

  struct process *pcb = pcb_get();
  if(pcb == NULL){
    //++ln;fprintf(output, "Warning: No pcb available\n");
    return 0; //no free processes
  }
	const int pcb_index = pcb - shmp->procs; //process index

	const pid_t pid = fork();  //create process
	if(pid < 0){
		perror("fork");
		return -1;

	}else if(pid == 0){
		char buf[10];
		snprintf(buf, sizeof(buf), "%d", pcb_index);

    //run the specified program
		execl(prog, prog, buf, NULL);
		perror("execl");
		exit(1);

	}else{
    pcb->pid = pid;
    //pcb->id = pcb_index;
    VCLOCK_COPY(pcb->vclk[READY_TIME], shmp->vclk);
    VCLOCK_COPY(pcb->vclk[FORK_TIME],  shmp->vclk);

    ++ln;fprintf(output,"[%u:%u] OSS: Generating process with PID %u\n", shmp->vclk.sec, shmp->vclk.ns, pcb->id);

    //save child pid
		C++;
	}
	return pid;
}

//Wait for all processes to exit
static void master_waitall()
{
  int i;
  for(i=0; i < MAX_USERS; ++i){ //for each process
    if(shmp->procs[i].pid == 0){  //if pid is zero, process doesn't exist
      continue;
    }

    master_wait(shmp->procs[i].pid);
  }
}

static void print_counters(){
	int r, width=3;

	++ln;fprintf(output, "Stats per descriptor\n");

	//print resouce titles
	++ln;fprintf(output, "    ");

	for(r=0; r < RN; r++){
		++ln;fprintf(output, "R%02d ", r);
	}
	++ln;fprintf(output, "\n");

  ++ln;fprintf(output, "GET ");
	for(r=0; r < RN; r++){
		++ln;fprintf(output, "%*d ", width, counter_GET[r]);
	}
	++ln;fprintf(output, "\n");
}

static void output_result(){

  output = freopen(arg_l, "a", output);

  fprintf(output, "Simulation statistics:\n");
	fprintf(output, "Logical time: %u:%u\n", shmp->vclk.sec, shmp->vclk.ns);
	fprintf(output, "Total requests: %d\n", res_stats[TOTAL_GET]);
	fprintf(output, "Total releases: %d\n", res_stats[TOTAL_RETURN]);

	fprintf(output, "Granted requests: %d\n", res_stats[RGRANTED]);
	fprintf(output, "Blocked requests: %d\n", res_stats[RBLOCKED]);
	fprintf(output, "Denied requests: %d\n", res_stats[RDENIED]);

	float perc_granted = ((float) res_stats[RGRANTED] / (float) res_stats[TOTAL_GET]) * 100.0;
	fprintf(output, "%% Granted requests: %.2f\n", perc_granted);

	print_counters();
}

//Called at end to cleanup all resources and exit
static void master_exit(const int ret)
{
  struct msgbuf mb;

  mysemop(-1);
  shmp->term_flag = 1;
  mysemop(1);

  //tell all users to terminate
  int i;
  for(i=0; i < MAX_USERS; i++){
    struct process * pcb = &shmp->procs[i];
    if(pcb->pid == 0){
      continue;
    }

    //unblock waiting user
    pcb->res = DENIED;
    mb.mtype = pcb->pid;	//send to user
    send_msg(&mb); //unblock waiting user by reply
    get_msg(&mb, 0); //receive the RETURN_ALL message
  }
  master_waitall();

  output_result();

  if(shmp){
    shmdt(shmp);
    shmctl(shmid, IPC_RMID, NULL);
  }

  if(msgid > 0){
    msgctl(msgid, IPC_RMID, NULL);
  }

  if(semid > 0){
    semctl(semid, 0, IPC_RMID);
  }

  fclose(output);
	exit(ret);
}

static void vclock_increment(struct vclock * x, struct vclock * inc){
  x->sec += inc->sec;
  x->ns += inc->ns;
	if(x->ns > 1000000000){
		x->sec++;
		x->ns = 0;
	}
}

static void vclock_substract(struct vclock * x, struct vclock * y, struct vclock * z){
  z->sec = x->sec - y->sec;

  if(y->ns > x->ns){
    z->ns = y->ns - x->ns;
    z->sec--;
  }else{
    z->ns = x->ns - y->ns;
  }
}

//Move time forward
static int update_timer(struct shared *shmp, struct vclock * fork_vclock)
{
  static const int maxTimeBetweenNewProcsSecs = 1;
  static const int maxTimeBetweenNewProcsNS = 500000;

  struct vclock inc = {0, 100};

  mysemop(-1);
  vclock_increment(&shmp->vclk, &inc);
  mysemop(1);

  usleep(10);
  //++ln;fprintf(output, "[%u:%u] OSS: Incremented system time with 100 ns\n", shmp->vclk.sec, shmp->vclk.ns);

  //if its time to fork
  if(  (shmp->vclk.sec  > fork_vclock->sec) ||
      ((shmp->vclk.sec == fork_vclock->sec) && (shmp->vclk.ns > fork_vclock->ns))){

    *fork_vclock = shmp->vclk;
    inc.sec = (rand() % maxTimeBetweenNewProcsSecs);
    inc.ns  = (rand() % maxTimeBetweenNewProcsNS);
    vclock_increment(fork_vclock, &inc);

    return 1;
  }

  return 0;
}

//Process program options
static int update_options(const int argc, char * const argv[])
{

  int opt;
	while((opt=getopt(argc, argv, "hc:l:t:v")) != -1){
		switch(opt){
			case 'h':
				++ln; fprintf(output,"Usage: master [-h]\n");
        ++ln; fprintf(output,"Usage: master [-c x] [-l logfile] [-t time] [-v]\n");
				++ln; fprintf(output," -h Describe program options\n");
				++ln; fprintf(output," -c x Total of child processes (Default is %d)\n", MAX_CHILDREN);
        ++ln; fprintf(output," -l filename Log filename (Default is log.txt)\n");
        ++ln; fprintf(output," -t x Maximum runtime (Default is %d)\n", MAX_RUNTIME);
				++ln; fprintf(output," -v Verbose (Default is off)\n");
				return 1;

      case 'c':
        arg_c	= atoi(optarg); //convert value -n from string to int
        break;

      case 't':
        arg_t	= atoi(optarg);
        break;

      case 'l':
				arg_l = strdup(optarg);
				break;
			case 'v':
				arg_verbose = 1;
				break;

			default:
				++ln; fprintf(output, "Error: Invalid option '%c'\n", opt);
				return -1;
		}
	}

	if(arg_l == NULL){
		arg_l = strdup("log.txt");
	}
  return 0;
}

//Initialize the shared memory
static int shared_initialize()
{
  key_t key = ftok(FTOK_SHM_PATH, FTOK_SHM_KEY);  //get a key for the shared memory
	if(key == -1){
		perror("ftok");
		return -1;
	}

  const long shared_size = sizeof(struct shared);

	shmid = shmget(key, shared_size, IPC_CREAT | IPC_EXCL | S_IRWXU);
	if(shmid == -1){
		perror("shmget");
		return -1;
	}

  shmp = (struct shared*) shmat(shmid, NULL, 0); //attach it
  if(shmp == NULL){
		perror("shmat");
		return -1;
	}

	key = ftok(FTOK_Q_PATH, FTOK_Q_KEY);
	if(key == -1){
		perror("ftok");
		return -1;
	}

	msgid = msgget(key, IPC_CREAT | IPC_EXCL | 0666);
	if(msgid == -1){
		perror("msgget");
		return -1;
	}

  key = ftok(FTOK_SEM_PATH, FTOK_SEM_KEY);
	if(key == -1){
		perror("ftok");
		return -1;
	}

  semid = semget(key, 1, IPC_CREAT | IPC_EXCL | S_IRWXU);
	if(semid == -1){
    ++ln; fprintf(output, "Error: Failed to create semaphore with key 0x%x\n", key);
		perror("semget");
		return -1;
	}

  union semun un;
	un.val = 1;
  if(semctl(semid, 0, SETVAL, un) ==-1){
  	perror("semid");
  	return -1;
  }
  return 0;
}

//Initialize the master process
static int master_initialize()
{

  if(shared_initialize() < 0){
    return -1;
  }

  //zero the shared clock
  shmp->vclk.sec	= 0;
	shmp->vclk.ns	= 0;

  shmp->term_flag = 0;

  //zero the processes
  bzero(shmp, sizeof(struct shared));
	bzero(res_stats, sizeof(res_stats));

  //initialize queues
  blockedq_init(&bq);

  //initialize the resources
  //20% +-5% must be shareable
  const int share_perc = 15 + (rand() % 10);
  const int num_shared = ((float) RN / 100.0f) * share_perc;

	//generate system resource descriptors
	int i;
	for(i=0; i < RN; i++){
		shmp->sysres[i] = 1; //not shared, only a single process can GET 1 unit
    if(i < num_shared){
			shmp->sysres[i] = 1 + (rand() % (RMAX-1));
    }
		shmp->available[i] = shmp->sysres[i];
  }

  return 0;
}

static void current_sys_res(){
	int r,p, width=3;

	++ln; fprintf(output, "Current system resources\n");

	//print resouce titles
	++ln; fprintf(output, "    ");
	for(r=0; r < RN; r++){
		++ln; fprintf(output, "R%02d ", r);
	}
	++ln; fprintf(output, "\n");

  //print left
  ++ln; fprintf(output, "LEFT");
	for(r=0; r < RN; r++){
		++ln; fprintf(output, "% 3d ", shmp->available[r]);
	}
	++ln; fprintf(output, "\n");

  //print total
  ++ln; fprintf(output, "TOTL");
  for(r=0; r < RN; r++){
    ++ln; fprintf(output, "% 3d ", shmp->sysres[r]);
  }
  ++ln; fprintf(output, "\n");

	for(p=0; p < MAX_USERS; p++){

		if(shmp->procs[p].pid == 0)	//skip empty PCBs
			continue;

		++ln; fprintf(output, "P%02d ",shmp->procs[p].id);
		for(r=0; r < RN; r++){
			++ln; fprintf(output, "%*d ", width, shmp->procs[p].allocation[r]);
		}
		++ln; fprintf(output, "\n");
	}
}

//Increment r1 with r2
static void res_inc(int r1[RN], const int r2[RN]){
	int i;
	for(i=0; i < RN; i++){
		r1[i] += r2[i];
  }
}

//just return first deadlocked process
static void deadlocked_procs(int *finished){
	int i;

	++ln; fprintf(output, "\tProcesses ");

  for(i=0; i < MAX_USERS; i++){
  	if(!finished[i]){
      struct process * proc = &shmp->procs[i];
      ++ln; fprintf(output, "P%d ", proc->id);
    }
  }
  ++ln; fprintf(output, " could deadlock in this scenario.\n");
}

//Check if the process need can be claimed from available system resources
static int claim_check(const struct process * pcb){
  int i;
  for(i=0; i < RN; i++){
    if(pcb->need[i] > shmp->available[i]){
      return 0; //it can't
    }
  }
  return 1; //need is within the available resources
}

//Test for deadlocked state after request
static int deadlock_state(struct res_req* req){

	res_stats[DEADLOCK_AVOIDED]++;
	if(arg_verbose){
    ++ln; fprintf(output, "[%u:%u] OSS running deadlock detection\n", shmp->vclk.sec, shmp->vclk.ns);
  }

	int i, avail[RN];  //available resources
	int finished[MAX_USERS]; //users finished

	bzero(finished, sizeof(int)*MAX_USERS);
  memcpy(avail, shmp->available, sizeof(int)*RN);

	mysemop(-1);

	i=0;
	while(i != MAX_USERS){

		for(i=0; i < MAX_USERS; i++){
			struct process * pcb = &shmp->procs[i];
      //skip terminated processes, procs with no request, or blocked
			if((pcb->pid == 0) || (pcb->req.qty == 0)){
				finished[i] = 1;
				continue;
			}

			if(	(finished[i] == 0) &&						  //process is not finished
				  ( pcb->req.type == RETURN ||
            pcb->req.type == RETURN_ALL ||
            claim_check(pcb))
        ){
				res_inc(avail, pcb->allocation);
				finished[i] = 1;	//mark process as finished
				break;
			}
		}
	}
	mysemop(1);

	//check if we have unfinished processes
	for(i=0; i < MAX_USERS; i++){
		if(!finished[i]){	//if not finised
			if(arg_verbose){
				++ln; fprintf(output, "\tUnsafe state after granting request; not granting\n");
				deadlocked_procs(finished);
			}
			return 1;	//deadlock
		}
	}

	++ln; fprintf(output, "\tSafe state found after granting request\n");
	return 0;	//no deadlock
}

static enum res_req_status process_request(struct process * pcb){
	int i, dlock=0;
	enum res_req_status rv = DENIED;
	struct res_req* req = &pcb->req;

	switch(req->type){
		case RETURN:
      ++ln; fprintf(output,"[%u:%u] OSS has acknowledged P%u is returning R%d=%d\n", shmp->vclk.sec, shmp->vclk.ns, pcb->id, pcb->req.id, pcb->req.qty);
			++res_stats[TOTAL_RETURN];
			pcb->allocation[req->id] 	-= req->qty;
			shmp->available[req->id] += req->qty;
			rv = GRANT;
			break;

		case RETURN_ALL:
			++ln; fprintf(output,"[%u:%u] OSS has acknowledged P%u is terminating\n", shmp->vclk.sec, shmp->vclk.ns, pcb->id);
			++ln; fprintf(output,"\tResources released ");
			for(i=0; i < RN; i++){
				if(pcb->allocation[i] > 0){
					++ln; fprintf(output,"R%d:%d", i, pcb->allocation[i]);
					++res_stats[TOTAL_RETURN];
					shmp->available[i] += pcb->allocation[i];
					pcb->allocation[i] = 0;
				}
			}
      ++ln; fprintf(output,"\n");


			vclock_substract(&shmp->vclk, &pcb->vclk[FORK_TIME], &pcb->vclk[TOTAL_SYSTEM]);

			rv = GRANT;
			break;

		case GET:
      ++ln; fprintf(output,"[%u:%u] OSS has acknowledged P%u is asking for R%d=%d\n", shmp->vclk.sec, shmp->vclk.ns, pcb->id, pcb->req.id, pcb->req.qty);
			++res_stats[TOTAL_GET];

			if(	(shmp->available[req->id] >= req->qty) &&
					((dlock = deadlock_state(req)) == 0)) {

      	pcb->allocation[req->id] 	+= req->qty;
				shmp->available[req->id] -= req->qty;

				rv = GRANT;
				res_stats[RGRANTED]++;		//average stat
				counter_GET[req->id]++;	//per descriptor stat
			}else{

				if(arg_verbose){
					if(dlock){
						++ln; fprintf(output, "\tP%d added to wait queue, waiting on R%d\n", pcb->id, pcb->req.id);
					}else{
						++ln; fprintf(output, "P%d added to wait queue, waiting on R%d\n", pcb->id, pcb->req.id);
					}
				}
				//add to blocked queue
				const int pcb_index = pcb - shmp->procs;
				blockedq_enq(&bq, pcb_index);

				pcb->state = IOBLK;	//block until resource is available
				//save time the process was blocked
				vclock_increment(&pcb->vclk[BLOCKED_TIME], &shmp->vclk);

				rv = BLOCK;
				res_stats[RBLOCKED]++;
			}
			break;

		default:
			fprintf(stderr, "OSS: Error: Invalid type in process request\n");
			rv = DENIED;
			++res_stats[RDENIED];
			break;
	}

	if(arg_verbose == 1){
		if((res_stats[TOTAL_GET] % 20) == 0){
			current_sys_res();
		}
	}

	return rv;
}

static enum res_req_status dispatch_request(struct process * pcb){

  enum res_req_status rr = process_request(pcb);

	if(arg_verbose){
	  switch(rr){
	    case GRANT:
	      if(pcb->res == BLOCK){	//if we are in the block "queue"
	        ++ln; fprintf(output, "[%u:%u] OSS: unblocking P%d and granting it R%d=%d\n",
	          shmp->vclk.sec, shmp->vclk.ns, pcb->id, pcb->req.id, pcb->req.qty);

	      }else if(pcb->res == PENDING){

	        if(pcb->req.type == GET){
	          ++ln; fprintf(output, "[%u:%u] OSS: granting P%d request R%d=%d\n",
	            shmp->vclk.sec, shmp->vclk.ns, pcb->id, pcb->req.id, pcb->req.qty);

	        }else if(pcb->req.type == RETURN){
	          ++ln; fprintf(output, "[%u:%u] OSS: has acknowledged Process P%d releasing R%d=%d\n",
	            shmp->vclk.sec, shmp->vclk.ns, pcb->id, pcb->req.id, pcb->req.qty);
	        }
	      }
	      break;

	    case BLOCK:
	      if(pcb->req.type == GET){	//process request is blocked
	        ++ln; fprintf(output, "[%u:%u] OSS: blocking P%d for requesting R%d=%d\n",
	          shmp->vclk.sec, shmp->vclk.ns, pcb->id, pcb->req.id, pcb->req.qty);
	      }

	      break;

	    case DENIED:
	      ++ln; fprintf(output, "[%u:%u] OSS: denied P%d invalid request R%d=%d\n",
	            shmp->vclk.sec, shmp->vclk.ns, pcb->id, pcb->req.id, pcb->req.qty);
	      break;

	    default:
	      break;
	  }
	}
  pcb->res = rr;	//this will unblock the user process

  return 0;
}

static int dispatch_bq(){
	struct msgbuf mb;
  int i, count=0;

  for(i=0; i < blockedq_size(&bq); i++){

    const int pcb_index = bq.queue[i];
    struct process * pcb = &shmp->procs[pcb_index];

    //if we don't have the requested quantity of resource
    if(shmp->available[pcb->req.id] < pcb->req.qty){
      continue;
    }

    blockedq_deq(&bq, i);
    ++ln; fprintf(output,"[%u:%u] OSS: Removed process P%d from blocked queue\n", shmp->vclk.sec, shmp->vclk.ns, pcb->id);

    dispatch_request(pcb);
    if(pcb->res != BLOCK){ //if request wasn't blocked

      //calculate how muchtime process was blocked
			vclock_substract(&shmp->vclk, &pcb->vclk[BLOCKED_TIME], &pcb->vclk[BURST_TIME]);
      vclock_increment(&vclk_stat[SLEEP_TIME], &pcb->vclk[BURST_TIME]);	//add to sleep time

      //change process pcb to ready, and reset timers
      pcb->state = READY;
			//clear blocked/burst time
      pcb->vclk[BLOCKED_TIME].sec = pcb->vclk[BLOCKED_TIME].ns = 0;
			pcb->vclk[BURST_TIME].sec   = pcb->vclk[BURST_TIME].ns   = 0;


			mb.mtype = pcb->pid;	//send to user
      send_msg(&mb); //unblock waiting user by reply

      count++;
    }
  }
	return count;	//count of unblocked users
}

static int dispatch(){
  int rv = 0;
  struct msgbuf mb;

  //tell process he can run and get his decision
  if(get_msg(&mb, IPC_NOWAIT) == -1){
    return -1;
  }

  const int pcb_index = mb.id;
  struct process * pcb = &shmp->procs[pcb_index];

  dispatch_request(pcb);
  enum res_req_op type = pcb->req.type; //save before we release user

  if(pcb->res != BLOCK){ //if request wasn't blocked
		mb.mtype = pcb->pid;	//send to user
    send_msg(&mb); //unblock waiting user by reply
    rv = 1;
  }


  if(type == RETURN){	//if a resouce was released
    dispatch_bq();	//try to unblock a process

  }else if(type == RETURN_ALL){	//if process terminated
		pcb_release(shmp->procs, pcb_index);	//free the process control block
    dispatch_bq();	//try to unblock a process
	}

  //calculate dispatch time
  struct vclock temp;
  temp.sec = 0;
  temp.ns = rand() % 100;
  ++ln; fprintf(output, "[%u:%u] OSS: total time this dispatching was %d nanoseconds\n", shmp->vclk.sec, shmp->vclk.ns, temp.ns);
  vclock_increment(&shmp->vclk, &temp);

  return rv;
}

//Kill the process with highest number of descriptors
static int resolve_deadlock(){
  struct msgbuf mb;
  int i;

  int victim = 0; //index of victim, which request will be denied
  int max_desc = 0;

  for(i=0; i < blockedq_size(&bq); i++){

    const int pcb_index = bq.queue[i];
    struct process * pcb = &shmp->procs[pcb_index];

    int j, num_desc = 0;
    for(j=0; j < RN; j++){
      if(pcb->allocation[j] > 0){
        num_desc++;
      }
    }

    if(num_desc > max_desc){
      victim = i;
      max_desc = num_desc;
    }
  }

  const int pcb_index = bq.queue[victim];
  struct process * pcb = &shmp->procs[pcb_index];

  blockedq_deq(&bq, victim);

  ++ln; fprintf(output,"[%u:%u] OSS: Denied process P%d from blocked queue, waitin for R%d=%d\n",
    shmp->vclk.sec, shmp->vclk.ns, pcb->id, pcb->req.id, pcb->req.qty);

  //calculate how muchtime process was blocked
  vclock_substract(&shmp->vclk, &pcb->vclk[BLOCKED_TIME], &pcb->vclk[BURST_TIME]);
  vclock_increment(&vclk_stat[SLEEP_TIME], &pcb->vclk[BURST_TIME]);	//add to sleep time

  //change process pcb to ready, and reset timers
  pcb->state = READY;
  //clear blocked/burst time
  pcb->vclk[BLOCKED_TIME].sec = pcb->vclk[BLOCKED_TIME].ns = 0;
  pcb->vclk[BURST_TIME].sec   = pcb->vclk[BURST_TIME].ns = 0;

  pcb->res = DENIED;

  mb.mtype = pcb->pid;	//send to user
  send_msg(&mb); //unblock waiting user by reply

  return 0;
}

int main(const int argc, char * const argv[])
{
  output = stdout;
  if(update_options(argc, argv) < 0){
    master_exit(1);
  }

  output = fopen(arg_l, "w");
  if(output == NULL){
    perror("fopen");
    return 1;
  }

  //signal(SIGCHLD, master_waitall);
  signal(SIGTERM, sign_handler);
  signal(SIGALRM, sign_handler);
  //alarm(arg_t);

  if(master_initialize() < 0){
    master_exit(1);
  }

  struct vclock fork_vclock = {0,0};

  //run until interrupted
  while(!interrupted){

    if(update_timer(shmp, &fork_vclock) > 0){
      if(C < MAX_CHILDREN){
        master_fork("./user");
      }else{  //we have generated all of the children
        interrupted = 1;  //stop master loop
      }
    }

    if(dispatch() <= 0){

      if(dispatch_bq() == 0){	//try to unblock a process
        //if we can't shedule from a full blocked queue
        if(blockedq_size(&bq) == MAX_USERS){
          resolve_deadlock();
        }
      }

      //jump to next fork time
      //++ln; fprintf(output,"[%u:%u] OSS: No process ready. Setting time to next fork at %u:%u.\n",
      //    shmp->vclk.sec, shmp->vclk.ns, fork_vclock.sec, fork_vclock.ns);
      shmp->vclk = fork_vclock;
    }

    if(ln > 100000){
      output = freopen("/dev/null", "w", output);
    }
	}

  ++ln; fprintf(output,"[%u:%u] Master exit\n", shmp->vclk.sec, shmp->vclk.ns);
	master_exit(0);

	return 0;
}
