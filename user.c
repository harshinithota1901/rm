#include <stdio.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/shm.h>
#include <sys/sem.h>
#include <sys/types.h>
#include <time.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include "oss.h"

static int shmid = -1, msgid = -1, semid = -1;  //semaphore identifier
static struct shared * shmp = NULL;
static int end_sec = 0, end_ns = 0;

static struct process *pcb = NULL;

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

//Initialize the shared memory pointer
static int shared_initialize()
{
	key_t key = ftok(FTOK_SHM_PATH, FTOK_SHM_KEY);  //get a key for the shared memory
	if(key == -1){
		perror("ftok");
		return -1;
	}

	shmid = shmget(key, 0, 0);
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

	msgid = msgget(key, 0);
	if(msgid == -1){
		perror("msgget");
		return EXIT_FAILURE;
	}

	key = ftok(FTOK_SEM_PATH, FTOK_SEM_KEY);
	if(key == -1){
		perror("ftok");
		return -1;
	}

  semid = semget(key, 1, 0);
	if(semid == -1){
    fprintf(stderr, "Error: Failed to create semaphore with key 0x%x\n", key);
		perror("semget");
		return -1;
	}
	return 0;
}

static int send_msg(const int msgid, struct msgbuf *m)
{
	m->mtype = getppid();	//send to parent
	m->from = getpid();	//mark who is sending the message
	if(msgsnd(msgid, m, MSG_SIZE, 0) == -1){
		perror("msgsnd");
		return -1;
	}
	return 0;
}

static int get_msg(const int msgid, struct msgbuf *m){
	if(msgrcv(msgid, (void*)m, MSG_SIZE, getpid(), 0) == -1){
		perror("msgrcv");
		return -1;
	}
	return 0;
}

static int rand_rid(const int res[RN]){
  int i, group[RN], len=0;

  for(i=0; i < RN; i++){
    if(res[i] > 0)
      group[len++] = i;
  }

  if(len > 0){
    return group[rand() % len];
  }else{
    return -1;
  }
}

static int release_request(){
  int rid = rand_rid(pcb->allocation);
  if(rid >= 0){
    //printf("USER: Release RID=%d\n", rid);
    pcb->req.id = rid;
    pcb->req.qty  = pcb->allocation[pcb->req.id];
    pcb->req.type = RETURN;
    return 1;
  }else{
    return 0; //nothing to release
  }
}

static int acquire_request(){
  const int rid = rand_rid(pcb->need);
  if(rid >= 0){
    //printf("USER: Get RID: %d\n", rid);
    pcb->req.id = rid;
    if(pcb->need[pcb->req.id] == 1){
      pcb->req.qty = 1;
    }else{
      pcb->req.qty = 1 + (rand() % (pcb->need[pcb->req.id]-1));
    }
    pcb->req.type = GET;
    return 1;
  }else{
    return -1;  //nothing more to request
  }
}

static int decide_request()
{
	//40 % chance to release
	static const int release_chance = 40;
	const int release = ((rand() % 100) < release_chance) ? 1 : 0;

  pcb->res = PENDING;
  int rv;
  if(release){
    rv = release_request();
  }else{
    rv = acquire_request();
  }
  return rv;
}

static void generate_b(){
	end_ns = shmp->vclk.ns + (rand() % BOUND_B);
	if(end_ns > 1000000000){
		end_ns %= 1000000000;
		end_sec = shmp->vclk.sec + 1;
	}else{
		end_sec = shmp->vclk.sec;
	}
}

static void generate_max(){
  int i;
  for(i=0; i < RN; i++){
    pcb->allocation[i] = 0;
    if(shmp->sysres[i] == 1){
      pcb->need[i] = 1;
    }else{
      pcb->need[i] = 1 + (rand() % (shmp->sysres[i]-1));
    }
  }
}

static void update_need(){
  //if request was granted
  if(pcb->res == GRANT){
    //remove it from need
    pcb->need[pcb->req.id] -= pcb->req.qty;
    //printf("NEED[%d]: %d\n", pcb->req.id, pcb->need[pcb->req.id]);
  }
}

int main(const int argc, char * const argv[]){

	struct msgbuf msg;
  int started_sec = 0;

  if(shared_initialize() < 0){
		return EXIT_FAILURE;
	}

  const int my_index = atoi(argv[1]);
  pcb = &shmp->procs[my_index];

	//initialize the rand() function
	srand(getpid());

  //time when we have to request/release
  mysemop(-1);
  generate_b();
  generate_max();
  started_sec = shmp->vclk.sec;  //save time when we started
  mysemop(1);

	int terminate_me = 0;
	while(terminate_me == 0){

    //if its time to release
    if(mysemop(-1) < 0){
      break;
    }

    if(shmp->term_flag){  //if we have to quit
      mysemop(1);
      break;
    }

    int action = 0;
    //check if b interval has passed
    if(	 (end_sec < shmp->vclk.sec) ||
				((end_sec == shmp->vclk.sec) && (end_ns <= shmp->vclk.ns)) ){
      generate_b(); //update next release/request time
      action = decide_request();
      if(action == -1){ //if we have to terminate
        terminate_me = (started_sec < shmp->vclk.sec);
      }
    }
    if(mysemop(1) < 0){
      break;
    }

    if(action > 0){
      //send request msg and wait reply
      msg.id = my_index;
      if( (send_msg(msgid, &msg) == -1) ||
          (get_msg(msgid, &msg)  == -1)    ){  //wait for resource
  			break;
  		}

      //if((pcb->res == GRANT) || (pcb->res == DENIED)){
        //printf("USER: Released with R%d=%d, res=%d\n", pcb->req.id, pcb->req.qty, pcb->res);
      //}
      update_need();
		}

    usleep(100);
	}

  //release all
  pcb->req.type = RETURN_ALL;
  msg.id = my_index;
  send_msg(msgid, &msg);

	shmdt(shmp);
	return EXIT_SUCCESS;
}
