#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "blockedq.h"

void blockedq_init(struct blockedq * bq){
  memset(bq->queue, -1, sizeof(int)*MAX_USERS);
  bq->count = 0;
}

int blockedq_enq(struct blockedq * bq, const int p){

  int i;
  for(i=0; i < bq->count; i++){
    if(bq->queue[i] == p){
      printf("OSS Error: %d already in queue\n", p);
      exit(1);
    }
  }

  if(bq->count < MAX_USERS){
    bq->queue[bq->count++] = p;
    return bq->count - 1;
  }else{
    return -1;
  }
}


static void blockedq_shift(struct blockedq * bq, const int pos){
  int i;
  for(i=pos; i < bq->count; i++){
    bq->queue[i] = bq->queue[i+1];
  }
  bq->queue[i] = -1;
}

int blockedq_deq(struct blockedq * bq, const int pos){
  const unsigned int pi = bq->queue[pos];
  bq->count--;
  blockedq_shift(bq, pos);

  int i;
  for(i=0; i < bq->count; i++){
    if(bq->queue[i] == pi){
      printf("OSS Error: %d left in queue\n", pi);
      exit(1);
    }
  }

  return pi;
}

int blockedq_top(struct blockedq * bq){
  return bq->queue[0];
}

int blockedq_size(struct blockedq * bq){
  return bq->count;
}
