#include "oss.h"

struct blockedq {
	int queue[MAX_USERS];
	int count;
};

void blockedq_init(struct blockedq * bq);

int blockedq_enq(struct blockedq * bq, const int p);
int blockedq_deq(struct blockedq * bq, const int pos);

//int blockedq_deq(struct blockedq * bq, const int pos);
int blockedq_top(struct blockedq * bq);

int blockedq_size(struct blockedq * bq);
