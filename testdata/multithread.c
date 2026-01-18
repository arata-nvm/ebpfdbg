#include <stdio.h>
#include <pthread.h>
#include <unistd.h>

#define NUM_THREADS 5

void* worker(void* arg) {
    int id = *((int*)arg);

    printf("[thread %d] started\n", id);
    sleep(1);
    printf("[thread %d] finished\n", id);

    return NULL;
}

int main() {
    pthread_t threads[NUM_THREADS];
    int thread_ids[NUM_THREADS];

    puts("[main] started");

    for (int i = 0; i < NUM_THREADS; i++) {
        thread_ids[i] = i + 1;
        if (pthread_create(&threads[i], NULL, worker, (void*)&thread_ids[i])) {
            return 1;
        }
    }

    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }

    puts("[main] finished");

    return 0;
}
