/*
   american fuzzy lop++ - afl_brifge_external
   ---------------------------------------------------

   Written by Flavian Dola

   Copyright 2021 by Airbus CyberSecurity. All rights reserved.
   Copyright 2019-2020 AFLplusplus Project. All rights reserved.

   Adapted from afl_proxy (https://github.com/AFLplusplus/AFLplusplus/blob/stable/utils/afl_proxy/afl-proxy.c)

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

   http://www.apache.org/licenses/LICENSE-2.0


*/

#include "types.h"

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>
#include <errno.h>

#include <sys/mman.h>
#include <sys/shm.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <fcntl.h>


#define FORKSRV_FD 198
#define MAP_SIZE_POW2 16
#define MAP_SIZE (1U << MAP_SIZE_POW2)
#define SHM_ENV_VAR "__AFL_SHM_ID"

u8 *__afl_area_ptr;
u32 __afl_map_size = MAP_SIZE;

unsigned long afl_prev_loc = 0;
int isSocketServerRunning = 0;
int sockfd = -1;
int connfd = -1;
FILE* logfd;
u32 id_sample = 0;


#define CONFIG 0x2

#define TRACE  0x3
#define STOP   0xff
#define CRASH  0xfe
#define END    0xfd
#define ERR    0xfc


#define EXEC_END_OK 1
#define EXEC_CRASH 2
#define EXEC_ERR -1
#define EXEC_UNK -2



#define CLOSE_SOCKET(sock)({if (sock != -1) {close(sock); sock = -1;} })
#define MAX_SZ_SAMPLE 0x7fff
#define SA struct sockaddr






/* Error reporting to forkserver controller */

void send_forkserver_error(int error) {

  u32 status;
  if (!error || error > 0xffff) return;
  status = (FS_OPT_ERROR | FS_OPT_SET_ERROR(error));
  if (write(FORKSRV_FD + 1, (char *)&status, 4) != 4) return;

}

/* SHM setup. */



static void __afl_map_shm(void) {

  char *id_str = getenv(SHM_ENV_VAR);
  char *ptr;

  /* NOTE TODO BUG FIXME: if you want to supply a variable sized map then
     uncomment the following: */

  /*
  if ((ptr = getenv("AFL_MAP_SIZE")) != NULL) {

    u32 val = atoi(ptr);
    if (val > 0) __afl_map_size = val;

  }

  */

  if (__afl_map_size > MAP_SIZE) {

    if (__afl_map_size > FS_OPT_MAX_MAPSIZE) {

      fprintf(stderr,
              "Error: AFL++ tools *require* to set AFL_MAP_SIZE to %u to "
              "be able to run this instrumented program!\n",
              __afl_map_size);
      if (id_str) {

        send_forkserver_error(FS_ERROR_MAP_SIZE);
        exit(-1);

      }

    } else {

      fprintf(stderr,
              "Warning: AFL++ tools will need to set AFL_MAP_SIZE to %u to "
              "be able to run this instrumented program!\n",
              __afl_map_size);

    }

  }

  if (id_str) {

#ifdef USEMMAP
    const char *   shm_file_path = id_str;
    int            shm_fd = -1;
    unsigned char *shm_base = NULL;

    /* create the shared memory segment as if it was a file */
    shm_fd = shm_open(shm_file_path, O_RDWR, 0600);
    if (shm_fd == -1) {

      fprintf(stderr, "shm_open() failed\n");
      send_forkserver_error(FS_ERROR_SHM_OPEN);
      exit(1);

    }

    /* map the shared memory segment to the address space of the process */
    shm_base =
        mmap(0, __afl_map_size, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);

    if (shm_base == MAP_FAILED) {

      close(shm_fd);
      shm_fd = -1;

      fprintf(stderr, "mmap() failed\n");
      send_forkserver_error(FS_ERROR_MMAP);
      exit(2);

    }

    __afl_area_ptr = shm_base;
#else
    u32 shm_id = atoi(id_str);

    __afl_area_ptr = shmat(shm_id, 0, 0);

#endif

    if (__afl_area_ptr == (void *)-1) {

      send_forkserver_error(FS_ERROR_SHMAT);
      exit(1);

    }

    /* Write something into the bitmap so that the parent doesn't give up */

    __afl_area_ptr[0] = 1;

  }

}

/* Fork server logic. */

static void __afl_start_forkserver(void) {

  u8  tmp[4] = {0, 0, 0, 0};
  u32 status = 0;

  if (__afl_map_size <= FS_OPT_MAX_MAPSIZE)
    status |= (FS_OPT_SET_MAPSIZE(__afl_map_size) | FS_OPT_MAPSIZE);
  if (status) status |= (FS_OPT_ENABLED);
  memcpy(tmp, &status, 4);

  /* Phone home and tell the parent that we're OK. */

  if (write(FORKSRV_FD + 1, tmp, 4) != 4) return;

}

static u32 __afl_next_testcase(u8 *buf, u32 max_len) {

  s32 status, res = 0xffffff;

  /* Wait for parent by reading from the pipe. Abort if read fails. */
  if (read(FORKSRV_FD, &status, 4) != 4) return 0;

  /* we have a testcase - read it */
  memset(buf, 0, max_len);
  status = read(0, buf, max_len);

  /* report that we are starting the target */
  if (write(FORKSRV_FD + 1, &res, 4) != 4) return 0;

  return status;

}

static void __afl_end_testcase(int status) {

  //int status = 0xffffff;

  if (write(FORKSRV_FD + 1, &status, 4) != 4) exit(1);

}









void clear_afl_trace()
{
    afl_prev_loc = 0;
}



void afl_maybe_log(unsigned long cur_loc) {

  cur_loc = (cur_loc >> 4) ^ (cur_loc << 8);
  unsigned long afl_idx = cur_loc ^ afl_prev_loc;
  afl_idx &= __afl_map_size - 1;
  __afl_area_ptr[afl_idx]++;

  afl_prev_loc = cur_loc >> 1;
}


int flush_socket() {
    char c;
    int r = 1;

    while (r == 1) {
        r = recv(sockfd, &c, 1, SO_RCVTIMEO);
    }
}


int get_exec_info() {

    int r = 0;
    unsigned char buff[4];
    u32 rcv_id = 0;


    clear_afl_trace();


    for (;;) {

        r = recv(sockfd, buff, 1, 0);
        if (r != 1){
            fprintf(logfd, "get_exec_info: Error on recv\n");
            fflush(logfd);
            return(EXEC_ERR);
        }

        switch (buff[0]) {
            case END:
                r = recv(sockfd, &rcv_id, 4, 0);
                if (r != 4) {
                    fprintf(logfd, "get_exec_info: (END) Error on rcv_id\n");
                    fflush(logfd);
                    return(EXEC_ERR);
                }
                if (rcv_id != id_sample) {
                    fprintf(logfd, "get_exec_info: (END) rcv_id (%d) not match id_sample (%d)\n", rcv_id, id_sample);
                    fflush(logfd);
                    return(EXEC_ERR);
                }

                // Remote execution ended without a crash
                return(EXEC_END_OK);


            case CRASH:
                r = recv(sockfd, &rcv_id, 4, 0);
                if (r != 4) {
                    fprintf(logfd, "get_exec_info: (CRASH) Error on rcv_id\n");
                    fflush(logfd);
                    return(EXEC_ERR);
                }
                if (rcv_id != id_sample) {
                    fprintf(logfd, "get_exec_info: (CRASH) rcv_id (%d) not match id_sample (%d)\n", rcv_id, id_sample);
                    fflush(logfd);
                    return(EXEC_ERR);
                }

                // Remote execution ended with a crash
                return(EXEC_CRASH);


            case TRACE:
                r = recv(sockfd, &rcv_id, 4, 0);
                if (r != 4) {
                    fprintf(logfd, "get_exec_info: (TRACE) Error on rcv_id\n");
                    fflush(logfd);
                    return(EXEC_ERR);
                }
                if (rcv_id != id_sample) {
                    fprintf(logfd, "get_exec_info: (TRACE) rcv_id (%d) not match id_sample (%d)\n", rcv_id, id_sample);
                    fflush(logfd);
                    return(EXEC_ERR);
                }


                r = recv(sockfd, buff, 4, 0);
                if (r != 4) {
                    fprintf(logfd, "get_exec_info: Error on get exec trace\n");
                    fflush(logfd);
                    return(EXEC_ERR);
                }
                afl_maybe_log(*(unsigned long*) buff);
                break;

            case ERR:
                if (rcv_id != id_sample) {
                    fprintf(logfd, "get_exec_info: (ERR) error received\n");
                    fflush(logfd);
                    return(EXEC_ERR);
                }

            default:
                fprintf(logfd, "get_exec_info: Error unknown receive code: 0x%X\nn", buff[0]);
                fflush(logfd);
                return(EXEC_UNK);

        }
    }
}












int connect_to_ext(char* pIpAddress, u32 port, u32 timeout_ms) {

    struct sockaddr_in servaddr;
    int res = 0;


    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
            fprintf(logfd, "socket creation failed...\n");
            fflush(logfd);
            return(res);
        }

    // set timeout
    struct timeval tv;
    tv.tv_sec = timeout_ms/1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv) != 0) {
        fprintf(logfd, "setsockopt creation failed...\n");
        fflush(logfd);
        return(res);
    }

    bzero(&servaddr, sizeof(servaddr));
    // assign IP, PORT
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr(pIpAddress);
    servaddr.sin_port = htons(port);

    if (connect(sockfd, (SA*)&servaddr, sizeof(servaddr)) != 0) {
            fprintf(logfd, "connection with the server failed...\n");
            fflush(logfd);
            CLOSE_SOCKET(sockfd);
            return(res);
    }

    res = 1;

    return res;

}


int send_all(void *data2send, size_t length) {
    int res = 0;
    char *ptr = (char*) data2send;
    while (length > 0)
    {
        int i = send(sockfd, ptr, length, 0);
        if (i < 1) {
            return(res);
        }
        ptr += i;
        length -= i;
    }
    res = 1;
    return(res);

}



int send_input_data(char* pInputData, u16 sz) {
    int res = 0;
    int offset = 0;
    char buf[1+4+sz+MAX_SZ_SAMPLE];

    memset(buf, 0, sizeof(buf));


    if (pInputData == 0)
    {
        return(res);
    }

    if (sz > MAX_SZ_SAMPLE) {
        sz = MAX_SZ_SAMPLE;
    }

    buf[offset] = CONFIG;
    offset++;

    *(u32*)(buf+offset) = id_sample;
    offset = offset + sizeof(u32);

    *(u16*)(buf+offset) = sz;
    offset = offset + sizeof(u16);
    memcpy(buf+offset, pInputData, sz);

    if (1 != send_all(buf, offset+sz))
    {
        fprintf(logfd, "send_input_data: Send failed\n");
        fflush(logfd);
        return(res);
    }


    /* Write something into the bitmap so that the parent doesn't give up */
    __afl_area_ptr[0] = 1;

    res = 1;
    return(res);
}


void exit_with_segfault() {
    kill(getpid(), SIGSEGV);
    sleep(5);
}




void print_usage() {
    fprintf(stderr, "USAGE:\n afl_bridge_external IP PORT timeout_ms\n");
    fprintf(logfd, "USAGE:\n afl_bridge_external IP PORT timeout_ms\n");
    fflush(logfd);
    return;
}



int main(int argc, char *argv[]) {

  /* This is were the testcase data is written into */
  u8  buf[MAX_SZ_SAMPLE];
  s32 len;
  int res_exec = 0;

  // log to log
  logfd = fopen("./afl_bridge_external.log", "a");
  if (logfd == 0) {
      fprintf(stderr, "Error open log file\n");
      goto END_MAIN;
  }

  if (argc != 4)
  {
      fprintf(stderr, "Error: bad args\n");
      fprintf(logfd, "Error: bad args\n");
      print_usage();
      goto END_MAIN;
  }

  if (1 != connect_to_ext(argv[1], atoi(argv[2]), atoi(argv[3])) ) {
      fprintf(stderr, "Error: Failed to connect %s:%s\n", argv[1], argv[2]);
      fprintf(logfd, "Error: Failed to connect %s:%s\n", argv[1], argv[2]);
      fflush(logfd);
      goto END_MAIN;
  }


  /* here you specify the map size you need that you are reporting to
     afl-fuzz.  Any value is fine as long as it can be divided by 32. */
  __afl_map_size = MAP_SIZE;  // default is 65536

  /* then we initialize the shared memory map and start the forkserver */
  __afl_map_shm();
  __afl_start_forkserver();

  while ((len = __afl_next_testcase(buf, sizeof(buf))) > 0) {
    id_sample++;

    if (1 != send_input_data(buf, (u16)len)){
        fprintf(logfd, "Error on send input data\n");
        goto END_MAIN;
    }


    res_exec = get_exec_info();
    switch (res_exec)
    {
        case EXEC_ERR:
            fprintf(logfd, "EXEC_ERR: Error on collect execution info\n");
            fflush(logfd);
            //goto END_MAIN;
            // TODO: to improve....
            flush_socket();
            __afl_end_testcase(0x0);
            break;
        case EXEC_END_OK:
            // remote execution ended
            // no crash detect
            __afl_end_testcase(0x0);
            break;
        case EXEC_CRASH:
            // remote execution crashed
            // report to AFL
            //exit_with_segfault();
            __afl_end_testcase(0x0005);
            break;
        default:
            fprintf(logfd, "Unknown execution code %d\n", res_exec);
            fflush(logfd);
            goto END_MAIN;
    }

  }

END_MAIN:
  fclose(logfd);
  CLOSE_SOCKET(sockfd);

  return 0;

}

