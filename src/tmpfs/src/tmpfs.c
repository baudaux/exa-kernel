/*
 * Copyright (C) 2022 Benoit Baudaux
 */

#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "msg.h"
#include "tmpnode.h"

#include <emscripten.h>

#define TMPFS_FILE "tmpfs.peer"
#define TMPFS_PATH "/tmp/" TMPFS_FILE

#define RESMGR_FILE "resmgr.peer"
#define RESMGR_PATH "/tmp/" RESMGR_FILE

struct tmpnode * tmproot = NULL;

int main() {

  int sock;
  struct sockaddr_un local_addr, resmgr_addr, remote_addr;
  int bytes_rec;
  socklen_t len;
  char buf[256];
  unsigned short major;
  
  // Use console.log as tty is not yet started
  emscripten_log(EM_LOG_CONSOLE,"Starting tmpfs v0.1.0 ...");

  tmproot = create_tmpdir(NULL,"/");

  /* Create the server local socket */
  sock = socket (AF_UNIX, SOCK_DGRAM, 0);
  if (sock < 0) {
    return -1;
  }

  /* Bind server socket to TMPFS_PATH */
  memset(&local_addr, 0, sizeof(local_addr));
  local_addr.sun_family = AF_UNIX;
  strcpy(local_addr.sun_path, TMPFS_PATH);
  
  if (bind(sock, (struct sockaddr *) &local_addr, sizeof(struct sockaddr_un))) {
    
    return -1;
  }

  /* As we are in tmpfs, we need to add the file in the file system */
  create_tmpfile(tmproot, TMPFS_FILE);
  create_tmpfile(tmproot, RESMGR_FILE);

  memset(&resmgr_addr, 0, sizeof(resmgr_addr));
  resmgr_addr.sun_family = AF_UNIX;
  strcpy(resmgr_addr.sun_path, RESMGR_PATH);

  struct message * msg = (struct message *)&buf[0];

  msg->msg_id = REGISTER_DRIVER;
  msg->_u.dev_msg.dev_type = BLK_DEV;
  memset(msg->_u.dev_msg.dev_name,0,sizeof(msg->_u.dev_msg.dev_name));
  strcpy((char *)&msg->_u.dev_msg.dev_name[0],"tmpfs");
  
  sendto(sock, buf, 256, 0, (struct sockaddr *) &resmgr_addr, sizeof(resmgr_addr));

  emscripten_log(EM_LOG_CONSOLE,"waiting to recvfrom...\n");

  while (1) {
    
    bytes_rec = recvfrom(sock, buf, 256, 0, (struct sockaddr *) &remote_addr, &len);

    if (msg->msg_id == DRIVER_REGISTERED) {

      major = msg->_u.dev_msg.major;

      emscripten_log(EM_LOG_CONSOLE,"Driver registered: major=%d",major);

      msg->msg_id = REGISTER_DEVICE;
      msg->_u.dev_msg.minor = 1;
      
      sendto(sock, buf, 256, 0, (struct sockaddr *) &resmgr_addr, sizeof(resmgr_addr));
    }
  }
  
  
  return 0;
}
