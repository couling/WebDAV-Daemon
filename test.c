/**************************************************************************/
/* Server example that uses sendmsg() to create worker jobs               */
/**************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <spawn.h>

#define SERVER_PORT  12345

main (int argc, char *argv[])
{
   int    i, num, pid, rc, on = 1;
   int    listen_sd, accept_sd;
   int    server_sd, worker_sd, pair_sd[2];
   int    spawn_fdmap[1];
   char  *spawn_argv[1];
   char  *spawn_envp[1];
   struct inheritance   inherit;
   struct msghdr        msg;
   struct sockaddr_in6   addr;

   /*************************************************/
   /* If an argument was specified, use it to       */
   /* control the number of incoming connections    */
   /*************************************************/
   if (argc >= 2)
      num = atoi(argv[1]);
   else
      num = 1;

   /*************************************************/
   /* Create an AF_INET6 stream socket to receive   */
   /* incoming connections on                       */
   /*************************************************/
   listen_sd = socket(AF_INET6, SOCK_STREAM, 0);
   if (listen_sd < 0)
   {
      perror("socket() failed");
      exit(-1);
   }

   /*************************************************/
   /* Allow socket descriptor to be reuseable       */
   /*************************************************/
   rc = setsockopt(listen_sd,
                   SOL_SOCKET,  SO_REUSEADDR,
                   (char *)&on, sizeof(on));
   if (rc < 0)
   {
      perror("setsockopt() failed");
      close(listen_sd);
      exit(-1);
   }

   /*************************************************/
   /* Bind the socket                               */
   /*************************************************/
   memset(&addr, 0, sizeof(addr));
   addr.sin6_family      = AF_INET6;
   memcpy(&addr.sin6_addr, &in6addr_any, sizeof(in6addr_any));
   addr.sin6_port        = htons(SERVER_PORT);
   rc = bind(listen_sd,
             (struct sockaddr *)&addr, sizeof(addr));
   if (rc < 0)
   {
      perror("bind() failed");
      close(listen_sd);
      exit(-1);
   }

   /*************************************************/
   /* Set the listen back log                       */
   /*************************************************/
   rc = listen(listen_sd, 5);
   if (rc < 0)
   {
      perror("listen() failed");
      close(listen_sd);
      exit(-1);
   }

   /*************************************************/
   /* Create a pair of UNIX datagram sockets        */
   /*************************************************/
   rc = socketpair(AF_UNIX, SOCK_DGRAM, 0, pair_sd);
   if (rc != 0)
   {
      perror("socketpair() failed");
      close(listen_sd);
      exit(-1);
   }
   server_sd = pair_sd[0];
   worker_sd = pair_sd[1];

   /*************************************************/
   /* Initialize parms before entering for loop   */
   /*                                               */
   /* The worker socket descriptor is mapped to     */
   /* descriptor 0 in the child program.            */
   /*************************************************/
   memset(&inherit, 0, sizeof(inherit));
   spawn_argv[0]  = NULL;
   spawn_envp[0]  = NULL;
   spawn_fdmap[0] = worker_sd;

   /*************************************************/
   /* Create each of the worker jobs                */
   /*************************************************/
   printf("Creating worker jobs...\n");
   for (i=0; i < num; i++)
   {
      pid = spawn("/QSYS.LIB/QGPL.LIB/WRKR2.PGM",
                  1, spawn_fdmap, &inherit,
                  spawn_argv, spawn_envp);
      if (pid < 0)
      {
         perror("spawn() failed");
         close(listen_sd);
         close(server_sd);
         close(worker_sd);
         exit(-1);
      }
      printf("  Worker = %d\n", pid);
   }

   /*************************************************/
   /* Close down the worker side of the socketpair  */
   /*************************************************/
   close(worker_sd);

   /*************************************************/
   /* Inform the user that the server is ready      */
   /*************************************************/
   printf("The server is ready\n");

   /*************************************************/
   /* Go through the loop once for each connection  */
   /*************************************************/
   for (i=0; i < num; i++)
   {
      /**********************************************/
      /* Wait for an incoming connection            */
      /**********************************************/
      printf("Interation: %d\n", i+1);
      printf("  waiting on accept()\n");
      accept_sd = accept(listen_sd, NULL, NULL);
      if (accept_sd < 0)
      {
         perror("accept() failed");
         close(listen_sd);
         close(server_sd);
         exit(-1);
      }
      printf("  accept completed successfully\n");

      /**********************************************/
      /* Initialize message header structure        */
      /**********************************************/
      memset(&msg, 0, sizeof(msg));

      /**********************************************/
      /* We are not sending any data so we do not   */
      /* need to set either of the msg_iov fields.  */
      /* The memset of the message header structure */
      /* will set the msg_iov pointer to NULL and   */
      /* it will set the msg_iovcnt field to 0.     */
      /**********************************************/

      /**********************************************/
      /* The only fields in the message header      */
      /* structure that need to be filled in are    */
      /* the msg_accrights fields.                  */
      /**********************************************/
      msg.msg_accrights  = (char *)&accept_sd;
      msg.msg_accrightslen = sizeof(accept_sd);

      /**********************************************/
      /* Give the incoming connection to one of the */
      /* worker jobs.                               */
      /*                                            */
      /* NOTE: We do not know which worker job will */
      /*       get this inbound connection.         */
      /**********************************************/
      rc = sendmsg(server_sd, &msg, 0);
      if (rc < 0)
      {
         perror("sendmsg() failed");
         close(listen_sd);
         close(accept_sd);
         close(server_sd);
         exit(-1);
      }
      printf("  sendmsg completed successfully\n");

      /**********************************************/
      /* Close down the incoming connection since   */
      /* it has been given to a worker to handle    */
      /**********************************************/
      close(accept_sd);
   }

   /*************************************************/
   /* Close down the server and listen sockets      */
   /*************************************************/
   close(server_sd);
   close(listen_sd);
}
