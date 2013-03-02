#include "zhelpers.h"
#include "ssl_helpers.h"


struct Client
{
   SSL_CTX *ctx;
   SSL     *ssl;
   int      connected;
   BIO     *bio_internal;
   BIO     *bio_network;
};


struct Client * init_client(void)
{   
   struct Client *cli = malloc(sizeof(struct Client));

   cli->connected = 0;

   SSL_library_init();
   SSL_load_error_strings();			
   
   cli->ctx = SSL_CTX_new(DTLSv1_client_method());

   SSL_CTX_set_mode(cli->ctx, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

   BIO_new_bio_pair(&cli->bio_internal, 16*1024, &cli->bio_network, 16*1024);

   load_certs(cli->ctx, "certs/client-cert.pem", "certs/client-key.pem");

   cli->ssl = SSL_new(cli->ctx);

   if (!cli->ssl) err("failed to create new ssl context");

   SSL_set_bio(cli->ssl, cli->bio_internal, cli->bio_internal);

   return cli;
}


void say_hello(struct Client *cli, void *sock)
{
   int  n;
   char buff[16*1024];
   char rbuff[] = "Hello World!";
   
   memset(buff, 0, sizeof(buff));
   
   n = SSL_write(cli->ssl, rbuff, strlen(rbuff));
   
   printf("Sending SSL data: %s\n", rbuff);
   
   SSL_write(cli->ssl, rbuff, n);
   
   n = BIO_read(cli->bio_network, buff, sizeof(buff));
   
   r_send(sock, buff, n);
}


void do_ssl(void *sock)
{
   int first = 1;
   struct Client *cli = init_client();

   while(1)
   {
      int   r;
      char *s;
      void *d;      

      if (!first)
      {
         // read data packet and write to network bio
         d = r_recv(sock, &r);
         
         printf("Packet received\n");
         
         BIO_write(cli->bio_network, d, r);
         s_free(d);
      }
      
      first = 0;

      if (!cli->connected)
      {
         r = SSL_connect(cli->ssl);

         printf("Connect return: %d\n", r);
         
         if ( r == 1 )
         {
            printf("SSL Connected!!!\n");
            cli->connected = 1;
            show_cipher( cli->ssl );
            say_hello(cli, sock);
         }
         else if (r < 0)
         {
            char buff[16*1024];
            int nbytes = BIO_read(cli->bio_network, buff, sizeof(buff));
            printf("Sending Handshake packet\n");
            r_send(sock, buff, nbytes);
         }
         else
         {
            printf("ACK!!!\n");
            ERR_print_errors_fp(stderr);
         }
      }
      else
      {
         int  n;
         char rbuff[1024];
         memset(rbuff, 0, sizeof(rbuff));
         
         n = SSL_read(cli->ssl, rbuff, sizeof(rbuff));
         printf("Read SSL data: %s\n", rbuff);         
      }
      
   }
}


int main (void)
{
   void *context = zmq_ctx_new ();

   printf ("Connecting to hello world server\n");
   
   void *requester = zmq_socket (context, ZMQ_DEALER);

   zmq_setsockopt(requester, ZMQ_IDENTITY, "client", 6);
   
   zmq_connect(requester, "tcp://localhost:5555");
   
   do_ssl(requester);
   
   zmq_close (requester);
   zmq_ctx_destroy (context);
   return 0;
}
