#include "zhelpers.h"
#include "ssl_helpers.h"


struct Server
{
   SSL_CTX *ctx;
   SSL     *ssl;
   int      connected;
   BIO     *bio_internal;
   BIO     *bio_network;
};


struct Server * init_server(void)
{   
   struct Server *svr = malloc(sizeof(struct Server));

   svr->connected = 0;

   SSL_library_init();
   SSL_load_error_strings();			
   
   svr->ctx = SSL_CTX_new(DTLSv1_server_method());

   SSL_CTX_set_mode(svr->ctx, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

   BIO_new_bio_pair(&svr->bio_internal, 16*1024, &svr->bio_network, 16*1024);

   load_certs(svr->ctx, "certs/server-cert.pem", "certs/server-key.pem");

   svr->ssl = SSL_new(svr->ctx);

   if (!svr->ssl) err("failed to creat new ssl context");

   SSL_set_bio(svr->ssl, svr->bio_internal, svr->bio_internal);
   
   return svr;
}


void zmq_forward(void * sock, struct Server * svr)
{
   BIO_flush(svr->bio_network);
   
   if ( BIO_pending(svr->bio_network) > 0 )
   {
      char buff[16*1024];
      int nbytes = BIO_read(svr->bio_network, buff, sizeof(buff));
      s_sendmore(sock, "client");
      r_send(sock, buff, nbytes);
   }
}


void do_ssl(void *sock)
{
   struct Server *svr = init_server();

   while(1)
   {
      int   r;
      char *s;
      void *d;

      // read and discard "client"
      s = s_recv(sock);
      s_free(s);

      printf("Packet received\n");

      // read data packet and write to network bio
      d = r_recv(sock, &r);
      BIO_write(svr->bio_network, d, r);
      s_free(d);

      if (!svr->connected)
      {
         r = SSL_accept(svr->ssl);
         
         if ( r == 1 )
         {
            printf("SSL Connected!!!\n");
            svr->connected = 1;

            zmq_forward(sock, svr);

            show_cipher( svr->ssl );
         }
         else if (r < 0)
         {
            printf("Sending SSL Handshake packet\n");
            zmq_forward(sock, svr);
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
         char buff[16*1024];
         char rbuff[1024];
         memset(buff,  0, sizeof(buff));
         memset(rbuff, 0, sizeof(rbuff));
         
         n = SSL_read(svr->ssl, rbuff, sizeof(rbuff));
         printf("Read SSL data: %s\n", rbuff);
         
         SSL_write(svr->ssl, rbuff, n);
         
         n = BIO_read(svr->bio_network, buff, sizeof(buff));
         s_sendmore(sock, "client");
         r_send(sock, buff, n);
      }
   }
}


int main (void)
{
   void *context = zmq_ctx_new ();

   // Socket to talk to clients
   void *responder = zmq_socket (context, ZMQ_ROUTER);
   
   zmq_setsockopt(responder, ZMQ_IDENTITY, "server", 6);
   
   zmq_bind (responder, "tcp://*:5555");

   do_ssl(responder);
   
   zmq_close (responder);
   zmq_ctx_destroy (context);
   return 0;
}
