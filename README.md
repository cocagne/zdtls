# DTLS over ZeroMQ

Traditional SSL/TLS isn't well suited to use on top of message-passing
frameworks as dropped messages and out-of-order delivery will break the
protocol. DTLS, however, was specifically designed to support these two
conditions and can be used effectively over message-passing frameworks.

This project provides a minimal, proof-of-concept implementation of DTLS
running on top of ZeroMQ.
