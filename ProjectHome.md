This example code is for linux >= 3.1-rc1 on x86\_64.

The goal is to demonstrate the followings.

  * Transparent injection of a thread into the target process using new ptrace commands - PTRACE\_SEIZE and INTERRUPT.
  * Using the injected thread to capture a TCP connection and restoring it in another process.

Both are primarily to serve as the start point for mostly userland
checkpoint-restart implementation.  The latter is likely to be of
interest to virtual server farms and high availability too.

The code contained here is by no means ready for production.  It's
more of proof-of-concept.

Please read [README](http://code.google.com/p/ptrace-parasite/source/browse/README) for more info.