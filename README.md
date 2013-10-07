# libcurvecpr [![Build Status](https://travis-ci.org/impl/libcurvecpr.png)](https://travis-ci.org/impl/libcurvecpr)

libcurvecpr is a low-level, networking-independent implementation of Daniel J. Bernstein's [CurveCP](http://curvecp.org/).

## How does it work?

libcurvecpr is based on a system of callbacks that must be implemented by library users. Like the reference CurveCP implementation, the client, server, and message-handling portions of libcurvecpr are entirely independent of each other.

This means that while it's slightly more effort to build software based on libcurvecpr than other packages, it provides complete freedom to use any underlying mechanism for handling network traffic you want&mdash;whether it's an IPC connection to another program, standard `poll(2)`-type functionality, or [libev](http://software.schmorp.de/pkg/libev.html).

## How do I get it?

The current source code release can be obtained from the GitHub [releases page](https://github.com/impl/libcurvecpr/releases).

libcurvecpr is currently packaged for the following operating systems:

* For OS X using [Homebrew](https://github.com/mxcl/homebrew):

  ```
  $ brew tap impl/libcurvecpr
  $ brew install libcurvecpr
  ```

* For NetBSD in `security/libcurvecpr`.

## Can I see an example?

Here's how one might implement sending an encrypted message using `sendto(2)`:

```c
struct cl_priv {
    struct sockaddr_storage dest;
    socklen_t dest_len;
    int s;
};

static int cl_send (struct curvecpr_client *client, const unsigned char *buf, size_t num)
{
    struct cl_priv *priv = (struct cl_priv *)client->cf.priv;
    if (sendto(priv->s, buf, num, 0, (struct sockaddr *)&priv->dest, priv->dest_len) != num)
        return -1;

    return 0;
}

struct curvecpr_client_cf cl_cf = {
    .ops = {
        .send = cl_send,
        /* ... */
    }
};

int main (void)
{
    struct curvecpr_client cl;
    struct cl_priv cl_priv = /* ... */;

    cl_cf.priv = &cl_priv;

    curvecpr_client_new(&cl, &cl_cf);
    curvecpr_client_connected(&cl);

    curvecpr_client_send(&cl, "Hello,ThisIsDog", 16);
}
```

## What makes it different from the reference implementation?

The reference implementation is intended to be used as standalone programs. Additionally, the reference implementation source code is extremely difficult to understand.

libcurvecpr is a library proper: for instance, to send a message, you use one of the `curvecpr_client_send` or `curvecpr_server_send` functions, or a callback (depending on how you're sending the message).

## Has this been audited by anyone?

No. I don't claim to be a security or cryptography expert in any senses of the terms. I am inviting experts in these fields to review the source code and provide feedback as I believe it will be beneficial to the global computer security community.

## Where's the documentation?

It's coming.

## Is it fast?

It's a little slower than the reference implementation. That said, all of the quirks of the congestion control algorithm haven't been worked out yet.

## How is libcurvecpr licensed?

Like the [NaCl](http://nacl.cr.yp.to/) library on which it is based, libcurvecpr is released to the public domain. Should there be any confusion about the meaning of this statement, please consult [this document](http://creativecommons.org/publicdomain/zero/1.0/).
