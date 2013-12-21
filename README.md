SLDR: Super Light DNS Resolver
==============================

SLDR is a tiny asynchronous DNS resolver written in C. It is capable of
doing A, AAAA and MX requests. SLDR is supposed to be used on embedded
systems and in applications that performs large amount of DNS requests.
SLDR keeps query cache, therefore subsequent calls to resolve the same
host hit the cache, saving time and traffic.

SLDR usage pattern is as follows:

   * Application clreates SLDR context by means of `sldr_create()`
   * Application schedules queries on SLDR context with `sldr_queue()`, which
     sends DNS UDP request and remembers which callback to call on success
     or failure, with optional unique application-defined parameter (application
     context).
   * Application does `sldr_poll()` which reads DNS replies and calls
     respective callbacks. `sldr_poll()` Is supposed to be called in a loop,
     with `sldr_queue()` calls in between to schedule new queries.
   * When done, application calls `sldr_destroy()`
   * Queued queries could be canceled with `sldr_cancel()`

## API

    struct sldr *sldr_create(void);
    void sldr_destroy(struct sldr **);

Create and destroy SLDR instance, which is handled by an opaque `struct sldr`.

    typedef void (*sldr_callback_t)(struct sldr_cb_data *);
    void sldr_queue(struct sldr *, void *context, const char *host,
                    enum dns_query_type type, sldr_callback_t callback);

Queue DNS request. `context` is an optional application-defined parameter,
`host` is the hostname to resolve, `type` is DNS query type (either
`DNS_A_RECORD`, or `DNS_MX_RECORD`, or `DNS_AAAA_RECORD`), and `callback` is
a function to call on success or error. Callback function will be called
with `struct sldr_cb_data` as a parameter, which is defined as:

    struct sldr_cb_data {
      void *context;
      enum sldr_error error;
      enum dns_query_type query_type;
      const char *name;               // Requested host name
      const unsigned char *addr;      // Resolved address
      size_t addr_len;                // Resolved address len
    };

From `struct sldr_cb_data`, an application can fetch resolved address, or
error code.


    int sldr_poll(struct sldr *, int milliseconds);

Read DNS replies and call user-defined callbacks. Wait not more than
`milliseconds` for DNS replies to arrive.

    int sldr_get_fd(struct sldr *);

Return UDP socket used to send and receive DNS queries. Could be used by an
application to multiplex IO, or to set specific socket option, for example to
increase kernel socket buffer.

    void sldr_cancel(struct sldr *, const void *context);

Cancel queued DNS query.

## Example

    #include <stdio.h>
    #include "sldr.h"

    static const struct dns_callback(struct sldr_cb_data *cbd) {
      if (cbd->error == SLDR_OK) {
        printf("%s: %u.%u.%u.%u\n", cbd->name,
               cbd->addr[0], cbd->addr[1], cbd->addr[2], cbd->addr[3]);
      } else {
        printf("Error: %d\n", cbd->error);
      }
    }

    int main(void) {
      struct sldr *sldr = sldr_create();
      sldr_queue(sldr, NULL, "google.com", DNS_A_RECORD, dns_callback);
      sldr_poll(sldr, 5 * 1000); // Resolve, wait no more then 5 sec
      sldr_destroy(&sldr);
      return 0;
    }

## Using SLDR as a command line tool

SLDR could be built as a command line tool:

    cc -o sldr sldr.c -DSLDR_CLI      # On Unix
    cl sldr.c /DSLDR_CLI              # On Windows

Then, one can send queries like:

    $ ./sldr google.com
    google.com: 74.125.24.113
    $ ./sldr google.com aaaa
    google.com: 2a00:1450:400b:0c02:0000:0000:0000:0066
    $ ./sldr google.com aaaa mx
    alt3.aspmx.l.google.com

# Licensing

SLDR is dual licensed. It is available either under the terms of [GNU GPL
v.2 license](http://www.gnu.org/licenses/old-licenses/gpl-2.0.html) for
free, or under the terms of standard commercial license provided by [Cesanta
Software](http://cesanta.com). Businesses who whish to use Cesanta's products
have an option to
[license commercial version](http://cesanta.com/products.html).

[Super Light Regular Expression library](https://github.com/cesanta/slre),
[Mongoose web server](https://github.com/cesanta/mongoose)
are other projects by Cesanta Software, developed with the same philosophy
of functionality and simplicity.
