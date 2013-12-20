// Copyright (c) 2004-2013 Sergey Lyubka <valenok@gmail.com>
// Copyright (c) 2013 Cesanta Software Limited
// All rights reserved
//
// This library is dual-licensed: you can redistribute it and/or modify
// it under the terms of the GNU General Public License version 2 as
// published by the Free Software Foundation. For the terms of this
// license, see <http://www.gnu.org/licenses/>.
//
// You are free to use this library under the terms of the GNU General
// Public License, but WITHOUT ANY WARRANTY; without even the implied
// warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
// See the GNU General Public License for more details.
//
// Alternatively, you can license this library under a commercial
// license, as set out in <http://cesanta.com/products.html>.

// This is an asynchronous DNS resolver library.
// Please refer to README.md for a detailed reference.

#ifndef SLDR_HEADER_INCLUDED
#define SLDR_HEADER_INCLUDED

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#define  DNS_QUERY_TIMEOUT  30  // Query timeout, seconds

enum dns_query_type {
  DNS_A_RECORD = 0x01,      // Lookup IP address
  DNS_AAAA_RECORD = 0x1c,   // Lookup IPv6 address
  DNS_MX_RECORD = 0x0f      // Lookup mail server for domain
};

// User defined function that will be called when DNS reply arrives for
// requested hostname. "struct sldr_cb_data" is passed to the user callback,
// which has an error indicator, resolved address, etc.
enum sldr_error {
  SLDR_OK,                  // No error
  SLDR_DOES_NOT_EXIST,      // Error: adress does not exist
  SLDR_TIMEOUT,             // Lookup time expired
  SLDR_ERROR                // No memory or other error
};

struct sldr_cb_data {
  void *context;
  enum sldr_error error;
  enum dns_query_type query_type;
  const char *name;               // Requested host name
  const unsigned char *addr;      // Resolved address
  size_t addr_len;                // Resolved address len
};

typedef void (*sldr_callback_t)(struct sldr_cb_data *);

struct sldr *sldr_create(void);
void sldr_destroy(struct sldr **);
void sldr_queue(struct sldr *, void *context, const char *host,
                enum dns_query_type type, sldr_callback_t callback);
int sldr_poll(struct sldr *, int milliseconds);
int sldr_get_fd(struct sldr *);
void sldr_cancel(struct sldr *, const void *context);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // SLDR_HEADER_INCLUDED
