//
// Copyright 2011 ZooWar.com. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
//
#ifndef _bcrypt_h_
#define _bcrypt_h_

#include <stdint.h>
#include <stdlib.h>
#include "pybc_blf.h"

typedef uint8_t         u_int8_t;
typedef uint16_t        u_int16_t;
typedef uint32_t        u_int32_t;

extern void encode_salt(char *, uint8_t *, uint16_t, uint8_t);
extern char *pybc_bcrypt(const char *, const char *);

#endif
