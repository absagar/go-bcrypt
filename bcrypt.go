//
// Copyright 2011 ZooWar.com. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
//

// Package bcrypt implements Blowfish password hashing.
//
// bcrypt is an implementation of the OpenBSD Blowfish password hashing
// algorithm, as described in "A Future-Adaptable Password Scheme" by
// Niels Provos and David Mazieres.
//
// This system hashes passwords using a version of Bruce Schneier's
// Blowfish block cipher with modifications designed to raise the cost
// of off-line password cracking. The computation cost of the algorithm
// is parametised, so it can be increased as computers get faster.
//
//  // generate a reasonable hash
//  var password = "WyWihatdyd?frub1"
//  hash, _ := Hash(password)
//
//  // generate a vary expensive hash
//  salt, _ := Salt(MaxRounds)
//  hash, _ = Hash(password, salt)
//
//  if Match(password, hash)) {
//      // they match!
//  }
//
package bcrypt

// #include "bcrypt.h"
import "C"

import (
	"crypto/rand"
	"errors"
	"unsafe"
)

const (
	DefaultRounds = 12
	MaxRounds     = 31
	MinRounds     = 4
	RandomSaltLen = 16
	SaltBufferLen = 64
)

var (
	InvalidRounds = errors.New("invalid rounds")
	InvalidSalt   = errors.New("invalid salt")
)

// Hash generates an encrypted hash of the unencrypted password
// and the random salt using the OpenBSD Blowfish password hashing algorithm.
// If the "salt" parameter is omitted, a random salt will be generated with
// a workload complexity of DefaultRounds.
//
// Returns the Blowfish encrypted password.
//
func Hash(password string, salt ...string) (hash string, err error) {
	var s string
	if len(salt) == 0 {
		var err error
		s, err = Salt(12)
		if err != nil {
			return "", err
		}
	} else {
		s = salt[0]
	}
	pc := C.CString(password)
	sc := C.CString(s)
	h := C.pybc_bcrypt(pc, sc)
	C.free(unsafe.Pointer(pc))
	C.free(unsafe.Pointer(sc))
	hash = C.GoString(h)
	if hash == ":" {
		return "", InvalidSalt
	}
	return C.GoString(h), err
}

// HashBytes provides a []byte based wrapper to Hash.
//
func HashBytes(password []byte, salt ...[]byte) (hash []byte, err error) {
	var s string
	if len(salt) == 0 {
		s, err = Hash(string(password))
	} else {
		s, err = Hash(string(password), string(salt[0]))
	}
	return []byte(s), err
}

// Match determines if an unencrypted password matches a previously encrypted
// password. It does so by generating a Blowfish encrypted hash of the
// unencrypted password and the random salt from the previously encrypted
// password.
//
// Returns 'true' when the encrypted passwords match, otherwise 'false'.
//
func Match(password, hash string) bool {
	h, err := Hash(password, hash)
	if err != nil {
		return false
	}
	return h == hash
}

// MatchBytes provides a []byte based wrapper to Match.
//
func MatchBytes(password, hash []byte) bool {
	return Match(string(password), string(hash))
}

// Salt generates a random salt for use with Hash(). The "rounds"
// parameter defines the complexity of the hashing, increasing the cost as
// 2**rounds.
//
// Returns a random salt.
//
func Salt(rounds ...int) (salt string, err error) {
	r := DefaultRounds
	if len(rounds) > 0 {
		// ensure the "rounds" parameter is valid.
		r = rounds[0]
		if r < MinRounds || r > MaxRounds {
			return "", InvalidRounds
		}
	}

	// generate and verify a random salt number
	rs := make([]byte, RandomSaltLen)
	n, err := rand.Read(rs)
	if err != nil {
		return
	}
	if n != RandomSaltLen {
		return "", InvalidSalt
	}

	b := make([]byte, SaltBufferLen)
	C.encode_salt(
		(*C.char)(unsafe.Pointer(&b[0])),
		(*C.uint8_t)(&rs[0]),
		(C.uint16_t)(len(rs)),
		(C.uint8_t)(r))
	return string(b), err
}

// SaltBytes provides a []byte based wrapper to Salt.
//
func SaltBytes(rounds int) (salt []byte, err error) {
	b, err := Salt(rounds)
	return []byte(b), err
}
