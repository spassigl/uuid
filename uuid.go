/*
 * Copyright 2017 Stefano Passiglia
 * stefano.passiglia@gmail.com
 * 
 * uuid package is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301, USA.
 * 
 */

package uuid

import (
	"crypto/rand"
	"crypto/md5"
	"crypto/sha1"
	"fmt"
	"sync"
	"time"
)

/*
  The b array will store the UUID according to the RFC4122 format:

   0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                          time_low                             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |       time_mid                |         time_hi_and_version   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |clk_seq_hi_res |  clk_seq_low  |         node (0-1)            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                         node (2-5)                            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   Field                  Data Type     Octet  Note
                                        #

   time_low               unsigned 32   0-3    The low field of the
                          bit integer          timestamp

   time_mid               unsigned 16   4-5    The middle field of the
                          bit integer          timestamp

   time_hi_and_version    unsigned 16   6-7    The high field of the
                          bit integer          timestamp multiplexed
                                               with the version number

   clock_seq_hi_and_rese  unsigned 8    8      The high field of the
   rved                   bit integer          clock sequence
                                               multiplexed with the
                                               variant

   clock_seq_low          unsigned 8    9      The low field of the
                          bit integer          clock sequence

   node                   unsigned 48   10-15  The spatially unique
                          bit integer          node identifier

*/
type UUID struct {
	u	[16]byte
}

var (
	uuidMtx		sync.Mutex
	lastTime	int64
	clockSeq	uint16
	nodeId		[6]byte
)

/* Nil UUID has all bits set to zero */
var NilUUID UUID

func init() {
	initNodeId()
	initClockSeq()
}

/* 
 * We don't use IEEE 802 network address but we prefer to
 * obtain a 47-bit cryptographic quality random number and
 * use it as the low 47 bits of the node ID, with the least
 * significant bit of the first octet of the node ID set to one.
 * This bit is the unicast/multicast bit, which will never 
 * be set in IEEE 802 addresses obtained from network cards.
 * (RFC 4122 par 4.5) 
 */
func initNodeId() {
	rand.Read(nodeId[:])
	nodeId[5] |= 1
}

/*
 * Initialize clock sequence with high quality random bits
 */
func initClockSeq() {
	var cs [2]byte
	rand.Read(cs[:])
	clockSeq = uint16(cs[1]) + uint16(cs[0]) << 8
	clockSeq &= 0x3FFF	// Use only 14 bits
}


/* 
 * Returns a 64 bit value Coordinated Universal Time (UTC) 
 * as a count of 100-nanosecond intervals since 00:00:00.00, 
 * 15 October 1582
 */
func getTimestampV1() int64 {
	/* Offset in 100s of ns between the Epoch and
         * the required inital date */
	const OFFSETNS = int64(122192928000000000)

	t := time.Now().UTC().UnixNano() / 100
	t += OFFSETNS
	if t <= lastTime {
		// Increment clock sequence value
		// as per 4.2.1. Use first 14 bits
		clockSeq = (clockSeq + 1) & 0x3FFF
	}
	lastTime = t
	return t
}

/*
 * Version 1 generator
 */
func (u *UUID) GenerateV1() {
	defer uuidMtx.Unlock()
	uuidMtx.Lock()

	ts := getTimestampV1()

	/* 
	 * Set the time_low field equal to the least significant 32 bits
	 * (bits zero through 31) of the timestamp in the same order of
	 * significance.
	 */
	u.u[0] = byte(uint32(ts) >> 24)
	u.u[1] = byte(uint32(ts) >> 16)
	u.u[2] = byte(uint32(ts) >> 8)
	u.u[3] = byte(uint32(ts))
	/*
	 * Set the time_mid field equal to bits 32 through 47 from the
	 * timestamp in the same order of significance.
	 */
	t := uint16((ts >> 32) & 0xFFFF)
	u.u[4] = byte(t >> 8)
	u.u[5] = byte(t)
	/*
	 * Set the 12 least significant bits (bits zero through 11) of the
	 * time_hi_and_version field equal to bits 48 through 59 from the
	 * timestamp in the same order of significance.
	 * Set the four most significant bits (bits 12 through 15) of the
	 * time_hi_and_version field to the 4-bit version number
	 * corresponding to the UUID version being created
	 */
	t = uint16((ts >> 48) & 0x0FFF | 0x1000)
	u.u[6] = byte(t >> 8)
	u.u[7] = byte(t)
	/*
	 * Set the 6 least significant bits (bits zero through 5) of the
	 * clock_seq_hi_and_reserved field to the 6 most significant bits
	 * (bits 8 through 13) of the clock sequence in the same order of
	 * significance.
	 * Set the two most significant bits (bits 6 and 7) of the
	 * clock_seq_hi_and_reserved to zero and one, respectively.
	 */
	cs := clockSeq & 0x3fff | 0x8000
	u.u[8] = byte(cs >> 8)
	u.u[9] = byte(cs)
	/*
	 * Set the node field to the 48-bit IEEE address in the same order of
	 * significance as the address.
	 */
	copy(u.u[10:], nodeId[:])
}

func GenerateV1() UUID {
	var u UUID
	u.GenerateV1()
	return u
}


/*
 * Version 3 generator
 */
func (u *UUID) GenerateV3(ns Namespace, name string) {
	defer uuidMtx.Unlock()
	uuidMtx.Lock()

	if len(ns.u[:]) != 16 || len(name) == 0 {
		return
	}

	/*
	 * Compute the MD5 hash of the name space ID 
	 * concatenated with the name.
	 */
	h := md5.New()
	h.Write(ns.u[:])
	h.Write([]byte(name))

	/* Copy the hash to the UUID */
	copy(u.u[:], h.Sum(nil))

	/* 
	 * Set the four most significant bits (bits 12 through 15) 
	 * of the time_hi_and_version field to the appropriate 
	 * 4-bit version number as follows:
         *       Msb0  Msb1  Msb2  Msb3
         *        0     0     1     1
	 * Set the two most significant bits (bits 6 and 7) of the
      	 * clock_seq_hi_and_reserved to zero and one, respectively.
	 */
	u.u[6] &= 0x0f
	u.u[6] |= 0x30

	u.u[8] &= 0x3f
	u.u[8] |= 0x80
}

func GenerateV3(ns Namespace, name string) UUID {
	var u UUID
	u.GenerateV3(ns, name)
	return u
}

/*
 * Version 5 generator
 */
func (u *UUID) GenerateV5(ns Namespace, name string) {
	defer uuidMtx.Unlock()
	uuidMtx.Lock()

	if len(ns.u[:]) != 16 || len(name) == 0 {
		return
	}

	/*
	 * Compute the SHA1 hash of the name space ID 
	 * concatenated with the name.
	 */
	h := sha1.New()
	h.Write(ns.u[:])
	h.Write([]byte(name))

	/* Copy the hash to the UUID */
	copy(u.u[:], h.Sum(nil))

	/* 
	 * Set the four most significant bits (bits 12 through 15) 
	 * of the time_hi_and_version field to the appropriate 
	 * 4-bit version number as follows:
         *       Msb0  Msb1  Msb2  Msb3
         *        0     1     0     1
	 * Set the two most significant bits (bits 6 and 7) of the
      	 * clock_seq_hi_and_reserved to zero and one, respectively.
	 */
	u.u[6] &= 0x0f
	u.u[6] |= 0x50

	u.u[8] &= 0x3f
	u.u[8] |= 0x80
}

func GenerateV5(ns Namespace, name string) UUID {
	var u UUID
	u.GenerateV5(ns, name)
	return u
}

/*
 * Version 4 generator
 */
func (u *UUID) GenerateV4() {
	defer uuidMtx.Unlock()
	uuidMtx.Lock()

	/*
	 * Set the four most significant bits (bits 12 through 15) of the
	 * time_hi_and_version field to the 4-bit version number as
	 * follows:
         *       Msb0  Msb1  Msb2  Msb3
         *        0     1     0     0
	 * Set the two most significant bits (bits 6 and 7) of the
	 * clock_seq_hi_and_reserved to zero and one, respectively.
	 * Set all the other bits to randomly (or pseudo-randomly) 
	 * chosen values.
	 */
	rand.Read(u.u[:])

	u.u[6] &= 0x0f
	u.u[6] |= 0x40

	u.u[8] &= 0x3f
	u.u[8] |= 0x80
}

func GenerateV4() UUID {
	var u UUID
	u.GenerateV4()
	return u
}

/*
 * Standard 8-4-4-4-12 representation
 */
func (u UUID) String() string {
	s := fmt.Sprintf("%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
			u.u[0], u.u[1], u.u[2], u.u[3],
			u.u[4], u.u[5],
			u.u[6], u.u[7],
			u.u[8], u.u[9],
			u.u[10], u.u[11], u.u[12], u.u[13], u.u[14], u.u[15]);
	return s
}

/*
 * Return the uuid version
 */
func (u UUID) Version() byte {
	return u.u[6] >> 4
}

/*
 * Parse a uuid from a string
 */
func (u *UUID) Parse(s string) bool {
	_, err := fmt.Sscanf(s, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
			&u.u[0], &u.u[1], &u.u[2], &u.u[3],
			&u.u[4], &u.u[5],
			&u.u[6], &u.u[7],
			&u.u[8], &u.u[9],
			&u.u[10], &u.u[11], &u.u[12], &u.u[13], &u.u[14], &u.u[15]);
	return err != nil
}

/*
 * Parse a UUID from a string, return the parsed UUID
 */
func Parse(s string) (UUID, bool) {
	var u UUID
	err := u.Parse(s)
	return u, err
}
