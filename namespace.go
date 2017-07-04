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


/* A Namespace is actually a special UUID */
type Namespace UUID


/*
 * A few useful and predefined namespaces IDs 
 * used for UUID v3 and v5
 * See RFC4122
 */


/* Name string is a fully-qualified domain name */
var Namespace_DNS = Namespace{u: [16]byte{
	0x6b, 0xa7, 0xb8, 0x10,
	0x9d, 0xad,
	0x11, 0xd1,
	0x80,
	0xb4,
	0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8}}

/* Name string is a URL */
var Namespace_URL = Namespace{u: [16]byte{
	0x6b, 0xa7, 0xb8, 0x11,
	0x9d, 0xad,
	0x11, 0xd1,
	0x80,
	0xb4,
	0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8}}

/* Name string is an ISO OID */
var Namespace_OID = Namespace{u: [16]byte{
	0x6b, 0xa7, 0xb8, 0x12,
	0x9d, 0xad,
	0x11, 0xd1,
	0x80,
	0xb4,
	0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8}}

/* Name string is an X.500 DN (in DER or a text output format) */
var Namespace_X500 = Namespace{u: [16]byte{
	0x6b, 0xa7, 0xb8, 0x14,
	0x9d, 0xad,
	0x11, 0xd1,
	0x80,
	0xb4,
	0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8}}


/*
 * Parse a string into a Namespace
 */
func (ns *Namespace) Parse(s string) bool {
	return (*UUID)(ns).Parse(s)
}

func (ns *Namespace) String() string {
	return (*UUID)(ns).String()
}

func (ns *Namespace) UUID() *UUID {
	return (*UUID)(ns)
}
