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
	"testing"
	"time"
)

func TestNil(t *testing.T) {
	t.Logf("Nil UUID: %s\n", NilUUID)
}

func TestV1(t *testing.T) {
	var uv1 UUID
	uv1.GenerateV1()
	if uv1.Version() != 1 {
		t.Errorf("Version should be 1, instead is %d\n", uv1.Version())
	}
}

func TestV1Parse(t *testing.T) {
	s := "d1723894-5fe7-11e7-907b-a6006ad3dba0" // Version 1
	var uv1 UUID
	uv1.Parse(s)
	if (uv1.String() != s) {
		t.Errorf("Parsing of %s returned %s\n", s, uv1.String())
	}
	if uv1.Version() != 1 {
		t.Errorf("Version should be 1, instead is %d\n", uv1.Version())
	}
}

func TestV3(t *testing.T) {
	/* The UUIDs generated at different times from the same name in the
           same namespace MUST be equal */
	var uv3a, uv3b UUID
	uv3a.GenerateV3(Namespace_DNS, "www.fanopassiglia.com")
	time.Sleep(100*time.Millisecond)
	uv3b.GenerateV3(Namespace_DNS, "www.fanopassiglia.com")
	if (uv3a != uv3b) {
		t.Errorf("UUIDs are different: %s - %s\n", uv3a.String(), uv3b.String())
	}
	/* The UUIDs generated from two different names in the same namespace
           should be different (with very high probability). */
	uv3a.GenerateV3(Namespace_DNS, "www.fanopassiglia.com")
	uv3b.GenerateV3(Namespace_DNS, "www.fnopassiglia.com")
	if (uv3a == uv3b) {
		t.Errorf("UUIDs are identical: %s - %s\n", uv3a.String(), uv3b.String())
	}
	/* The UUIDs generated from the same name in two different namespaces
           should be different with (very high probability). */
	uv3a.GenerateV3(Namespace_DNS, "www.fanopassiglia.com")
	uv3b.GenerateV3(Namespace_URL, "www.fanopassiglia.com")
	if (uv3a == uv3b) {
		t.Errorf("UUIDs are identical: %s - %s\n", uv3a.String(), uv3b.String())
	}
}

func TestV5(t *testing.T) {
	/* The UUIDs generated at different times from the same name in the
           same namespace MUST be equal */
	var uv5a, uv5b UUID
	uv5a.GenerateV5(Namespace_DNS, "www.fanopassiglia.com")
	time.Sleep(100*time.Millisecond)
	uv5b.GenerateV5(Namespace_DNS, "www.fanopassiglia.com")
	if (uv5a != uv5b) {
		t.Errorf("UUIDs are different: %s - %s\n", uv5a.String(), uv5b.String())
	}
	/* The UUIDs generated from two different names in the same namespace
           should be different (with very high probability). */
	uv5a.GenerateV5(Namespace_DNS, "www.fanopassiglia.com")
	uv5b.GenerateV5(Namespace_DNS, "www.fnopassiglia.com")
	if (uv5a == uv5b) {
		t.Errorf("UUIDs are identical: %s - %s\n", uv5a.String(), uv5b.String())
	}
	/* The UUIDs generated from the same name in two different namespaces
           should be different with (very high probability). */
	uv5a.GenerateV5(Namespace_DNS, "www.fanopassiglia.com")
	uv5b.GenerateV5(Namespace_URL, "www.fanopassiglia.com")
	if (uv5a == uv5b) {
		t.Errorf("UUIDs are identical: %s - %s\n", uv5a.String(), uv5b.String())
	}
}

func TestV4(t *testing.T) {
	var uv4 UUID
	uv4.GenerateV4()
	if uv4.Version() != 4 {
		t.Errorf("Version should be 4, instead is %d\n", uv4.Version())
	}
}

func TestV4Parse(t *testing.T) {
	s := "0f2a8ca7-7ca0-4f43-b71a-d9cb041b890a" // Version 4
	var uv4 UUID
	uv4.Parse(s)
	if (uv4.String() != s) {
		t.Errorf("Parsing of %s returned %s\n", s, uv4.String())
	}
	if uv4.Version() != 4 {
		t.Errorf("Version should be 4, instead is %d\n", uv4.Version())
	}
}

// Generate as many UUID v1 as possible for 1 minute 
// and search for duplicates
func TestV1Collisions(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}

	done :=  make(chan struct{})
	defer close(done)

	// Enough buffering not to block the generators
	uuidch := make(chan UUID, 10000)

	terminator := time.NewTicker(60*time.Second)

	// Increase parallelism
	for i := 0; i < 4; i++ {
		go func() {
			for {
				select {
				case <- done:
					return
				case uuidch <- GenerateV1():
				}
			}
		}()
	}

	m := make(map[UUID]bool)
	cnt := 0
	for u := range uuidch {
		select {
		case <- terminator.C:
			terminator.Stop()
			done <- struct{}{}
			t.Logf("Analyzed %d UUIDs with no collision\n", cnt)
			return
		default:
			if m[u] {
				t.Fatalf("Collision detected with UUID: %s (after %d generated)\n", u.String(), cnt)
				return
			}
			m[u] = true
			cnt++
		}
	}
}

// ---------------------------------------------------------------------------

func BenchmarkV1(b *testing.B) {
	var uv1 UUID
	for i := 0; i < b.N; i++ {
		uv1.GenerateV1()
	}
}

func BenchmarkV3(b *testing.B) {
	var uv3 UUID
	for i := 0; i < b.N; i++ {
		uv3.GenerateV3(Namespace_DNS, "fanopassiglia.com")
	}
}

func BenchmarkV5(b *testing.B) {
	var uv5 UUID
	for i := 0; i < b.N; i++ {
		uv5.GenerateV5(Namespace_DNS, "fanopassiglia.com")
	}
}

func BenchmarkV4(b *testing.B) {
	var uv4 UUID
	for i := 0; i < b.N; i++ {
		uv4.GenerateV4()
	}
}
