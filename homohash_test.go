package homohash

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"github.com/klauspost/reedsolomon"
	"testing"
)

const (
	dataShards   = 10
	parityShards = 3
)

func TestHomo(t *testing.T) {
	data := make([]byte, 1000)
	_, err := rand.Read(data)
	if err != nil {
		t.Fatal(err)
	}

	enc, err := reedsolomon.New(dataShards, parityShards)
	if err != nil {
		t.Fatal(err)
	}

	shards, err := enc.Split(data)
	if err != nil {
		t.Fatal(err)
	}

	ho := New()
	//
	homohashes := make([][]byte, len(shards))
	for i, shard := range shards {
		ho.Reset()
		homohashes[i] = make([]byte, 32)
		ho.Write(shard)
		copy(homohashes[i], ho.Sum(nil))
	}

	err = enc.Encode(homohashes)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("Homohashes:")
	for _, hash := range homohashes {
		fmt.Print(hash, " ")
	}
	fmt.Println()

	err = enc.Encode(shards)
	hashes := make([][]byte, len(shards))
	fmt.Println("Hashes:")
	for i, shard := range shards {
		ho.Reset()
		hashes[i] = make([]byte, 32)
		ho.Write(shard)
		copy(hashes[i], ho.Sum(nil))
		fmt.Print(hashes[i], " ")
	}
	fmt.Println()

	for i := 0; i < len(hashes); i++ {
		if bytes.Compare(hashes[i], homohashes[i]) != 0 {
			t.Fatal("Hash is not homo!")
		}
	}
}
