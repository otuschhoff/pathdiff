package store

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"time"

	"github.com/cockroachdb/pebble"
)

type Event struct {
	Inode      uint64    `json:"inode"`
	Path       string    `json:"path"`
	Operation  string    `json:"operation"`
	Timestamp  time.Time `json:"timestamp"`
	Vserver    string    `json:"vserver,omitempty"`
	VolumeUUID string    `json:"volume_uuid,omitempty"`
}

type DB struct {
	db *pebble.DB
}

func Open(path string) (*DB, error) {
	db, err := pebble.Open(path, &pebble.Options{
		MaxConcurrentCompactions: func() int { return 4 },
		L0CompactionThreshold:    2,
	})
	if err != nil {
		return nil, err
	}
	return &DB{db: db}, nil
}

func (d *DB) Close() error {
	return d.db.Close()
}

func timeBytes(t time.Time) []byte {
	buf := make([]byte, 8)
	// Big-endian microseconds preserve chronological order in Pebble's byte sort.
	binary.BigEndian.PutUint64(buf, uint64(t.UnixMicro()))
	return buf
}

func timeKey(t time.Time, inode uint64) []byte {
	key := append([]byte("t:"), timeBytes(t)...)
	key = append(key, ':')
	return append(key, fmt.Sprintf("%d", inode)...)
}

func pathKey(path string, t time.Time) []byte {
	key := append([]byte("p:"), path...)
	key = append(key, ':')
	return append(key, timeBytes(t)...)
}

func pathPrefix(path string) []byte {
	return append([]byte("p:"), path...)
}

func prefixEnd(prefix []byte) []byte {
	end := append([]byte(nil), prefix...)
	for index := len(end) - 1; index >= 0; index-- {
		if end[index] != math.MaxUint8 {
			end[index]++
			return end[:index+1]
		}
	}
	return nil
}

func (d *DB) Store(event Event) error {
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}
	data, err := json.Marshal(event)
	if err != nil {
		return err
	}

	batch := d.db.NewBatch()
	defer batch.Close()
	if err := batch.Set(timeKey(event.Timestamp, event.Inode), data, pebble.NoSync); err != nil {
		return err
	}
	if err := batch.Set(pathKey(event.Path, event.Timestamp), data, pebble.NoSync); err != nil {
		return err
	}
	return batch.Commit(pebble.NoSync)
}

func (d *DB) InodesSince(since time.Time) ([]uint64, error) {
	iter, err := d.db.NewIter(&pebble.IterOptions{
		LowerBound: []byte("t:"),
		UpperBound: []byte("u:"),
	})
	if err != nil {
		return nil, err
	}
	defer iter.Close()

	seek := append(append([]byte("t:"), timeBytes(since)...), ':')
	seen := make(map[uint64]struct{})
	var inodes []uint64
	for iter.SeekGE(seek); iter.Valid(); iter.Next() {
		var event Event
		if err := json.Unmarshal(iter.Value(), &event); err != nil {
			return nil, fmt.Errorf("decode stored event: %w", err)
		}
		if _, exists := seen[event.Inode]; !exists {
			seen[event.Inode] = struct{}{}
			inodes = append(inodes, event.Inode)
		}
	}
	sort.Slice(inodes, func(left, right int) bool { return inodes[left] < inodes[right] })
	return inodes, iter.Error()
}

func (d *DB) EventsSince(since time.Time) ([]Event, error) {
	iter, err := d.db.NewIter(&pebble.IterOptions{
		LowerBound: []byte("t:"),
		UpperBound: []byte("u:"),
	})
	if err != nil {
		return nil, err
	}
	defer iter.Close()

	seek := append(append([]byte("t:"), timeBytes(since)...), ':')
	var events []Event
	for iter.SeekGE(seek); iter.Valid(); iter.Next() {
		var event Event
		if err := json.Unmarshal(iter.Value(), &event); err != nil {
			return nil, fmt.Errorf("decode stored event: %w", err)
		}
		events = append(events, event)
	}
	return events, iter.Error()
}

func (d *DB) EventsByPath(path string, start, end time.Time) ([]Event, error) {
	prefix := pathPrefix(path)
	iter, err := d.db.NewIter(&pebble.IterOptions{
		LowerBound: prefix,
		UpperBound: prefixEnd(prefix),
	})
	if err != nil {
		return nil, err
	}
	defer iter.Close()

	var events []Event
	for iter.First(); iter.Valid() && bytes.HasPrefix(iter.Key(), prefix); iter.Next() {
		var event Event
		if err := json.Unmarshal(iter.Value(), &event); err != nil {
			return nil, fmt.Errorf("decode stored event: %w", err)
		}
		if event.Timestamp.Before(start) || event.Timestamp.After(end) {
			continue
		}
		events = append(events, event)
	}
	return events, iter.Error()
}
