package store

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/cockroachdb/pebble"
)

type Event struct {
	Path       string    `json:"path"`
	Operation  string    `json:"operation"`
	Timestamp  time.Time `json:"timestamp"`
	VolumeMSID string    `json:"volume_msid,omitempty"`
	VolumeName string    `json:"volume_name,omitempty"`
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

func timeKey(t time.Time, path, operation, volumeMSID string) []byte {
	key := append([]byte("t:"), timeBytes(t)...)
	key = append(key, ':')
	key = append(key, path...)
	key = append(key, ':')
	key = append(key, operation...)
	key = append(key, ':')
	return append(key, volumeMSID...)
}

func pathKey(path string, t time.Time, operation, volumeMSID string) []byte {
	key := append([]byte("p:"), path...)
	key = append(key, ':')
	key = append(key, timeBytes(t)...)
	key = append(key, ':')
	key = append(key, operation...)
	key = append(key, ':')
	return append(key, volumeMSID...)
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
	event.VolumeName = ""
	data, err := json.Marshal(event)
	if err != nil {
		return err
	}

	batch := d.db.NewBatch()
	defer batch.Close()
	if err := batch.Set(timeKey(event.Timestamp, event.Path, event.Operation, event.VolumeMSID), data, pebble.NoSync); err != nil {
		return err
	}
	if err := batch.Set(pathKey(event.Path, event.Timestamp, event.Operation, event.VolumeMSID), data, pebble.NoSync); err != nil {
		return err
	}
	return batch.Commit(pebble.NoSync)
}

func (d *DB) SetVolumeName(msid, name string) error {
	if msid == "" {
		return fmt.Errorf("volume MSID is required")
	}
	if name == "" {
		return fmt.Errorf("volume name is required")
	}
	return d.db.Set(append([]byte("v:"), msid...), []byte(name), pebble.NoSync)
}

// ResetEvents atomically removes time and path index entries without removing volume mappings.
func (d *DB) ResetEvents() error {
	batch := d.db.NewBatch()
	defer batch.Close()
	if err := batch.DeleteRange([]byte("t:"), []byte("u:"), pebble.NoSync); err != nil {
		return err
	}
	if err := batch.DeleteRange([]byte("p:"), []byte("q:"), pebble.NoSync); err != nil {
		return err
	}
	return batch.Commit(pebble.NoSync)
}

func (d *DB) EventCount() (uint64, error) {
	iter, err := d.db.NewIter(&pebble.IterOptions{LowerBound: []byte("t:"), UpperBound: []byte("u:")})
	if err != nil {
		return 0, err
	}
	defer iter.Close()
	var count uint64
	for iter.First(); iter.Valid(); iter.Next() {
		count++
	}
	return count, iter.Error()
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
		if err := d.resolveVolumeName(&event); err != nil {
			return nil, err
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
		if err := d.resolveVolumeName(&event); err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	return events, iter.Error()
}

func (d *DB) resolveVolumeName(event *Event) error {
	if event.VolumeMSID == "" {
		return nil
	}
	name, closer, err := d.db.Get(append([]byte("v:"), event.VolumeMSID...))
	if errors.Is(err, pebble.ErrNotFound) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("look up volume name: %w", err)
	}
	defer closer.Close()
	event.VolumeName = string(name)
	return nil
}
