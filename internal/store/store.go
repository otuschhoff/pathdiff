package store

import (
	"bytes"
	cryptorand "crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cockroachdb/pebble"
)

type Event struct {
	Path       string    `json:"path"`
	Operation  string    `json:"operation"`
	Timestamp  time.Time `json:"timestamp"`
	VolumeMSID string    `json:"volume_msid,omitempty"`
	VolumeName string    `json:"volume_name,omitempty"`
	SVMID      string    `json:"svm_id,omitempty"`
	SVMName    string    `json:"svm_name,omitempty"`
	NodeID     string    `json:"node_id,omitempty"`
	LIFIPv4    string    `json:"lif_ipv4,omitempty"`
}

type DB struct {
	db        *pebble.DB
	path      string
	cleanupMu sync.Mutex
	scanSlots chan struct{}
	eventID   [8]byte
	eventSeq  atomic.Uint64
}

var retentionKey = []byte("c:retention")

func Open(path string) (*DB, error) {
	var eventID [8]byte
	if _, err := cryptorand.Read(eventID[:]); err != nil {
		return nil, fmt.Errorf("initialize event key sequence: %w", err)
	}
	db, err := pebble.Open(path, &pebble.Options{
		MaxConcurrentCompactions: func() int { return 4 },
		L0CompactionThreshold:    2,
	})
	if err != nil {
		return nil, err
	}
	return &DB{db: db, path: path, scanSlots: make(chan struct{}, scanQueryLimit(runtime.GOMAXPROCS(0))), eventID: eventID}, nil
}

func scanQueryLimit(processors int) int {
	return max(1, min(4, (processors-1)/2))
}

func (d *DB) beginScan() func() {
	d.scanSlots <- struct{}{}
	return func() { <-d.scanSlots }
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

const eventKeySuffixSize = 18

func (d *DB) nextEventKeySuffix() []byte {
	suffix := make([]byte, eventKeySuffixSize)
	suffix[0] = ':'
	suffix[1] = 0
	copy(suffix[2:10], d.eventID[:])
	binary.BigEndian.PutUint64(suffix[10:], d.eventSeq.Add(1))
	return suffix
}

func eventKeySuffix(key []byte) []byte {
	if len(key) >= eventKeySuffixSize && key[len(key)-eventKeySuffixSize] == ':' && key[len(key)-eventKeySuffixSize+1] == 0 {
		return key[len(key)-eventKeySuffixSize:]
	}
	return nil
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
	event.SVMName = ""
	data, err := json.Marshal(event)
	if err != nil {
		return err
	}

	batch := d.db.NewBatch()
	defer batch.Close()
	suffix := d.nextEventKeySuffix()
	if err := batch.Set(append(timeKey(event.Timestamp, event.Path, event.Operation, event.VolumeMSID), suffix...), data, pebble.NoSync); err != nil {
		return err
	}
	if err := batch.Set(append(pathKey(event.Path, event.Timestamp, event.Operation, event.VolumeMSID), suffix...), data, pebble.NoSync); err != nil {
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

func (d *DB) Retention() (time.Duration, bool, error) {
	value, closer, err := d.db.Get(retentionKey)
	if errors.Is(err, pebble.ErrNotFound) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("read retention policy: %w", err)
	}
	defer closer.Close()
	nanoseconds, err := strconv.ParseInt(string(value), 10, 64)
	if err != nil || nanoseconds <= 0 {
		return 0, false, fmt.Errorf("invalid persisted retention policy %q", value)
	}
	return time.Duration(nanoseconds), true, nil
}

func (d *DB) SetRetention(retention time.Duration) error {
	if retention <= 0 {
		return errors.New("retention duration must be greater than zero")
	}
	return d.db.Set(retentionKey, []byte(strconv.FormatInt(int64(retention), 10)), pebble.Sync)
}

func (d *DB) ApplyRetention(now time.Time) (uint64, error) {
	retention, enabled, err := d.Retention()
	if err != nil || !enabled {
		return 0, err
	}
	return d.DeleteEventsBefore(now.Add(-retention))
}

func (d *DB) DeleteEventsBefore(cutoff time.Time) (uint64, error) {
	d.cleanupMu.Lock()
	defer d.cleanupMu.Unlock()
	upperBound := append([]byte("t:"), timeBytes(cutoff)...)
	iter, err := d.db.NewIter(&pebble.IterOptions{LowerBound: []byte("t:"), UpperBound: upperBound})
	if err != nil {
		return 0, err
	}
	defer iter.Close()
	batch := d.db.NewBatch()
	defer func() { _ = batch.Close() }()
	var deleted uint64
	pending := 0
	flush := func() error {
		if pending == 0 {
			return nil
		}
		if err := batch.Commit(pebble.NoSync); err != nil {
			return err
		}
		if err := batch.Close(); err != nil {
			return err
		}
		batch = d.db.NewBatch()
		pending = 0
		return nil
	}
	for iter.First(); iter.Valid(); iter.Next() {
		var event Event
		if err := json.Unmarshal(iter.Value(), &event); err != nil {
			return deleted, fmt.Errorf("decode expired event: %w", err)
		}
		if err := batch.Delete(iter.Key(), pebble.NoSync); err != nil {
			return deleted, err
		}
		pathIndexKey := append(pathKey(event.Path, event.Timestamp, event.Operation, event.VolumeMSID), eventKeySuffix(iter.Key())...)
		if err := batch.Delete(pathIndexKey, pebble.NoSync); err != nil {
			return deleted, err
		}
		deleted++
		pending++
		if pending == 10000 {
			if err := flush(); err != nil {
				return deleted, err
			}
		}
	}
	if err := iter.Error(); err != nil {
		return deleted, err
	}
	if err := flush(); err != nil {
		return deleted, err
	}
	return deleted, nil
}

func (d *DB) EventCount() (uint64, error) {
	defer d.beginScan()()
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

type Stats struct {
	Path string
	Size uint64
}

type Mapping struct {
	ID   string
	Name string
}

type ParentSummary struct {
	Path       string    `json:"path"`
	Timestamp  time.Time `json:"timestamp"`
	ChildCount uint64    `json:"child_count"`
	VolumeMSID string    `json:"volume_msid,omitempty"`
	VolumeName string    `json:"volume_name,omitempty"`
	SVMID      string    `json:"svm_id,omitempty"`
	SVMName    string    `json:"svm_name,omitempty"`
}

func (d *DB) Stats() (Stats, error) {
	var size uint64
	err := filepath.Walk(d.path, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			size += uint64(info.Size())
		}
		return nil
	})
	if err != nil {
		return Stats{}, err
	}
	return Stats{Path: d.path, Size: size}, nil
}

func (d *DB) ListVolumeMappings() ([]Mapping, error) {
	return d.listMappings("v:")
}

func (d *DB) SetSVMName(id, name string) error {
	if id == "" {
		return fmt.Errorf("SVM ID is required")
	}
	if name == "" {
		return fmt.Errorf("SVM name is required")
	}
	return d.db.Set(append([]byte("s:"), id...), []byte(name), pebble.NoSync)
}

func (d *DB) SetVolumeSVMName(msid, name string) error {
	if msid == "" {
		return fmt.Errorf("volume MSID is required")
	}
	if name == "" {
		return fmt.Errorf("SVM name is required")
	}
	return d.db.Set(append([]byte("w:"), msid...), []byte(name), pebble.NoSync)
}

func (d *DB) CacheParentMappings(summaries []ParentSummary) error {
	batch := d.db.NewBatch()
	defer batch.Close()
	for _, summary := range summaries {
		if summary.VolumeMSID != "" && summary.VolumeName != "" {
			if err := batch.Set(append([]byte("v:"), summary.VolumeMSID...), []byte(summary.VolumeName), pebble.NoSync); err != nil {
				return err
			}
		}
		if summary.VolumeMSID != "" && summary.SVMName != "" {
			if err := batch.Set(append([]byte("w:"), summary.VolumeMSID...), []byte(summary.SVMName), pebble.NoSync); err != nil {
				return err
			}
		}
		if summary.SVMID != "" && summary.SVMName != "" {
			if err := batch.Set(append([]byte("s:"), summary.SVMID...), []byte(summary.SVMName), pebble.NoSync); err != nil {
				return err
			}
		}
	}
	return batch.Commit(pebble.NoSync)
}

func (d *DB) MarkFPolicyLIFUnreachable(svm, lif, address string) error {
	if svm == "" || lif == "" || address == "" {
		return errors.New("SVM, LIF, and address are required")
	}
	return d.db.Set([]byte("r:"+svm+"\x00"+lif), []byte(address), pebble.NoSync)
}

func (d *DB) FPolicyLIFUnreachable(svm, lif, address string) (bool, error) {
	value, closer, err := d.db.Get([]byte("r:" + svm + "\x00" + lif))
	if errors.Is(err, pebble.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("look up unreachable FPolicy LIF: %w", err)
	}
	defer closer.Close()
	return string(value) == address, nil
}

func (d *DB) ListSVMMappings() ([]Mapping, error) {
	return d.listMappings("s:")
}

func (d *DB) listMappings(prefix string) ([]Mapping, error) {
	prefixBytes := []byte(prefix)
	iter, err := d.db.NewIter(&pebble.IterOptions{LowerBound: prefixBytes, UpperBound: prefixEnd(prefixBytes)})
	if err != nil {
		return nil, err
	}
	defer iter.Close()
	var mappings []Mapping
	for iter.First(); iter.Valid() && bytes.HasPrefix(iter.Key(), prefixBytes); iter.Next() {
		mappings = append(mappings, Mapping{ID: string(iter.Key()[len(prefixBytes):]), Name: string(iter.Value())})
	}
	return mappings, iter.Error()
}

func (d *DB) EventsSince(since time.Time) ([]Event, error) {
	defer d.beginScan()()
	volumeNames, svmNames, err := d.eventMappingNames()
	if err != nil {
		return nil, err
	}
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
		event.VolumeName = volumeNames[event.VolumeMSID]
		event.SVMName = svmNames[event.SVMID]
		events = append(events, event)
	}
	return events, iter.Error()
}

func (d *DB) EventsByPath(path string, start, end time.Time) ([]Event, error) {
	defer d.beginScan()()
	volumeNames, svmNames, err := d.eventMappingNames()
	if err != nil {
		return nil, err
	}
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
		event.VolumeName = volumeNames[event.VolumeMSID]
		event.SVMName = svmNames[event.SVMID]
		events = append(events, event)
	}
	return events, iter.Error()
}

func (d *DB) ParentSummariesByPath(path, wildcard string, start, end time.Time) ([]ParentSummary, error) {
	defer d.beginScan()()
	matcher, err := compilePathWildcard(wildcard)
	if err != nil {
		return nil, err
	}
	volumeNames, err := d.mappingNames("v:")
	if err != nil {
		return nil, err
	}
	svmNames, err := d.mappingNames("s:")
	if err != nil {
		return nil, err
	}
	volumeSVMNames, err := d.mappingNames("w:")
	if err != nil {
		return nil, err
	}
	prefix := pathPrefix(path)
	iter, err := d.db.NewIter(&pebble.IterOptions{LowerBound: prefix, UpperBound: prefixEnd(prefix)})
	if err != nil {
		return nil, err
	}
	defer iter.Close()

	type parentKey struct {
		path, volumeMSID string
	}
	parents := make(map[parentKey]*ParentSummary)
	svmIDsByVolume := make(map[string]string)
	seenForChild := make(map[parentKey]struct{})
	var previousChild, previousVolume []byte
	parent := ""
	matched := false
	volumeMSID := ""
	for iter.First(); iter.Valid() && bytes.HasPrefix(iter.Key(), prefix); iter.Next() {
		childPath, timestamp, volumeID, err := decodePathIndexKey(iter.Key())
		if err != nil {
			return nil, err
		}
		if timestamp.Before(start) || timestamp.After(end) {
			continue
		}
		if !bytes.Equal(childPath, previousChild) {
			previousChild = append(previousChild[:0], childPath...)
			previousVolume = previousVolume[:0]
			parent = filepath.Dir(string(childPath))
			matched = matcher.MatchString(parent)
			clear(seenForChild)
		}
		if !matched {
			continue
		}
		if !bytes.Equal(volumeID, previousVolume) {
			previousVolume = append(previousVolume[:0], volumeID...)
			volumeMSID = string(volumeID)
		}
		key := parentKey{path: parent, volumeMSID: volumeMSID}
		svmID := svmIDsByVolume[volumeMSID]
		if svmID == "" {
			if encoded := eventJSONString(iter.Value(), []byte(`"svm_id":"`)); len(encoded) > 0 {
				svmID = string(encoded)
				svmIDsByVolume[volumeMSID] = svmID
			}
		}
		summary := parents[key]
		if summary == nil {
			svmName := svmNames[svmID]
			if svmName == "" {
				svmName = volumeSVMNames[volumeMSID]
			}
			summary = &ParentSummary{Path: parent, VolumeMSID: volumeMSID, VolumeName: volumeNames[volumeMSID], SVMID: svmID, SVMName: svmName}
			parents[key] = summary
		} else if summary.SVMID == "" && svmID != "" {
			summary.SVMID = svmID
			if name := svmNames[svmID]; name != "" {
				summary.SVMName = name
			}
		}
		if timestamp.After(summary.Timestamp) {
			summary.Timestamp = timestamp
		}
		if _, seen := seenForChild[key]; !seen {
			summary.ChildCount++
			seenForChild[key] = struct{}{}
		}
	}
	if err := iter.Error(); err != nil {
		return nil, err
	}
	summaries := make([]ParentSummary, 0, len(parents))
	cacheNeeded := false
	for _, summary := range parents {
		summaries = append(summaries, *summary)
		if summary.SVMID != "" && summary.SVMName != "" && svmNames[summary.SVMID] == "" {
			cacheNeeded = true
		}
	}
	if cacheNeeded {
		if err := d.CacheParentMappings(summaries); err != nil {
			return nil, err
		}
	}
	return summaries, nil
}

func eventJSONString(data, prefix []byte) []byte {
	start := bytes.Index(data, prefix)
	if start < 0 {
		return nil
	}
	start += len(prefix)
	end := bytes.IndexByte(data[start:], '"')
	if end < 0 {
		return nil
	}
	return data[start : start+end]
}

func decodePathIndexKey(key []byte) ([]byte, time.Time, []byte, error) {
	if len(key) < 14 || !bytes.HasPrefix(key, []byte("p:")) {
		return nil, time.Time{}, nil, fmt.Errorf("invalid path index key")
	}
	if suffix := eventKeySuffix(key); suffix != nil {
		key = key[:len(key)-len(suffix)]
	}
	volumeSeparator := bytes.LastIndexByte(key, ':')
	if volumeSeparator < 0 {
		return nil, time.Time{}, nil, fmt.Errorf("invalid path index key")
	}
	operationSeparator := bytes.LastIndexByte(key[:volumeSeparator], ':')
	pathSeparator := operationSeparator - 9
	if operationSeparator < 0 || pathSeparator < 2 || key[pathSeparator] != ':' {
		return nil, time.Time{}, nil, fmt.Errorf("invalid path index key")
	}
	timestamp := time.UnixMicro(int64(binary.BigEndian.Uint64(key[pathSeparator+1 : operationSeparator]))).UTC()
	return key[2:pathSeparator], timestamp, key[volumeSeparator+1:], nil
}

func compilePathWildcard(pattern string) (*regexp.Regexp, error) {
	var expression strings.Builder
	expression.WriteString("(?i)^")
	for _, character := range pattern {
		switch character {
		case '*':
			expression.WriteString(".*")
		case '?':
			expression.WriteByte('.')
		default:
			expression.WriteString(regexp.QuoteMeta(string(character)))
		}
	}
	expression.WriteString("$")
	matcher, err := regexp.Compile(expression.String())
	if err != nil {
		return nil, fmt.Errorf("invalid path wildcard %q: %w", pattern, err)
	}
	return matcher, nil
}

func (d *DB) mappingNames(prefix string) (map[string]string, error) {
	mappings, err := d.listMappings(prefix)
	if err != nil {
		return nil, err
	}
	names := make(map[string]string, len(mappings))
	for _, mapping := range mappings {
		names[mapping.ID] = mapping.Name
	}
	return names, nil
}

func (d *DB) eventMappingNames() (map[string]string, map[string]string, error) {
	volumeNames, err := d.mappingNames("v:")
	if err != nil {
		return nil, nil, err
	}
	svmNames, err := d.mappingNames("s:")
	if err != nil {
		return nil, nil, err
	}
	return volumeNames, svmNames, nil
}
