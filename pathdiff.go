// Package pathdiff receives, stores, and queries ONTAP FPolicy path-change events.
//
// A Receiver may be embedded in a Go process and queried through its Database.
// A Client queries a Receiver running in another process through its control socket.
package pathdiff

import (
	"time"

	"github.com/otuschhoff/pathdiff/internal/store"
)

// Event is a persisted FPolicy path-change notification.
type Event = store.Event

// ParentSummary aggregates changed child paths by parent directory and volume.
type ParentSummary = store.ParentSummary

// Mapping associates an ONTAP object ID with its display name.
type Mapping = store.Mapping

// DatabaseStats describes the database's path and on-disk size.
type DatabaseStats = store.Stats

// FPolicyActivation is the persisted activation backoff for one SVM policy.
type FPolicyActivation = store.FPolicyActivation

// ListenerSnapshot is the last persisted receiver endpoint configuration.
type ListenerSnapshot = store.ListenerSnapshot

// Sender is the last known state of one FPolicy sender.
type Sender = store.Sender

// Database provides direct, concurrency-safe access to pathdiff's event store.
type Database struct {
	store *store.DB
}

// OpenDatabase opens or creates a pathdiff database.
func OpenDatabase(path string) (*Database, error) {
	database, err := store.Open(path)
	if err != nil {
		return nil, err
	}
	return &Database{store: database}, nil
}

func wrapDatabase(database *store.DB) *Database {
	return &Database{store: database}
}

// Close flushes and closes the database.
func (d *Database) Close() error { return d.store.Close() }

// Store persists an event atomically in the chronological and path indexes.
func (d *Database) Store(event Event) error { return d.store.Store(event) }

// EventCount returns the number of persisted events.
func (d *Database) EventCount() (uint64, error) { return d.store.EventCount() }

// Stats returns the database path and current on-disk size.
func (d *Database) Stats() (DatabaseStats, error) { return d.store.Stats() }

// EventsSince returns events at or after since in chronological order.
func (d *Database) EventsSince(since time.Time) ([]Event, error) {
	return d.store.EventsSince(since)
}

// EventsByPath returns events below path in the inclusive time range.
func (d *Database) EventsByPath(path string, start, end time.Time) ([]Event, error) {
	return d.store.EventsByPath(path, start, end)
}

// ParentSummariesByPath aggregates matching parent directories in the inclusive time range.
func (d *Database) ParentSummariesByPath(path, wildcard string, start, end time.Time) ([]ParentSummary, error) {
	return d.store.ParentSummariesByPath(path, wildcard, start, end)
}

// ResetEvents atomically removes event indexes while preserving mappings.
func (d *Database) ResetEvents() error { return d.store.ResetEvents() }

// Retention returns the persisted retention duration and whether it is enabled.
func (d *Database) Retention() (time.Duration, bool, error) { return d.store.Retention() }

// SetRetention persists an event retention duration.
func (d *Database) SetRetention(retention time.Duration) error {
	return d.store.SetRetention(retention)
}

// ApplyRetention removes events older than the configured retention duration.
func (d *Database) ApplyRetention(now time.Time) (uint64, error) {
	return d.store.ApplyRetention(now)
}

// DeleteEventsBefore removes events older than cutoff from both indexes.
func (d *Database) DeleteEventsBefore(cutoff time.Time) (uint64, error) {
	return d.store.DeleteEventsBefore(cutoff)
}

// SetVolumeName persists a volume MSID-to-name mapping.
func (d *Database) SetVolumeName(msid, name string) error {
	return d.store.SetVolumeName(msid, name)
}

// SetSVMName persists an SVM ID-to-name mapping.
func (d *Database) SetSVMName(id, name string) error { return d.store.SetSVMName(id, name) }

// SetVolumeSVMName persists a volume MSID-to-SVM-name mapping.
func (d *Database) SetVolumeSVMName(msid, name string) error {
	return d.store.SetVolumeSVMName(msid, name)
}

// ListVolumeMappings returns persisted volume mappings.
func (d *Database) ListVolumeMappings() ([]Mapping, error) {
	return d.store.ListVolumeMappings()
}

// ListSVMMappings returns persisted SVM mappings.
func (d *Database) ListSVMMappings() ([]Mapping, error) {
	return d.store.ListSVMMappings()
}

// CacheParentMappings persists names present in parent summaries.
func (d *Database) CacheParentMappings(summaries []ParentSummary) error {
	return d.store.CacheParentMappings(summaries)
}

// FPolicyLIFUnreachable reports whether a LIF address was previously marked unreachable.
func (d *Database) FPolicyLIFUnreachable(svm, lif, address string) (bool, error) {
	return d.store.FPolicyLIFUnreachable(svm, lif, address)
}

// MarkFPolicyLIFUnreachable persists an unreachable LIF address.
func (d *Database) MarkFPolicyLIFUnreachable(svm, lif, address string) error {
	return d.store.MarkFPolicyLIFUnreachable(svm, lif, address)
}

// FPolicyActivation returns the persisted activation backoff for a policy.
func (d *Database) FPolicyActivation(svm, policy string) (FPolicyActivation, error) {
	return d.store.FPolicyActivation(svm, policy)
}

// SetFPolicyActivation persists activation backoff so it survives restarts.
func (d *Database) SetFPolicyActivation(svm, policy string, activation FPolicyActivation) error {
	return d.store.SetFPolicyActivation(svm, policy, activation)
}

// ClearFPolicyActivation removes persisted activation backoff after success.
func (d *Database) ClearFPolicyActivation(svm, policy string) error {
	return d.store.ClearFPolicyActivation(svm, policy)
}

// ListenerSnapshot returns the last persisted receiver endpoint configuration.
func (d *Database) ListenerSnapshot() (ListenerSnapshot, error) {
	return d.store.ListenerSnapshot()
}

// SetListenerSnapshot persists the current receiver endpoint configuration.
func (d *Database) SetListenerSnapshot(snapshot ListenerSnapshot) error {
	return d.store.SetListenerSnapshot(snapshot)
}

// Sender returns the last known state of one FPolicy sender.
func (d *Database) Sender(lifIPv4 string) (Sender, error) {
	return d.store.Sender(lifIPv4)
}

// Senders returns the last known state of every observed FPolicy sender.
func (d *Database) Senders() ([]Sender, error) {
	return d.store.Senders()
}

// SetSender persists the last known state of one FPolicy sender.
func (d *Database) SetSender(sender Sender) error {
	return d.store.SetSender(sender)
}
