package geo

import "time"

// NewTestUpdater builds an Updater that downloads from base/dbip-country-lite-YYYY-MM.mmdb.gz
// with a fixed clock.
func NewTestUpdater(db *DB, path, base string, now time.Time) *Updater {
	return &Updater{
		DB:   db,
		Path: path,
		now:  func() time.Time { return now },
		url:  func(month string) string { return base + "/dbip-country-lite-" + month + ".mmdb.gz" },
	}
}
