package geo

import (
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// Like PK95 Proxy: DB-IP publishes monthly; a database older than a month is replaced, and
// a failed download is only retried after a pause.
const (
	MaxAge     = 32 * 24 * time.Hour
	RetryAfter = 6 * time.Hour
	maxSize    = 256 << 20 // decompressed; the country file is a few MiB
)

// Updater keeps the database file at Path current and loads it into DB.
type Updater struct {
	DB        *DB
	Path      string
	UserAgent string
	HTTP      *http.Client // nil: 5 minute timeout

	// replaced in tests
	now     func() time.Time
	url     func(month string) string
	every   time.Duration
	lastTry time.Time
}

func (u *Updater) clock() time.Time {
	if u.now != nil {
		return u.now()
	}
	return time.Now()
}

func (u *Updater) monthURL(month string) string {
	if u.url != nil {
		return u.url(month)
	}
	return "https://download.db-ip.com/free/dbip-country-lite-" + month + ".mmdb.gz"
}

// Due reports whether a download should be tried now: the file is missing or older than
// MaxAge, and the last attempt is longer than RetryAfter ago (as geoipDue in PK95 Proxy).
func Due(path string, lastTry, now time.Time) bool {
	if !lastTry.IsZero() && now.Sub(lastTry) < RetryAfter {
		return false
	}
	fi, err := os.Stat(path)
	return err != nil || now.Sub(fi.ModTime()) > MaxAge
}

// Run loads the existing file, then checks every hour (and right away) whether a new one is
// due, until ctx is done. A file that cannot be loaded is downloaded again.
func (u *Updater) Run(ctx context.Context) {
	if _, err := os.Stat(u.Path); err == nil {
		if err := u.DB.Load(u.Path); err != nil {
			log.Printf("GeoIP-Datenbank unbrauchbar, lade neu: %v", err)
			_ = os.Remove(u.Path)
		}
	}
	every := u.every
	if every <= 0 {
		every = time.Hour
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		if now := u.clock(); Due(u.Path, u.lastTry, now) {
			u.lastTry = now
			if err := u.Update(ctx); err != nil && ctx.Err() == nil {
				log.Printf("GeoIP-Datenbank nicht geladen (nächster Versuch in %s): %v", RetryAfter, err)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Update downloads the file of the current month (it appears during the first days of a
// month, so the previous month is tried as well), checks it and loads it.
func (u *Updater) Update(ctx context.Context) error {
	now := u.clock().UTC()
	var errs []error
	for _, month := range []string{now.Format("2006-01"), now.AddDate(0, -1, 0).Format("2006-01")} {
		err := u.fetch(ctx, u.monthURL(month))
		if err == nil {
			log.Printf("GeoIP-Datenbank %s geladen (%s)", month, u.DB.Date())
			return nil
		}
		errs = append(errs, fmt.Errorf("%s: %w", month, err))
		if ctx.Err() != nil {
			break
		}
	}
	return errors.Join(errs...)
}

func (u *Updater) fetch(ctx context.Context, url string) error {
	client := u.HTTP
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Minute}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	if u.UserAgent != "" {
		req.Header.Set("User-Agent", u.UserAgent)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	zr, err := gzip.NewReader(resp.Body)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(u.Path), 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(u.Path), ".geoip-*.mmdb")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	n, err := io.Copy(tmp, io.LimitReader(zr, maxSize+1))
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if n == 0 || n > maxSize {
		return fmt.Errorf("unerwartete Größe (%d Bytes)", n)
	}
	// Load from the temporary file first: a broken download never replaces a good one.
	probe := &DB{}
	if err := probe.Load(tmp.Name()); err != nil {
		return fmt.Errorf("Datei ungültig: %w", err)
	}
	probe.cur.Load().r.Close()
	if err := os.Rename(tmp.Name(), u.Path); err != nil {
		return err
	}
	return u.DB.Load(u.Path)
}
