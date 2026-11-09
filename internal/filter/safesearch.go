package filter

import "pk95dns/internal/config"

// SafeSearchTarget returns the host a name is rewritten to when SafeSearch is enabled for its
// engine (docs/design.md → SafeSearch). opts.Enabled false → ("", false).
func SafeSearchTarget(name string, opts config.SafeSearch) (string, bool) {
	panic("not implemented")
}
