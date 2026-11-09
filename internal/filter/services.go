package filter

// Service is one entry of the blocked services catalog.
type Service struct {
	ID    string   `json:"id"`
	Name  string   `json:"name"`
	Group string   `json:"group"` // social, messenger, video, music, gaming, shopping, ai, other
	Rules []string `json:"-"`     // "||domain^" rules
}

// Services returns the catalog, ordered by group then name (docs/design.md → Blocked services).
func Services() []Service {
	panic("not implemented")
}

// KnownService reports whether id is in the catalog.
func KnownService(id string) bool {
	panic("not implemented")
}
