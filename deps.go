package main

// Pins the dependencies the packages share, so parallel work never has to touch go.mod.
// Can go once internal/store and internal/api import them themselves.
import (
	_ "golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)
