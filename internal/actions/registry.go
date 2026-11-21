package actions

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Registry is the loaded, linted action vocabulary.
type Registry struct {
	cards map[string]Card // by id
	order []string        // stable iteration order
}

// Filter selects candidate cards for a planner turn.
type Filter struct {
	Adapter string // lib | proc | vm ("" = any)
	Phase   string // preconditions.phase ("" = any)
}

// LoadRegistry walks root for *.card.json files, lints every card, and
// indexes them by id. Any lint failure or duplicate id is an error — the
// registry refuses to come up partially valid (fail-closed).
func LoadRegistry(root string) (*Registry, error) {
	r := &Registry{cards: map[string]Card{}}
	if _, err := os.Stat(root); err != nil {
		return nil, fmt.Errorf("registry: stat %s: %w", root, err)
	}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".card.json") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("registry: read %s: %w", path, err)
		}
		var c Card
		if err := json.Unmarshal(b, &c); err != nil {
			return fmt.Errorf("registry: parse %s: %w", path, err)
		}
		if err := c.Lint(); err != nil {
			return fmt.Errorf("registry: %s: %w", path, err)
		}
		if _, dup := r.cards[c.ID]; dup {
			return fmt.Errorf("registry: duplicate card id %q (%s)", c.ID, path)
		}
		r.cards[c.ID] = c
		r.order = append(r.order, c.ID)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(r.order)
	return r, nil
}

// Get returns the card by id. ok=false means unknown id — callers treat it
// as a hallucinated proposal (design §5.6).
func (r *Registry) Get(id string) (Card, bool) {
	c, ok := r.cards[id]
	return c, ok
}

// Candidates returns cards matching the filter, in stable id order.
func (r *Registry) Candidates(f Filter) []Card {
	var out []Card
	for _, id := range r.order {
		c := r.cards[id]
		if f.Adapter != "" && c.Executor.Adapter != f.Adapter {
			continue
		}
		if f.Phase != "" && c.Preconditions.Phase != f.Phase {
			continue
		}
		out = append(out, c)
	}
	return out
}

// Count returns the number of loaded cards.
func (r *Registry) Count() int { return len(r.cards) }
