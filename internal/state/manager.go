package state

import (
	"context"
	"fmt"
	"sync"

	"vertica-mcp-server/pkg/models"
)

// ContextType represents the type of state context
type ContextType string

const (
	// SampleContext is for user-driven sample YAML generation
	SampleContext ContextType = "sample"
	// InspectContext is for database inspection
	InspectContext ContextType = "inspect"
)

// contextKey is a private type for context keys
type contextKey string

const (
	stateContextKey contextKey = "stateContext"
)

// State represents the YAML generation state
type State struct {
	YamlState models.VerticaDB
	Kobjs     models.KObjs
	mu        sync.RWMutex
}

// Manager manages multiple state contexts safely
type Manager struct {
	states map[ContextType]*State
	mu     sync.RWMutex
}

// NewManager creates a new state manager
func NewManager() *Manager {
	return &Manager{
		states: make(map[ContextType]*State),
	}
}

// GetOrCreate returns the state for a context, creating it if it doesn't exist
func (m *Manager) GetOrCreate(ctx ContextType) *State {
	m.mu.RLock()
	state, exists := m.states[ctx]
	m.mu.RUnlock()

	if exists {
		return state
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Double-check after acquiring write lock
	if state, exists := m.states[ctx]; exists {
		return state
	}

	state = &State{
		YamlState: models.VerticaDB{},
		Kobjs:     models.KObjs{},
	}
	m.states[ctx] = state
	return state
}

// Get returns the state for a context
func (m *Manager) Get(ctx ContextType) (*State, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	state, exists := m.states[ctx]
	if !exists {
		return nil, fmt.Errorf("state not found for context: %s", ctx)
	}
	return state, nil
}

// Delete removes the state for a context
func (m *Manager) Delete(ctx ContextType) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.states, ctx)
}

// GetYamlState returns a copy of the YAML state (thread-safe read)
func (s *State) GetYamlState() models.VerticaDB {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.YamlState
}

// SetYamlState updates the YAML state (thread-safe write)
func (s *State) SetYamlState(yamlState models.VerticaDB) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.YamlState = yamlState
}

// UpdateYamlState updates the YAML state using a function (thread-safe)
func (s *State) UpdateYamlState(fn func(*models.VerticaDB)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(&s.YamlState)
}

// GetKobjs returns a copy of the Kobjs (thread-safe read)
func (s *State) GetKobjs() models.KObjs {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.Kobjs
}

// SetKobjs updates the Kobjs (thread-safe write)
func (s *State) SetKobjs(kobjs models.KObjs) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Kobjs = kobjs
}

// UpdateKobjs updates the Kobjs using a function (thread-safe)
func (s *State) UpdateKobjs(fn func(*models.KObjs)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(&s.Kobjs)
}

// WithContext adds the state context type to a Go context
func WithContext(ctx context.Context, ctxType ContextType) context.Context {
	return context.WithValue(ctx, stateContextKey, ctxType)
}

// FromContext extracts the state context type from a Go context
func FromContext(ctx context.Context) (ContextType, bool) {
	ctxType, ok := ctx.Value(stateContextKey).(ContextType)
	return ctxType, ok
}
