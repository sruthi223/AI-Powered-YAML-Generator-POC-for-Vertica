package jobs

import (
	"sync"
	"time"
)

// Status represents job execution status
type Status string

const (
	StatusAccepted  Status = "accepted"
	StatusRunning   Status = "running"
	StatusComplete  Status = "complete"
	StatusFailed    Status = "failed"
)

// Job represents a background job
type Job struct {
	ID          string                 `json:"request_id"`
	Status      Status                 `json:"status"`
	Message     string                 `json:"message,omitempty"`
	Progress    map[string]interface{} `json:"progress,omitempty"`
	Result      interface{}            `json:"result,omitempty"`
	Error       string                 `json:"error,omitempty"`
	CreatedAt   time.Time              `json:"created_at"`
	CompletedAt *time.Time             `json:"completed_at,omitempty"`
}

// Manager manages background jobs
type Manager struct {
	jobs map[string]*Job
	mu   sync.RWMutex
}

// NewManager creates a new job manager
func NewManager() *Manager {
	return &Manager{
		jobs: make(map[string]*Job),
	}
}

// Create creates a new job
func (m *Manager) Create(id, message string) *Job {
	m.mu.Lock()
	defer m.mu.Unlock()

	job := &Job{
		ID:        id,
		Status:    StatusAccepted,
		Message:   message,
		CreatedAt: time.Now(),
	}
	m.jobs[id] = job
	return job
}

// UpdateProgress updates job progress
func (m *Manager) UpdateProgress(id string, progress map[string]interface{}) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if job, exists := m.jobs[id]; exists {
		job.Status = StatusRunning
		job.Progress = progress
	}
}

// Complete marks job as complete
func (m *Manager) Complete(id string, result interface{}) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if job, exists := m.jobs[id]; exists {
		now := time.Now()
		job.Status = StatusComplete
		job.Result = result
		job.CompletedAt = &now
	}
}

// Fail marks job as failed
func (m *Manager) Fail(id string, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if job, exists := m.jobs[id]; exists {
		now := time.Now()
		job.Status = StatusFailed
		job.Error = err.Error()
		job.CompletedAt = &now
	}
}

// Get retrieves a job
func (m *Manager) Get(id string) (*Job, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	job, exists := m.jobs[id]
	return job, exists
}

// Cleanup removes old jobs (older than 1 hour)
func (m *Manager) Cleanup() {
	m.mu.Lock()
	defer m.mu.Unlock()

	cutoff := time.Now().Add(-1 * time.Hour)
	for id, job := range m.jobs {
		if job.CompletedAt != nil && job.CompletedAt.Before(cutoff) {
			delete(m.jobs, id)
		}
	}
}
