package dispatcher

import (
	sync "sync"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
)

type WriterManager struct {
	writers map[string]map[*ManagedWriter]struct{}
	mu      sync.Mutex
}

func (m *WriterManager) AddWriter(writer *ManagedWriter) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.writers[writer.email]; !exists {
		m.writers[writer.email] = make(map[*ManagedWriter]struct{})
	}
	m.writers[writer.email][writer] = struct{}{}
}

func (m *WriterManager) RemoveWriter(writer *ManagedWriter) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.writers[writer.email]; !exists {
		return
	}
	delete(m.writers[writer.email], writer)
}

func (m *WriterManager) RemoveWritersForUser(email string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.writers[email]; !exists {
		return
	}
	for writer := range m.writers[email] {
		delete(m.writers[email], writer)
		common.Close(writer.writer)
	}
	delete(m.writers, email)
}

type ManagedWriter struct {
	writer  buf.Writer
	email   string
	manager *WriterManager
}

func (w *ManagedWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	return w.writer.WriteMultiBuffer(mb)
}

func (w *ManagedWriter) Close() error {
	w.manager.RemoveWriter(w)
	return common.Close(w.writer)
}
