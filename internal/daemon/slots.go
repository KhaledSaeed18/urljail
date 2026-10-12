package daemon

import "sync"

// slots hands out VM slot numbers 0..n-1; a slot fixes the run's TAP name and subnet.
type slots struct {
	mu   sync.Mutex
	used []bool
}

func newSlots(n int) *slots { return &slots{used: make([]bool, n)} }

func (s *slots) size() int { return len(s.used) }

func (s *slots) inUse() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, u := range s.used {
		if u {
			n++
		}
	}
	return n
}

func (s *slots) acquire() (int, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, u := range s.used {
		if !u {
			s.used[i] = true
			return i, true
		}
	}
	return 0, false
}

func (s *slots) release(i int) {
	s.mu.Lock()
	s.used[i] = false
	s.mu.Unlock()
}
