package crawler

import (
	"sync"
)

// URLQueue manages the queue of URLs to be crawled
type URLQueue struct {
	queue        []string
	visited      map[string]bool
	mutex        sync.Mutex
	cond         *sync.Cond
	maxQueueSize int
	closed       bool
}

// NewURLQueue creates a new URL queue
func NewURLQueue(maxSize int) *URLQueue {
	q := &URLQueue{
		queue:        make([]string, 0, maxSize),
		visited:      make(map[string]bool),
		maxQueueSize: maxSize,
	}
	q.cond = sync.NewCond(&q.mutex)
	return q
}

// Push adds a URL to the queue if not already visited
func (q *URLQueue) Push(url string) bool {
	q.mutex.Lock()
	defer q.mutex.Unlock()

	if q.closed {
		return false
	}

	// Check if already visited
	if _, ok := q.visited[url]; ok {
		return false
	}

	// Check if queue is full
	if len(q.queue) >= q.maxQueueSize {
		return false
	}

	// Add to queue and mark as visited
	q.queue = append(q.queue, url)
	q.visited[url] = true

	// Signal waiting consumers
	q.cond.Signal()

	return true
}

// Pop removes and returns a URL from the queue
// If the queue is empty, it blocks until a URL is available or the queue is closed
func (q *URLQueue) Pop() (string, bool) {
	q.mutex.Lock()
	defer q.mutex.Unlock()

	// Wait for an item or for the queue to be closed
	for len(q.queue) == 0 && !q.closed {
		q.cond.Wait()
	}

	// If the queue is closed and empty, return
	if len(q.queue) == 0 {
		return "", false
	}

	// Get the next URL
	url := q.queue[0]
	q.queue = q.queue[1:]

	return url, true
}

// Close closes the queue
func (q *URLQueue) Close() {
	q.mutex.Lock()
	q.closed = true
	q.mutex.Unlock()

	// Wake up all waiting consumers
	q.cond.Broadcast()
}

// Size returns the current size of the queue
func (q *URLQueue) Size() int {
	q.mutex.Lock()
	defer q.mutex.Unlock()
	return len(q.queue)
}

// VisitedCount returns the number of unique URLs visited
func (q *URLQueue) VisitedCount() int {
	q.mutex.Lock()
	defer q.mutex.Unlock()
	return len(q.visited)
}
