package parallel

import (
	"context"
	"github.com/sirupsen/logrus"
	"sync"
	"sync/atomic"
	"time"
)

type Pool interface {
	Run(ctx context.Context, job Job)
	Close() error
}

type Job interface {
	Run(ctx context.Context)
}

type Option interface {
	apply(*pool)
}

func NewPool(ctx context.Context, options ...Option) Pool {
	p := &pool{
		ctx:           ctx,
		maxGoroutines: 4,
		notifier:      make(chan struct{}, 1),
	}

	for _, o := range options {
		o.apply(p)
	}

	if p.maxGoroutines <= 0 {
		p.maxGoroutines = 4
	}

	return p
}

type pool struct {
	maxGoroutines int32
	idles         int32
	size          int32

	ctx context.Context

	jobs     jobList
	notifier chan struct{}

	closed int32
}

func (p *pool) Run(ctx context.Context, job Job) {
	if job == nil || atomic.LoadInt32(&p.closed) == 1 {
		return
	}

	p.jobs.enqueue(ctx, job)
	if atomic.LoadInt32(&p.idles) == 0 && atomic.LoadInt32(&p.size) < atomic.LoadInt32(&p.maxGoroutines) {
		atomic.AddInt32(&p.size, 1)
		go p.work()
	}

	select {
	case p.notifier <- struct{}{}:
	default:
	}

	return
}

func (p *pool) Close() error {
	if !atomic.CompareAndSwapInt32(&p.closed, 0, 1) {
		return nil
	}

	close(p.notifier)

	ticker := time.NewTicker(time.Millisecond * 100)
	defer ticker.Stop()

	start := time.Now()

	for {
		if atomic.LoadInt32(&p.size) == 0 {
			logrus.Debugf("All parallel workers have been stopped")
			break
		}

		select {
		case tm := <-ticker.C:
			if tm.Sub(start) > time.Second*10 {
				return nil
			}
		}
	}

	return nil
}

func (p *pool) work() {
	atomic.AddInt32(&p.idles, 1)
	defer atomic.AddInt32(&p.size, -1)

	for {
		select {
		case _, ok := <-p.notifier:
			if !ok {
				return
			}

			atomic.AddInt32(&p.idles, -1)

			for {
				job := p.jobs.dequeue()
				if job == nil {
					break
				}

				if atomic.LoadInt32(&p.closed) == 1 {
					job.cancel()
				}

				job.Run()

				p.jobs.release(job)
			}

			atomic.AddInt32(&p.idles, 1)
		case <-p.ctx.Done():
			return
		}
	}
}

type maxGoroutinesOption int32

func (opt maxGoroutinesOption) apply(p *pool) {
	p.maxGoroutines = int32(opt)
}

func MaxGoroutines(maxGoroutines int) Option {
	return maxGoroutinesOption(maxGoroutines)
}

type jobList struct {
	head *element
	tail *element

	pool sync.Pool

	rwl sync.RWMutex
}

func (jobs *jobList) enqueue(ctx context.Context, job Job) {
	if job == nil {
		return
	}

	elem := jobs.acquire()
	elem.job = job
	elem.ctx, elem.cancel = context.WithCancel(ctx)

	jobs.rwl.Lock()
	if jobs.tail != nil {
		jobs.tail.next = elem
		jobs.tail = elem
	} else {
		jobs.head = elem
		jobs.tail = elem
	}
	jobs.rwl.Unlock()
}

func (jobs *jobList) dequeue() (elem *element) {
	jobs.rwl.Lock()
	if jobs.head != nil {
		elem = jobs.head
		jobs.head = jobs.head.next
		if jobs.head == nil {
			jobs.tail = nil
		}

		elem.next = nil
	}
	jobs.rwl.Unlock()

	return
}

func (jobs *jobList) isEmpty() (empty bool) {
	jobs.rwl.RLock()
	empty = jobs.head == nil
	jobs.rwl.RUnlock()

	return
}

func (jobs *jobList) acquire() *element {
	if elem, ok := jobs.pool.Get().(*element); ok && elem != nil {
		return elem
	}

	return &element{}
}

func (jobs *jobList) release(elem *element) {
	if elem != nil {
		elem.reset()
		jobs.pool.Put(elem)
	}
}

type element struct {
	job  Job
	next *element

	ctx    context.Context
	cancel context.CancelFunc
}

func (elem *element) Run() {
	defer func() {
		elem.cancel()
		if reason := recover(); reason != nil {
			logrus.Debugf("Recover parallel job from execution, %v", reason)
		}
	}()

	elem.job.Run(elem.ctx)
}

func (elem *element) reset() {
	elem.job = nil
	elem.next = nil
	elem.ctx = nil
	elem.cancel = nil
}
