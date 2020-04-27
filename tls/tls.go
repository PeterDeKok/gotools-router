package tls

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"github.com/fsnotify/fsnotify"
	"path/filepath"
	"peterdekok.nl/gotools/logger"
	"sync"
	"time"
)

type Watcher struct {
	mux sync.RWMutex

	certFile string
	keyFile  string

	cert      *tls.Certificate
	NotAfter  time.Time
	NotBefore time.Time

	watcher *fsnotify.Watcher
	wg      sync.WaitGroup

	TLSConfig *tls.Config
}

var (
	log logger.Logger

	ErrNoCert        = errors.New("no certificate found")
	ErrInvalidCert   = errors.New("certificate invalid")
	ErrFailedWatcher = errors.New("failed to create file watcher")
)

func init() {
	log = logger.New("router.tls")
}

func NewWatcher(certFile, keyFile string) (watcher *Watcher, err error) {
	certFile, err = filepath.Abs(certFile)

	if err != nil {
		log.WithError(err).Error("Failed to compute cert file path")

		return nil, err
	}

	keyFile, err = filepath.Abs(keyFile)

	if err != nil {
		log.WithError(err).Error("Failed to compute key file path")

		return nil, err
	}

	w := &Watcher{
		mux:      sync.RWMutex{},
		certFile: certFile,
		keyFile:  keyFile,
	}

	w.TLSConfig = &tls.Config{
		GetCertificate: w.GetCertificateFactory(),
	}

	return w, nil
}

func (w *Watcher) Start() error {
	w.mux.Lock()
	defer w.mux.Unlock()

	if w.watcher != nil {
		log.Error("Watcher already initialized, failed to start watcher")

		return ErrFailedWatcher
	}

	// Start watcher before first load to ensure last changes are always loaded
	watcher, err := fsnotify.NewWatcher()

	if err != nil {
		log.WithError(err).Error("Can't create file watcher")

		if err := w.watcher.Close(); err != nil {
			log.WithError(err).Error("Failed to close file watcher")
		}

		return ErrFailedWatcher
	}

	if err := watcher.Add(w.certFile); err != nil {
		log.WithError(err).Error("Can't watch cert file")

		if err := w.watcher.Close(); err != nil {
			log.WithError(err).Error("Failed to close file watcher")
		}

		return ErrFailedWatcher
	}
	if err := watcher.Add(w.keyFile); err != nil {
		log.WithError(err).Error("Can't watch key file")

		if err := w.watcher.Close(); err != nil {
			log.WithError(err).Error("Failed to close file watcher")
		}

		return ErrFailedWatcher
	}

	w.watcher = watcher

	// Attempt first load in sync
	if err := w.load(); err != nil {
		if err := w.watcher.Close(); err != nil {
			log.WithError(err).Error("Failed to close file watcher")
		}

		w.watcher = nil

		return err
	}

	w.wg.Add(1)

	go w.run()

	return nil
}

func (w *Watcher) Stop() error {
	w.mux.Lock()
	defer w.mux.Unlock()

	if err := w.watcher.Close(); err != nil {
		log.WithError(err).Error("Failed to close file watcher")

		return err
	}

	w.wg.Wait()

	log.Debug("All watchers stopped")

	return nil
}

func (w *Watcher) Load() error {
	w.mux.Lock()
	defer w.mux.Unlock()

	return w.load()
}

func (w *Watcher) load() error {
	cert, err := tls.LoadX509KeyPair(w.certFile, w.keyFile)

	if err != nil {
		log.WithError(err).Error("Failed to load certificate")

		return err
	}

	if cert.Leaf == nil {
		cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])

		if err != nil {
			log.WithError(err).Error("Failed to parse certificate")

			return err
		}

		log.Debug("Filled cert Leaf")
	}

	if err := checkExpiry(cert.Leaf); err != nil {
		return err
	}

	w.cert = &cert

	return nil
}

func (w *Watcher) run() {
	log.Debug("Started watcher")

	var ok bool
	var event fsnotify.Event
	var err error

	for {
		select {
		case event, ok = <-w.watcher.Events:
			if ok {
				log.Infof("File changed: %s", event)

				if err := w.Load(); err != nil {
					log.WithError(err).Error("Failed to load cert or key file")

					// Just ignore for now.. and wait for another file event
					// If load produced an error it is most likely one of 2 cases:
					//
					// - The certificate has expired and should be updated soon by an external process
					//
					// - Only one of the certificate files was updated and the files don't match.
					// 	 We are most likely in a race condition, so just wait for the other file to update.
				}
			}
		case err, ok = <-w.watcher.Errors:
			if ok {
				log.WithError(err).Warn("Error watching files")
			}
		}

		if !ok {
			break
		}
	}

	log.Debug("Stopped watcher")

	w.wg.Done()
}

func (w *Watcher) GetCertificateFactory() func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(ci *tls.ClientHelloInfo) (*tls.Certificate, error) {
		w.mux.RLock()
		defer w.mux.RUnlock()

		if w.cert == nil {
			log.WithError(ErrNoCert).Error("Could not find certificate")

			return nil, ErrNoCert
		}

		if err := checkExpiry(w.cert.Leaf); err != nil {
			return nil, ErrInvalidCert
		}

		return w.cert, nil
	}
}

func checkExpiry(cert *x509.Certificate) error {
	timeNow := time.Now()

	if timeNow.After(cert.NotAfter) {
		log.WithError(ErrInvalidCert).Error("Certificate expired")

		return ErrInvalidCert
	} else if timeNow.Before(cert.NotBefore) {
		log.WithError(ErrInvalidCert).Error("Certificate not valid yet")

		return ErrInvalidCert
	}

	return nil
}
