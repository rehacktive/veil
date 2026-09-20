package directory

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"veil/cell"
	"veil/channel"
	"veil/ntor"
	"veil/relaycrypto"
)

// TorSource fetches directory documents through authenticated one-hop ntor
// circuits and BEGIN_DIR streams. With DirectoryOnlyFast, the one-hop circuit
// uses CREATE_FAST inside the authenticated channel without an onion key. Relay
// identity pins always come from bundled/out-of-band pins or a verified Snapshot.
// This is a directory transport, never an anonymous application stream. There
// is no direct HTTP fallback.
// Fetch is a one-shot convenience call. Open returns a session that reuses its
// authenticated channel for sequential directory circuits.
type TorSource struct {
	// DirectoryOnlyFast permits CREATE_FAST solely for bootstrapping without an
	// onion key. Channel identity pins remain mandatory. Never used by circuits.
	DirectoryOnlyFast bool
	Target            channel.Target
	OnionKey          [32]byte
	Timeout           time.Duration // Whole request; defaults to 60 seconds.
}

func (s TorSource) Fetch(ctx context.Context, path string, limit int) ([]byte, error) {
	session := s.Open(ctx)
	defer session.Close()
	return session.Fetch(ctx, path, limit)
}

func validateRequest(path string, limit int) error {
	if limit <= 0 || limit > MaxConsensusSize || len(path) > 4096 || !strings.HasPrefix(path, "/tor/") || strings.ContainsAny(path, "\r\n\t ?#%") {
		return errors.New("invalid directory request path/limit")
	}
	for _, r := range path {
		if r < 33 || r > 126 {
			return errors.New("invalid directory request path")
		}
	}
	return nil
}

// RequestError distinguishes a failed directory operation on an authenticated
// circuit from failure to reach/authenticate a guard.
type RequestError struct {
	Authenticated bool
	Err           error
}

func (e *RequestError) Error() string { return e.Err.Error() }
func (e *RequestError) Unwrap() error { return e.Err }

func fetchCircuit(ctx context.Context, ch cellChannel, id uint32, s TorSource, path string, limit int, onCircuit func(context.Context) error) (result []byte, err error) {
	authenticated := false
	defer func() {
		if err != nil {
			err = &RequestError{Authenticated: authenticated, Err: err}
		}
	}()

	keys, err := directoryKeys(ctx, ch, id, s)
	if err != nil {
		return nil, err
	}
	crypt, err := relaycrypto.NewClient(keys)
	if err != nil {
		return nil, err
	}
	defer crypt.Close()
	authenticated = true
	if onCircuit != nil {
		if err := onCircuit(ctx); err != nil {
			return nil, err
		}
	}
	stream := &directoryStream{ctx: ctx, ch: ch, id: id, crypt: crypt, maxCells: limit/cell.RelayDataSize*4 + 1024}
	if err := stream.send(cell.RelayMessage{Command: cell.RelayBeginDir, StreamID: 1}); err != nil {
		return nil, err
	}
	m, _, err := stream.receive()
	if err != nil {
		return nil, err
	}
	if m.Command != cell.RelayConnected || m.StreamID != 1 || len(m.Data) != 0 {
		return nil, errors.New("directory stream: expected empty CONNECTED")
	}
	requestBytes := []byte("GET " + path + " HTTP/1.0\r\nHost: " + s.Target.Address.String() + "\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n")
	for len(requestBytes) > 0 {
		n := min(len(requestBytes), cell.RelayDataSize)
		if err := stream.send(cell.RelayMessage{Command: cell.RelayData, StreamID: 1, Data: requestBytes[:n]}); err != nil {
			return nil, err
		}
		requestBytes = requestBytes[n:]
	}
	b, err := readResponse(stream, limit)
	if err != nil {
		return nil, err
	}
	// Consume END before retiring the circuit; a bounded drain prevents a peer
	// from keeping an otherwise finished request alive with extra DATA.
	n, err := io.Copy(io.Discard, io.LimitReader(stream, 4097))
	if err != nil {
		return nil, err
	}
	if n > 4096 || !stream.ended {
		return nil, errors.New("directory stream did not end")
	}
	return b, nil
}

type cellChannel interface {
	Receive(context.Context) (cell.Cell, error)
	Send(context.Context, cell.Cell) error
}

func receiveCircuit(ctx context.Context, ch cellChannel, id uint32) (cell.Cell, error) {
	for count := 0; count < 128; count++ {
		f, err := ch.Receive(ctx)
		if err != nil {
			return f, err
		}
		if f.Command == cell.PaddingNegotiate {
			continue
		}
		if f.CircuitID != id || f.Command == cell.Destroy {
			return cell.Cell{}, errors.New("directory circuit: wrong ID or DESTROY")
		}
		return f, nil
	}
	return cell.Cell{}, errors.New("directory circuit: excess control cells")
}

type directoryStream struct {
	ctx                        context.Context
	ch                         cellChannel
	id                         uint32
	crypt                      *relaycrypto.Client
	pending                    []byte
	ended                      bool
	cells, dataCells, maxCells int
}

func (s *directoryStream) send(m cell.RelayMessage) error {
	body, err := cell.EncodeRelay(m)
	if err != nil {
		return err
	}
	body, _, err = s.crypt.Encrypt(0, body)
	if err != nil {
		return err
	}
	return s.ch.Send(s.ctx, cell.Cell{Command: cell.Relay, CircuitID: s.id, Payload: body[:]})
}
func (s *directoryStream) receive() (cell.RelayMessage, relaycrypto.Tag, error) {
	for count := 0; count < 128; count++ {
		s.cells++
		if s.cells > s.maxCells {
			return cell.RelayMessage{}, relaycrypto.Tag{}, errors.New("directory circuit: cell budget exceeded")
		}
		f, err := receiveCircuit(s.ctx, s.ch, s.id)
		if err != nil {
			return cell.RelayMessage{}, relaycrypto.Tag{}, err
		}
		if f.Command != cell.Relay || len(f.Payload) != cell.PayloadSize {
			return cell.RelayMessage{}, relaycrypto.Tag{}, errors.New("directory circuit: expected RELAY")
		}
		var body cell.RelayBody
		copy(body[:], f.Payload)
		body, hop, tag, err := s.crypt.Decrypt(body)
		if err != nil {
			return cell.RelayMessage{}, tag, err
		}
		if hop != 0 {
			return cell.RelayMessage{}, tag, errors.New("directory circuit: unexpected hop")
		}
		m, err := cell.DecodeRelay(body)
		if err != nil {
			return m, tag, err
		}
		if m.Command == cell.RelayDrop {
			continue
		}
		return m, tag, nil
	}
	return cell.RelayMessage{}, relaycrypto.Tag{}, errors.New("directory circuit: excess DROP cells")
}
func (s *directoryStream) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if len(s.pending) > 0 {
		n := copy(p, s.pending)
		s.pending = s.pending[n:]
		return n, nil
	}
	if s.ended {
		return 0, io.EOF
	}
	for empty := 0; empty < 128; empty++ {
		m, tag, err := s.receive()
		if err != nil {
			return 0, err
		}
		if m.StreamID != 1 {
			return 0, errors.New("directory stream: unexpected stream ID/control")
		}
		switch m.Command {
		case cell.RelayEnd:
			s.ended = true
			if len(m.Data) != 1 || m.Data[0] != 6 {
				return 0, errors.New("directory stream: abnormal END")
			}
			return 0, io.EOF
		case cell.RelayData:
			s.dataCells++
			if s.dataCells%100 == 0 {
				data := append([]byte{1, 0, 20}, tag[:]...)
				if err := s.send(cell.RelayMessage{Command: cell.RelaySendme, Data: data}); err != nil {
					return 0, err
				}
			}
			if s.dataCells%50 == 0 {
				if err := s.send(cell.RelayMessage{Command: cell.RelaySendme, StreamID: 1}); err != nil {
					return 0, err
				}
			}
			n := copy(p, m.Data)
			s.pending = m.Data[n:]
			if n > 0 {
				return n, nil
			}
		default:
			// Requests contain fewer than 50 DATA cells; no SENDME is expected.
			return 0, fmt.Errorf("directory stream: unexpected relay command %d", m.Command)
		}
	}
	return 0, errors.New("directory stream: excess empty DATA")
}
func readResponse(stream io.Reader, limit int) ([]byte, error) {
	// Bound both framing and decompressed payload; compression is deliberately
	// not requested/supported yet. The body reader also checks Content-Length.
	br := bufio.NewReader(io.LimitReader(stream, int64(limit)+65536))
	var header []byte
	for {
		line, err := br.ReadSlice('\n')
		if err != nil {
			return nil, fmt.Errorf("directory HTTP header: %w", err)
		}
		header = append(header, line...)
		if len(header) > 32768 {
			return nil, errors.New("directory HTTP header too large")
		}
		if bytes.Equal(line, []byte("\r\n")) || bytes.Equal(line, []byte("\n")) {
			break
		}
	}
	response, err := http.ReadResponse(bufio.NewReader(io.MultiReader(bytes.NewReader(header), br)), nil)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return nil, fmt.Errorf("directory HTTP status %d", response.StatusCode)
	}
	if encoding := response.Header.Get("Content-Encoding"); encoding != "" && encoding != "identity" {
		return nil, errors.New("compressed directory response is not supported")
	}
	if response.ContentLength > int64(limit) {
		return nil, errors.New("directory response exceeds size limit")
	}
	b, err := io.ReadAll(io.LimitReader(response.Body, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(b) > limit {
		return nil, errors.New("directory response exceeds size limit")
	}
	return b, nil
}

func directoryKeys(ctx context.Context, ch cellChannel, id uint32, s TorSource) (ntor.KeyMaterial, error) {
	if s.DirectoryOnlyFast {
		return fastDirectoryKeys(ctx, ch, id)
	}
	state, request, err := ntor.Start(ntor.Relay{Identity: s.Target.Identity.RSA, OnionKey: s.OnionKey})
	if err != nil {
		return ntor.KeyMaterial{}, err
	}
	payload, err := cell.EncodeCreate2(cell.HandshakeNtor, request[:])
	if err != nil {
		return ntor.KeyMaterial{}, err
	}
	if err := ch.Send(ctx, cell.Cell{Command: cell.Create2, CircuitID: id, Payload: payload}); err != nil {
		return ntor.KeyMaterial{}, err
	}
	f, err := receiveCircuit(ctx, ch, id)
	if err != nil {
		return ntor.KeyMaterial{}, err
	}
	if f.Command != cell.Created2 {
		return ntor.KeyMaterial{}, errors.New("directory circuit: expected CREATED2")
	}
	reply, err := cell.DecodeCreated2(f.Payload)
	if err != nil {
		return ntor.KeyMaterial{}, err
	}
	keys, err := state.Finish(reply)
	if err != nil {
		return ntor.KeyMaterial{}, err
	}
	return keys, nil
}
