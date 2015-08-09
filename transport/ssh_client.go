/*
 *
 * Copyright 2014, Google Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *     * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

// TODO: lockers

package transport

import (
	// "bytes"
	"errors"
	"github.com/Sirupsen/logrus"
	"strconv"
	// "io"
	// "math"
	// "net"
	// "sync"
	//"time"

	// "github.com/bradfitz/http2"
	// "github.com/bradfitz/http2/hpack"
	"golang.org/x/net/context"
	// "google.golang.org/grpc/codes"
	// "google.golang.org/grpc/credentials"
	// "google.golang.org/grpc/grpclog"
	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc/metadata"

	"github.com/kardianos/osext"

	"github.com/taruti/sshutil"

	"encoding/hex"
	"google.golang.org/grpc/codes"
	"io"
	"path/filepath"
)

// ssh2Client implements the ClientTransport interface with HTTP2.
type ssh2Client struct {
	// target    string // server name/addr
	// userAgent string
	conn   *ssh.Client // underlying communication channel
	nextID uint32      // the next stream ID to be used

	// // writableChan synchronizes write access to the transport.
	// // A writer acquires the write lock by sending a value on writableChan
	// // and releases it by receiving from writableChan.
	writableChan chan int
	// shutdownChan is closed when Close is called.
	// Blocking operations should select on shutdownChan to avoid
	// blocking forever after Close.
	// TODO(zhaoq): Maybe have a channel context?
	shutdownChan chan struct{}
	// errorChan is closed to notify the I/O error to the caller.
	errorChan chan struct{}

	framer *framer

	// controlBuf delivers all the control related tasks (e.g., window
	// updates, reset streams, and various settings) to the controller.
	controlBuf *recvBuffer
	// fc         *inFlow
	// sendQuotaPool provides flow control to outbound message.
	sendQuotaPool *quotaPool

	// streamsQuota limits the max number of concurrent streams.
	streamsQuota *quotaPool

	// mu    sync.Mutex     // guard the following variables
	state transportState // the state of underlying connection

	// the per-stream outbound flow control window size set by the peer.
	streamSendQuota uint32

	// gaetan
	// channels indexed on stream ids
	channelsByStreamId map[uint32]*ssh.Channel
}

// newSSH2Client constructs a connected ClientTransport to addr based on HTTP2
// and starts to receive messages on it. Non-nil error returns if construction
// fails.
func newSSH2Client(addr string, opts *ConnectOptions) (_ ClientTransport, err error) {

	logrus.SetLevel(logrus.DebugLevel)

	logrus.Debugln("newSSH2Client")
	logrus.Debugln("newSSH2Client -- addr:", addr)
	logrus.Debugln("newSSH2Client -- opts:", opts)

	// generate hostKey, needed to ssh connect
	appPath, err := osext.Executable()
	if err != nil {
		return nil, err
	}
	keyPath := filepath.Join(filepath.Dir(appPath), "key.pem")
	hostKey, err := sshutil.KeyLoader{Path: keyPath, Flags: sshutil.Create + sshutil.Save + sshutil.RSA2048}.Load()
	if err != nil {
		return nil, err
	}

	config := &ssh.ClientConfig{
		User: "test",
		Auth: []ssh.AuthMethod{
			ssh.Password("test"),
			ssh.PublicKeys(hostKey),
		},
	}

	// client is an ssh.Client with is of type ssh.Conn
	client, err := ssh.Dial("tcp", addr, config)

	if err != nil {
		return nil, ConnectionErrorf("transport: %v", err)
	}

	// Ad: original code sends http2.ClientPreface here (conn.Write)
	// I don't think it's needed in our case. We have SSH auth, subsystems...

	// Ad: then creates a new "framer"
	// We will implement this differently. From what I understood, each frame comes with a header
	// And it allows get the corresponding stream...etc
	// In our case, each request will have its dedicated ssh Channel (Stream), so we don't have
	// to do any logic to find the context.

	t := &ssh2Client{
		conn:               client,
		writableChan:       make(chan int, 1),
		shutdownChan:       make(chan struct{}),
		errorChan:          make(chan struct{}),
		controlBuf:         newRecvBuffer(),
		sendQuotaPool:      newQuotaPool(defaultWindowSize),
		state:              reachable,
		streamSendQuota:    defaultWindowSize,
		channelsByStreamId: make(map[uint32]*ssh.Channel),
	}

	t.writableChan <- 0
	return t, nil
}

func (t *ssh2Client) newStream(ctx context.Context, callHdr *CallHdr) *Stream {

	logrus.Debugln("new stream with method:", callHdr.Method)

	s := &Stream{
		id:         t.nextID,
		method:     callHdr.Method,
		buf:        newRecvBuffer(),
		headerChan: make(chan struct{}),
		header:     metadata.MD{},
	}
	t.nextID += 2

	// Make a stream be able to cancel the pending operations by itself.
	s.ctx, s.cancel = context.WithCancel(ctx)
	s.dec = &recvBufferReader{
		ctx:  s.ctx,
		recv: s.buf,
	}

	// s.windowHandler is called at some point in
	// the process. It's necessary to implement it,
	// even if it does nothing
	s.windowHandler = func(n int) {
		// do nothing
	}

	return s
}

// NewStream creates a stream and register it into the transport as "active"
// streams.
func (t *ssh2Client) NewStream(ctx context.Context, callHdr *CallHdr) (_ *Stream, err error) {

	logrus.Debugln("NewStream")
	logrus.Debugln("NewStream -- ctx:", ctx)
	logrus.Debugln("NewStream -- callHdr:", callHdr)

	// wait for t.writableChan or t.shutdownChan
	if _, err := wait(ctx, t.shutdownChan, t.writableChan); err != nil {
		logrus.Debugln("NewStream -- wait error:", err.Error())
		return nil, err
	}

	s := t.newStream(ctx, callHdr)

	// build the NewChannel extra data (http2 uses headers)
	// it contains the Stream ID, the method name, and the host name
	extraData := ""
	// convert Stream ID into a string -- Ad: may not be required
	intStr := strconv.FormatUint(uint64(s.id), 10)
	logrus.Debugln("EXTRA DATA ID:", intStr)
	extraData += intStr + "|"
	// add host -- Ad: may not be required
	logrus.Debugln("EXTRA DATA HOST:", callHdr.Host)
	extraData += callHdr.Host + "|"
	// add method
	logrus.Debugln("EXTRA DATA METHOD:", callHdr.Method)
	extraData += callHdr.Method + "|"
	logrus.Debugln("EXTRA DATA FINAL:", extraData)

	ch, _, err := t.conn.OpenChannel("grpc", []byte(extraData))
	if err != nil {
		logrus.Debugln("NewStream -- ERROR OPENNING CHANNEL")
		return nil, errors.New("NewStream -- ERROR OPENNING CHANNEL")
	}

	t.channelsByStreamId[s.id] = &ch

	// read from channel (for response)
	go t.reader(&ch, s)

	t.writableChan <- 0
	return s, nil
}

// CloseStream clears the footprint of a stream when the stream is not needed any more.
// This must not be executed in reader's goroutine.
func (t *ssh2Client) CloseStream(s *Stream, err error) {
	logrus.Debugln("CloseStream")
	// TODO: make sure ssh Channel is closed
	// and not kept in memory
}

// Close kicks off the shutdown process of the transport. This should be called
// only once on a transport. Once it is called, the transport should not be
// accessed any more.
func (t *ssh2Client) Close() (err error) {
	logrus.Debugln("Close")
	return errors.New("ssh2Client Close WORK IN PROGRESS")
	// TODO: make sure ssh connection is closed
	// and that nothing remains in memory
}

// Write sends out data in Stream corresponding ssh Channel.
// opts.Last indicates last packet.
// opts.Delay is ignored in this implementation.
func (t *ssh2Client) Write(s *Stream, data []byte, opts *Options) error {

	logrus.Debugln("Write -- stream ID:", s.id, "- data:", hex.EncodeToString(data))
	logrus.Debugf("Write -- opts: %+v", opts)

	// wait for t.writableChan or t.shutdownChan
	if _, err := wait(s.ctx, t.shutdownChan, t.writableChan); err != nil {
		logrus.Debugln("Write -- wait error:", err.Error())
		return err
	}

	// get channel corresponding to the Stream
	ch := t.channelsByStreamId[s.id]
	n, err := (*ch).Write(data)
	if err != nil {
		logrus.Debugln("Write -- error:", err.Error())
	}
	logrus.Debugln("Write -- bytes written:", n)

	// Done writing, close write (server will receive EOF)
	// TODO: CloseWrite & and update s.state only if opts.Last == true
	// + test to see if opts.Last is correctly received
	(*ch).CloseWrite()

	// Ad: necessary?
	t.writableChan <- 0

	if s.state != streamDone {
		if s.state == streamReadDone {
			s.state = streamDone
			logrus.Debugln("s.state: streamDone")
		} else {
			s.state = streamWriteDone
			logrus.Debugln("s.state: streamWriteDone")
		}
	}

	return nil
}

// reader runs as a separate goroutine in charge of reading data from network
// connection.
// TODO: make sure services with stream returns work
func (t *ssh2Client) reader(ch *ssh.Channel, s *Stream) {

	data := make([]byte, 0)

	for {
		// TODO: define default buffer size
		// TODO: allow dynamic buffer size
		buf := make([]byte, 64)
		n, err := (*ch).Read(buf)
		if err != nil {
			if err.Error() == "EOF" {
				buf = buf[:n]
				data = append(data, buf...)
				break
			} else {
				logrus.Fatalln(err.Error())
			}
		}
		buf = buf[:n]
		data = append(data, buf...)
	}

	logrus.Debugln("reader -- data:", hex.EncodeToString(data))

	// end of response
	s.write(recvMsg{data: data})

	if s.state == streamWriteDone {
		s.state = streamDone
		logrus.Debugln("s.state: streamDone")
	} else {
		s.state = streamReadDone
		logrus.Debugln("s.state: streamReadDone")
	}

	s.statusCode = codes.OK

	s.write(recvMsg{err: io.EOF})

	// close headerChan to progress in
	// google.golang.org/grpc/call.go: func recvResponse
	// this line -> c.headerMD, err = stream.Header()
	// look at func (s *Stream) Header() in grpc/transport/transport.go
	// it waits for headerChan to be closed or stream cancellation
	close(s.headerChan)
}

func (t *ssh2Client) Error() <-chan struct{} {
	return t.errorChan
}
