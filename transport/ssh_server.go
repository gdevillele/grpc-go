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

package transport

import (
	"encoding/hex"
	"io"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	// "sync"
	// "math"
	// "errors"
	// "bytes"

	"golang.org/x/net/context"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	// "github.com/bradfitz/http2"
	// "github.com/bradfitz/http2/hpack"
	// "google.golang.org/grpc/grpclog"

	"github.com/Sirupsen/logrus"
	"github.com/kardianos/osext"
	"github.com/taruti/sshutil"
	"golang.org/x/crypto/ssh"
)

// type ServerTransport interface {
// 	// WriteStatus sends the status of a stream to the client.
// 	WriteStatus(s *Stream, statusCode codes.Code, statusDesc string) error
// 	// Write sends the data for the given stream.
// 	Write(s *Stream, data []byte, opts *Options) error
// 	// WriteHeader sends the header metedata for the given stream.
// 	WriteHeader(s *Stream, md metadata.MD) error
// 	// HandleStreams receives incoming streams using the given handler.
// 	HandleStreams(func(*Stream))
// 	// Close tears down the transport. Once it is called, the transport
// 	// should not be accessed any more. All the pending streams and their
// 	// handlers will be terminated asynchronously.
// 	Close() error
// }

// ErrIllegalHeaderWrite indicates that setting header is illegal because of
// the stream's state.
// var ErrIllegalHeaderWrite = errors.New("transport: the stream is done or WriteHeader was already called")

// TODO
// - locks/mutex ?
// - check use of gochannels
// - support data -> stream / stream -> data / stream -> stream

// ssh2Server implements the ServerTransport interface with HTTP2.
type ssh2Server struct {
	conn net.Conn
	// top level SSH attributes
	sshServerConn *ssh.ServerConn
	newChans      <-chan ssh.NewChannel
	globalReqs    <-chan *ssh.Request

	// channels indexed on stream ids
	channelsByStreamId map[uint32]*ssh.Channel

	// maxStreamID uint32 // max stream ID ever seen
	// // writableChan synchronizes write access to the transport.
	// // A writer acquires the write lock by sending a value on writableChan
	// // and releases it by receiving from writableChan.
	writableChan chan int
	// // shutdownChan is closed when Close is called.
	// // Blocking operations should select on shutdownChan to avoid
	// // blocking forever after Close.
	// shutdownChan chan struct{}
	// framer       *framer
	// hBuf *bytes.Buffer  // the buffer for HPACK encoding
	// hEnc *hpack.Encoder // HPACK encoder

	// // The max number of concurrent streams.
	// maxStreams uint32
	// // controlBuf delivers all the control related tasks (e.g., window
	// // updates, reset streams, and various settings) to the controller.
	// controlBuf *recvBuffer
	// fc         *inFlow
	// // sendQuotaPool provides flow control to outbound message.
	// sendQuotaPool *quotaPool

	// mu            sync.Mutex // guard the following
	// state         transportState
	// activeStreams map[uint32]*Stream
	// // the per-stream outbound flow control window size set by the peer.
	// streamSendQuota uint32
}

// newSSH2Server constructs a ServerTransport based on HTTP2. ConnectionError is
// returned if something goes wrong.
func newSSH2Server(conn net.Conn, maxStreams uint32) (_ ServerTransport, err error) {

	logrus.SetLevel(logrus.DebugLevel)

	logrus.Debugln("newSSH2Server")

	keyAuthCallback := func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		logrus.Debugln("newSSH2Server -- user public key: ", hex.EncodeToString(key.Marshal())[:64]+"...")
		return &ssh.Permissions{}, nil
	}

	config := &ssh.ServerConfig{
		PublicKeyCallback: keyAuthCallback,
	}

	// get or create host key for ssh server
	appPath, err := osext.Executable()
	if err != nil {
		return nil, err
	}
	keyPath := filepath.Join(filepath.Dir(appPath), "hostKey.pem")
	hostKey, err := sshutil.KeyLoader{Path: keyPath, Flags: sshutil.Create + sshutil.Save + sshutil.RSA2048}.Load()
	if err != nil {
		return nil, err
	}
	config.AddHostKey(hostKey)

	t := &ssh2Server{
		conn:               conn,
		writableChan:       make(chan int, 1),
		channelsByStreamId: make(map[uint32]*ssh.Channel),
	}

	t.sshServerConn, t.newChans, t.globalReqs, err = ssh.NewServerConn(conn, config)

	if err != nil {
		logrus.Debugln("newSSH2Server -- Failed to hanshake:", err.Error())
		return nil, err
	} else {
		logrus.Debugln("newSSH2Server -- hanshake OK")
	}

	t.writableChan <- 0
	return t, nil
}

// WriteStatus sends stream status to the client and terminates the stream.
// There is no further I/O operations being able to perform on this stream.
// TODO(zhaoq): Now it indicates the end of entire stream. Revisit if early
// OK is adopted.
func (t *ssh2Server) WriteStatus(s *Stream, statusCode codes.Code, statusDesc string) error {
	logrus.Debugln("WriteStatus")
	logrus.Debugln("WriteStatus -- statusCode:", statusCode)
	logrus.Debugln("WriteStatus -- statusDesc:", statusDesc)

	ch := t.channelsByStreamId[s.id]
	err := (*ch).CloseWrite()
	return err

	// =================================== original code ======================================
	// s.mu.RLock()
	// if s.state == streamDone {
	// 	s.mu.RUnlock()
	// 	return nil
	// }
	// s.mu.RUnlock()
	// if _, err := wait(s.ctx, t.shutdownChan, t.writableChan); err != nil {
	// 	return err
	// }
	// t.hBuf.Reset()
	// t.hEnc.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
	// t.hEnc.WriteField(
	// 	hpack.HeaderField{
	// 		Name:  "grpc-status",
	// 		Value: strconv.Itoa(int(statusCode)),
	// 	})
	// t.hEnc.WriteField(hpack.HeaderField{Name: "grpc-message", Value: statusDesc})
	// // Attach the trailer metadata.
	// for k, v := range s.trailer {
	// 	t.hEnc.WriteField(hpack.HeaderField{Name: k, Value: v})
	// }
	// if err := t.writeHeaders(s, t.hBuf, true); err != nil {
	// 	t.Close()
	// 	return err
	// }
	// t.closeStream(s)
	// t.writableChan <- 0
	// return nil
}

// Write converts the data into HTTP2 data frame and sends it out. Non-nil error
// is returns if it fails (e.g., framing error, transport error).
func (t *ssh2Server) Write(s *Stream, data []byte, opts *Options) error {

	logrus.Debugln("Write")
	// logrus.Debugln("Write -- data:", hex.EncodeToString(data))
	// logrus.Debugf("Write -- opts: %+v", opts)

	ch := t.channelsByStreamId[s.id]
	_, err := (*ch).Write(data)
	if err != nil {
		logrus.Debugln("ERROR writing back in the channel...", err.Error())
	}
	return nil

	// =================================== original code ======================================
	// // TODO(zhaoq): Support multi-writers for a single stream.
	// var writeHeaderFrame bool
	// s.mu.Lock()
	// if !s.headerOk {
	// 	writeHeaderFrame = true
	// 	s.headerOk = true
	// }
	// s.mu.Unlock()
	// if writeHeaderFrame {
	// 	if _, err := wait(s.ctx, t.shutdownChan, t.writableChan); err != nil {
	// 		return err
	// 	}
	// 	t.hBuf.Reset()
	// 	t.hEnc.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
	// 	t.hEnc.WriteField(hpack.HeaderField{Name: "content-type", Value: "application/grpc"})
	// 	p := http2.HeadersFrameParam{
	// 		StreamID:      s.id,
	// 		BlockFragment: t.hBuf.Bytes(),
	// 		EndHeaders:    true,
	// 	}
	// 	if err := t.framer.writeHeaders(false, p); err != nil {
	// 		t.Close()
	// 		return ConnectionErrorf("transport: %v", err)
	// 	}
	// 	t.writableChan <- 0
	// }
	// r := bytes.NewBuffer(data)
	// for {
	// 	if r.Len() == 0 {
	// 		return nil
	// 	}
	// 	size := http2MaxFrameLen
	// 	s.sendQuotaPool.add(0)
	// 	// Wait until the stream has some quota to send the data.
	// 	sq, err := wait(s.ctx, t.shutdownChan, s.sendQuotaPool.acquire())
	// 	if err != nil {
	// 		return err
	// 	}
	// 	t.sendQuotaPool.add(0)
	// 	// Wait until the transport has some quota to send the data.
	// 	tq, err := wait(s.ctx, t.shutdownChan, t.sendQuotaPool.acquire())
	// 	if err != nil {
	// 		if _, ok := err.(StreamError); ok {
	// 			t.sendQuotaPool.cancel()
	// 		}
	// 		return err
	// 	}
	// 	if sq < size {
	// 		size = sq
	// 	}
	// 	if tq < size {
	// 		size = tq
	// 	}
	// 	p := r.Next(size)
	// 	ps := len(p)
	// 	if ps < sq {
	// 		// Overbooked stream quota. Return it back.
	// 		s.sendQuotaPool.add(sq - ps)
	// 	}
	// 	if ps < tq {
	// 		// Overbooked transport quota. Return it back.
	// 		t.sendQuotaPool.add(tq - ps)
	// 	}
	// 	t.framer.adjustNumWriters(1)
	// 	// Got some quota. Try to acquire writing privilege on the
	// 	// transport.
	// if _, err := wait(s.ctx, t.shutdownChan, t.writableChan); err != nil {
	// 	if t.framer.adjustNumWriters(-1) == 0 {
	// 		// This writer is the last one in this batch and has the
	// 		// responsibility to flush the buffered frames. It queues
	// 		// a flush request to controlBuf instead of flushing directly
	// 		// in order to avoid the race with other writing or flushing.
	// 		t.controlBuf.put(&flushIO{})
	// 	}
	// 	return err
	// }
	// 	var forceFlush bool
	// 	if r.Len() == 0 && t.framer.adjustNumWriters(0) == 1 && !opts.Last {
	// 		forceFlush = true
	// 	}
	// 	if err := t.framer.writeData(forceFlush, s.id, false, p); err != nil {
	// 		t.Close()
	// 		return ConnectionErrorf("transport: %v", err)
	// 	}
	// 	if t.framer.adjustNumWriters(-1) == 0 {
	// 		t.framer.flushWrite()
	// 	}
	// 	t.writableChan <- 0
	// }
}

// WriteHeader sends the header metadata md back to the client.
func (t *ssh2Server) WriteHeader(s *Stream, md metadata.MD) error {

	logrus.Debugln("WriteHeader")
	return nil

	// =================================== original code ======================================
	// s.mu.Lock()
	// if s.headerOk || s.state == streamDone {
	// 	s.mu.Unlock()
	// 	return ErrIllegalHeaderWrite
	// }
	// s.headerOk = true
	// s.mu.Unlock()
	// if _, err := wait(s.ctx, t.shutdownChan, t.writableChan); err != nil {
	// 	return err
	// }
	// t.hBuf.Reset()
	// t.hEnc.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
	// t.hEnc.WriteField(hpack.HeaderField{Name: "content-type", Value: "application/grpc"})
	// for k, v := range md {
	// 	t.hEnc.WriteField(hpack.HeaderField{Name: k, Value: v})
	// }
	// if err := t.writeHeaders(s, t.hBuf, false); err != nil {
	// 	return err
	// }
	// t.writableChan <- 0
	// return nil
}

// HandleStreams receives incoming streams using the given handler. This is
// typically run in a separate goroutine.
func (t *ssh2Server) HandleStreams(handle func(*Stream)) {

	logrus.Debugln("HandleStreams")

	// service the global requests channel (by discarding all incoming requests)
	go ssh.DiscardRequests(t.globalReqs)

	// handle new ssh channels (one channel == one rpc)
	for newChannel := range t.newChans {

		logrus.Debugln("HandleStreams -- new channel", newChannel.ChannelType())

		chType := newChannel.ChannelType()
		chArgs := newChannel.ExtraData()

		if chType != "grpc" {
			newChannel.Reject(ssh.UnknownChannelType, "unknown/unsupported channel type")
		} else {
			channel, requests, err := newChannel.Accept()
			if err != nil {
				logrus.Debugln("ERROR: failed to accept new channel (" + chType + ")")
				continue
			}

			// parse NewChannel extra data to get the grpc headers
			args := strings.Split(string(chArgs), "|")
			// logrus.Debugln("args:", args)

			// Using Channel's extra data to send the Stream ID
			streamID, err := strconv.ParseUint(args[0], 10, 32)
			if err != nil {
				logrus.Fatalln("cannot parse Stream ID")
			}
			logrus.Debugln("HandleStreams -- Stream ID is", streamID)

			logrus.Debugln("HandleStreams -- HOST is", args[1])
			logrus.Debugln("HandleStreams -- METHODS is", args[2])

			t.channelsByStreamId[uint32(streamID)] = &channel

			// create a Stream with the stream id
			s := &Stream{
				id:     uint32(streamID),
				buf:    newRecvBuffer(),
				method: args[2],
			}

			s.ctx, s.cancel = context.WithCancel(context.TODO())

			s.dec = &recvBufferReader{
				ctx:  s.ctx,
				recv: s.buf,
			}

			s.windowHandler = func(n int) {
				// ABSOLUTELY NEEDED?
				// t.updateWindow(s, uint32(n))
			}

			handleChannel(s, channel, requests, handle)
		}
	}
	return

	// =================================== original code ======================================
	// // Check the validity of client preface.
	// preface := make([]byte, len(clientPreface))
	// if _, err := io.ReadFull(t.conn, preface); err != nil {
	// 	grpclog.Printf("transport: http2Server.HandleStreams failed to receive the preface from client: %v", err)
	// 	t.Close()
	// 	return
	// }
	// if !bytes.Equal(preface, clientPreface) {
	// 	grpclog.Printf("transport: http2Server.HandleStreams received bogus greeting from client: %q", preface)
	// 	t.Close()
	// 	return
	// }

	// frame, err := t.framer.readFrame()
	// if err != nil {
	// 	grpclog.Printf("transport: http2Server.HandleStreams failed to read frame: %v", err)
	// 	t.Close()
	// 	return
	// }
	// sf, ok := frame.(*http2.SettingsFrame)
	// if !ok {
	// 	grpclog.Printf("transport: http2Server.HandleStreams saw invalid preface type %T from client", frame)
	// 	t.Close()
	// 	return
	// }
	// t.handleSettings(sf)

	// hDec := newHPACKDecoder()
	// var curStream *Stream
	// var wg sync.WaitGroup
	// defer wg.Wait()
	// for {
	// 	frame, err := t.framer.readFrame()
	// 	if err != nil {
	// 		t.Close()
	// 		return
	// 	}
	// 	switch frame := frame.(type) {
	// 	case *http2.HeadersFrame:
	// 		id := frame.Header().StreamID
	// 		if id%2 != 1 || id <= t.maxStreamID {
	// 			// illegal gRPC stream id.
	// 			grpclog.Println("transport: http2Server.HandleStreams received an illegal stream id: ", id)
	// 			t.Close()
	// 			break
	// 		}
	// 		t.maxStreamID = id
	// 		buf := newRecvBuffer()
	// 		fc := &inFlow{
	// 			limit: initialWindowSize,
	// 			conn:  t.fc,
	// 		}
	// 		curStream = &Stream{
	// 			id:  frame.Header().StreamID,
	// 			st:  t,
	// 			buf: buf,
	// 			fc:  fc,
	// 		}
	// 		endStream := frame.Header().Flags.Has(http2.FlagHeadersEndStream)
	// 		curStream = t.operateHeaders(hDec, curStream, frame, endStream, handle, &wg)
	// 	case *http2.ContinuationFrame:
	// 		curStream = t.operateHeaders(hDec, curStream, frame, false, handle, &wg)
	// 	case *http2.DataFrame:
	// 		t.handleData(frame)
	// 	case *http2.RSTStreamFrame:
	// 		t.handleRSTStream(frame)
	// 	case *http2.SettingsFrame:
	// 		t.handleSettings(frame)
	// 	case *http2.PingFrame:
	// 		t.handlePing(frame)
	// 	case *http2.WindowUpdateFrame:
	// 		t.handleWindowUpdate(frame)
	// 	case *http2.GoAwayFrame:
	// 		break
	// 	default:
	// 		grpclog.Printf("transport: http2Server.HandleStreams found unhandled frame type %v.", frame)
	// 	}
	// }
}

func handleChannel(s *Stream, ch ssh.Channel, reqs <-chan *ssh.Request, handle func(*Stream)) {

	// handle requests receive for this Channel
	go func(in <-chan *ssh.Request) {
		for req := range in {
			logrus.Debugln("AdminTool -> Request of type:", req.Type, "len:", len(req.Type))
			logrus.Debugln("AdminTool -> Request payload:", string(req.Payload), "len:", len(req.Payload))

			if req.WantReply {
				req.Reply(false, nil)
			}
		}
		logrus.Debugln("AdminTool -> End of request GO chan")
	}(reqs)

	// read data from channel
	go func() {
		for {
			buffer := make([]byte, 64)
			n, err := ch.Read(buffer)
			if err != nil {
				if err.Error() == "EOF" {
					handleData(s, []byte{}, true)
					// all data received: handle Stream message
					handle(s)
					break
				} else {
					logrus.Fatalln("failed to read channel : " + err.Error())
				}
			}
			handleData(s, buffer[:n], false)
		}
	}()
}

// Close starts shutting down the http2Server transport.
// TODO(zhaoq): Now the destruction is not blocked on any pending streams. This
// could cause some resource issue. Revisit this later.
func (t *ssh2Server) Close() (err error) {

	logrus.Debugln("Close")
	return nil

	// =================================== original code ======================================
	// t.mu.Lock()
	// if t.state == closing {
	// 	t.mu.Unlock()
	// 	return errors.New("transport: Close() was already called")
	// }
	// t.state = closing
	// streams := t.activeStreams
	// t.activeStreams = nil
	// t.mu.Unlock()
	// close(t.shutdownChan)
	// err = t.conn.Close()
	// // Notify all active streams.
	// for _, s := range streams {
	// 	s.write(recvMsg{err: ErrConnClosing})
	// }
	// return
}

// ===========================================================================================
// UNEXPOSED FUNCTIONS
// ===========================================================================================

func handleData(s *Stream, data []byte, EOF bool) {

	logrus.Debugln("handleData -- data:", hex.EncodeToString(data))

	if len(data) > 0 {
		logrus.Debugln("handleData -- write")
		s.write(recvMsg{data: data})
	}

	if EOF {
		logrus.Debugln("handleData -- EOF")

		if s.state != streamDone {
			if s.state == streamWriteDone {
				s.state = streamDone
			} else {
				s.state = streamReadDone
			}
		}

		s.write(recvMsg{err: io.EOF})
	}
}
