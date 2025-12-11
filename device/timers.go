/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 *
 * This is based heavily on timers.c from the kernel implementation.
 */

package device

import (
	"sync"
	"time"
	_ "unsafe"
)

//go:linkname fastrandn runtime.fastrandn
func fastrandn(n uint32) uint32

// A Timer manages time-based aspects of the WireGuard protocol.
// Timer roughly copies the interface of the Linux kernel's struct timer_list.
type Timer struct {
	*time.Timer
	modifyingLock sync.RWMutex
	runningLock   sync.Mutex
	isPending     bool
}

func (peer *Peer) NewTimer(expirationFunction func(*Peer)) *Timer {
	timer := &Timer{}
	timer.Timer = time.AfterFunc(time.Hour, func() {
		timer.runningLock.Lock()
		defer timer.runningLock.Unlock()

		timer.modifyingLock.Lock()
		if !timer.isPending {
			timer.modifyingLock.Unlock()
			return
		}
		timer.isPending = false
		timer.modifyingLock.Unlock()

		expirationFunction(peer)
	})
	timer.Stop()
	return timer
}

func (timer *Timer) Mod(d time.Duration) {
	timer.modifyingLock.Lock()
	timer.isPending = true
	timer.Reset(d)
	timer.modifyingLock.Unlock()
}

func (timer *Timer) Del() {
	timer.modifyingLock.Lock()
	timer.isPending = false
	timer.Stop()
	timer.modifyingLock.Unlock()
}

func (timer *Timer) DelSync() {
	timer.Del()
	timer.runningLock.Lock()
	timer.Del()
	timer.runningLock.Unlock()
}

func (timer *Timer) IsPending() bool {
	timer.modifyingLock.RLock()
	defer timer.modifyingLock.RUnlock()
	return timer.isPending
}

func (peer *Peer) timersActive() bool {
	return peer.isRunning.Load() && peer.device != nil && peer.device.isUp()
}

func expiredRetransmitHandshake(peer *Peer) {
	peer.device.log.Verbosef("DEBUG_CALLBACK: expiredRetransmitHandshake called for %s (attempt=%d)", peer, peer.timers.handshakeAttempts.Load())
	
	if peer.timers.handshakeAttempts.Load() > MaxTimerHandshakes {
		peer.device.log.Verbosef("%s - Handshake did not complete after %d attempts, giving up", peer, MaxTimerHandshakes+2)

		// Fire final failure callback
		peer.handshakeCallbackMutex.RLock()
		callback := peer.handshakeEventCallback
		peer.handshakeCallbackMutex.RUnlock()

		if callback != nil {
			go callback(peer.PublicKeyBase64(), "handshake_failed_final", peer.timers.handshakeAttempts.Load())
		}

		peer.handshakeFailureNotified.Store(true)

		if peer.timersActive() {
			peer.timers.sendKeepalive.Del()
		}

		/* We drop all packets without a keypair and don't try again,
		 * if we try unsuccessfully for too long to make a handshake.
		 */
		peer.FlushStagedPackets()

		/* We set a timer for destroying any residue that might be left
		 * of a partial exchange.
		 */
		if peer.timersActive() && !peer.timers.zeroKeyMaterial.IsPending() {
			peer.timers.zeroKeyMaterial.Mod(RejectAfterTime * 3)
		}
	} else {
		attemptNum := peer.timers.handshakeAttempts.Add(1)
		peer.device.log.Verbosef("%s - Handshake did not complete after %d seconds, retrying (try %d)", peer, int(RekeyTimeout.Seconds()), attemptNum)

		// Fire callback on EVERY retry (not just first) - health monitor needs continuous signals
		peer.handshakeCallbackMutex.RLock()
		callback := peer.handshakeEventCallback
		peer.handshakeCallbackMutex.RUnlock()

		if callback != nil {
			// Set failure flag on first attempt
			if attemptNum == 1 {
				peer.handshakeFailureNotified.Store(true)
			}
			// Fire callback every time for continuous health monitoring
			go callback(peer.PublicKeyBase64(), "handshake_timeout", attemptNum)
		}

		/* We clear the endpoint address src address, in case this is the cause of trouble. */
		peer.markEndpointSrcForClearing()

		peer.SendHandshakeInitiation(true)
	}
}

func expiredSendKeepalive(peer *Peer) {
	peer.SendKeepalive()
	if peer.timers.needAnotherKeepalive.Load() {
		peer.timers.needAnotherKeepalive.Store(false)
		if peer.timersActive() {
			peer.timers.sendKeepalive.Mod(KeepaliveTimeout)
		}
	}
}

func expiredNewHandshake(peer *Peer) {
	peer.device.log.Verbosef("%s - Retrying handshake because we stopped hearing back after %d seconds", peer, int((KeepaliveTimeout + RekeyTimeout).Seconds()))
	/* We clear the endpoint address src address, in case this is the cause of trouble. */
	peer.markEndpointSrcForClearing()
	peer.SendHandshakeInitiation(false)
}

func expiredZeroKeyMaterial(peer *Peer) {
	peer.device.log.Verbosef("%s - Removing all keys, since we haven't received a new one in %d seconds", peer, int((RejectAfterTime * 3).Seconds()))
	peer.ZeroAndFlushAll()
}

func expiredPersistentKeepalive(peer *Peer) {
	if peer.persistentKeepaliveInterval.Load() > 0 {
		peer.SendKeepalive()
	}
}

/* Should be called after an authenticated data packet is sent. */
func (peer *Peer) timersDataSent() {
	if peer.timersActive() && !peer.timers.newHandshake.IsPending() {
		peer.timers.newHandshake.Mod(KeepaliveTimeout + RekeyTimeout + time.Millisecond*time.Duration(fastrandn(RekeyTimeoutJitterMaxMs)))
	}
}

/* Should be called after an authenticated data packet is received. */
func (peer *Peer) timersDataReceived() {
	if peer.timersActive() {
		if !peer.timers.sendKeepalive.IsPending() {
			peer.timers.sendKeepalive.Mod(KeepaliveTimeout)
		} else {
			peer.timers.needAnotherKeepalive.Store(true)
		}
	}
}

/* Should be called after any type of authenticated packet is sent -- keepalive, data, or handshake. */
func (peer *Peer) timersAnyAuthenticatedPacketSent() {
	if peer.timersActive() {
		peer.timers.sendKeepalive.Del()
	}
}

/* Should be called after any type of authenticated packet is received -- keepalive, data, or handshake. */
func (peer *Peer) timersAnyAuthenticatedPacketReceived() {
	if peer.timersActive() {
		peer.timers.newHandshake.Del()
	}
}

/* Should be called after a handshake initiation message is sent. */
func (peer *Peer) timersHandshakeInitiated() {
	if peer.timersActive() {
		peer.device.log.Verbosef("DEBUG_CALLBACK: timersHandshakeInitiated - setting retransmit timer for %s", peer)
		peer.timers.retransmitHandshake.Mod(RekeyTimeout + time.Millisecond*time.Duration(fastrandn(RekeyTimeoutJitterMaxMs)))
	}
}

/* Should be called after a handshake response message is received and processed or when getting key confirmation via the first data message. */
func (peer *Peer) timersHandshakeComplete() {
	if peer.timersActive() {
		peer.device.log.Verbosef("DEBUG_CALLBACK: timersHandshakeComplete - deleting retransmit timer for %s", peer)
		peer.timers.retransmitHandshake.Del()
	}

	// Check if this is a recovery from failure
	previouslyFailed := peer.handshakeFailureNotified.Swap(false)

	peer.timers.handshakeAttempts.Store(0)
	peer.timers.sentLastMinuteHandshake.Store(false)
	peer.lastHandshakeNano.Store(time.Now().UnixNano())

	// Fire recovery callback if peer was previously failed
	if previouslyFailed {
		peer.handshakeCallbackMutex.RLock()
		callback := peer.handshakeEventCallback
		peer.handshakeCallbackMutex.RUnlock()

		if callback != nil {
			go callback(peer.PublicKeyBase64(), "handshake_recovered", 0)
		}
	}
}

/* Should be called after an ephemeral key is created, which is before sending a handshake response or after receiving a handshake response. */
func (peer *Peer) timersSessionDerived() {
	if peer.timersActive() {
		peer.timers.zeroKeyMaterial.Mod(RejectAfterTime * 3)
	}
}

/* Should be called before a packet with authentication -- keepalive, data, or handshake -- is sent, or after one is received. */
func (peer *Peer) timersAnyAuthenticatedPacketTraversal() {
	keepalive := peer.persistentKeepaliveInterval.Load()
	if keepalive > 0 && peer.timersActive() {
		peer.timers.persistentKeepalive.Mod(time.Duration(keepalive) * time.Second)
	}
}

func (peer *Peer) timersInit() {
	peer.timers.retransmitHandshake = peer.NewTimer(expiredRetransmitHandshake)
	peer.timers.sendKeepalive = peer.NewTimer(expiredSendKeepalive)
	peer.timers.newHandshake = peer.NewTimer(expiredNewHandshake)
	peer.timers.zeroKeyMaterial = peer.NewTimer(expiredZeroKeyMaterial)
	peer.timers.persistentKeepalive = peer.NewTimer(expiredPersistentKeepalive)
}

func (peer *Peer) timersStart() {
	peer.timers.handshakeAttempts.Store(0)
	peer.timers.sentLastMinuteHandshake.Store(false)
	peer.timers.needAnotherKeepalive.Store(false)
}

func (peer *Peer) timersStop() {
	peer.timers.retransmitHandshake.DelSync()
	peer.timers.sendKeepalive.DelSync()
	peer.timers.newHandshake.DelSync()
	peer.timers.zeroKeyMaterial.DelSync()
	peer.timers.persistentKeepalive.DelSync()
}
