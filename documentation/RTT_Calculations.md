# RTT Calculation and One-Way Latency in SRT Protocol

## Packet Sending Flow

The SRT protocol uses a multi-stage pipeline to send data packets from the application to the network. Here's how packets flow through the system:

### 1. Application Write (`connection.go` lines 481-515)

When the application calls `Write()`, data is buffered and split into packets:

```go
func (c *srtConn) Write(b []byte) (int, error) {
    c.writeBuffer.Write(b)

    for {
        n, err := c.writeBuffer.Read(c.writeData)  // Read up to payload size
        if err != nil {
            return 0, err
        }

        p := packet.NewPacket(nil)
        p.SetData(c.writeData[:n])
        p.Header().IsControlPacket = false
        p.Header().PktTsbpdTime = c.getTimestamp()  // Set delivery timestamp

        // Non-blocking write to write queue
        c.writeQueue <- p
    }
}
```

**Key steps:**
- Data is buffered and split into packets of `PayloadSize` (typically 1456 bytes)
- Each packet gets a `PktTsbpdTime` timestamp (Timestamp-Based Packet Delivery)
- Packets are queued in `writeQueue` (non-blocking, 1024 packet capacity)

### 2. Write Queue Reader (`connection.go` lines 606-620)

A dedicated goroutine reads from `writeQueue` and feeds packets to congestion control:

```go
func (c *srtConn) writeQueueReader(ctx context.Context) {
    for {
        select {
        case <-ctx.Done():
            return
        case p := <-c.writeQueue:
            c.snd.Push(p)  // Send to congestion control
        }
    }
}
```

### 3. Congestion Control - Sender (`congestion/live/send.go` lines 120-162)

The sender assigns sequence numbers and prepares packets for transmission:

```go
func (s *sender) Push(p packet.Packet) {
    // Assign sequence number
    p.Header().PacketSequenceNumber = s.nextSequenceNumber
    s.nextSequenceNumber = s.nextSequenceNumber.Inc()

    // Set packet flags
    p.Header().PacketPositionFlag = packet.SinglePacket
    p.Header().OrderFlag = false
    p.Header().MessageNumber = 1

    // Set timestamp (32-bit, wrapped)
    p.Header().Timestamp = uint32(p.Header().PktTsbpdTime & uint64(packet.MAX_TIMESTAMP))

    // Link capacity probing: every 16th and 17th packet sent together
    probe := p.Header().PacketSequenceNumber.Val() & 0xF
    if probe == 0 {
        s.probeTime = p.Header().PktTsbpdTime
    } else if probe == 1 {
        p.Header().PktTsbpdTime = s.probeTime  // Send at same time
    }

    s.packetList.PushBack(p)  // Add to send queue
}
```

**Key operations:**
- **Sequence numbering**: Each packet gets a unique sequence number
- **Timestamp assignment**: 32-bit timestamp for RTT calculation
- **Link capacity probing**: Packets 16 and 17 are sent together to measure link capacity
- **Queueing**: Packets are stored in `packetList` for transmission

### 4. Sender Tick - Transmission (`congestion/live/send.go` lines 164-197)

The sender's `Tick()` method is called periodically to transmit packets:

```go
func (s *sender) Tick(now uint64) {
    // Send packets whose PktTsbpdTime has arrived
    for e := s.packetList.Front(); e != nil; e = e.Next() {
        p := e.Value.(packet.Packet)
        if p.Header().PktTsbpdTime <= now {
            s.deliver(p)  // Send packet
            // Move to lossList for retransmission tracking
            s.lossList.PushBack(e.Value)
            s.packetList.Remove(e)
        } else {
            break  // Packets are ordered by time
        }
    }
}
```

**Transmission timing:**
- Packets are sent when `PktTsbpdTime <= current_time`
- After sending, packets move to `lossList` for retransmission tracking
- Packets too old (beyond `dropThreshold`) are dropped

### 5. Packet Output (`connection.go` lines 541-586)

The `pop()` function finalizes and sends packets:

```go
func (c *srtConn) pop(p packet.Packet) {
    // Set destination
    p.Header().Addr = c.remoteAddr
    p.Header().DestinationSocketId = c.peerSocketId

    if !p.Header().IsControlPacket {
        // Encryption
        if c.crypto != nil {
            p.Header().KeyBaseEncryptionFlag = c.keyBaseEncryption
            c.crypto.EncryptOrDecryptPayload(p.Data(), ...)

            // Key management (periodic key rotation)
            // ...
        }
    }

    // Send to network via callback
    c.onSend(p)
}
```

**Final steps:**
- **Address assignment**: Sets destination address and socket ID
- **Encryption**: Encrypts payload if encryption is enabled
- **Key management**: Handles periodic key rotation (KMREQ/KMRSP)
- **Network transmission**: Calls `onSend()` callback which marshals and sends via UDP

### 6. Network Transmission (`dial.go` lines 258-281, `listen.go` lines 427-450)

The actual UDP transmission:

```go
func (dl *dialer) send(p packet.Packet) {
    dl.sndData.Reset()
    p.Marshal(&dl.sndData)  // Serialize packet
    buffer := dl.sndData.Bytes()
    dl.pc.Write(buffer)     // Send via UDP socket

    if p.Header().IsControlPacket {
        p.Decommission()  // Control packets not retransmitted
    }
}
```

**Summary of sending flow:**
```
Application Write()
    ↓
writeQueue (buffered channel)
    ↓
writeQueueReader goroutine
    ↓
sender.Push() - assign sequence numbers
    ↓
sender.Tick() - transmit when ready
    ↓
pop() - encrypt and finalize
    ↓
onSend() - marshal and send via UDP
```

---

## Packet Receiving Flow

The receiving side processes incoming UDP packets through multiple stages:

### 1. UDP Socket Reception (`listen.go` lines 216-252, `dial.go` similar)

A goroutine continuously reads from the UDP socket:

```go
for {
    n, addr, err := ln.pc.ReadFrom(buffer)  // Blocking UDP read
    if err != nil {
        // Handle errors/timeouts
        continue
    }

    p, err := packet.NewPacketFromData(addr, buffer[:n])  // Parse packet
    if err != nil {
        continue  // Invalid packet, drop
    }

    // Non-blocking queue to rcvQueue
    select {
    case ln.rcvQueue <- p:
    default:
        // Queue full, drop packet
    }
}
```

**Key operations:**
- **Blocking read**: Waits for UDP packets (with 3-second timeout)
- **Packet parsing**: Converts raw bytes to `Packet` structure
- **Queueing**: Non-blocking write to `rcvQueue` (2048 packet capacity)

### 2. Listener Reader (`listen.go` lines 375-424)

Routes packets to the correct connection:

```go
func (ln *listener) reader(ctx context.Context) {
    for {
        select {
        case p := <-ln.rcvQueue:
            if p.Header().DestinationSocketId == 0 {
                // Handshake packet, route to backlog
                if p.Header().IsControlPacket &&
                   p.Header().ControlType == packet.CTRLTYPE_HANDSHAKE {
                    ln.backlog <- p
                }
                break
            }

            // Find connection by socket ID
            conn, ok := ln.conns[p.Header().DestinationSocketId]
            if !ok {
                break  // Unknown connection, drop
            }

            // Security check: verify peer address
            if !ln.config.AllowPeerIpChange {
                if p.Header().Addr.String() != conn.RemoteAddr().String() {
                    break  // Wrong peer, drop
                }
            }

            conn.push(p)  // Route to connection
    }
}
```

**Routing logic:**
- **Handshake packets** (socket ID = 0) → `backlog` queue
- **Data/control packets** → Lookup connection by `DestinationSocketId`
- **Security**: Verifies peer address matches (unless `AllowPeerIpChange`)

### 3. Connection Network Queue (`connection.go` lines 518-526, 589-602)

Packets are queued for processing:

```go
func (c *srtConn) push(p packet.Packet) {
    // Non-blocking write to network queue
    select {
    case c.networkQueue <- p:
    default:
        // Queue full, log error
    }
}

func (c *srtConn) networkQueueReader(ctx context.Context) {
    for {
        select {
        case p := <-c.networkQueue:
            c.handlePacket(p)  // Process packet
        }
    }
}
```

### 4. Packet Handling (`connection.go` lines 636-744)

The `handlePacket()` function routes packets by type:

```go
func (c *srtConn) handlePacket(p packet.Packet) {
    c.peerIdleTimeout.Reset(c.config.PeerIdleTimeout)

    if p.Header().IsControlPacket {
        // Route to control packet handlers
        switch p.Header().ControlType {
        case packet.CTRLTYPE_ACK:
            c.handleACK(p)
        case packet.CTRLTYPE_ACKACK:
            c.handleACKACK(p)
        case packet.CTRLTYPE_NAK:
            c.handleNAK(p)
        case packet.CTRLTYPE_KEEPALIVE:
            c.handleKeepAlive(p)
        case packet.CTRLTYPE_SHUTDOWN:
            c.handleShutdown(p)
        // ... other control types
        }
        return
    }

    // Data packet processing
    // 1. Check for lost packets (sequence gap detection)
    if header.PacketSequenceNumber.Gt(c.debug.expectedRcvPacketSequenceNumber) {
        // Log lost packets
    }

    // 2. Ignore FEC filter control packets (MessageNumber == 0)
    if header.MessageNumber == 0 {
        return
    }

    // 3. TSBPD timestamp calculation (for packet delivery timing)
    header.PktTsbpdTime = c.tsbpdTimeBase + tsbpdTimeBaseOffset +
                          uint64(header.Timestamp) + c.tsbpdDelay + c.tsbpdDrift

    // 4. Decryption
    if c.crypto != nil {
        c.crypto.EncryptOrDecryptPayload(p.Data(), ...)
    }

    // 5. Send to receiver congestion control
    c.recv.Push(p)
}
```

**Data packet processing:**
- **Sequence tracking**: Detects gaps (lost packets)
- **TSBPD calculation**: Computes delivery time based on sender's timestamp
- **Decryption**: Decrypts payload if encryption enabled
- **Congestion control**: Routes to receiver for ordering and delivery

### 4.1. Optimizing Packet Buffer Allocation with sync.Pool

For high-performance packet processing, allocating a new `bytes.Buffer` for every packet can create significant memory pressure and GC overhead. Using `sync.Pool` to reuse buffers can dramatically reduce allocations and improve performance.

#### Current Implementation

The `packet` package already implements a `sync.Pool` for `bytes.Buffer` objects:

**Location**: `packet/packet.go` lines 253-278

```go
type pool struct {
    pool sync.Pool
}

func newPool() *pool {
    return &pool{
        pool: sync.Pool{
            New: func() interface{} {
                return new(bytes.Buffer)
            },
        },
    }
}

func (p *pool) Get() *bytes.Buffer {
    b := p.pool.Get().(*bytes.Buffer)
    b.Reset()  // Clear previous contents
    return b
}

func (p *pool) Put(b *bytes.Buffer) {
    p.pool.Put(b)
}

var payloadPool *pool = newPool()
```

#### How It Works

1. **Buffer Acquisition** (`NewPacket`, line 303):
   ```go
   func NewPacket(addr net.Addr) Packet {
       p := &pkt{
           header: PacketHeader{...},
           payload: payloadPool.Get(),  // Get buffer from pool
       }
       return p
   }
   ```

2. **Buffer Release** (`Decommission`, line 309-316):
   ```go
   func (p *pkt) Decommission() {
       if p.payload == nil {
           return
       }
       payloadPool.Put(p.payload)  // Return buffer to pool
       p.payload = nil
   }
   ```

3. **Buffer Reuse** (`Clone`, line 343-350):
   ```go
   func (p *pkt) Clone() Packet {
       clone := *p
       clone.payload = payloadPool.Get()  // Get new buffer from pool
       clone.payload.Write(p.payload.Bytes())
       return &clone
   }
   ```

#### Benefits

1. **Reduced Allocations**: Reuses buffers instead of allocating new ones for each packet
2. **Lower GC Pressure**: Fewer objects to garbage collect
3. **Better Cache Locality**: Reused buffers may stay in CPU cache
4. **Performance**: Can reduce allocation overhead by 50-90% in high-throughput scenarios

#### Performance Considerations

**When buffers are returned to the pool:**
- Control packets: After marshaling and sending (in `dial.go` line 160, `listen.go` line 443)
- Data packets: After retransmission timeout or successful delivery
- Cloned packets: When the clone is decommissioned

**Buffer size management:**
- `bytes.Buffer` automatically grows as needed
- When returned to pool, buffers retain their capacity (not reset to zero)
- This is beneficial: avoids reallocation if next packet is similar size
- `Reset()` only clears length, not capacity

**Thread safety:**
- `sync.Pool` is thread-safe and lock-free for common cases
- Each goroutine can safely Get/Put without explicit locking
- Pool automatically handles per-P (processor) local caches

#### Alternative: Pre-sized Buffer Pool

For even better performance, you could create a pool with pre-sized buffers:

```go
var payloadPool = sync.Pool{
    New: func() interface{} {
        // Pre-allocate with typical payload size (1456 bytes)
        buf := make([]byte, 0, 1500)
        return bytes.NewBuffer(buf)
    },
}
```

This avoids initial capacity growth for typical packet sizes, but the current implementation is more flexible for variable-sized packets.

#### Memory Footprint

**Without pool:**
- Each packet: ~1.5 KB buffer allocation
- At 1000 packets/second: ~1.5 MB/second allocated
- High GC frequency and pause times

**With pool:**
- Initial allocation: ~1.5 KB per buffer
- Reuse: Same buffers cycled through pool
- Memory usage: Stabilizes at pool size × buffer size
- GC pressure: Minimal (only new buffers when pool empty)

The pool automatically scales: when demand is high, it keeps more buffers; when demand is low, excess buffers are garbage collected.

### 5. Receiver Congestion Control (`congestion/live/receive.go` lines 134-255)

The receiver handles packet ordering, duplicates, and gaps:

```go
func (r *receiver) Push(pkt packet.Packet) {
    // 1. Link capacity probing (packets 16 and 17)
    if !pkt.Header().RetransmittedPacketFlag {
        probe := pkt.Header().PacketSequenceNumber.Val() & 0xF
        if probe == 0 {
            r.probeTime = time.Now()
        } else if probe == 1 {
            // Calculate link capacity from time between probe packets
        }
    }

    // 2. Check if packet is too old (already delivered)
    if pkt.Header().PacketSequenceNumber.Lte(r.lastDeliveredSequenceNumber) {
        // Drop belated packet
        return
    }

    // 3. Check if already acknowledged
    if pkt.Header().PacketSequenceNumber.Lt(r.lastACKSequenceNumber) {
        // Drop duplicate
        return
    }

    // 4. Handle in-order vs out-of-order
    if pkt.Header().PacketSequenceNumber.Equals(r.maxSeenSequenceNumber.Inc()) {
        // In order - expected packet
        r.maxSeenSequenceNumber = pkt.Header().PacketSequenceNumber
    } else if pkt.Header().PacketSequenceNumber.Lte(r.maxSeenSequenceNumber) {
        // Out of order - insert in correct position
        // (filling a gap)
    } else {
        // Gap detected - send immediate NAK
        r.sendNAK([...])
        r.maxSeenSequenceNumber = pkt.Header().PacketSequenceNumber
    }

    // 5. Add to ordered packet list
    r.packetList.PushBack(pkt)
}
```

**Receiver operations:**
- **Ordering**: Maintains ordered list of received packets
- **Gap detection**: Sends NAK for missing sequence numbers
- **Duplicate handling**: Drops already-acknowledged packets
- **Link capacity**: Measures capacity from probe packets

### 6. Receiver Tick - Delivery (`congestion/live/receive.go` lines 363-415)

Periodically delivers packets to the application:

```go
func (r *receiver) Tick(now uint64) {
    // 1. Send periodic ACK
    if ok, seq, lite := r.periodicACK(now); ok {
        r.sendACK(seq, lite)
    }

    // 2. Send periodic NAK for gaps
    if list := r.periodicNAK(now); len(list) != 0 {
        r.sendNAK(list)
    }

    // 3. Deliver packets whose TSBPD time has arrived
    for e := r.packetList.Front(); e != nil; e = e.Next() {
        p := e.Value.(packet.Packet)

        // Only deliver if:
        // - Already ACK'd (in sequence)
        // - TSBPD time has arrived
        if p.Header().PacketSequenceNumber.Lte(r.lastACKSequenceNumber) &&
           p.Header().PktTsbpdTime <= now {
            r.deliver(p)  // Send to application
            r.packetList.Remove(e)
        } else {
            break  // Packets are ordered
        }
    }
}
```

**Delivery conditions:**
- **In sequence**: Packet must be ≤ `lastACKSequenceNumber`
- **TSBPD ready**: `PktTsbpdTime <= current_time`
- **Ordered delivery**: Packets delivered in sequence order

### 7. Application Read (`connection.go` lines 622-631)

Packets are delivered to the application via `readQueue`:

```go
func (c *srtConn) deliver(p packet.Packet) {
    // Non-blocking write to read queue
    select {
    case c.readQueue <- p:
    default:
        // Queue full, drop packet
    }
}

// Application calls Read() which reads from readQueue
```

**Summary of receiving flow:**
```
UDP Socket Read()
    ↓
rcvQueue (listener)
    ↓
listener.reader() - route by socket ID
    ↓
connection.push() - networkQueue
    ↓
networkQueueReader goroutine
    ↓
handlePacket() - decrypt, calculate TSBPD
    ↓
receiver.Push() - ordering, gap detection
    ↓
receiver.Tick() - deliver when TSBPD ready
    ↓
readQueue → Application Read()
```

---

## How RTT (Round Trip Time) is Currently Calculated

The SRT protocol implementation uses **two methods** to calculate RTT, following the SRT specification (Section 4.10 - Round-Trip Time Estimation).

### 1. RTT Smoothing Algorithm

The RTT is stored as a smoothed value using an **Exponentially Weighted Moving Average (EWMA)**:

**Location**: `connection.go` lines 79-88

```go
func (r *rtt) Recalculate(rtt time.Duration) {
    // 4.10.  Round-Trip Time Estimation
    lastRTT := float64(rtt.Microseconds())

    r.lock.Lock()
    defer r.lock.Unlock()

    // Smoothing: 87.5% old value, 12.5% new measurement
    r.rtt = r.rtt*0.875 + lastRTT*0.125

    // RTT Variance: 75% old variance, 25% absolute difference
    r.rttVar = r.rttVar*0.75 + math.Abs(r.rtt-lastRTT)*0.25
}
```

**Initial Values** (line 277-280):
- Initial RTT: 100ms
- Initial RTT Variance: 50ms

### 2. Method 1: RTT from Peer's ACK Packet

When receiving a **full ACK packet** from the peer, the peer includes its own RTT measurement.

**Location**: `connection.go` lines 775-807

```go
func (c *srtConn) handleACK(p packet.Packet) {
    // ... unmarshal ACK packet ...

    if !cif.IsLite && !cif.IsSmall {
        // 4.10.  Round-Trip Time Estimation
        // The peer's RTT measurement is included in the ACK packet
        c.recalculateRTT(time.Duration(int64(cif.RTT)) * time.Microsecond)

        c.sendACKACK(p.Header().TypeSpecific)
    }
}
```

The peer calculates its RTT and includes it in the `CIFACK.RTT` field (see `packet/packet.go` line 1170).

### 3. Method 2: RTT from ACK-ACKACK Exchange

When sending an ACK, the local side records the timestamp. When the corresponding ACKACK is received, it calculates the RTT.

**Location**: `connection.go` lines 1228-1277 (sending ACK) and 833-864 (receiving ACKACK)

**Sending ACK** (line 1260):
```go
func (c *srtConn) sendACK(seq circular.Number, lite bool) {
    // ...
    if !lite {
        // Record timestamp when sending ACK
        p.Header().TypeSpecific = c.nextACKNumber.Val()
        c.ackNumbers[p.Header().TypeSpecific] = time.Now()  // <-- Timestamp stored
        c.nextACKNumber = c.nextACKNumber.Inc()
    }
    // ...
}
```

**Receiving ACKACK** (line 844-846):
```go
func (c *srtConn) handleACKACK(p packet.Packet) {
    // p.typeSpecific is the ACKNumber
    if ts, ok := c.ackNumbers[p.Header().TypeSpecific]; ok {
        // 4.10.  Round-Trip Time Estimation
        // Calculate RTT: time since we sent the ACK
        c.recalculateRTT(time.Since(ts))  // <-- RTT = now - send_time
        delete(c.ackNumbers, p.Header().TypeSpecific)
    }
    // ...
}
```

### Summary of RTT Calculation Flow

1. **Initialization**: RTT starts at 100ms, RTTVar at 50ms
2. **Updates occur**:
   - When receiving a full ACK (uses peer's RTT measurement)
   - When receiving an ACKACK (measures local ACK→ACKACK time)
3. **Smoothing**: Each new measurement is blended 12.5% into the smoothed RTT
4. **Variance**: Tracks RTT variability for NAK interval calculation

---

## Adding One-Way Latency Calculation

**Yes, it is definitely possible to add one-way latency calculations!** Here's how:

### Approach: Track Send and Receive Timestamps

The SRT protocol already includes timestamps in packet headers. We can leverage this to calculate:

1. **Send-to-Receive Latency** (outgoing): Time from when we send a data packet until the peer receives it
2. **Receive-to-Send Latency** (incoming): Time from when we receive a data packet until we send an ACK

### Implementation Strategy

#### Option 1: Using Packet Timestamps (Simpler)

The packet header already has a `Timestamp` field that represents when the packet was sent (relative to connection start).

**For Send-to-Receive Latency**:
- When sending a data packet, record the send time with the sequence number
- When receiving an ACK for that sequence number, calculate: `receive_time - send_time`
- This gives the one-way latency from sender to receiver

**For Receive-to-Send Latency**:
- When receiving a data packet, record the receive time with the sequence number
- When sending an ACK, include the receive timestamp
- The peer can calculate: `ack_send_time - data_receive_time`

#### Option 2: Using ACK Timestamps (More Accurate)

Similar to how RTT uses ACKACK, we can track:
- When a data packet is sent, record timestamp with sequence number
- When ACK is received, calculate one-way latency
- This requires the peer to echo back the original packet timestamp

### Code Locations to Modify

1. **Track send times**: In `congestion/live/send.go` when packets are sent (around line 144)
2. **Track receive times**: In `connection.go` when data packets are received (around line 722)
3. **Calculate latency**: In `handleACK` or create a new method similar to `recalculateRTT`
4. **Store latency**: Add fields to the `rtt` struct or create a new `oneWayLatency` struct
5. **Expose in statistics**: Add to `StatisticsInstantaneous` in `statistics.go`

### Example Structure

```go
type oneWayLatency struct {
    sendToRecv    float64 // microseconds (outgoing)
    recvToSend    float64 // microseconds (incoming)
    sendToRecvVar float64 // variance
    recvToSendVar float64 // variance
    lock          sync.RWMutex
}

// Track when packets are sent
func (c *srtConn) trackSentPacket(seq circular.Number) {
    c.sentPacketTimes[seq.Val()] = time.Now()
}

// Calculate latency when ACK received
func (c *srtConn) calculateOneWayLatency(seq circular.Number) {
    if sendTime, ok := c.sentPacketTimes[seq.Val()]; ok {
        latency := time.Since(sendTime)
        c.oneWayLatency.updateSendToRecv(latency)
        delete(c.sentPacketTimes, seq.Val())
    }
}
```

### Considerations

1. **Clock Synchronization**: One-way latency assumes clocks are synchronized. For accurate measurements, you may need NTP or similar.
2. **Packet Reordering**: Need to handle out-of-order packets correctly
3. **Retransmissions**: Should only measure latency for first transmission, not retransmissions
4. **Statistics**: Similar EWMA smoothing as RTT would be appropriate

### Benefits

- **Network Diagnostics**: Identify asymmetric network paths
- **Quality Monitoring**: Detect one-way delays that might not show in RTT
- **Congestion Control**: Better understand network conditions

---

## Current RTT Usage

The RTT is used for:
1. **NAK Interval Calculation** (line 104-114): Determines when to send NAK packets for lost packets
2. **Statistics** (line 1520): Exposed as `MsRTT` in connection statistics
3. **ACK Packets** (line 1251): Included in ACK packets sent to peer

---

## Comparison with Linux Kernel CUBIC Implementation

The Linux kernel's TCP implementation (used by CUBIC and other congestion control algorithms) uses a more sophisticated RTT estimation algorithm based on **RFC 6298** and **Van Jacobson's algorithm** from SIGCOMM '88.

### Linux Kernel Implementation (`tcp_rtt_estimator`)

The kernel's `tcp_rtt_estimator()` function in `tcp_input.c` implements:

```c
static void tcp_rtt_estimator(struct sock *sk, long mrtt_us)
{
    struct tcp_sock *tp = tcp_sk(sk);
    long m = mrtt_us; /* RTT */
    u32 srtt = tp->srtt_us;

    if (srtt != 0) {
        m -= (srtt >> 3);        /* m is now error in rtt est */
        srtt += m;               /* rtt = 7/8 rtt + 1/8 new */
        if (m < 0) {
            m = -m;              /* m is now abs(error) */
            m -= (tp->mdev_us >> 2);   /* similar update on mdev */
            if (m > 0)
                m >>= 3;
        } else {
            m -= (tp->mdev_us >> 2);   /* similar update on mdev */
        }
        tp->mdev_us += m;        /* mdev = 3/4 mdev + 1/4 new */
        // ... additional logic for mdev_max_us and rttvar_us ...
    } else {
        /* no previous measure. */
        srtt = m << 3;           /* take the measured time to be rtt */
        tp->mdev_us = m << 1;    /* make sure rto = 3*rtt */
        // ...
    }
    tp->srtt_us = max(1U, srtt);
}
```

**Key differences from gosrt:**

1. **Integer arithmetic with bit shifts**: The kernel uses integer math with bit shifts (`>> 3` = divide by 8, `<< 3` = multiply by 8) for performance, while gosrt uses floating-point arithmetic.

2. **Same EWMA weights**: Both use **α = 1/8 = 0.125** for SRTT:
   - Kernel: `srtt += m` where `m = (new_rtt - srtt/8)`, effectively `srtt = 7/8 * srtt + 1/8 * new_rtt`
   - gosrt: `r.rtt = r.rtt*0.875 + lastRTT*0.125` (same formula)

3. **Variance calculation**:
   - **Kernel**: Uses "mean deviation" (`mdev_us`) with **β = 1/4 = 0.25**:
     - `mdev = 3/4 * mdev + 1/4 * |error|`
     - Also tracks `mdev_max_us` and `rttvar_us` (RTT variance) separately
   - **gosrt**: Uses variance directly with **β = 1/4 = 0.25**:
     - `rttVar = 0.75 * rttVar + 0.25 * |RTT - new_measurement|`
   - **Same weights, different approach**: Both use 75%/25% split, but kernel tracks mean deviation first, then derives variance.

4. **Asymmetric error handling**: The kernel has special handling when RTT decreases (`m < 0`), applying an additional `>> 3` shift to prevent too-fast RTO decreases. This is an **Eifel-inspired improvement** to prevent spurious retransmissions.

5. **Initialization**:
   - **Kernel**: On first measurement, `srtt = measured_rtt * 8` (scaled), `mdev = measured_rtt * 2`
   - **gosrt**: Fixed initial values (100ms RTT, 50ms RTTVar)

6. **RTO calculation**: The kernel uses `RTO = srtt + 4 * rttvar` (RFC 6298), while gosrt uses RTT for NAK interval: `NAKInterval = (rtt + 4*rttVar) / 2` with a 20ms minimum.

### Summary

| Aspect | gosrt | Linux Kernel (CUBIC) |
|--------|-------|---------------------|
| **SRTT EWMA α** | 0.125 (1/8) | 0.125 (1/8) |
| **Variance EWMA β** | 0.25 (1/4) | 0.25 (1/4) |
| **Arithmetic** | Floating-point | Integer (bit shifts) |
| **Error handling** | Symmetric | Asymmetric (Eifel-inspired) |
| **Initialization** | Fixed (100ms/50ms) | Based on first sample |
| **Complexity** | Simple, direct | More sophisticated |

**Conclusion**: Both implementations use the **same core EWMA algorithm** with identical weights (α=1/8, β=1/4), following RFC 6298. The kernel's version is more optimized (integer math) and includes additional refinements for edge cases, but the fundamental smoothing behavior is the same. The gosrt implementation is simpler and more readable, which is appropriate for a user-space implementation.

---

## Packet Unmarshaling Implementation

The `Unmarshal` method in `packet/packet.go` does **NOT use reflection**. Instead, it uses **manual bit-level parsing** for maximum performance. This is a zero-reflection, zero-allocation approach (except for the payload buffer).

### How `NewPacketFromData` Works

**Location**: `packet/packet.go` lines 280-291, 369-396

```go
func NewPacketFromData(addr net.Addr, rawdata []byte) (Packet, error) {
    p := NewPacket(addr)

    if len(rawdata) != 0 {
        if err := p.Unmarshal(rawdata); err != nil {
            p.Decommission()
            return nil, fmt.Errorf("invalid data: %w", err)
        }
    }

    return p, nil
}
```

### The `Unmarshal` Method - Manual Binary Parsing

The `Unmarshal` method manually parses the SRT packet format byte-by-byte:

```go
func (p *pkt) Unmarshal(data []byte) error {
    if len(data) < 16 {
        return fmt.Errorf("data too short to unmarshal")
    }

    // 1. Determine packet type from first bit
    p.header.IsControlPacket = (data[0] & 0x80) != 0

    if p.header.IsControlPacket {
        // Control packet format (bytes 0-7)
        p.header.ControlType = CtrlType(binary.BigEndian.Uint16(data[0:]) & ^uint16(1<<15))
        p.header.SubType = CtrlSubType(binary.BigEndian.Uint16(data[2:]))
        p.header.TypeSpecific = binary.BigEndian.Uint32(data[4:])
    } else {
        // Data packet format (bytes 0-7)
        p.header.PacketSequenceNumber = circular.New(
            binary.BigEndian.Uint32(data[0:]), MAX_SEQUENCENUMBER)

        // Byte 4 contains multiple packed fields - extract with bitwise ops
        p.header.PacketPositionFlag = PacketPosition((data[4] & 0b11000000) >> 6)
        p.header.OrderFlag = (data[4] & 0b00100000) != 0
        p.header.KeyBaseEncryptionFlag = PacketEncryption((data[4] & 0b00011000) >> 3)
        p.header.RetransmittedPacketFlag = (data[4] & 0b00000100) != 0
        p.header.MessageNumber = binary.BigEndian.Uint32(data[4:]) & ^uint32(0b11111100<<24)
    }

    // Common fields (bytes 8-15)
    p.header.Timestamp = binary.BigEndian.Uint32(data[8:])
    p.header.DestinationSocketId = binary.BigEndian.Uint32(data[12:])

    // Payload (bytes 16+)
    p.payload.Reset()
    p.payload.Write(data[16:])

    return nil
}
```

### Key Techniques Used

1. **Direct byte array indexing**: `data[0]`, `data[4]`, `data[8]`, etc.
   - No reflection, no struct tags, no runtime type inspection

2. **Big-endian integer reading**: `binary.BigEndian.Uint16()`, `binary.BigEndian.Uint32()`
   - Network byte order (big-endian) as per SRT spec
   - Efficient, compiler-optimized functions

3. **Bitwise operations for packed fields**:
   ```go
   // Extract 2-bit field from bits 6-7
   PacketPositionFlag = (data[4] & 0b11000000) >> 6

   // Extract single bit flag
   OrderFlag = (data[4] & 0b00100000) != 0

   // Extract 2-bit field from bits 3-4
   KeyBaseEncryptionFlag = (data[4] & 0b00011000) >> 3
   ```

4. **Bit masking to clear bits**:
   ```go
   // Clear the control packet flag bit (bit 15)
   ControlType = binary.BigEndian.Uint16(data[0:]) & ^uint16(1<<15)

   // Clear upper bits to extract MessageNumber
   MessageNumber = binary.BigEndian.Uint32(data[4:]) & ^uint32(0b11111100<<24)
   ```

### SRT Packet Header Layout

The SRT packet format (16-byte header):

```
Bytes 0-3:   [Control/Data packet type dependent]
Bytes 4-7:   [Control/Data packet type dependent]
Bytes 8-11:  Timestamp (uint32, big-endian)
Bytes 12-15: Destination Socket ID (uint32, big-endian)
Bytes 16+:   Payload
```

**For Data Packets:**
- Bytes 0-3: Packet Sequence Number (uint32)
- Byte 4: Packed flags:
  - Bits 7-6: PacketPositionFlag (2 bits)
  - Bit 5: OrderFlag (1 bit)
  - Bits 4-3: KeyBaseEncryptionFlag (2 bits)
  - Bit 2: RetransmittedPacketFlag (1 bit)
  - Bits 1-0: Lower bits of MessageNumber
- Bytes 5-7: Remaining bits of MessageNumber

**For Control Packets:**
- Bytes 0-1: ControlType (uint16, bit 15 = control flag)
- Bytes 2-3: SubType (uint16)
- Bytes 4-7: TypeSpecific (uint32)

### Why Not Use Reflection?

**Performance benefits of manual parsing:**
1. **Zero reflection overhead**: No runtime type inspection
2. **Compiler optimizations**: Direct memory access, no interface conversions
3. **Predictable performance**: No dynamic dispatch
4. **Memory efficient**: Only allocates payload buffer (from pool)
5. **Type safety**: Compile-time checked field assignments

**Comparison with reflection-based approaches:**
- `encoding/binary` with struct tags: Would require reflection for struct field mapping
- `encoding/json`: Uses reflection extensively, much slower
- Manual parsing: Fastest, most control, but more verbose

### The Corresponding `Marshal` Method

The `Marshal` method (lines 398-441) does the reverse - it packs the struct fields back into binary format using the same techniques:

```go
func (p *pkt) Marshal(w io.Writer) error {
    var buffer [16]byte

    if p.header.IsControlPacket {
        binary.BigEndian.PutUint16(buffer[0:], p.header.ControlType.Value())
        binary.BigEndian.PutUint16(buffer[2:], p.header.SubType.Value())
        binary.BigEndian.PutUint32(buffer[4:], p.header.TypeSpecific)
        buffer[0] |= 0x80  // Set control packet flag
    } else {
        binary.BigEndian.PutUint32(buffer[0:], p.header.PacketSequenceNumber.Val())

        // Pack multiple fields into byte 4
        var field uint32 = 0
        field |= ((p.header.PacketPositionFlag.Val() & 0b11) << 6)
        if p.header.OrderFlag {
            field |= (1 << 5)
        }
        field |= ((p.header.KeyBaseEncryptionFlag.Val() & 0b11) << 3)
        if p.header.RetransmittedPacketFlag {
            field |= (1 << 2)
        }
        field = field << 24
        field += (p.header.MessageNumber & 0b00000011_11111111_11111111_11111111)

        binary.BigEndian.PutUint32(buffer[4:], field)
    }

    binary.BigEndian.PutUint32(buffer[8:], p.header.Timestamp)
    binary.BigEndian.PutUint32(buffer[12:], p.header.DestinationSocketId)

    w.Write(buffer[0:])
    w.Write(p.payload.Bytes())

    return nil
}
```

**Summary**: The unmarshaling is a **highly optimized, manual binary protocol parser** that directly maps bytes to struct fields using bitwise operations and big-endian integer reading. This approach is common in high-performance network protocols where every nanosecond counts.

---

## Channel Buffer Sizes

The SRT implementation uses several buffered channels to queue packets between different stages of processing. All channels are **non-blocking** (buffered), meaning writes will only block if the buffer is full.

### Connection-Level Channels (`connection.go`)

**Location**: Lines 182-190 (declarations), 282-294 (initialization)

| Channel | Buffer Size | Purpose | Location |
|---------|-------------|---------|----------|
| `networkQueue` | **1024 packets** | Queues packets received from UDP socket before processing | Line 282 |
| `writeQueue` | **1024 packets** | Queues packets from application `Write()` before congestion control | Line 284 |
| `readQueue` | **1024 packets** | Queues packets ready for application `Read()` after receiver processing | Line 294 |

**Code:**
```go
c.networkQueue = make(chan packet.Packet, 1024)
c.writeQueue = make(chan packet.Packet, 1024)
c.readQueue = make(chan packet.Packet, 1024)
```

### Listener-Level Channels (`listen.go`)

**Location**: Lines 124-131 (declarations), 196-198 (initialization)

| Channel | Buffer Size | Purpose | Location |
|---------|-------------|---------|----------|
| `backlog` | **128 packets** | Queues handshake packets (socket ID = 0) before connection establishment | Line 196 |
| `rcvQueue` | **2048 packets** | Queues all incoming UDP packets from socket before routing to connections | Line 198 |

**Code:**
```go
ln.backlog = make(chan packet.Packet, 128)
ln.rcvQueue = make(chan packet.Packet, 2048)
```

### Dialer-Level Channels (`dial.go`)

**Location**: Lines 42-46 (declarations), 113-117 (initialization)

| Channel | Buffer Size | Purpose | Location |
|---------|-------------|---------|----------|
| `rcvQueue` | **2048 packets** | Queues incoming UDP packets from socket before processing | Line 115 |
| `connChan` | **Unbuffered** | Synchronous channel for connection establishment response | Line 113 |

**Code:**
```go
dl.rcvQueue = make(chan packet.Packet, 2048)
dl.connChan = make(chan connResponse)  // Unbuffered
```

### Channel Size Rationale

**Why these sizes?**

1. **1024 packets for connection queues**:
   - Provides buffering for ~1-2 seconds of video at typical bitrates
   - Prevents blocking during brief processing delays
   - At 1456 bytes/packet: ~1.5 MB per queue

2. **2048 packets for UDP receive queues**:
   - Larger buffer to handle UDP packet bursts
   - Must accommodate all connections sharing the listener/dialer
   - At 1456 bytes/packet: ~3 MB per queue

3. **128 packets for backlog**:
   - Smaller buffer for handshake packets only
   - Handshakes are infrequent, don't need large buffer
   - Prevents SYN flood attacks by limiting queue size

**Memory footprint per connection:**
- Connection channels: 3 × 1024 packets ≈ 4.5 MB
- Plus congestion control buffers (sender/receiver packet lists)
- Plus retransmission buffers

**Non-blocking behavior:**
All channel writes use `select` with `default` case, so they will:
- **Succeed immediately** if buffer has space
- **Drop/log error** if buffer is full (prevents deadlocks)

Example from `connection.go` line 502:
```go
select {
case <-c.ctx.Done():
    return 0, io.EOF
case c.writeQueue <- p:
default:
    return 0, io.EOF  // Queue full, fail fast
}
```

