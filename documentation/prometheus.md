# Prometheus

## Introduction

This document describes how Prometheus metrics are going to be added to the SRT server project.

The Prometheus metrics are added to allow for detailed analysis of the internals of goSRT while it is running.  Prometheus will allow the metrics to be observed over the long term in a time series database.

This document will be used to clarify the design and implementation details before any code changes.

## High Level Design

To add the Prometheus metrics is relatively simple:
1. We will add a new ENVIRONMENT variable to allow setting the listening address.  This will allow users to set the listen address to 127.0.0.1 to listen only locally, or it will default to 0.0.0.0 so that the HTTP listener will listen on all interfaces.
2. In server.go we will add a HTTP listener to listen on a standard Prometheus port (default: 9000).  We will use the standard go http router, in the simplest implementation possible.
3. Metrics will be instrumented in key functions across the codebase, focusing on RTT calculations, packet processing, and channel operations as described in RTT_Calculations.md.


## Draft Prometheus Init Code

```
const(
	promListenCst           = ":9000" // [::1]:9000
	promPathCst             = "/metrics"
	promMaxRequestsInFlight = 10
	promEnableOpenMetrics   = true

	quantileError    = 0.05
	summaryVecMaxAge = 5 * time.Minute
)

// initPromHandler starts the prom handler with error checking
// https://pkg.go.dev/github.com/prometheus/client_golang/prometheus/promhttp?tab=doc#HandlerOpts
func initPromHandler(promPath string, promListen string) {
	http.Handle(promPath, promhttp.HandlerFor(
		prometheus.DefaultGatherer,
		promhttp.HandlerOpts{
			EnableOpenMetrics:   promEnableOpenMetrics,
			MaxRequestsInFlight: promMaxRequestsInFlight,
		},
	))
	go func() {
		err := http.ListenAndServe(promListen, nil)
		if err != nil {
			log.Fatal("prometheus error", err)
		}
	}()
}

// environmentOverrideProm MUTATES promListen, promPath, if the environment
// variables exist.  This allows over riding the cli flags
//
//lint:ignore SA4009 this is nasty, but it's going to be ok
func environmentOverrideProm(promListen, promPath *string, debugLevel uint) {
	key := "PROM_LISTEN"
	if value, exists := os.LookupEnv(key); exists {
		promListen = &value
		if debugLevel > 10 {
			log.Printf("key:%s, c.PromListen:%s", key, *promListen)
		}
	}

	key = "PROM_PATH"
	if value, exists := os.LookupEnv(key); exists {
		promPath = &value
		if debugLevel > 10 {
			log.Printf("key:%s, c.PromListen:%s", key, *promPath)
		}
	}
}
```

## HTTP Listener Setup

The Prometheus HTTP listener will be initialized in `server.go` during server startup. The implementation will follow this approach:

### Integration Point

The Prometheus HTTP server will be started in the `Server.Listen()` method in `server.go`, after the SRT listener is successfully initialized. This ensures that:

1. The Prometheus metrics endpoint is available as soon as the server is ready to accept connections
2. The HTTP server runs in a separate goroutine and does not block the main SRT server
3. The HTTP server can be configured independently from the SRT listener

### Server Struct Fields

To allow programmatic configuration of the Prometheus HTTP listener (similar to how `Addr` configures the SRT listener), we should add two fields to the `Server` struct:

**Location**: `server.go` - `Server` struct definition

```go
// Server is a framework for a SRT server
type Server struct {
    // The address the SRT server should listen on, e.g. ":6001".
    Addr string

    // The address the Prometheus HTTP server should listen on, e.g. ":9000".
    // If empty, defaults to the value from PROM_LISTEN environment variable,
    // or ":9000" if the environment variable is not set.
    AddrProm string

    // The HTTP path for the Prometheus metrics endpoint, e.g. "/metrics".
    // If empty, defaults to the value from PROM_PATH environment variable,
    // or "/metrics" if the environment variable is not set.
    PromPath string

    // Config is the configuration for a SRT listener.
    Config *Config

    // ... other fields ...
}
```

**Initialization Priority**:
1. **First**: Use `s.AddrProm` if set (non-empty)
2. **Second**: Use `PROM_LISTEN` environment variable if set
3. **Third**: Use default constant `promListenDefault` (":9000")

Same priority applies to `PromPath`:
1. **First**: Use `s.PromPath` if set (non-empty)
2. **Second**: Use `PROM_PATH` environment variable if set
3. **Third**: Use default constant `promPathDefault` ("/metrics")

### Implementation Details

**Location**: `server.go` - `Server.Listen()` method (after line 82, where `s.ln = ln`)

**Initialization Flow**:
1. Determine Prometheus listen address: use `s.AddrProm` if set, otherwise call `environmentOverrideProm()` to get from environment or defaults
2. Determine Prometheus path: use `s.PromPath` if set, otherwise call `environmentOverrideProm()` to get from environment or defaults
3. Call `initPromHandler()` to register the Prometheus handler with the default HTTP mux
4. Start the HTTP server in a background goroutine using `http.ListenAndServe()`
5. The HTTP server will use the standard `net/http` package with the default mux (`http.DefaultServeMux`)

**Configuration**:
- **Default Listen Address**: `:9000` (listens on all interfaces, port 9000)
- **Default Metrics Path**: `/metrics`
- **Server Field Override**: `s.AddrProm` (e.g., `"127.0.0.1:9000"` for local-only access)
- **Server Field Override**: `s.PromPath` (e.g., `"/prometheus/metrics"`)
- **Environment Variable Override**: `PROM_LISTEN` (e.g., `127.0.0.1:9000` for local-only access)
- **Environment Variable Override**: `PROM_PATH` (e.g., `/prometheus/metrics`)

**Security Considerations**:
- Users can restrict access by setting `AddrProm="127.0.0.1:9000"` to listen only on localhost
- The HTTP server runs independently and does not affect SRT connection handling
- No authentication is implemented at the HTTP level (users should use firewall rules or reverse proxy if needed)

**Error Handling**:
- If the HTTP server fails to start, it will log a fatal error
- The SRT server will continue to operate normally even if Prometheus metrics are unavailable
- The HTTP server runs in a separate goroutine, so failures do not crash the main server

### Code Structure

```go
// In server.go, Server.Listen() method:
func (s *Server) Listen() error {
    // ... existing SRT listener setup ...

    s.ln = ln

    // Initialize Prometheus HTTP listener
    // Priority: s.AddrProm > PROM_LISTEN env var > default
    promListen := promListenDefault
    promPath := promPathDefault

    if s.AddrProm != "" {
        // Use server field if set
        if validateListenAddress(s.AddrProm) {
            promListen = s.AddrProm
        } else {
            log.Printf("prometheus: invalid AddrProm value '%s', using default '%s'", s.AddrProm, promListenDefault)
        }
    } else {
        // Fall back to environment variable or default
        promListen, _ = environmentOverrideProm()
    }

    if s.PromPath != "" {
        // Use server field if set
        if validateMetricsPath(s.PromPath) {
            promPath = s.PromPath
        } else {
            log.Printf("prometheus: invalid PromPath value '%s', using default '%s'", s.PromPath, promPathDefault)
        }
    } else {
        // Fall back to environment variable or default
        _, promPath = environmentOverrideProm()
    }

    initPromHandler(promPath, promListen)

    return err
}
```

**Alternative Implementation** (if we want to modify `environmentOverrideProm` to accept server fields):

We could modify `environmentOverrideProm()` to accept optional server field values:

```go
// environmentOverrideProm returns the Prometheus listen address and path,
// using the provided server field values if set, otherwise falling back to
// environment variables, and finally to defaults.
//
// Parameters:
//   - serverAddrProm: Optional server field value (empty string means not set)
//   - serverPromPath: Optional server field value (empty string means not set)
//
// Returns:
//   - promListen: The listen address (priority: server field > env var > default)
//   - promPath: The metrics path (priority: server field > env var > default)
func environmentOverrideProm(serverAddrProm, serverPromPath string) (promListen, promPath string) {
    // Determine listen address
    if serverAddrProm != "" {
        if validateListenAddress(serverAddrProm) {
            promListen = serverAddrProm
        } else {
            log.Printf("prometheus: invalid AddrProm value '%s', using default '%s'", serverAddrProm, promListenDefault)
            promListen = promListenDefault
        }
    } else {
        promListen = promListenDefault
        if value, exists := os.LookupEnv("PROM_LISTEN"); exists {
            if validateListenAddress(value) {
                promListen = value
            } else {
                log.Printf("prometheus: invalid PROM_LISTEN value '%s', using default '%s'", value, promListenDefault)
            }
        }
    }

    // Determine metrics path
    if serverPromPath != "" {
        if validateMetricsPath(serverPromPath) {
            promPath = serverPromPath
        } else {
            log.Printf("prometheus: invalid PromPath value '%s', using default '%s'", serverPromPath, promPathDefault)
            promPath = promPathDefault
        }
    } else {
        promPath = promPathDefault
        if value, exists := os.LookupEnv("PROM_PATH"); exists {
            if validateMetricsPath(value) {
                promPath = value
            } else {
                log.Printf("prometheus: invalid PROM_PATH value '%s', using default '%s'", value, promPathDefault)
            }
        }
    }

    return promListen, promPath
}
```

Then in `Server.Listen()`:

```go
// Initialize Prometheus HTTP listener
promListen, promPath := environmentOverrideProm(s.AddrProm, s.PromPath)
initPromHandler(promPath, promListen)
```

This approach centralizes the priority logic in one function and makes it easier to maintain.

### Usage Example

```go
// Example 1: Use default values (":9000" and "/metrics")
server := &Server{
    Addr: ":6001",
    // AddrProm and PromPath are empty, will use defaults
}

// Example 2: Configure via server fields
server := &Server{
    Addr:     ":6001",
    AddrProm: "127.0.0.1:9000",  // Listen only on localhost
    PromPath: "/metrics",         // Use standard path
}

// Example 3: Override via environment variables (when server fields are empty)
// Set PROM_LISTEN=127.0.0.1:9001 and PROM_PATH=/prometheus/metrics
server := &Server{
    Addr: ":6001",
    // AddrProm and PromPath are empty, will use environment variables
}
```

## Go Files for Metrics Instrumentation

The following Go files will have Prometheus metrics added to instrument key functions and operations:

### 1. `server.go`
**Purpose**: Server-level metrics and Prometheus HTTP listener initialization
**Metrics to Add**:
- Server startup/shutdown events
- Active connection count (gauge)
- Connection acceptance rate (counter)
- Connection rejection count (counter)

### 2. `connection.go`
**Purpose**: Connection-level metrics, RTT calculations, and packet handling
**Key Functions to Instrument**:
- `Write()` (lines 481-515): Application write operations, packet creation
- `Read()`: Application read operations
- `handlePacket()` (lines 636-744): Packet processing time, packet type distribution
- `handleACK()` (lines 775-807): ACK processing, RTT updates from peer
- `handleACKACK()` (lines 833-864): ACKACK processing, RTT calculation from ACK-ACKACK exchange
- `recalculateRTT()` (lines 79-88): RTT smoothing algorithm execution time
- `push()` (lines 518-526): Network queue operations
- `networkQueueReader()` (lines 589-602): Network queue processing
- `writeQueueReader()` (lines 606-620): Write queue processing
- `deliver()`: Packet delivery to application

**Metrics to Add**:
- Function call counts and durations
- RTT values (gauge) and RTT variance (gauge)
- Packet processing latency (histogram)
- Queue operation counts and blocking durations

### 3. `congestion/live/send.go`
**Purpose**: Sender-side congestion control metrics
**Key Functions to Instrument**:
- `Push()` (lines 120-162): Packet sequence number assignment, timestamp setting
- `Tick()` (lines 164-197): Packet transmission timing, packet delivery
- `deliver()`: Packet transmission to network

**Metrics to Add**:
- Packet send rate (counter)
- Sequence number assignment operations
- Transmission timing (histogram)
- Link capacity probe measurements (gauge)

### 4. `congestion/live/receive.go`
**Purpose**: Receiver-side congestion control metrics
**Key Functions to Instrument**:
- `Push()` (lines 134-255): Packet ordering, gap detection, duplicate handling
- `Tick()` (lines 363-415): Periodic ACK/NAK sending, packet delivery timing
- `deliver()`: Packet delivery to application

**Metrics to Add**:
- Packet receive rate (counter)
- Out-of-order packet count (counter)
- Gap detection count (counter)
- Duplicate packet count (counter)
- ACK/NAK send rates (counter)
- Packet delivery latency (histogram)

### 5. `listen.go`
**Purpose**: Listener-level metrics for incoming connections
**Key Functions to Instrument**:
- UDP socket read operations (lines 216-252): Packet reception from network
- `reader()` (lines 375-424): Packet routing to connections
- `Accept2()`: Connection acceptance

**Metrics to Add**:
- UDP packet receive rate (counter)
- Packet routing operations (counter)
- Connection acceptance rate (counter)
- Backlog queue operations (counter)
- `rcvQueue` channel blocking (histogram)

### 6. `dial.go`
**Purpose**: Dialer-level metrics for outgoing connections
**Key Functions to Instrument**:
- UDP socket read operations: Packet reception from network
- `send()` (lines 258-281): Packet transmission to network
- Connection establishment operations

**Metrics to Add**:
- UDP packet send/receive rates (counter)
- Connection establishment attempts (counter)
- `rcvQueue` channel operations (counter)

### 7. Channel Operations (Multiple Files)
**Purpose**: Monitor channel blocking and queue health
**Channels to Instrument**:
- `connection.go`: `networkQueue`, `writeQueue`, `readQueue` (1024 packet buffers)
- `listen.go`: `backlog` (128 packet buffer), `rcvQueue` (2048 packet buffer)
- `dial.go`: `rcvQueue` (2048 packet buffer)

**Metrics to Add**:
- Channel blocking duration (histogram)
- Channel blocking count (counter)
- Longest blocked duration (gauge)
- Channel utilization (gauge: current queue length / buffer size)

### Metrics Focus Areas

Based on `RTT_Calculations.md`, the instrumentation will prioritize:

1. **RTT Calculation Functions**:
   - `recalculateRTT()` - RTT smoothing algorithm
   - `handleACK()` - RTT from peer's ACK packet
   - `handleACKACK()` - RTT from ACK-ACKACK exchange

2. **Packet Flow Functions**:
   - Sending flow: `Write()` → `writeQueueReader()` → `sender.Push()` → `sender.Tick()` → `pop()`
   - Receiving flow: UDP read → `listener.reader()` → `push()` → `networkQueueReader()` → `handlePacket()` → `receiver.Push()` → `receiver.Tick()` → `deliver()`

3. **Channel Operations**:
   - All channel sends will be instrumented to detect blocking
   - Queue depth monitoring for all buffered channels

4. **Performance Critical Paths**:
   - Packet encryption/decryption operations
   - Packet marshaling/unmarshaling
   - Congestion control calculations

## Implementation Plan

This section outlines the step-by-step process for implementing Prometheus metrics in the goSRT project.

### Phase 1: Prerequisites and Setup

**Step 1.1: Add Prometheus Dependencies**
- Add `github.com/prometheus/client_golang/prometheus` to `go.mod`
- Add `github.com/prometheus/client_golang/prometheus/promauto` for automatic metric registration
- Add `github.com/prometheus/client_golang/prometheus/promhttp` for HTTP handler
- Run `go mod tidy` to download dependencies

**Step 1.2: Create Prometheus Package Structure**
- Decide on package location for Prometheus initialization code (likely in `server.go` or a new `prometheus.go` file)
- Plan metric naming convention: `gosrt_<subsystem>_<metric_name>`
- Define label names consistently: `function`, `connectionID`, `variable`, `type`

### Phase 2: Core Prometheus Infrastructure

**Step 2.1: Create Prometheus Initialization Code**
- Create constants for Prometheus configuration (listen address, path, max requests, etc.)
- Implement `initPromHandler()` function with error handling
- Implement `environmentOverrideProm()` function for environment variable support
- Add necessary imports: `net/http`, `os`, `log`, `time`

**Step 2.2: Integrate HTTP Listener in `server.go`**
- Modify `Server.Listen()` method to initialize Prometheus HTTP server
- Add Prometheus initialization after SRT listener is successfully created (after line 67)
- Test that HTTP server starts correctly and `/metrics` endpoint is accessible
- Verify environment variable overrides work (`PROM_LISTEN`, `PROM_PATH`)

**Step 2.3: Verify Basic Setup**
- Start the server and verify Prometheus endpoint is accessible: `curl http://localhost:9000/metrics`
- Check that default Go metrics are present (goroutines, memory, etc.)
- Test with custom listen address: `PROM_LISTEN=127.0.0.1:9001`
- Test with custom path: `PROM_PATH=/prometheus/metrics`

### Phase 3: Server-Level Metrics

**Step 3.1: Add Metrics to `server.go`**
- Declare server-level metrics (counters, gauges) in `var` section
- Add connection acceptance counter in `Server.Serve()` method
- Add connection rejection counter in `Server.Serve()` method
- Add active connection gauge (increment on accept, decrement on close)
- Add server startup timestamp gauge

**Step 3.2: Test Server Metrics**
- Verify metrics appear in `/metrics` endpoint
- Test with multiple connections to verify counters increment
- Verify active connection gauge updates correctly

### Phase 4: Connection-Level Metrics

**Step 4.1: Add Metrics to `connection.go`**
- Declare connection-level metrics in `var` section
- Instrument `Write()` function: add timing and call count metrics
- Instrument `Read()` function: add timing and call count metrics
- Instrument `handlePacket()`: add packet type distribution counters and processing time
- Instrument `handleACK()`: add ACK processing metrics and RTT update tracking
- Instrument `handleACKACK()`: add ACKACK processing metrics and RTT calculation tracking
- Instrument `recalculateRTT()`: add RTT smoothing algorithm execution time
- Add RTT gauge metric to track current RTT value
- Add RTT variance gauge metric to track RTT variance

**Step 4.2: Add Queue Metrics to `connection.go`**
- Instrument `push()` function: add network queue operation metrics
- Instrument `networkQueueReader()`: add queue processing metrics
- Instrument `writeQueueReader()`: add write queue processing metrics
- Instrument `deliver()`: add packet delivery metrics
- Add channel blocking detection to all channel operations (`networkQueue`, `writeQueue`, `readQueue`)

**Step 4.3: Test Connection Metrics**
- Create test connections and verify metrics increment
- Verify RTT metrics update when ACK/ACKACK packets are received
- Test channel blocking detection by filling queues
- Verify function timing metrics are recorded correctly

### Phase 5: Congestion Control Metrics

**Step 5.1: Add Metrics to `congestion/live/send.go`**
- Declare sender metrics in `var` section
- Instrument `Push()`: add sequence number assignment and timestamp setting metrics
- Instrument `Tick()`: add packet transmission timing and rate metrics
- Instrument `deliver()`: add packet delivery to network metrics
- Add link capacity probe measurement gauge

**Step 5.2: Add Metrics to `congestion/live/receive.go`**
- Declare receiver metrics in `var` section
- Instrument `Push()`: add packet ordering, gap detection, and duplicate handling metrics
- Instrument `Tick()`: add ACK/NAK send rate metrics and packet delivery timing
- Instrument `deliver()`: add packet delivery to application metrics
- Add counters for out-of-order packets, gaps detected, and duplicates

**Step 5.3: Test Congestion Control Metrics**
- Verify packet send/receive rates are tracked
- Test gap detection by dropping packets
- Verify ACK/NAK send rates are recorded
- Check link capacity probe measurements

### Phase 6: Listener and Dialer Metrics

**Step 6.1: Add Metrics to `listen.go`**
- Declare listener metrics in `var` section
- Instrument UDP socket read operations: add packet receive rate counter
- Instrument `reader()`: add packet routing operation metrics
- Instrument `Accept2()`: add connection acceptance metrics
- Add channel blocking detection for `backlog` and `rcvQueue` channels

**Step 6.2: Add Metrics to `dial.go`**
- Declare dialer metrics in `var` section
- Instrument UDP socket read operations: add packet receive rate counter
- Instrument `send()`: add packet transmission rate counter
- Instrument connection establishment: add connection attempt counter
- Add channel blocking detection for `rcvQueue` channel

**Step 6.3: Test Listener/Dialer Metrics**
- Verify UDP packet rates are tracked correctly
- Test connection acceptance metrics
- Verify channel blocking is detected on high load

### Phase 7: Channel Blocking Instrumentation

**Step 7.1: Implement Channel Blocking Detection**
- Update all channel send operations to use `select` with `default` case
- Add blocking duration measurement when channel is full
- Add blocking count counter for each channel
- Add longest blocked duration gauge per channel
- Add channel utilization gauge (current length / buffer size)

**Step 7.2: Instrument Channels in All Files**
- `connection.go`: `networkQueue`, `writeQueue`, `readQueue`
- `listen.go`: `backlog`, `rcvQueue`
- `dial.go`: `rcvQueue`

**Step 7.3: Test Channel Blocking**
- Create high load scenarios to fill channels
- Verify blocking metrics are recorded
- Check that longest blocked duration is tracked
- Verify channel utilization gauges update correctly

### Phase 8: Testing and Validation

**Step 8.1: Integration Testing**
- Run full server with multiple connections
- Verify all metrics are exposed in `/metrics` endpoint
- Check metric labels are correctly populated
- Verify no performance degradation from metrics collection

**Step 8.2: Metric Validation**
- Verify metric names follow convention: `gosrt_<subsystem>_<name>`
- Check that all labels are properly set
- Verify counter values increment correctly
- Verify gauge values reflect current state
- Verify histogram/summary quantiles are calculated

**Step 8.3: Performance Testing**
- Benchmark server with and without metrics
- Verify metrics collection overhead is minimal (< 5% recommended)
- Test under high load to ensure metrics don't cause blocking

**Step 8.4: Prometheus Integration Testing**
- Configure Prometheus to scrape the `/metrics` endpoint
- Verify metrics are collected correctly in Prometheus
- Create sample Grafana dashboards for key metrics
- Test metric queries and aggregations

### Phase 9: Documentation and Cleanup

**Step 9.1: Code Documentation**
- Add godoc comments to all metric declarations
- Document metric labels and their meanings
- Add examples of metric queries

**Step 9.2: Update Documentation**
- Update README.md with Prometheus setup instructions
- Document environment variables
- Add example Prometheus scrape configuration
- Document available metrics and their meanings

**Step 9.3: Code Review**
- Review all metric instrumentation for consistency
- Verify error handling is appropriate
- Check for any potential memory leaks from metrics
- Ensure metrics are properly cleaned up on connection close

### Implementation Order Summary

1. **Week 1**: Phase 1-2 (Setup and Core Infrastructure)
2. **Week 2**: Phase 3-4 (Server and Connection Metrics)
3. **Week 3**: Phase 5-6 (Congestion Control and Listener/Dialer)
4. **Week 4**: Phase 7-8 (Channel Blocking and Testing)
5. **Week 5**: Phase 9 (Documentation and Final Polish)

### Testing Checklist

- [ ] Prometheus HTTP endpoint is accessible
- [ ] Environment variables work correctly
- [ ] All declared metrics appear in `/metrics` endpoint
- [ ] Counters increment correctly
- [ ] Gauges reflect current state
- [ ] Histograms/Summaries calculate quantiles
- [ ] Channel blocking is detected
- [ ] RTT metrics update correctly
- [ ] No performance degradation
- [ ] Metrics work with multiple concurrent connections
- [ ] Prometheus can scrape and store metrics
- [ ] Documentation is complete

## Implementation Progress

This section tracks the progress of implementing Prometheus metrics against the Implementation Plan.

### Phase 1: Prerequisites and Setup

- [x] **Step 1.1: Add Prometheus Dependencies** - *Completed*
  - [x] Add `github.com/prometheus/client_golang/prometheus` to `go.mod`
  - [x] Add `github.com/prometheus/client_golang/prometheus/promauto` to `go.mod`
  - [x] Add `github.com/prometheus/client_golang/prometheus/promhttp` to `go.mod`
  - [x] Run `go mod tidy` to download dependencies
  - **Note**: Added `github.com/prometheus/client_golang v1.23.2` which includes all required subpackages (prometheus, promauto, promhttp)
- [x] **Step 1.2: Create Prometheus Package Structure** - *Completed*
  - [x] Created `prometheus.go` file in root package for metrics infrastructure
  - [x] Defined metric naming convention: `gosrt_<subsystem>_<metric_name>`
  - [x] Defined subsystem names: server, connection, congestion_sender, congestion_receiver, listener, dialer
  - [x] Defined standard label names: function, connectionID, variable, type, channel, packet_type, result
  - [x] Defined common function names, variable names, type values, and channel names as constants
  - **Note**: All constants are defined in `prometheus.go` for consistent use across the codebase

### Phase 2: Core Prometheus Infrastructure

- [x] **Step 2.1: Create Prometheus Initialization Code** - *Completed*
  - [x] Created constants for Prometheus configuration (listen address, path, max requests, etc.)
  - [x] Implemented `initPromHandler()` function with error handling
  - [x] Implemented `environmentOverrideProm()` function for environment variable support
  - [x] Added necessary imports: `net/http`, `os`, `log`, `time`, `prometheus`, `promhttp`
  - [x] Added constants: `promListenDefault`, `promPathDefault`, `promMaxRequestsInFlight`, `promEnableOpenMetrics`, `quantileError`, `summaryVecMaxAge`
  - **Note**: All initialization code added to `prometheus.go` with proper documentation
- [x] **Step 2.2: Integrate HTTP Listener in `server.go`** - *Completed*
  - [x] Modified `Server.Listen()` method to initialize Prometheus HTTP server
  - [x] Added Prometheus initialization after SRT listener is successfully created (after line 67)
  - [x] Used constants `promListenDefault` and `promPathDefault` from `prometheus.go`
  - [x] Integrated `environmentOverrideProm()` to support environment variable overrides
  - [x] Integrated `initPromHandler()` to start the HTTP server in background goroutine
  - **Note**: Prometheus HTTP server will start automatically when `Server.Listen()` is called
- [x] **Step 2.3: Verify Basic Setup** - *Completed*
  - [x] Started the server and verified Prometheus endpoint is accessible: `curl http://localhost:9000/metrics`
  - [x] Verified default Go metrics are present (goroutines, memory, etc.)
  - [x] Updated logging format to match existing style (using `fmt.Fprintf(os.Stderr, ...)`)
  - [x] Added Makefile targets: `make run-server` and `make metrics` for easy testing
  - [x] Added input validation for `PROM_LISTEN` (supports IPv4, IPv6, and hostnames)
  - [x] Added input validation for `PROM_PATH` (must start with `/`, max 50 chars, no invalid characters)
  - **Note**: Environment variable overrides can be tested with `PROM_LISTEN` and `PROM_PATH` env vars

### Phase 3: Server-Level Metrics

- [x] **Step 3.1: Add Metrics to `server.go`** - *Completed*
  - [x] Declared server-level metrics (counters) in `var` section
  - [x] Added `gosrt_server_counts` CounterVec with single label: `variable` (simplified since only one function is instrumented)
  - [x] Instrumented connection events:
    - `serverCounts.WithLabelValues("accepted").Inc()` - when connection is accepted
    - `serverCounts.WithLabelValues("rejected").Inc()` - when Accept() fails
    - `serverCounts.WithLabelValues("reject").Inc()` - when handler returns REJECT mode
    - `serverCounts.WithLabelValues("nil").Inc()` - when HandleConnect is nil
    - `serverCounts.WithLabelValues("publish").Inc()` - when connection is published
    - `serverCounts.WithLabelValues("subscribe").Inc()` - when connection is subscribed
  - **Note**: For `server.go`, only the `variable` label is used since we're instrumenting a single function. Other files with multiple functions will use the `function` label as well.
- [ ] **Step 3.2: Test Server Metrics**

### Phase 4: Connection-Level Metrics

- [x] **Step 4.1: Add Metrics to `connection.go`** - *Completed*
  - [x] Declared connection-level metrics in `var` section
  - [x] Added `gosrt_connection_counts` CounterVec with labels: function, variable, type
  - [x] Added `gosrt_connection_durations_seconds` SummaryVec with labels: function, variable, type
  - [x] Added `gosrt_connection_rtt_microseconds` GaugeVec with label: connectionID
  - [x] Added `gosrt_connection_rtt_variance_microseconds` GaugeVec with label: connectionID
  - [x] Instrumented `Write()` function: added timing and call count metrics
  - [x] Instrumented `Read()` function: added timing and call count metrics
  - [x] Instrumented `handlePacket()`: added packet type distribution counters (data/control) and processing time
  - [x] Instrumented `handleACK()`: added ACK processing metrics and RTT update tracking
  - [x] Instrumented `handleACKACK()`: added ACKACK processing metrics and RTT calculation tracking
  - [x] Instrumented `recalculateRTT()`: added RTT smoothing algorithm execution time and RTT gauge updates
  - [x] Initialized RTT gauges with initial values (100ms RTT, 50ms RTTVar) in `newSRTConn()`
  - **Note**: RTT gauges are updated whenever `recalculateRTT()` is called, using socketId as connectionID
- [x] **Step 4.2: Add Queue Metrics to `connection.go`** - *Completed*
  - [x] Added channel blocking metrics: `connectionChannelBlockedDuration` (SummaryVec), `connectionChannelBlockedCount` (CounterVec), `connectionChannelLongestBlocked` (GaugeVec)
  - [x] Instrumented `push()` function: added network queue operation metrics and channel blocking detection
  - [x] Instrumented `networkQueueReader()`: added queue processing count metrics
  - [x] Instrumented `writeQueueReader()`: added write queue processing count metrics
  - [x] Instrumented `deliver()`: added packet delivery metrics and channel blocking detection
  - [x] Added channel blocking detection to `Write()` for `writeQueue` channel
  - [x] Added channel blocking detection to `push()` for `networkQueue` channel
  - [x] Added channel blocking detection to `deliver()` for `readQueue` channel
  - [x] Channel blocking detection uses select/default pattern to detect when channels are full
  - [x] Tracks blocking duration, count, and longest blocked duration per channel
  - **Note**: Channel blocking metrics track when channel sends are not immediate (default case), measuring the time until the send succeeds
- [ ] **Step 4.3: Test Connection Metrics**

### Phase 5: Congestion Control Metrics

- [x] **Step 5.1: Add Metrics to `congestion/live/send.go`** - *Completed*
  - [x] Declared sender-level metrics in `var` section
  - [x] Added `gosrt_congestion_sender_counts` CounterVec with labels: function, variable, type
  - [x] Added `gosrt_congestion_sender_durations_seconds` SummaryVec with labels: function, variable, type
  - [x] Added `gosrt_congestion_sender_link_capacity_mbps` GaugeVec (no labels)
  - [x] Instrumented `Push()`: added timing, sequence number assignment, and link capacity probe tracking
  - [x] Instrumented `Tick()`: added timing, packet transmission counts, and dropped packet tracking
  - [x] Instrumented `ACK()`: added timing and packets ACK'd count
  - [x] Instrumented `NAK()`: added timing and packets retransmitted count
  - [x] Updated link capacity gauge in `Tick()` rate calculation section
- [x] **Step 5.2: Add Metrics to `congestion/live/receive.go`** - *Completed*
  - [x] Declared receiver-level metrics in `var` section
  - [x] Added `gosrt_congestion_receiver_counts` CounterVec with labels: function, variable, type
  - [x] Added `gosrt_congestion_receiver_durations_seconds` SummaryVec with labels: function, variable, type
  - [x] Added `gosrt_congestion_receiver_link_capacity_packets_per_second` GaugeVec (no labels)
  - [x] Instrumented `Push()`: added timing, packet ordering metrics (in-order, out-of-order, duplicate, belated, already-acked), gap detection, and link capacity probe tracking
  - [x] Instrumented `periodicACK()`: added timing and light ACK tracking
  - [x] Instrumented `periodicNAK()`: added timing and gaps detected tracking
  - [x] Instrumented `Tick()`: added timing, ACK/NAK sent counts, and packets delivered count
  - [x] Updated link capacity gauge in `Push()` when probe measurement is successful
- [ ] **Step 5.3: Test Congestion Control Metrics**

### Phase 6: Listener and Dialer Metrics

- [x] **Step 6.1: Add Metrics to `listen.go`** - *Completed*
  - [x] Declared listener-level metrics in `var` section
  - [x] Added `gosrt_listener_counts` CounterVec with labels: function, variable, type
  - [x] Added `gosrt_listener_durations_seconds` SummaryVec with labels: function, variable, type
  - [x] Instrumented `Listen()`: added timing, listener creation, packet receive/parse errors, and receive queue full tracking
  - [x] Instrumented `Accept2()`: added timing, connection request acceptance/failure tracking
  - [x] Instrumented `reader()`: added handshake packet tracking, backlog full tracking, unknown destination tracking, peer IP mismatch tracking, and packet routing tracking
  - [x] Instrumented `send()`: added timing, marshal error tracking, and packet type (data/control) tracking
- [x] **Step 6.2: Add Metrics to `dial.go`** - *Completed*
  - [x] Declared dialer-level metrics in `var` section
  - [x] Added `gosrt_dialer_counts` CounterVec with labels: function, variable, type
  - [x] Added `gosrt_dialer_durations_seconds` SummaryVec with labels: function, variable, type
  - [x] Instrumented `Dial()`: added timing, packet receive/parse errors, receive queue full tracking, connection establishment/failure tracking
  - [x] Instrumented `reader()`: added wrong socket ID tracking, handshake packet tracking, no connection tracking, and packet routing tracking
  - [x] Instrumented `send()`: added timing, marshal error tracking, and packet type (data/control) tracking
  - [x] Instrumented `handleHandshake()`: added timing, unmarshal error tracking, unsupported version tracking, induction response sent tracking, conclusion success tracking, connection rejection tracking, and unsupported handshake tracking
  - [x] Instrumented `sendInduction()`: added timing and induction sent tracking
- [ ] **Step 6.3: Test Listener/Dialer Metrics**

### Phase 7: Channel Blocking Instrumentation

- [x] **Step 7.1: Implement Channel Blocking Detection** - *Completed*
  - [x] Channel blocking detection pattern already implemented in `connection.go` (Phase 4, Step 4.2)
  - [x] Pattern uses `select` with `default` case to detect when channels are full
  - [x] Measures blocking duration, count, and longest blocked duration per channel
- [x] **Step 7.2: Instrument Channels in All Files** - *Completed*
  - [x] Added channel blocking metrics to `listen.go`: `listenerChannelBlockedDuration`, `listenerChannelBlockedCount`, `listenerChannelLongestBlocked`
  - [x] Instrumented `rcvQueue` channel in `listen.go` UDP read goroutine with blocking detection
  - [x] Instrumented `backlog` channel in `listen.go` reader() function with blocking detection
  - [x] Added channel blocking metrics to `dial.go`: `dialerChannelBlockedDuration`, `dialerChannelBlockedCount`, `dialerChannelLongestBlocked`
  - [x] Instrumented `rcvQueue` channel in `dial.go` UDP read goroutine with blocking detection
  - [x] Connection-level channels already instrumented in Phase 4: `networkQueue`, `writeQueue`, `readQueue`
- [ ] **Step 7.3: Test Channel Blocking**

### Phase 8: Testing and Validation

- [ ] **Step 8.1: Integration Testing**
- [ ] **Step 8.2: Metric Validation**
- [ ] **Step 8.3: Performance Testing**
- [ ] **Step 8.4: Prometheus Integration Testing**

### Phase 9: Documentation and Cleanup

- [ ] **Step 9.1: Code Documentation**
- [ ] **Step 9.2: Update Documentation**
- [ ] **Step 9.3: Code Review**

## Example of prometheus counters

This is an example of the Prometheus counters that can be added to the project's .go files, so that functions can be instrumented.

e.g. This code get's added to the top "var" section of the .go file.

```
	pC = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Subsystem: "gosrt",
			Name:      "counts",
			Help:      "gosrt counts",
		},
		[]string{"function", "connectionID", "variable", "type"},
	)

	pH = promauto.NewSummaryVec(
		prometheus.SummaryOpts{
			Subsystem: "gosrt",
			Name:      "histograms",
			Help:      "gosrt histograms",
			Objectives: map[float64]float64{
				0.1:  quantileError,
				0.5:  quantileError,
				0.99: quantileError,
			},
			MaxAge: summaryVecMaxAge,
		},
		[]string{"function", "connectionID", "variable", "type"},
	)

  // gauge needs labels for function, connectionID, variable, type
	pG = promauto.NewGauge(
		prometheus.GaugeOpts{
			Subsystem: "gosrt",
			Name:      "gauge",
			Help:      "gosrt gauge",
		},
	)
```

Then key functions will be decorated with this code at the top of the function, so that it records how often the function is being used, and how long the function takes.  We will focus on key functions relating to the RTT calculations as described in the RTT_Calculations.md

```
	startTime := time.Now()
	defer func() {
		pH.WithLabelValues("myFunction", "complete", "count").Observe(time.Since(startTime).Seconds())
	}()
	pC.WithLabelValues("myFunction", "start", "count").Inc()
```

## Channels

To allow us to determine if the channels are getting blocked, we will change the way we send on the channel to use a select, like follows.

```
var(
  longestBlockedDuration time.Duration
)

select {
	# non-blocking attempt to send
	case outCh <- myMessage:
		# non-blocked send
	default:
		# blocked
		blockedStartTime = time.Now()
		outCh <- myMessage
		blockedDuration = time.Since(blockedStartTime)
		pH.WithLabelValues("outCh", "complete", "count").Observe(blockedDuration.Seconds())
		pC.WithLabelValues("outCh", "blocked", "count").Inc()
		if blockedDuration > longestBlockedDuration {
			longestBlockedDuration = blockedDuration
			pG.Set(longestBlockedDuration)
		}
}

```