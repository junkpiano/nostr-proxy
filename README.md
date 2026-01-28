# Nostr Proxy - OGP Metadata API

A secure, production-ready HTTP proxy API for fetching Open Graph Protocol (OGP) metadata from web pages.

## Features

- **SSRF Protection**: DNS resolution with private IP blocking (RFC1918, loopback, link-local, cloud metadata endpoints)
- **Response Size Limits**: 1MB maximum response size with streaming validation
- **Rate Limiting**: 60 requests/minute per IP with burst capacity of 10
- **Content-Type Validation**: Only accepts HTML content, rejects images/videos/PDFs
- **JSON Bloat Protection**: Limits meta tags (64), content length (2KB), key length (128 chars)
- **Redirect Control**: Manual redirect following with loop detection (max 3 hops)
- **Structured Logging**: JSON-formatted logs with security event tracking

## API Specification

### Endpoint

```
GET /api/ogp
```

### Query Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `url` | string | Yes | Target URL to fetch OGP metadata from (must be http:// or https://) |

### Request Example

```bash
curl "http://localhost:3000/api/ogp?url=https://example.com/"
```

### Response Format

#### Success Response (200 OK)

```json
{
  "url": "https://example.com/",
  "data": {
    "og:title": "Example Domain",
    "og:description": "Example Domain for documentation",
    "og:image": "https://example.com/image.png",
    "og:url": "https://example.com/",
    "twitter:card": "summary_large_image",
    "twitter:title": "Example Domain",
    "description": "Example Domain for documentation",
    "title": "Example Domain"
  }
}
```

**Response Fields:**
- `url` (string): The requested URL
- `data` (object): Key-value pairs of extracted metadata
  - Includes OGP tags (prefix: `og:`)
  - Includes Twitter Card tags (prefix: `twitter:`)
  - Includes standard meta tags (`description`, `title`)
  - Falls back to `<title>` element if no title meta tag exists

### Error Responses

All errors return a plain text message with appropriate HTTP status code.

#### 400 Bad Request

**Invalid URL:**
```
invalid url
```
- Malformed URL or unsupported scheme (only http/https allowed)

**SSRF Blocked:**
```
blocked: private IP
```
- Target resolves to private/reserved IP address
- Includes: RFC1918 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
- Includes: Loopback (127.0.0.0/8, ::1)
- Includes: Link-local (169.254.0.0/16, fe80::/10)
- Includes: Cloud metadata endpoints (169.254.169.254)

**DNS Resolution Failed:**
```
dns resolution failed
```
- Hostname cannot be resolved

**Too Many Redirects:**
```
too many redirects
```
- More than 3 redirects encountered

**Redirect Loop:**
```
redirect loop detected
```
- Circular redirect chain detected

#### 413 Payload Too Large

```
payload too large
```
- Response size exceeds 1MB limit
- Detected via Content-Length header or streaming size check

#### 415 Unsupported Media Type

```
unsupported content type
```
- Content-Type is not `text/html` or `application/xhtml+xml`
- Prevents downloading images, videos, PDFs, JSON, etc.

#### 429 Too Many Requests

```
Too Many Requests
```
- Rate limit exceeded (60 requests/minute per IP)
- Burst capacity: 10 requests
- Response includes `x-ratelimit-after` header indicating retry time

Headers:
```
x-ratelimit-after: 2
x-ratelimit-limit: 10
x-ratelimit-remaining: 0
```

#### 502 Bad Gateway

```
fetch failed
```
- Network error, connection refused, or other request failure

```
parse failed
```
- HTML parsing error or invalid UTF-8 encoding

## Security Features

### SSRF Protection

The API validates all target URLs before making requests:

1. **DNS Resolution**: Resolves hostnames to IP addresses
2. **IP Validation**: Blocks private, reserved, and cloud metadata IPs
3. **Redirect Validation**: Re-validates each redirect target
4. **Scheme Restriction**: Only allows http:// and https://

### Rate Limiting

- **Limit**: 60 requests per minute per IP address
- **Burst**: 10 requests allowed in quick succession
- **Refill Rate**: 1 request per second
- **Granularity**: Per source IP (not spoofable via X-Forwarded-For)

### Resource Limits

| Limit | Value | Purpose |
|-------|-------|---------|
| Max response size | 1 MB | Prevent memory exhaustion |
| Max redirects | 3 | Prevent redirect chains |
| Max meta tags | 64 | Prevent JSON bloat |
| Max content length | 2048 chars | Prevent large values |
| Max key length | 128 chars | Prevent long keys |
| Connection timeout | 5 seconds | Prevent hanging connections |
| Request timeout | 10 seconds | Prevent slow requests |

## Running the Server

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `BIND_ADDR` | `0.0.0.0:3000` | Server bind address (host:port) |
| `USER_AGENT` | Chrome 122 | User-Agent header for outgoing requests |
| `RUST_LOG` | - | Log level (e.g., `info`, `debug`, `warn`) |

### Build and Run

```bash
# Development build
cargo build
RUST_LOG=info cargo run

# Production build (optimized)
cargo build --release
RUST_LOG=info ./target/release/nostr-proxy

# Custom bind address
BIND_ADDR=127.0.0.1:8080 ./target/release/nostr-proxy
```

### Docker

```bash
# Build image
docker build -t nostr-proxy .

# Run container
docker run -p 3000:3000 -e RUST_LOG=info nostr-proxy
```

## Usage Examples

### Fetch OGP metadata

```bash
curl "http://localhost:3000/api/ogp?url=https://example.com/"
```

### Handle rate limiting

```bash
# Make 11 rapid requests (burst + 1)
for i in {1..11}; do
  curl -w "\nStatus: %{http_code}\n" \
    "http://localhost:3000/api/ogp?url=https://example.com/"
done

# First 10 succeed (burst), 11th returns 429
# Wait 2 seconds for token refill
sleep 2

# Request succeeds again
curl "http://localhost:3000/api/ogp?url=https://example.com/"
```

### Test SSRF protection

```bash
# These should all return 400 "blocked: private IP"
curl "http://localhost:3000/api/ogp?url=http://127.0.0.1/"
curl "http://localhost:3000/api/ogp?url=http://192.168.1.1/"
curl "http://localhost:3000/api/ogp?url=http://169.254.169.254/latest/meta-data/"
```

### Test Content-Type validation

```bash
# Should return 415 "unsupported content type"
curl "http://localhost:3000/api/ogp?url=https://httpbin.org/image/png"
curl "http://localhost:3000/api/ogp?url=https://httpbin.org/json"

# Should succeed (text/html)
curl "http://localhost:3000/api/ogp?url=https://example.com/"
```

## Logging

The server uses structured logging with the `tracing` crate. Set `RUST_LOG` to control verbosity:

```bash
RUST_LOG=info    # Standard production logging
RUST_LOG=debug   # Detailed request/response logging
RUST_LOG=warn    # Warnings and errors only
```

### Log Events

Security events are logged with structured fields:

**SSRF Blocked:**
```json
{
  "level": "WARN",
  "ssrf_blocked": true,
  "resolved_ip": "127.0.0.1",
  "reason": "loopback",
  "message": "SSRF attempt blocked"
}
```

**Payload Too Large:**
```json
{
  "level": "WARN",
  "payload_too_large": true,
  "size": 2097152,
  "limit": 1048576,
  "message": "Response size exceeds limit"
}
```

**Content-Type Rejected:**
```json
{
  "level": "WARN",
  "unsupported_content_type": true,
  "content_type": "image/png",
  "message": "Content-Type not supported"
}
```

## Dependencies

- **axum**: Web framework
- **reqwest**: HTTP client with streaming
- **hickory-resolver**: DNS resolver for SSRF protection
- **tower-governor**: Rate limiting middleware
- **scraper**: HTML parsing
- **tracing**: Structured logging

## License

MIT
