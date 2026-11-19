/*
 * Minimal in-process fake MQTT broker / WebSocket server / HTTP proxy for the paho harnesses.
 *
 * A listening TCP socket on 127.0.0.1 (ephemeral port) is opened once. For each fuzz input a
 * helper thread accepts exactly ONE connection from the client under test, writes the fuzz bytes
 * (the "server's" side of the conversation), half-closes its write side (so the client sees EOF
 * right after the data and every library wait ends promptly) and drains whatever the client sends
 * until the client closes. The client is the paho library itself, driven through its public API.
 *
 * State kept across inputs: only the listening socket (read-only after setup). Each input's
 * connection, thread and client handle are created and torn down within the input.
 */
#ifndef PAHO_FAKE_SERVER_H
#define PAHO_FAKE_SERVER_H

#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <unistd.h>

static int fs_listen_fd = -1;
static int fs_port = 0;
static int fs_cancel[2] = {-1, -1}; /* self-pipe: "the client is gone, stop waiting for it" */

typedef struct {
	const uint8_t *data;
	size_t size;
	int accepted; /* set once a connection was accepted */
	int ws_handshake; /* WebSocket mode: answer the client's upgrade request first */
} fs_job;

#ifdef FS_WEBSOCKET
/*
 * WebSocket server handshake (RFC 6455 4.2.2). The client's Sec-WebSocket-Key is a fresh random
 * nonce per connection (WebSocket.c seeds rand() with time()), so no stored input can carry the
 * matching Sec-WebSocket-Accept; a real (malicious) server simply computes it, and so does this one.
 */
typedef struct { uint32_t h[5]; uint64_t n; uint8_t b[64]; size_t bl; } fs_sha1;
#define FS_ROL(x, c) (((x) << (c)) | ((x) >> (32 - (c))))
static void fs_sha1_block(fs_sha1 *s, const uint8_t *p)
{
	uint32_t w[80], a, b, c, d, e, t;
	int i;
	for (i = 0; i < 16; i++) w[i] = (uint32_t)p[4*i] << 24 | (uint32_t)p[4*i+1] << 16 | (uint32_t)p[4*i+2] << 8 | p[4*i+3];
	for (i = 16; i < 80; i++) w[i] = FS_ROL(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
	a = s->h[0]; b = s->h[1]; c = s->h[2]; d = s->h[3]; e = s->h[4];
	for (i = 0; i < 80; i++)
	{
		uint32_t f, k;
		if (i < 20) { f = (b & c) | (~b & d); k = 0x5A827999; }
		else if (i < 40) { f = b ^ c ^ d; k = 0x6ED9EBA1; }
		else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC; }
		else { f = b ^ c ^ d; k = 0xCA62C1D6; }
		t = FS_ROL(a, 5) + f + e + k + w[i];
		e = d; d = c; c = FS_ROL(b, 30); b = a; a = t;
	}
	s->h[0] += a; s->h[1] += b; s->h[2] += c; s->h[3] += d; s->h[4] += e;
}
static void fs_sha1_add(fs_sha1 *s, const uint8_t *p, size_t n)
{
	while (n--) { s->b[s->bl++] = *p++; s->n += 8; if (s->bl == 64) { fs_sha1_block(s, s->b); s->bl = 0; } }
}
static void fs_sha1_sum(const uint8_t *p, size_t n, uint8_t out[20])
{
	fs_sha1 s = {{0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0}, 0, {0}, 0};
	uint64_t bits;
	uint8_t pad = 0x80, z = 0, len[8];
	int i;
	fs_sha1_add(&s, p, n);
	bits = s.n;
	fs_sha1_add(&s, &pad, 1);
	while (s.bl != 56) fs_sha1_add(&s, &z, 1);
	for (i = 0; i < 8; i++) len[i] = (uint8_t)(bits >> (56 - 8 * i));
	fs_sha1_add(&s, len, 8);
	for (i = 0; i < 20; i++) out[i] = (uint8_t)(s.h[i / 4] >> (24 - 8 * (i % 4)));
}
static size_t fs_ws_response(const char *req, char *out, size_t outlen)
{
	static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	const char *k = req;
	char cat[128], acc[32];
	uint8_t d[20];
	size_t kl = 0, i, o = 0;
	int n;
	while (*k && strncasecmp(k, "Sec-WebSocket-Key:", 18) != 0) k++;
	if (!*k) return 0;
	k += strlen("Sec-WebSocket-Key:");
	while (*k == ' ') k++;
	while (k[kl] && k[kl] != '\r' && k[kl] != '\n' && kl < 64) kl++;
	n = snprintf(cat, sizeof(cat), "%.*s258EAFA5-E914-47DA-95CA-C5AB0DC85B11", (int)kl, k);
	fs_sha1_sum((const uint8_t *)cat, (size_t)n, d);
	for (i = 0; i < 18; i += 3)
	{
		uint32_t v = (uint32_t)d[i] << 16 | (uint32_t)d[i+1] << 8 | d[i+2];
		acc[o++] = b64[v >> 18 & 63]; acc[o++] = b64[v >> 12 & 63]; acc[o++] = b64[v >> 6 & 63]; acc[o++] = b64[v & 63];
	}
	{
		uint32_t v = (uint32_t)d[18] << 16 | (uint32_t)d[19] << 8;
		acc[o++] = b64[v >> 18 & 63]; acc[o++] = b64[v >> 12 & 63]; acc[o++] = b64[v >> 6 & 63]; acc[o++] = '=';
	}
	acc[o] = 0;
	n = snprintf(out, outlen, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
		"Connection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", acc);
	return n > 0 ? (size_t)n : 0;
}
#endif

static void fs_setup(void)
{
	struct sockaddr_in a;
	socklen_t alen = sizeof(a);
	int one = 1;

	if (fs_listen_fd >= 0)
		return;
	signal(SIGPIPE, SIG_IGN);
	fs_listen_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fs_listen_fd < 0) { perror("socket"); abort(); }
	setsockopt(fs_listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	memset(&a, 0, sizeof(a));
	a.sin_family = AF_INET;
	a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	a.sin_port = 0;
	if (bind(fs_listen_fd, (struct sockaddr *)&a, sizeof(a)) != 0) { perror("bind"); abort(); }
	if (listen(fs_listen_fd, 4) != 0) { perror("listen"); abort(); }
	if (getsockname(fs_listen_fd, (struct sockaddr *)&a, &alen) != 0) { perror("getsockname"); abort(); }
	fs_port = ntohs(a.sin_port);
	if (pipe(fs_cancel) != 0) { perror("pipe"); abort(); }
	fcntl(fs_cancel[0], F_SETFL, O_NONBLOCK);
}

static void *fs_thread(void *arg)
{
	fs_job *job = (fs_job *)arg;
	char sink[4096];
	size_t off = 0;
	int c;

	for (;;)
	{
		struct pollfd p[2] = {{fs_listen_fd, POLLIN, 0}, {fs_cancel[0], POLLIN, 0}};
		if (poll(p, 2, -1) < 0)
			continue;
		if (p[0].revents & POLLIN)
			break;  /* a pending client connection always wins over the cancel signal */
		if (p[1].revents & POLLIN)
			return NULL;
	}
	c = accept(fs_listen_fd, NULL, NULL);
	if (c < 0)
		return NULL;
	job->accepted = 1;
#ifdef FS_WEBSOCKET
	if (job->ws_handshake)
	{
		/* read the upgrade request up to its blank line, then answer it */
		char req[4096], resp[256];
		size_t rl = 0, n;
		while (rl < sizeof(req) - 1)
		{
			ssize_t r = recv(c, req + rl, sizeof(req) - 1 - rl, 0);
			if (r <= 0) break;
			rl += (size_t)r;
			req[rl] = 0;
			if (strstr(req, "\r\n\r\n")) break;
		}
		req[rl] = 0;
		n = fs_ws_response(req, resp, sizeof(resp));
		if (n)
			send(c, resp, n, MSG_NOSIGNAL);
	}
#endif
	while (off < job->size)
	{
		ssize_t n = send(c, job->data + off, job->size - off, MSG_NOSIGNAL);
		if (n <= 0)
			break;
		off += (size_t)n;
	}
	shutdown(c, SHUT_WR);
	while (recv(c, sink, sizeof(sink), 0) > 0)
		;
	close(c);
	return NULL;
}

/* Start serving one connection with the given bytes. */
static void fs_start(pthread_t *t, fs_job *job, const uint8_t *data, size_t size)
{
	job->data = data;
	job->size = size;
	job->accepted = 0; /* ws_handshake is set by the caller before this */
	if (pthread_create(t, NULL, fs_thread, job) != 0) { perror("pthread_create"); abort(); }
}

/*
 * Finish the input, after the client handle has been destroyed (so any connection it made is
 * already queued on the listening socket). If it never connected, the cancel byte ends the wait.
 */
static void fs_finish(pthread_t t, fs_job *job)
{
	char b = 1;
	(void)job;
	if (write(fs_cancel[1], &b, 1) != 1) { perror("write"); abort(); }
	pthread_join(t, NULL);
	while (read(fs_cancel[0], &b, 1) == 1)
		;
	/* Drop any extra connection the client queued (e.g. a reconnect) so it cannot leak into the
	 * next input. */
	for (;;)
	{
		struct pollfd p = {fs_listen_fd, POLLIN, 0};
		int c;
		if (poll(&p, 1, 0) <= 0 || !(p.revents & POLLIN))
			break;
		c = accept(fs_listen_fd, NULL, NULL);
		if (c >= 0)
			close(c);
	}
}

#endif
