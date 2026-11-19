/*
 * Fuzz the restore of persisted client state through the public user-persistence interface
 * (MQTTCLIENT_PERSISTENCE_USER, MQTTClientPersistence.h).
 *
 * The fuzz input is the content of the persistence store the client finds when it is created:
 * byte 0 bit 0 selects an MQTT 5 client (else 3.1.1); then records of
 *   [prefix selector:1][sequence number:1][value length:2, little endian][value bytes]
 * become (key, value) pairs whose keys carry the library's own prefixes (c-, c5-, s-, s5-, sc-,
 * sc5-, r-, r5-, q-, q5-) followed by the sequence number. Creating the client restores them:
 * MQTTPersistence_initialize/restorePackets/restoreMessageQueue and MQTTPersistence_restorePacket
 * (-> MQTTPacket decoders) in both front-ends, plus MQTTAsync_restoreCommands/restoreCommand when
 * built with -DFUZZ_ASYNC (fuzz_persistence_async; otherwise fuzz_persistence_sync).
 *
 * The in-memory store is rebuilt from scratch for every input; nothing touches the filesystem or
 * the network (the server URI is never connected to).
 */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef FUZZ_ASYNC
#include "MQTTAsync.h"
#else
#include "MQTTClient.h"
#endif
#include "MQTTClientPersistence.h"

typedef struct { char *key; char *val; int len; int live; } rec;
static rec *recs;
static int nrecs;

static void store_reset(void)
{
	int i;
	for (i = 0; i < nrecs; i++) { free(recs[i].key); free(recs[i].val); }
	free(recs);
	recs = NULL;
	nrecs = 0;
}

static void store_add(const char *key, const char *val, int len)
{
	rec *r = realloc(recs, sizeof(rec) * (size_t)(nrecs + 1));
	if (!r) abort();
	recs = r;
	recs[nrecs].key = strdup(key);
	recs[nrecs].val = malloc(len > 0 ? (size_t)len : 1);
	if (!recs[nrecs].key || !recs[nrecs].val) abort();
	if (len > 0) memcpy(recs[nrecs].val, val, (size_t)len);
	recs[nrecs].len = len;
	recs[nrecs].live = 1;
	nrecs++;
}

static rec *store_find(const char *key)
{
	int i;
	for (i = 0; i < nrecs; i++)
		if (recs[i].live && strcmp(recs[i].key, key) == 0)
			return &recs[i];
	return NULL;
}

static int p_open(void **h, const char *cid, const char *uri, void *ctx)
{ (void)cid; (void)uri; (void)ctx; *h = &recs; return 0; }
static int p_close(void *h) { (void)h; return 0; }
static int p_put(void *h, char *key, int bufcount, char *buffers[], int buflens[])
{
	int i, total = 0, off = 0;
	char *v;
	rec *old;
	(void)h;
	for (i = 0; i < bufcount; i++) total += buflens[i];
	v = malloc(total > 0 ? (size_t)total : 1);
	if (!v) abort();
	for (i = 0; i < bufcount; i++) { memcpy(v + off, buffers[i], (size_t)buflens[i]); off += buflens[i]; }
	if ((old = store_find(key)) != NULL) old->live = 0;
	store_add(key, v, total);
	free(v);
	return 0;
}
static int p_get(void *h, char *key, char **buffer, int *buflen)
{
	rec *r = store_find(key);
	(void)h;
	if (!r) return MQTTCLIENT_PERSISTENCE_ERROR;
	/* the library frees this buffer with free() */
	*buffer = malloc(r->len > 0 ? (size_t)r->len : 1);
	if (!*buffer) abort();
	if (r->len > 0) memcpy(*buffer, r->val, (size_t)r->len);
	*buflen = r->len;
	return 0;
}
static int p_remove(void *h, char *key)
{
	rec *r = store_find(key);
	(void)h;
	if (r) r->live = 0;
	return 0;
}
static int p_keys(void *h, char ***keys, int *nkeys)
{
	int i, n = 0;
	(void)h;
	*keys = NULL;
	*nkeys = 0;
	for (i = 0; i < nrecs; i++) if (recs[i].live) n++;
	if (n == 0) return 0;
	*keys = malloc(sizeof(char *) * (size_t)n);
	if (!*keys) abort();
	for (i = 0; i < nrecs; i++)
		if (recs[i].live)
		{
			(*keys)[*nkeys] = strdup(recs[i].key);
			if (!(*keys)[*nkeys]) abort();
			(*nkeys)++;
		}
	return 0;
}
static int p_clear(void *h)
{
	int i;
	(void)h;
	for (i = 0; i < nrecs; i++) recs[i].live = 0;
	return 0;
}
static int p_containskey(void *h, char *key)
{ (void)h; return store_find(key) ? 0 : MQTTCLIENT_PERSISTENCE_ERROR; }

static const char *prefixes[] = {"c-", "c5-", "s-", "s5-", "sc-", "sc5-", "r-", "r5-", "q-", "q5-"};

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	MQTTClient_persistence pers = {NULL, p_open, p_close, p_put, p_get, p_remove, p_keys, p_clear, p_containskey};
	size_t off = 1;
	int v5;

	if (size < 1)
		return -1;
	v5 = data[0] & 1;
	store_reset();
	while (off + 4 <= size)
	{
		char key[16];
		const char *pfx = prefixes[data[off] % (sizeof(prefixes) / sizeof(prefixes[0]))];
		size_t len = (size_t)data[off + 2] | ((size_t)data[off + 3] << 8);
		snprintf(key, sizeof(key), "%s%u", pfx, (unsigned)data[off + 1]);
		off += 4;
		if (len > size - off)
			len = size - off;
		store_add(key, (const char *)data + off, (int)len);
		off += len;
	}

#ifdef FUZZ_ASYNC
	{
		MQTTAsync c = NULL;
		MQTTAsync_createOptions co = MQTTAsync_createOptions_initializer;
		co.MQTTVersion = v5 ? MQTTVERSION_5 : MQTTVERSION_3_1_1;
		co.sendWhileDisconnected = 1;
		if (MQTTAsync_createWithOptions(&c, "tcp://127.0.0.1:1", "fuzzclient", MQTTCLIENT_PERSISTENCE_USER,
				&pers, &co) == MQTTASYNC_SUCCESS)
			MQTTAsync_destroy(&c);
		else if (c)
			MQTTAsync_destroy(&c);
	}
#else
	{
		MQTTClient c = NULL;
		MQTTClient_createOptions co = MQTTClient_createOptions_initializer;
		co.MQTTVersion = v5 ? MQTTVERSION_5 : MQTTVERSION_3_1_1;
		MQTTClient_createWithOptions(&c, "tcp://127.0.0.1:1", "fuzzclient", MQTTCLIENT_PERSISTENCE_USER,
				&pers, &co);
		if (c)
			MQTTClient_destroy(&c);
	}
#endif
	store_reset();
	return 0;
}
