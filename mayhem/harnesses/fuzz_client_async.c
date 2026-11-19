/*
 * Fuzz the asynchronous MQTT client (MQTTAsync) against a broker that sends the fuzz input.
 *
 * Input: byte 0 bit 0 selects the protocol (1 = MQTT 5, 0 = MQTT 3.1.1); the remaining bytes are
 * the stream the broker sends over TCP (CONNACK, SUBACK, PUBACK/PUBREC/PUBREL/PUBCOMP, PUBLISH,
 * DISCONNECT, ...). Reaches MQTTAsync.c / MQTTAsyncUtils.c (send/receive threads, command queue,
 * completion and connection-lost handling, QoS 0/1/2 publish bookkeeping) and the shared packet,
 * property and socket parsers.
 *
 * The connect result is awaited on a condition variable signalled by the library's own
 * onSuccess/onFailure callback; the broker half-closes after the fuzz bytes, so the library always
 * reaches one of them (its connectTimeout is only an upper bound).
 */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "MQTTAsync.h"
#include "fake_server.h"

static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cv = PTHREAD_COND_INITIALIZER;
static int connect_done; /* 0 pending, 1 ok, -1 failed — reset per input */

static void set_done(int v)
{
	pthread_mutex_lock(&mu);
	connect_done = v;
	pthread_cond_broadcast(&cv);
	pthread_mutex_unlock(&mu);
}
static void on_ok(void *ctx, MQTTAsync_successData *r) { (void)ctx; (void)r; set_done(1); }
static void on_fail(void *ctx, MQTTAsync_failureData *r) { (void)ctx; (void)r; set_done(-1); }
static void on_ok5(void *ctx, MQTTAsync_successData5 *r) { (void)ctx; (void)r; set_done(1); }
static void on_fail5(void *ctx, MQTTAsync_failureData5 *r) { (void)ctx; (void)r; set_done(-1); }
static void conn_lost(void *ctx, char *cause) { (void)ctx; (void)cause; }
static int msg_arrived(void *ctx, char *topic, int topiclen, MQTTAsync_message *m)
{
	(void)ctx; (void)topiclen;
	MQTTAsync_freeMessage(&m);
	MQTTAsync_free(topic);
	return 1;
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc; (void)argv;
	fs_setup();
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	char uri[64];
	MQTTAsync c = NULL;
	MQTTAsync_createOptions co = MQTTAsync_createOptions_initializer;
	MQTTAsync_connectOptions opts = MQTTAsync_connectOptions_initializer;
	MQTTAsync_connectOptions opts5 = MQTTAsync_connectOptions_initializer5;
	MQTTAsync_connectOptions *o;
	pthread_t t;
	fs_job job;
	int v5, ok;

	if (size < 1)
		return -1;
	v5 = data[0] & 1;
	data++;
	size--;

	fs_setup();
	snprintf(uri, sizeof(uri), "tcp://127.0.0.1:%d", fs_port);
	co.MQTTVersion = v5 ? MQTTVERSION_5 : MQTTVERSION_3_1_1;
	if (MQTTAsync_createWithOptions(&c, uri, "fuzzclient", MQTTCLIENT_PERSISTENCE_NONE, NULL, &co)
			!= MQTTASYNC_SUCCESS)
		return 0;
	MQTTAsync_setCallbacks(c, NULL, conn_lost, msg_arrived, NULL);

	if (v5)
	{
		o = &opts5;
		o->cleanstart = 1;
		o->onSuccess5 = on_ok5;
		o->onFailure5 = on_fail5;
	}
	else
	{
		o = &opts;
		o->cleansession = 1;
		o->MQTTVersion = MQTTVERSION_3_1_1;
		o->onSuccess = on_ok;
		o->onFailure = on_fail;
	}
	o->connectTimeout = 1;
	o->keepAliveInterval = 0;

	connect_done = 0;
	fs_start(&t, &job, data, size);
	if (MQTTAsync_connect(c, o) == MQTTASYNC_SUCCESS)
	{
		pthread_mutex_lock(&mu);
		while (connect_done == 0)
			pthread_cond_wait(&cv, &mu);
		ok = connect_done;
		pthread_mutex_unlock(&mu);

		if (ok == 1)
		{
			char *topics[3] = {"fuzz/a", "fuzz/+/b", "fuzz/#"};
			int qoss[3] = {0, 1, 2};
			MQTTAsync_responseOptions ro = MQTTAsync_responseOptions_initializer;
			MQTTAsync_message msg = MQTTAsync_message_initializer;
			MQTTAsync_token toks[4];
			int n = 0, q, i;

			if (MQTTAsync_subscribeMany(c, 3, topics, qoss, &ro) == MQTTASYNC_SUCCESS)
				toks[n++] = ro.token;
			msg.payload = "hello";
			msg.payloadlen = 5;
			for (q = 0; q <= 2; q++)
			{
				MQTTAsync_responseOptions po = MQTTAsync_responseOptions_initializer;
				msg.qos = q;
				if (MQTTAsync_sendMessage(c, "fuzz/a", &msg, &po) == MQTTASYNC_SUCCESS)
					toks[n++] = po.token;
			}
			for (i = 0; i < n; i++)
				MQTTAsync_waitForCompletion(c, toks[i], 200);
		}
	}
	MQTTAsync_destroy(&c);
	fs_finish(t, &job);
	return 0;
}
