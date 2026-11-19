/*
 * Fuzz the synchronous MQTT client (MQTTClient) against a broker that sends the fuzz input.
 *
 * Built twice: -DFUZZ_MQTT_VERSION=5 (fuzz_client_sync_v5: MQTT 5 connect5/subscribeMany5/
 * publishMessage5, properties everywhere) and -DFUZZ_MQTT_VERSION=4 (fuzz_client_sync_v3:
 * MQTT 3.1.1 connect/subscribeMany/publish). The whole input is the byte stream the broker sends
 * back over TCP: CONNACK, then SUBACK/PUBACK/PUBREC/PUBREL/PUBCOMP/PUBLISH/DISCONNECT/... in any
 * order. Reaches MQTTPacket.c (packet factory + decoders), MQTTProperties_read, MQTTPacketOut.c
 * (connack/suback/unsuback), MQTTProtocolClient.c (QoS 1/2 state machine, incoming publishes and
 * MQTTPacket_formatPayload), MQTTClient.c and the Socket/SocketBuffer read paths.
 *
 * After the fuzz bytes the fake broker half-closes the connection, so every library wait ends on
 * EOF; the library's own API timeouts are only an upper bound.
 *
 * Transport variants (-DFUZZ_TRANSPORT=...):
 *   0 tcp://  (default) the input is the raw MQTT stream.
 *   1 ws://   (fuzz_client_ws) the client speaks MQTT over WebSocket (WebSocket.c). Byte 0 bit 0:
 *             1 = the fake server first answers the upgrade request with a correct 101 response
 *             (the accept hash depends on the client's random nonce, see fake_server.h) and the rest
 *             is the server's WebSocket frame stream; 0 = the rest is sent raw, so the HTTP upgrade
 *             response parser itself is fuzzed.
 *   2 HTTP proxy: MQTTClient_connectOptions.httpProxy points at the fake server; the input is the
 *             proxy's reply to CONNECT (Proxy.c) followed by the tunnelled MQTT stream. Not shipped
 *             as a target: Proxy_connect polls for 10 s on any reply shorter than 12 bytes, ignoring
 *             EOF (Proxy.c, the usleep loop), so most mutated inputs would be 10-second stalls.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "MQTTClient.h"
#ifndef FUZZ_TRANSPORT
#define FUZZ_TRANSPORT 0
#endif
#if FUZZ_TRANSPORT == 1
#define FS_WEBSOCKET 1
#endif
#include "fake_server.h"

#ifndef FUZZ_MQTT_VERSION
#define FUZZ_MQTT_VERSION 5
#endif

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc; (void)argv;
	fs_setup();
	return 0;
}

static void drain(MQTTClient c)
{
	int i;
	for (i = 0; i < 4; i++)
	{
		char *topic = NULL;
		int topiclen = 0;
		MQTTClient_message *m = NULL;
		int rc = MQTTClient_receive(c, &topic, &topiclen, &m, 10);
		if (m)
			MQTTClient_freeMessage(&m);
		if (topic)
			MQTTClient_free(topic);
		if (rc != MQTTCLIENT_SUCCESS && rc != MQTTCLIENT_TOPICNAME_TRUNCATED)
			break;
	}
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	char uri[64];
	MQTTClient c = NULL;
	MQTTClient_createOptions co = MQTTClient_createOptions_initializer;
	pthread_t t;
	fs_job job = {0};
	char proxy[64];
	char *topics[3] = {"fuzz/a", "fuzz/+/b", "fuzz/#"};
	int qoss[3] = {0, 1, 2};
	int rc;

	fs_setup();
	snprintf(uri, sizeof(uri), "tcp://127.0.0.1:%d", fs_port);
	snprintf(proxy, sizeof(proxy), "http://127.0.0.1:%d", fs_port);
#if FUZZ_TRANSPORT == 1
	if (size < 1)
		return -1;
	job.ws_handshake = data[0] & 1;
	data++;
	size--;
	snprintf(uri, sizeof(uri), "ws://127.0.0.1:%d/mqtt", fs_port);
#elif FUZZ_TRANSPORT == 2
	/* the broker address is only named in the CONNECT request; the proxy is what we dial */
	snprintf(uri, sizeof(uri), "tcp://broker.invalid:1883");
#endif
	co.MQTTVersion = FUZZ_MQTT_VERSION;
	if (MQTTClient_createWithOptions(&c, uri, "fuzzclient", MQTTCLIENT_PERSISTENCE_NONE, NULL, &co)
			!= MQTTCLIENT_SUCCESS)
		return 0;
	MQTTClient_setCommandTimeout(c, 1000);

	fs_start(&t, &job, data, size);
#if FUZZ_MQTT_VERSION == 5
	{
		MQTTClient_connectOptions opts = MQTTClient_connectOptions_initializer5;
		MQTTResponse r;
		opts.cleanstart = 1;
		opts.connectTimeout = 1;
		opts.keepAliveInterval = 0;
#if FUZZ_TRANSPORT == 2
		opts.httpProxy = proxy;
#endif
		r = MQTTClient_connect5(c, &opts, NULL, NULL);
		rc = r.reasonCode;
		MQTTResponse_free(r);
		if (rc == MQTTCLIENT_SUCCESS)
		{
			MQTTClient_message msg = MQTTClient_message_initializer;
			MQTTProperties props = MQTTProperties_initializer;
			int q;

			r = MQTTClient_subscribeMany5(c, 3, topics, qoss, NULL, NULL);
			MQTTResponse_free(r);
			msg.payload = "hello";
			msg.payloadlen = 5;
			for (q = 0; q <= 2; q++)
			{
				MQTTClient_deliveryToken tok = 0;
				msg.qos = q;
				r = MQTTClient_publishMessage5(c, "fuzz/a", &msg, &tok);
				MQTTResponse_free(r);
				if (r.reasonCode == MQTTCLIENT_SUCCESS && q > 0)
					MQTTClient_waitForCompletion(c, tok, 100);
			}
			drain(c);
			r = MQTTClient_unsubscribeMany5(c, 3, topics, NULL);
			MQTTResponse_free(r);
			MQTTClient_disconnect5(c, 0, MQTTREASONCODE_SUCCESS, &props);
		}
	}
#else
	{
		MQTTClient_connectOptions opts = MQTTClient_connectOptions_initializer;
		opts.cleansession = 1;
		opts.connectTimeout = 1;
		opts.keepAliveInterval = 0;
		opts.MQTTVersion = FUZZ_MQTT_VERSION;
#if FUZZ_TRANSPORT == 2
		opts.httpProxy = proxy;
#endif
		rc = MQTTClient_connect(c, &opts);
		if (rc == MQTTCLIENT_SUCCESS)
		{
			MQTTClient_message msg = MQTTClient_message_initializer;
			int q;

			MQTTClient_subscribeMany(c, 3, topics, qoss);
			msg.payload = "hello";
			msg.payloadlen = 5;
			for (q = 0; q <= 2; q++)
			{
				MQTTClient_deliveryToken tok = 0;
				msg.qos = q;
				if (MQTTClient_publishMessage(c, "fuzz/a", &msg, &tok) == MQTTCLIENT_SUCCESS && q > 0)
					MQTTClient_waitForCompletion(c, tok, 100);
			}
			drain(c);
			MQTTClient_unsubscribeMany(c, 3, topics);
			MQTTClient_disconnect(c, 0);
		}
	}
#endif
	MQTTClient_destroy(&c);
	fs_finish(t, &job);
	return 0;
}
