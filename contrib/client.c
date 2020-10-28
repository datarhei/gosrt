/*
 * SRT - Secure, Reliable, Transport
 * Copyright (c) 2017 Haivision Systems Inc.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; If not, see <http://www.gnu.org/licenses/>
 */

// Build from a subdirectory of the srt repository with compiled, but not installed libsrt
// clang -Wall -O2 -I.. -I../srtcore -o client client.c -L.. -lsrt -L/usr/local/Cellar/openssl@1.1/1.1.1h/lib -lssl -lcrypto

// Build using the libsrt installed on the system.
// clang -Wall -O2 -o client client.c -lsrt -L/usr/local/Cellar/openssl@1.1/1.1.1h/lib -lssl -lcrypto

#include <stdio.h>
#include <stdlib.h>
#include <signal.h> 
#ifdef _WIN32
#define usleep(x) Sleep(x / 1000)
#else
#include <unistd.h>
#endif

#include <srt/srt.h>

static int finish = 0;

void sigintHandler(int sig_num) {
	finish = 1;

	return;
}

int main(int argc, char** argv)
{
	int ss, st;
	struct sockaddr_in sa;

	if (argc != 4) {
	  fprintf(stderr, "Usage: %s <host> <port> <streamid>\n", argv[0]);
	  return 1;
	}

	fprintf(stderr, "srt startup\n");
	srt_startup();

	fprintf(stderr, "srt socket\n");
	ss = srt_create_socket();
	if (ss == SRT_ERROR)
	{
		fprintf(stderr, "srt_socket: %s\n", srt_getlasterror_str());
		return 1;
	}

	fprintf(stderr, "srt remote address\n");
	sa.sin_family = AF_INET;
	sa.sin_port = htons(atoi(argv[2]));
	if (inet_pton(AF_INET, argv[1], &sa.sin_addr) != 1)
	{
		return 1;
	}

	fprintf(stderr, "srt setsockflag\n");
	int minversion = SRT_VERSION_FEAT_HSv5;
	srt_setsockflag(ss, SRTO_MINVERSION, &minversion, sizeof minversion);
	int file_mode = SRTT_LIVE;
	srt_setsockflag(ss, SRTO_TRANSTYPE, &file_mode, sizeof file_mode);
	srt_setsockflag(ss, SRTO_STREAMID, argv[3], strlen(argv[3]));

	fprintf(stderr, "srt connect\n");
	st = srt_connect(ss, (struct sockaddr*)&sa, sizeof sa);
	if (st == SRT_ERROR)
	{
		fprintf(stderr, "srt_connect: %s\n", srt_getlasterror_str());
		return 1;
	}

	signal(SIGINT, sigintHandler);

	for (;;)
	{
		if (finish == 1) {
			break;
		}

		fprintf(stderr, "srt recvmsg ... ");
		char msg[2048];
		st = srt_recvmsg(ss, msg, sizeof msg);
		if (st == SRT_ERROR)
		{
			fprintf(stderr, "srt_recvmsg: %s\n", srt_getlasterror_str());
			break;
		}

		fprintf(stderr, "got msg of len %d\n", st);

		fwrite(msg, st, 1, stdout);
	}

	fprintf(stderr, "srt close\n");
	st = srt_close(ss);
	if (st == SRT_ERROR)
	{
		fprintf(stderr, "srt_close: %s\n", srt_getlasterror_str());
		return 1;
	}

	fprintf(stderr, "srt cleanup\n");
	srt_cleanup();
	return 0;
}
