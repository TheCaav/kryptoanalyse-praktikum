#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <sys/types.h>

#include "../include/praktikum.h"
#include "../include/network.h"

#include "breach.h"

#define msgLength 70

Connection con;

void enc(const char *guess, struct Reply *rpl) {
	/* get the encrypted message from the daemon */
	struct Message msg;
	msg.Type = Guess;
	assert(strlen(guess) < sizeof(((struct Message *) 0)->Guess));
	strcpy(msg.Guess, guess);
	Transmit(con, &msg, sizeof(msg));
	ReceiveAll(con, rpl, sizeof(struct Reply));
}

int attack(void) {
	struct Reply rpl;
	char test[msgLength] = "pw: %";
	enc(test, &rpl);
	int lastMessageLength = rpl.Len;
	char pw[70];
	int found = 0;
	int end;
	int numRetries = 0;

	for (int i = 4; i < msgLength; i++) {
		found = 0;
		for (int j = 0; j < 26; j++) {
			test[i] = (char)j+97;
			printf("testing %s\n", test);
			enc(test, &rpl);
			if (rpl.Len < lastMessageLength) {
				printf("Found %c at %d", (char)test[i], i);
				found = 1;
				lastMessageLength = rpl.Len;
				break;
			}
		}
		// Maybe aes broke detection so try again with a different message (append space to front)
		// Also solves the issue if space was right last iteration but aes broke detection
		if (found != 1) {
			for (int i = msgLength; i > 0; i--) {
				test[i] = test[i-1];
				test[0] = 32;
				numRetries++;
			}	
		}
		test[i+2] = '%';
		enc(test, &rpl);
		lastMessageLength = rpl.Len;
		test[i+1] = 32;
		enc(test, &rpl);
		if (rpl.Len < lastMessageLength) {
			end = i+1;
			break;
		}
		test[i+2] = '%';
		enc(test, &rpl);
		lastMessageLength = rpl.Len;
	}

	if (found != 1) {
		printf("Couldnt find out password within message space. Maybe try again");
		return 0;
	}

	for (int i = 4+numRetries; i < end; i++) {
		pw[i-4-numRetries] = test[i];
	}
	enc(pw, &rpl);

	if(rpl.Type == Correct) {
		printf("Password is \"%s\" (%d bytes total message size)\n", pw, rpl.Len);
		return 1;
	} else {
		printf("Password not found\n");
		return 0;
	}
}

int main(int argc, char *argv[]) {
	/* initiate communication with daemon */
	char *us = MakeNetName("");
	const char *them = "breach"; /* mind the ro */
	if(!(con = ConnectTo((const char *) us, (const char *) them))) {
		printf("Failed to get daemon's attention: %s\n", NET_ErrorText());
		return 0;
	}
	free(us);
	int result = !attack();
	DisConnect(con);
	return result;
}
