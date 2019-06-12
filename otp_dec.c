//Client program that sends an encrypted file and key file to otp_dec_d for decryption using OTP.
// Input example: otp_dec encryptedfile keyfile port
// Supports output file redirection: otp_dec encryptedfile keyfile port > outputfile
//Author: Shawn McMannis
//Last mod date: 6/7/2019


#include <assert.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>


//Gets the number of characters in the provided string, converts it to a string, and saves it in numChars
void getNumChars(char* inputString, char** numChars)
{
	int charCount = strlen(inputString);

	//Convert int to string
	int length = snprintf(NULL, 0, "%d", charCount);

	//Allocate memory
	*numChars = malloc(length + 1 * sizeof(char));
	assert(numChars != NULL);

	//Copy charCount to numChars
	snprintf(*numChars, length + 1, "%d", charCount);
}


//Verifies that there are no illegal characters in the provided string. Returns 0 if there are no illegal characters, 1 otherwise
int verifyText(char* inputString)
{
	int i;
	for(i = 0;i < strlen(inputString);i++)
	{
		if((inputString[i] != 32) && (inputString[i] < 64 || inputString[i] > 90))
		{
			return 1;
		}
	}
	return 0;
}


//main
int main(int argc, char *argv[])
{
	int socketFD, portNumber, charsWritten, charsRead;
	int checkSend = -5;
	struct sockaddr_in serverAddress;
	struct hostent* serverHostInfo;
	char buffer[100000];
	char plaintext[100000];
	char key[100000];
	char encText[100000];
	char* numChars = NULL;
	char* progID = "otp_dec";
	FILE* plaintextFD;
	FILE* keyFD;
	FILE* encFD;

	//Check for proper arguments
	if(argc < 4)
	{
		fprintf(stderr, "USAGE: %s encryptedfile keyfile port\n", argv[0]);
		exit(1);
	}

	//Read encrypted file
	//Clear the buffer
	memset(buffer, '\0', sizeof(buffer));
	encFD = fopen(argv[1], "r");
	if(encFD == NULL)
	{
		fprintf(stderr, "Cannot open file %s\n", argv[1]);
		exit(1);
	}
	else
	{
		fgets(buffer, 100000, encFD);
	}

	//Copy buffer to encrypted text variable
	memset(encText, '\0', sizeof(encText));
	strcpy(encText, buffer);

	//Strip newline off of encrypted text
	encText[strcspn(encText, "\n")] = '\0';

	//Check encrypted text for illegal characters	
	if(verifyText(encText) == 1)
	{
		fprintf(stderr, "Illegal character found in %s\n", argv[1]);
		exit(1);
	}

	//Read key file
	//Clear the buffer
	memset(buffer, '\0', sizeof(buffer));
	keyFD = fopen(argv[2], "r");
	if(keyFD == NULL)
	{
		fprintf(stderr, "Cannot open file %s\n", argv[2]);
		exit(1);
	}
	else
	{
		fgets(buffer, 100000, keyFD);
	}

	//Copy buffer to key variable
	memset(key, '\0', sizeof(key));
	strcpy(key, buffer);

	//Strip newline off of key
	key[strcspn(key, "\n")] = '\0';

	//Check key for illegal characters	
	if(verifyText(key) == 1)
	{
		fprintf(stderr, "Illegal character found in %s\n", argv[2]);
		exit(1);
	}

	//Check that key file is at least as long as plaintext
	if(strlen(key) < strlen(encText))
	{
		fprintf(stderr, "Key string not long enough\n");
		exit(1);
	}


	//Set up the server address struct
	//Clear the address struct
	memset((char*)&serverAddress, '\0', sizeof(serverAddress));

	//Convert port number from string to int
	portNumber = atoi(argv[3]);

	//Create a network-capable socket
	serverAddress.sin_family = AF_INET;

	//Store the port number
	serverAddress.sin_port = htons(portNumber);

	//Convert the hostname to an address
	serverHostInfo = gethostbyname("localhost");

	//Copy in addrss
	memcpy((char*)&serverAddress.sin_addr.s_addr, (char*)serverHostInfo->h_addr, serverHostInfo->h_length);

	//Set up socket
	socketFD = socket(AF_INET, SOCK_STREAM, 0);
	if(socketFD < 0)
	{
		fprintf(stderr, "Error opening socket\n");
		exit(2);
	}

	//Connect to server
	if(connect(socketFD, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0)
	{
		fprintf(stderr, "Error connecting to server on %d\n", portNumber);
		exit(2);
	}

	//Send program ID to server
	charsWritten = send(socketFD, progID, strlen(progID), 0);
	if(charsWritten < 0)
	{
		fprintf(stderr, "Error writing to socket (program ID)\n");
	}
	
	//Receive confirmation from server
	memset(buffer, '\0', sizeof(buffer));
	charsRead = recv(socketFD, buffer, 100, 0);
	if(charsRead < 0)
	{
		fprintf(stderr, "Error reading from socket\n");
	}
	else if(strcmp(buffer, "incorrect program ID") == 0)
	{
		fprintf(stderr, "Connection refused on %d: wrong program\n", portNumber);
		exit(2);
	}

	//Send number of chars in plaintext to server
	getNumChars(encText, &numChars);

	charsWritten = send(socketFD, numChars, strlen(numChars), 0);
	if(charsWritten < 0)
	{
		fprintf(stderr, "Error writing to socket (number of incoming chars)\n");
	}

	//Receive confirmation from server
	memset(buffer, '\0', sizeof(buffer));
	charsRead = recv(socketFD, buffer, 8, 0);
	if(charsRead < 0)
	{
		fprintf(stderr, "Error reading from socket\n");
	}

	//Send encrypted text to server
	charsWritten = send(socketFD, encText, strlen(encText), 0);
	if(charsWritten < 0)
	{
		fprintf(stderr, "Error writing to socket (encrypted text)\n");
	}

	//Recieve confirmation from server
	memset(buffer, '\0', sizeof(buffer));
	charsRead = recv(socketFD, buffer, 8, 0);
	if(charsRead < 0)
	{
		fprintf(stderr, "Error reading from socket\n");
	}

	//Send number of chars in key to server
	getNumChars(key, &numChars);

	charsWritten = send(socketFD, numChars, strlen(numChars), 0);
	if(charsWritten < 0)
	{
		fprintf(stderr, "Error writing to socket (number of incoming chars)\n");
	}

	//Receive confirmation from server
	memset(buffer, '\0', sizeof(buffer));
	charsRead = recv(socketFD, buffer, 8, 0);
	if(charsRead < 0)
	{
		fprintf(stderr, "Error reading from socket\n");
	}
	
	//Send key to server
	charsWritten = send(socketFD, key, strlen(key), 0);
	if(charsWritten < 0)
	{
		fprintf(stderr, "Error writing to socket (key)\n");
	}	

	//Receive confirmation from server
	memset(buffer, '\0', sizeof(buffer));
	charsRead = recv(socketFD, buffer, 8, 0);
	if(charsRead < 0)
	{
		fprintf(stderr, "Error reading from socket\n");
	}

	//Receive plaintext from server
	//Clear plaintext variable
	memset(plaintext, '\0', 100000);

	//Loop to ensure all chars received
	charsRead = 0;
	do
	{
		memset(buffer, '\0', sizeof(buffer));
		charsRead += recv(socketFD, buffer, 1000, 0);
		strcat(plaintext, buffer);
	} while(charsRead < strlen(encText));

	//Send confirmation to server
	charsWritten = send(socketFD, "received", 8, 0);
	if(charsWritten < 0)
	{
		fprintf(stderr, "Error writing to socket\n");
	}

	//Print plaintext to stdout, or send to output file
	if(argc == 4)
	{
		printf("%s\n", plaintext);
	}
	else if(argv[4] == ">" && argc == 6)
	{
		plaintextFD = fopen(argv[5], "w");
		if(plaintextFD = NULL)
		{
			fprintf(stderr, "Cannot open file %s\n", argv[5]);
			exit(2);
		}
		else
		{
			fprintf(plaintextFD, plaintext);
			fclose(plaintextFD);
		}
	}

	//Verify socket buffer is empty
	do
	{
		ioctl(socketFD, TIOCOUTQ, &checkSend);
	}while(checkSend < 0);

	//Close socket
	close(socketFD);

	//Close file descriptors
	fclose(encFD);
	fclose(keyFD);

	//Free memory
	free(numChars);

	return 0;
}
