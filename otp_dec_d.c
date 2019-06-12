//A small server daemon that accepts communication from it's companion client program, otp_dec
// The purpose of this program is to accept an encrypted file and an OTP key, and to decrypt
// the file, using the key, via the OTP process. Decrypted data is then sent back
// to the client.
//Author: Shawn McMannis
//Last mod date: 6/7/2019


#include <assert.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>


//Node declaration
typedef struct node{
	int Pid;
	struct node* next;
} node;


//Creates a new node and returns it
node* create(int Pid, node* next)
{
	node* new = (node*)malloc(sizeof(node));
	assert(new != NULL);

	new->Pid = Pid;
	new->next = next;

	return new;
}


//Insert a new node at the beginning of the list
node* insert(node* head, int Pid)
{
	node* new = create(Pid, head);
	head = new;
	return head;
}


//Converts a char to a numerical value
int convertChar(char c)
{
	//Massive if list to convert char to numerical value
	if(c  == 'A')
	{
		return 0;
	}
	else if(c == 'B')
	{
		return 1;
	}
	else if(c == 'C')
	{
		return 2;
	}
	else if(c == 'D')
	{
		return 3;
	}
	else if(c == 'E')
	{
		return 4;
	}
	else if(c == 'F')
	{
		return 5;
	}
	else if(c == 'G')
	{
		return 6;
	}
	else if(c == 'H')
	{
		return 7;
	}
	else if(c == 'I')
	{
		return 8;
	}
	else if(c == 'J')
	{
		return 9;
	}
	else if(c == 'K')
	{
		return 10;
	}
	else if(c == 'L')
	{
		return 11;
	}
	else if(c == 'M')
	{
		return 12;
	}
	else if(c == 'N')
	{
		return 13;
	}
	else if(c == 'O')
	{
		return 14;
	}
	else if(c == 'P')
	{
		return 15;
	}
	else if(c == 'Q')
	{
		return 16;
	}
	else if(c == 'R')
	{
		return 17;
	}
	else if(c == 'S')
	{
		return 18;
	}
	else if(c == 'T')
	{
		return 19;
	}
	else if(c == 'U')
	{
		return 20;
	}
	else if(c == 'V')
	{
		return 21;
	}
	else if(c == 'W')
	{
		return 22;
	}
	else if(c == 'X')
	{
		return 23;
	}
	else if(c == 'Y')
	{
		return 24;
	}
	else if(c == 'Z')
	{
		return 25;
	}
	else if(c == ' ')
	{
		return 26;
	}
	else
	{
		return -1;
	}
}


//Converts the provided integer to a char. Returns the char
char* convertInt(int toConv)
{
	switch(toConv)
	{
		case 0:
			return "A";
			break;
		case 1:
			return "B";
			break;
		case 2:
			return "C";
			break;
		case 3:
			return "D";
			break;
		case 4:
			return "E";
			break;
		case 5:
			return "F";
			break;
		case 6:
			return "G";
			break;
		case 7:
			return "H";
			break;
		case 8:	
			return "I";
			break;
		case 9:
			return "J";
			break;
		case 10:
			return "K";
			break;
		case 11:
			return "L";
			break;
		case 12:
			return "M";
			break;
		case 13:
			return "N";
			break;
		case 14:
			return "O";
			break;
		case 15:
			return "P";
			break;
		case 16:
			return "Q";
			break;
		case 17:
			return "R";
			break;
		case 18:
			return "S";
			break;
		case 19:
			return "T";
			break;
		case 20:
			return "U";
			break;
		case 21:
			return "V";
			break;
		case 22:
			return "W";
			break;
		case 23:
			return "X";
			break;
		case 24:
			return "Y";
			break;
		case 25:
			return "Z";
			break;
		case 26:
			return " ";
			break;
	}
}


//Decrypts the encrypted string using the key string. Returns the decrypted string
char* decrypt(char* enctext, char* key)
{
	int i, e, k, temp;
	char* decString;
	char* tempChar;

	//Allocate memory for encrypted string
	decString = calloc(strlen(enctext), sizeof(char));
	assert(decString != NULL);

	for(i = 0;i < strlen(enctext);i++)
	{
		e = convertChar(enctext[i]);
		k = convertChar(key[i]);
		temp = e - k;
		if(temp < 0)
		{
			temp += 27;
		}
		tempChar = convertInt(temp);
		strcat(decString, tempChar);
	}

	return decString;
}


//main

int main(int argc, char* argv[])
{
	int listenSockFD, estConnFD, portNumber, charsRead, charsWritten, inChars;
	int childExitMethod = -5;
	int checkSend = -5;
	socklen_t sizeOfClientInfo;
	char* buffer;
	char* plaintext;
	char* key;
	char* enctext;
	char numChars[100];
	char progID[8];
	char* targetProgID = "otp_dec";
	struct sockaddr_in serverAddress, clientAddress;
	pid_t spawnPid = -5;
	node* head = NULL;

	//Check for proper arguments
	if(argc < 2)
	{
		fprintf(stderr, "USAGE: %s port\n", argv[0]);
		exit(1);
	}

	//Set up address struct for server
	//Clear address struct
	memset((char *)&serverAddress, '\0', sizeof(serverAddress));
	
	//Convert port number from string to int and store
	portNumber = atoi(argv[1]);

	//Create a network-capable socket
	serverAddress.sin_family = AF_INET;

	//Store port number
	serverAddress.sin_port = htons(portNumber);

	//Any address is allowed
	serverAddress.sin_addr.s_addr = INADDR_ANY;

	//Set up listening socket
	//Create the socket
	listenSockFD = socket(AF_INET, SOCK_STREAM, 0);
	if(listenSockFD < 0)
	{
		fprintf(stderr, "Error opening socket\n");
		exit(1);
	}

	//Enable the listening socket to begin listening
	//Connect socket to port
	if(bind(listenSockFD, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0)
	{
		fprintf(stderr, "Error on binding\n");
		exit(1);
	}

	//Activate the socket for up to 5 connections
	listen(listenSockFD, 5);

	//Continuous loop
	while(1)
	{
		//Cycle through list of previously-spawned Pids and wait as needed
		node* curr = head;
		while(curr != NULL)
		{
			waitpid(curr->Pid, &childExitMethod, WNOHANG);
			curr = curr->next;
		}

		//Accept a connection, blocking until one connects
		//Get size of the address for the connecting client
		sizeOfClientInfo = sizeof(clientAddress);

		//Accept the connection
		estConnFD = accept(listenSockFD, (struct sockaddr *)&clientAddress, &sizeOfClientInfo);
		if(estConnFD < 0)
		{		
			fprintf(stderr, "Error on accept\n");
		}
		//fork() a child process to handle the established connection
		else
		{
			spawnPid = -5;
			spawnPid = fork();
		}

		//Add the Pid to the linked list, for removal later
		head = insert(head, spawnPid);

		//Differentiate between the main process and children
		switch(spawnPid)
		{
			case 0:
				//Receive name of program attempting to send data
				charsRead = recv(estConnFD, progID, 9, 0);
				if(charsRead < 0)
				{
					fprintf(stderr, "Error reading from socket\n");
				}
				//Kill connection if connecting program not 'otp_dec'
				else if(strcmp(progID, targetProgID) != 0)
				{
					//Send 'wrong program' message to client
					charsWritten = send(estConnFD, "incorrect program ID", 21, 0);
					if(charsWritten < 0)
					{
						fprintf(stderr, "Error writing to socket\n");
					}

					close(estConnFD);
					return 0;
				}
				//Send confirmation message back to client
				else
				{
					charsWritten = send(estConnFD, "received", 8, 0);
					if(charsWritten < 0)
					{
						fprintf(stderr, "Error writing to socket\n");
					}
				}

				//Receive the number of chars incoming for the encrypted text
				charsRead = recv(estConnFD, numChars, sizeof(numChars), 0);
				if(charsRead < 0)
				{
					fprintf(stderr, "Error reading from socket\n");
				}
				else
				{
					charsWritten = send(estConnFD, "received", 8, 0);
					if(charsWritten < 0)
					{
						fprintf(stderr, "Error writing to socket\n");
					}
				}

				//Convert numChars to int
				inChars = atoi(numChars);

				//Allocate memory for plaintext string
				plaintext = calloc(inChars, sizeof(char));
				assert(plaintext != NULL);

				//Receive ecrypted string
				//Allocate memory for the buffer and encrypted string
				buffer = calloc(1000, sizeof(char));
				enctext = calloc(inChars, sizeof(char));
				assert(buffer != NULL);
				assert(enctext != NULL);

				//Loop to ensure all chars received
				charsRead = 0;
				do
				{
					memset(buffer, '\0', 1000);
					charsRead += recv(estConnFD, buffer, sizeof(buffer), 0);
					strcat(enctext, buffer);
				} while(charsRead < inChars);
				if(charsRead <=0)
				{
					fprintf(stderr, "Error reading from socket\n");
				}
				
				//Send confirmation to client
				charsWritten = send(estConnFD, "received", 8, 0);
				if(charsWritten < 0)
				{
					fprintf(stderr, "Error writing to socket\n");
				}

				//Receive the number of chars incoming from key
				charsRead = recv(estConnFD, numChars, sizeof(numChars), 0);
				if(charsRead < 0)
				{
					fprintf(stderr, "Error reading from socket\n");
				}
				else
				{
					charsWritten = send(estConnFD, "received", 8, 0);
					if(charsWritten < 0)
					{
						fprintf(stderr, "Error writing to socket\n");
					}
				}

				//Convert numChars to int
				inChars = atoi(numChars);

				//Receive key string
				//Allocate memory for key
				key = calloc(inChars, sizeof(char));
				assert(key != NULL);

				//Loop to ensure all chars received
				charsRead = 0;
				do
				{
					memset(buffer, '\0', 1000);
					charsRead += recv(estConnFD, buffer, sizeof(buffer), 0);
					strcat(key, buffer);
				} while(charsRead < inChars);
				if(charsRead <=0)
				{
					fprintf(stderr, "Error reading from socket\n");
				}

				//Send confirmation to client
				charsWritten = send(estConnFD, "received", 8, 0);
				if(charsWritten < 0)
				{
					fprintf(stderr, "Error writing to socket\n");
				}
				
				//Decrypt encrypted text using key
				plaintext = decrypt(enctext, key);

				//Send plaintext back to client
				charsWritten = send(estConnFD, plaintext, strlen(plaintext), 0);
				if(charsWritten < 0)
				{
					fprintf(stderr, "Error writing to socket");
				}

				//Receive confirmation from client
				memset(buffer, '\0', sizeof(buffer));
				charsRead = recv(estConnFD, buffer, 8, 0);
				if(charsRead < 0)
				{
					fprintf(stderr, "Error reading from socket\n");
				}

				//Verify socket buffer is empty
				do
				{
					ioctl(estConnFD, TIOCOUTQ, &checkSend);
				} while(checkSend < 0);

				//Close the connected socket
				close(estConnFD);

				//Free memory
				free(buffer);
				free(plaintext);
				free(key);
				free(enctext);

				return 0;

				break;
			default:
				break;
		}
	
	}

	//Close listening socket
	close(listenSockFD);

	return 0;
}
