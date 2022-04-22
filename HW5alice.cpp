#include <tomcrypt.h>
#include <string>
#include <iostream>
#include <cstdlib>
#include <iomanip>
#include <fstream>
#include <math.h>
#include <chrono>
#include <thread>
#include "zmq.hpp"
#include "Methods.cpp"
extern ltc_math_descriptor ltc_mp;
extern const ltc_math_descriptor ltm_desc;
using namespace std;
using namespace std::chrono_literals;
// Name : Shivakarthik Pamulapati
// Need handshake.txt file for sending hmac
int main()
{
    //creating alice key
    ltc_mp = ltm_desc;
    prng_state prng;
    prng = make_prng(&prng);
    ecc_key alice_key = make_pk_sk_pair(prng);
    unsigned char alice_out_pk_exp[4096];
    unsigned long int alice_length = 4096;
    //exporting alice public key
    export_public_key(alice_key, &alice_length, alice_out_pk_exp);
    
    //cout << "Alice Key---" << alice_out_pk_exp << "--" << endl;
    //cout << "Alice Key length : " << alice_length << endl;
    //send to client
    // initialize the zmq context with a single IO thread
    //sendiing alice public and length to bob
    zmq::context_t context{1};

    // construct a REP (reply) socket and bind to interface
    zmq::socket_t socket{context, zmq::socket_type::rep};
    socket.bind("tcp://*:5556");
    // prepare some static data for responses
    const std::string data{"Sending Cipher text"};

    zmq::message_t request;
    unsigned char bob_out_puk_exp[4096];
    // receive a request from client
    //receiving bob public key
    socket.recv(&request);
    memcpy(bob_out_puk_exp, request.data(), request.size());
    unsigned long int bob_length;
    bob_length = (unsigned long int)request.size();
    //cout << "Bob Key--" << bob_out_puk_exp << "--"<<endl;
    //cout << "bob key length : " << bob_length << endl;
    // simulate work
    std::this_thread::sleep_for(1s);

    size_t size = alice_length; 
    zmq::message_t message(size);
    memcpy(message.data(), alice_out_pk_exp, size);
    bool rc = socket.send(message);
    //importing bob public key
    ecc_key bob_public_key = import_public_key(bob_length, bob_out_puk_exp);
    //computing shared key
    unsigned char shared_key[4096];
    unsigned long int shared_key_length = 4096;
    compute_shared_secret(alice_key, bob_public_key, shared_key, &shared_key_length);
    
    //cout << "shared key-" << shared_key << endl<<shared_key_length;
    // Reading data from handshake.txt for computing hmac
    fstream newfile;
    string pt="";
    newfile.open("handshake.txt",ios::in);
    if (newfile.is_open()){ //checking whether the file is open
        string tp;
        while(getline(newfile, tp)){ //read data from file object and put it into string.
            pt += tp; //print the data of the string
        }
      newfile.close();
    }

    char *mess = const_cast<char*>(pt.c_str());
    unsigned char mac[32];
    HMAC_Computation(mess, mac, shared_key);
    string hmac_hex;
    stringstream ss;
    for (int k=0; k<int(sha256_desc.hashsize); k++)
    {
        ss<<hex<<(int)mac[k];
        hmac_hex = ss.str();
    }
    cout << hmac_hex << endl;

    zmq::message_t request_mac;

    // receive a request from client
    // sending hmac to bob
    socket.recv(request_mac, zmq::recv_flags::none);
    std::cout << "Received " << request_mac.to_string() << std::endl;

    // simulate work
    std::this_thread::sleep_for(1s);

    // send the reply to the client with Cipher text and Plain text hash
    socket.send(zmq::buffer(hmac_hex), zmq::send_flags::none);

    return 0;
}