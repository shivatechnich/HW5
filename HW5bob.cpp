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

int main()
{
    // Creating bob key
    ltc_mp = ltm_desc;
    prng_state prng;
    prng = make_prng(&prng);
    ecc_key bob_key = make_pk_sk_pair(prng);
    unsigned char bob_out_pk_exp[4096];
    unsigned long int bob_length = 4096;
    // Export bob public key
    export_public_key(bob_key, &bob_length, bob_out_pk_exp);
    //cout << "Bob Key--" << bob_out_pk_exp << "--"<<endl;
    //cout << "Bob Key length : " << bob_length << endl;
    zmq::context_t context{1};

    // construct a REQ (request) socket and connect to interface
    zmq::socket_t socket{context, zmq::socket_type::req};
    socket.connect("tcp://localhost:5556");

    size_t size = bob_length; 
    zmq::message_t message(size);
    memcpy(message.data(), bob_out_pk_exp, size);
    bool rc = socket.send(message);
    
    // simulate work
    std::this_thread::sleep_for(1s);

    zmq::message_t request;
    unsigned char alice_out_puk_exp[4096];
    // receive a request from client
    // receive alice public key
    socket.recv(&request);
    memcpy(alice_out_puk_exp, request.data(), request.size());
    unsigned long int alice_length;
    alice_length = (unsigned long int)request.size();
    //cout << "Alice Key--" << alice_out_puk_exp << "--" << endl;
    //cout << "Alice key length : " << alice_length << endl;
    //import alice public key
    ecc_key alice_public_key = import_public_key(alice_length, alice_out_puk_exp);

    
    unsigned char shared_key[4096];
    unsigned long int shared_key_length = 4096;
    // compute shared key
    compute_shared_secret(bob_key, alice_public_key, shared_key, &shared_key_length);
    
    //cout << "shared key-" << shared_key << endl<<shared_key_length <<endl;

    // reading
    fstream newfile;
    string pt="";
    // Reading data from handshake.txt for computing hmac
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
    // computing hmac
    HMAC_Computation(mess, mac, shared_key);
    string hmac_hex;
    stringstream ss;
    for (int k=0; k<int(sha256_desc.hashsize); k++)
    {
        ss<<hex<<(int)mac[k];
        hmac_hex = ss.str();
    }
    cout << hmac_hex << endl;

    const std::string data{"Send Hmac"};

    // send the request message for server
    std::cout << "Requesting Server for Hmac" << "..." << std::endl;
    socket.send(zmq::buffer(data), zmq::send_flags::none);

    // wait for reply from server
    // Getting hmac from alice
    zmq::message_t reply{};
    socket.recv(reply, zmq::recv_flags::none);
    string hmac_hex_recv = reply.to_string();

    //cout << "Recived Hmac " << hmac_hex_recv << endl;
    // verifying the received hmac with the one bob created
    if ( hmac_hex == hmac_hex_recv)
        cout << "Verified" << endl;
    else
        cout << "Hmac verification failed" << endl;

    return 0;
}