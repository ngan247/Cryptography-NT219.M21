
#include <iostream>
using std::cerr;
using std::endl;
using std::wcin;
using std::wcout;

//integer convert
#include <sstream>
using std::ostringstream;

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;
using CryptoPP::byte;

#include <string>
using std::string;
using std::wstring;

#include "cryptopp/hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include <assert.h>

// source, sink
#include "cryptopp/filters.h"
using CryptoPP::StringSink; // output
using CryptoPP::StringSource; // input
using CryptoPP::BufferedTransformation;
using CryptoPP::PK_EncryptorFilter; // Public key encryption
using CryptoPP::PK_DecryptorFilter; // Public key decryption

// file input output
#include "cryptopp/files.h"
using CryptoPP::FileSource;
using CryptoPP::FileSink;

// convert string 
#include <locale>
using std::wstring_convert;
#include <codecvt>
using  std::codecvt_utf8;

#include "cryptopp/cryptlib.h"
using CryptoPP::Exception;

//integer algo
#include <cryptopp/integer.h>
using CryptoPP::Integer;

#include <cryptopp/nbtheory.h>
using CryptoPP::ModularSquareRoot;
using CryptoPP::PrimeAndGenerator;

#include <cryptopp/modarith.h> // compute in Z_p
using CryptoPP::ModularArithmetic;

//hex trans
#include "cryptopp/hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

/*RSA cipher*/
#include "cryptopp/rsa.h"
using CryptoPP::RSA;
// OAEP padding
using CryptoPP::RSAES_OAEP_SHA_Encryptor;
using CryptoPP::RSAES_OAEP_SHA_Decryptor;
using CryptoPP::InvertibleRSAFunction;

//Genererate keys
#include "cryptopp/cryptlib.h"
using CryptoPP::PrivateKey;
using CryptoPP::PublicKey;
using CryptoPP::Exception;
using CryptoPP::DecodingResult;

/*Reading key input from file*/
#include <cryptopp/queue.h>
using CryptoPP::ByteQueue;

using namespace std;

/* Set mode */ 
#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#else
#endif

/* Def function*/ 
// convert string to wstring và in ra màn hình
wstring s2ws (const std::string& str);

// convert wstring to string và in ra màn hình
string ws2s (const std::wstring& str);

// convert integer
wstring in2ws(const CryptoPP::Integer &t);
string in2s(const CryptoPP::Integer &t);

// The keys load from files
void LoadPublicKey(const string &filename, PublicKey &key);
void LoadPrivateKey(const string &filename, PrivateKey &key);
void Load(const string &filename, BufferedTransformation &bt);

// convert string to hex wtring
void PrettyPrint(string str);

void PrintKey(RSA::PrivateKey pri_key, RSA::PublicKey pub_key);

//Chọn cách lấy input
int InputFrom();

void Encrypt(RSA::PublicKey pub_key);
void Decrypt(RSA::PrivateKey pri_key);

int main(int argc, char* argv[]){
    
    // support tiếng việt
	#ifdef __linux__
	setlocale(LC_ALL,"");
	#elif _WIN32
	_setmode(_fileno(stdin), _O_U16TEXT);
 	_setmode(_fileno(stdout), _O_U16TEXT);
	#else
	#endif

    RSA::PrivateKey pri_key;
    RSA::PublicKey pub_key;
    // get key form file
    #ifdef _WIN32
        LoadPublicKey("rsaPublic.key", pub_key);
        LoadPrivateKey("rsaPrivate.key", pri_key);
    #elif __linux__
        LoadPublicKey("./rsaPublic.key", pub_key);
        LoadPrivateKey("./rsaPrivate.key", pri_key);
    #endif

    int option;
    wcout << L"Chọn 1_Encrypt, 2_Decrypt: ";
    wcin >> option;
    switch (option)
    {
        case 1:
            PrintKey(pri_key, pub_key);
            Encrypt(pub_key);
            break;
        case 2: 
            PrintKey(pri_key, pub_key);
            Decrypt(pri_key);
            break;
        default:
            wcout << L"Nhập sai!";
            exit(1);
    }
}

wstring s2ws (const std::string& str)
{
    wstring_convert<codecvt_utf8<wchar_t> > towstring;
    return towstring.from_bytes(str);
}

string ws2s (const std::wstring& str)
{
    wstring_convert<codecvt_utf8<wchar_t> > tostring;
    return tostring.to_bytes(str);
}

wstring in2ws(const CryptoPP::Integer &t)
{
    std::ostringstream oss;
    oss.str("");
    oss.clear();
    oss << t;                       // pumb t to oss
    std::string encoded(oss.str()); // to string
    std::wstring_convert<codecvt_utf8<wchar_t>> towstring;
    return towstring.from_bytes(encoded); // string to wstring
}

string in2s(const CryptoPP::Integer &t)
{
    std::ostringstream oss;
    oss.str("");
    oss.clear();
    oss << t;                       // pumb t to oss
    std::string encoded(oss.str()); // to string
    return encoded; 
}

void LoadPublicKey(const string &filename, PublicKey &key)
{
    ByteQueue queue;
    Load(filename, queue);
    key.Load(queue);
}

void LoadPrivateKey(const string &filename, PrivateKey &key)
{
    ByteQueue queue;
    Load(filename, queue);
    key.Load(queue);
}

void Load(const string &filename, BufferedTransformation &bt)
{
    FileSource file(filename.c_str(), true /*pumpAll*/);
    file.TransferTo(bt);
    bt.MessageEnd();
}


void PrettyPrint(string str)
{
	string encode;
    // Convert string to hex
	StringSource(str, true, new HexEncoder(new StringSink(encode)));
    // convert to wstring and print
	wcout << s2ws(encode) << endl;
}

void PrintKey(RSA::PrivateKey pri_key, RSA::PublicKey pub_key) 
{
    wcout << "Modulo n = " << in2ws(pub_key.GetModulus()) << endl;
    wcout << "Prime p = " << in2ws(pri_key.GetPrime1()) << endl;
    wcout << "Prime q = " << in2ws(pri_key.GetPrime2()) << endl;
    wcout << "Private d = " << in2ws(pri_key.GetPrivateExponent()) << endl;
    wcout << "Public e = " << in2ws(pub_key.GetPublicExponent()) << endl;
}

int InputFrom()
{
    int option;
    wcout << L"Input từ 1_file, 2_screen: ";
    wcin >> option;
    if (option != 1 && option != 2)
    {
        wcout << L"Nhập sai!";
        exit(1);
    }
    return option;
}

void Encrypt(RSA::PublicKey pub_key)
{
    AutoSeededRandomPool prng;
    int option;
    option = InputFrom();
    wstring wplaintext;
    string plaintext, ciphertext;
    switch (option)
    {
        case 1:
            FileSource("plaintext.txt", true, new StringSink(plaintext));
            break;
        case 2:
            wcout << L"Nhập plaintext:\n";
            #ifdef _WIN32
				fflush(stdin);
			#elif linux
				wcin.ignore();
			#endif
			//Nhập input
			getline(wcin, wplaintext);
			//Chuyển đổi thành string
			plaintext = ws2s(wplaintext);
            break;
    }

    double runtime = 0;
    int time_start = 0, time_stop = 0;
    for (int i = 0; i < 10000; i++) 
    {
        ciphertext.clear();
        // time_start là thời gian bắt đầu mã hóa.
		time_start = clock();

        // Encrypt
        RSAES_OAEP_SHA_Encryptor e(pub_key);
        StringSource(plaintext, true, 
            new PK_EncryptorFilter(prng, e, 
                new StringSink(ciphertext)
            )
        );

        // time_stop là thời gian kết thúc mã hóa
	    time_stop = clock();
        runtime += double(time_stop - time_start) / CLOCKS_PER_SEC;
    }

    // print cipher
    wcout << L"Ciphertext:\n";
    PrettyPrint(ciphertext);

    // print run time
    wcout << L"\nThời gian chạy trung bình: " << 1000 * runtime / 10000 << "ms\n";

    //write output cipher to file
    ofstream outFile;
	outFile.open("./cipher.txt");
    string encode;
	StringSource(ciphertext, true, new HexEncoder(new StringSink(encode)));
	outFile << encode;
}

void Decrypt(RSA::PrivateKey pri_key)
{
    AutoSeededRandomPool prng;
    int option;
    option = InputFrom();

    wstring wciphertext;
    string cipher, ciphertext, recoveredtext;
    switch (option)
    {
        case 1:
            FileSource("cipher.txt", true, new StringSink(cipher));
            break;
        case 2:
            wcout << L"Nhập ciphertext:\n";
            #ifdef _WIN32
				fflush(stdin);
			#elif linux
				wcin.ignore();
			#endif
			getline(wcin, wciphertext);
            cipher = ws2s(wciphertext);
            break;
    }
    // cipher input là hex string, chuyển về string và lưu vào ciphertext
    StringSource(cipher, true, new HexDecoder(new StringSink(ciphertext)));

    double runtime = 0;
    int time_start = 0, time_stop = 0;
    for (int i = 0; i < 10000; i++) 
    {
        recoveredtext.clear();
        // time_start là thời gian bắt đầu giải mã
		time_start = clock();

        // Decrypt
        RSAES_OAEP_SHA_Decryptor d(pri_key);
        StringSource(ciphertext, true, 
            new PK_DecryptorFilter(prng, d, 
                new StringSink(recoveredtext)
            )
        );

        // time_stop là thời gian kết thúc giải mã
	    time_stop = clock();
        runtime += double(time_stop - time_start) / CLOCKS_PER_SEC;
    }

    // print recoveredtext
    wcout << L"recoveredtext:\n";
    wcout << s2ws(recoveredtext);

    // print run time
    wcout << L"\nThời gian chạy trung bình: " << 1000 * runtime /10000 << "ms\n";
}
