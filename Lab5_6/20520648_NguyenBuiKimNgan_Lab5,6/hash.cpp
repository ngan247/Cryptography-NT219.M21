#include <iostream>
using std::cin;
using std::cout;
using std::wcin;
using std::wcout;
using namespace std;

#include <cstdlib>
using std::exit;

#include <string>
using std::string;
using std::wstring;

// convert string 
#include <locale>
using std::wstring_convert;
#include <codecvt>
using  std::codecvt_utf8;

//integer convert
#include <sstream>
using std::ostringstream;

#include "cryptopp/hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

//integer algo
#include <cryptopp/integer.h>
using CryptoPP::Integer;
#include <cryptopp/nbtheory.h>
using CryptoPP::ModularSquareRoot;
using CryptoPP::PrimeAndGenerator;

#include "cryptopp/osrng.h"
using CryptoPP::byte;

// source, sink for string
#include "cryptopp/filters.h"
using CryptoPP::StringSink; // output
using CryptoPP::StringSource; // input
using CryptoPP::Redirector; // string to bytes

// file
#include <cryptopp/files.h>
using CryptoPP::FileSource;
using CryptoPP::FileSink;
using CryptoPP::BufferedTransformation;

// Header for hash funtions
#include "cryptopp/sha.h" // sha-1, sha-2
#include "cryptopp/sha3.h" // sha3
#include "cryptopp/shake.h" // shake

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

// convert string to hex string and print
void PrettyPrint(string str);

// get input from screen
string InputFromScreen();

//get input from file message.txt
string InputFromFile();

template <class HASH>
void Hash(const string &message, string &digest);

template <class HASH_SHAKE>
void HashShake(const string &message, string &digest, int DigestSize);

int main(int argc, char* argv[])
{
    // support Vietnamese
    #ifdef __linux__
	setlocale(LC_ALL,"");
	#elif _WIN32
	_setmode(_fileno(stdin), _O_U16TEXT);
 	_setmode(_fileno(stdout), _O_U16TEXT);
	#else
	#endif

    // chọn Input from screen or from file
    int option = 0;
    wcout << L"(1) Input from screen\n";
    wcout << L"(2) Input from file\n";
    wcout << L"Chọn cách nhập input: ";
    wcin >> option;
    if (option != 1 && option != 2)
    {
        wcout << L"Nhập sai yêu cầu";
        exit(1);
    }
    string message;
    switch (option)
    {
    case 1:
        message = InputFromScreen();
        break;
    case 2:
        message = InputFromFile();
        break;
    default:
        break;
    }

    // chọn hash func
    wcout << "(1) SHA224\n";
    wcout << "(2) SHA256\n";
    wcout << "(3) SHA384\n";
    wcout << "(4) SHA512\n";
    wcout << "(5) SHA3-224\n";
    wcout << "(6) SHA3-256\n";
    wcout << "(7) SHA3-384\n";
    wcout << "(8) SHA3-512\n";
    wcout << "(9) SHAKE128\n";
    wcout << "(10) SHAKE256\n";
    wcout << L"Chọn hàm hash: ";
    int choice;
    wcin >> choice;
    if (choice < 1 || choice > 10 )
    {
        wcout << L"Nhập sai yêu cầu";
        exit(1);
    }

    int DigestSize = 0;
    string digest = "";
    wcout << endl;
    switch (choice)
    {
    case 1:
        wcout << "SHA224" << endl;
        Hash<CryptoPP::SHA224>(message, digest);
        break;
    case 2:
        wcout << "SHA256" << endl;
        Hash<CryptoPP::SHA256>(message, digest);
        break;
    case 3:
        wcout << "SHA384" << endl;
        Hash<CryptoPP::SHA384>(message, digest);
        break;
    case 4:
        wcout << "SHA512" << endl;
        Hash<CryptoPP::SHA512>(message, digest);
        break;
    case 5:
        wcout << "SHA3_224" << endl;
        Hash<CryptoPP::SHA3_224>(message, digest);
        break;
    case 6:
        wcout << "SHA3_256" << endl;
        Hash<CryptoPP::SHA3_256>(message, digest);
        break;
    case 7:
        wcout << "SHA3_384" << endl;
        Hash<CryptoPP::SHA3_384>(message, digest);
        break;
    case 8:
        wcout << "SHA3_512" << endl;
        Hash<CryptoPP::SHA3_512>(message, digest);
        break;
    case 9:
        wcout << L"Nhập digest length: ";
        wcin >> DigestSize;
        wcout << "SHAKE128" << endl;
        HashShake<CryptoPP::SHAKE128>(message, digest, DigestSize);
        break;
    case 10: 
        wcout << L"Nhập digest length: ";
        wcin >> DigestSize;
        wcout << "SHAKE256" << endl;
        HashShake<CryptoPP::SHAKE256>(message, digest, DigestSize);
        break;  
    default:
        break;
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

void PrettyPrint(string str)
{
    string encode;
    // Convert string to hex
	StringSource(str, true, new HexEncoder(new StringSink(encode)));
    // convert to wstring and print
	wcout << s2ws(encode) << endl;
}

string InputFromScreen()
{
    wstring str;
    str.clear();
    #ifdef _WIN32
        fflush(stdin);
    #elif __linux__
        wcin.ignore();
    #endif
    getline(wcin, str);
    return (ws2s(str));
}

string InputFromFile()
{
    string str;
    str.clear();
    #ifdef _WIN32
        FileSource f("message.txt", true, new StringSink(str));
    #elif __linux__
        FileSource f("./message.txt", true, new StringSink(str));
    #endif
    return str;
}

template <class HASH>
void Hash(const string &message, string &digest) 
{
    HASH hash;
    float runtime = 0;
    int time_start = 0, time_stop = 0;
    for (int i = 0; i < 10000; i++) 
    {
        digest.clear();
        time_start = clock();

        hash.Restart(); // delete buffer
        hash.Update((const CryptoPP::byte*) message.data(), message.size()); // set input
        digest.resize(hash.DigestSize()); // set ouput length
        hash.TruncatedFinal((CryptoPP::byte*)&digest[0], digest.size()); // compute ouput

        time_stop = clock();
        runtime += float(time_stop - time_start) / CLOCKS_PER_SEC;
    }
    wcout  << "Run time = " << runtime * 1000 / 10000 << "ms\n";
    wcout << "Digest: ";
    PrettyPrint(digest);
}

template <class HASH_SHAKE>
void HashShake(const string &message, string &digest, int DigestSize) 
{
    HASH_SHAKE hash;
    float runtime = 0;
    int time_start = 0, time_stop = 0;
    for (int i = 0; i < 10000; i++) 
    {
        digest.clear();
        time_start = clock();

        hash.Restart(); // delete buffer
        hash.Update((const CryptoPP::byte*) message.data(), message.size()); // set input
        digest.resize(DigestSize); // set ouput length
        hash.TruncatedFinal((CryptoPP::byte*)&digest[0], digest.size()); // compute ouput

        time_stop = clock();
        runtime += float(time_stop - time_start) / CLOCKS_PER_SEC;
    }
    wcout  << "Run time = " << runtime * 1000 / 10000 << "ms\n";
    wcout << "Digest: ";
    PrettyPrint(digest);
}