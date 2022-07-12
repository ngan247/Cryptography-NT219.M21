#include <iostream>
using std::cerr;
using std::endl;
using std::wcin;
using std::wcout;
using namespace std;

#include <string>
using std::string;
using std::wstring;

//integer convert
#include <sstream>
using std::ostringstream;

// convert string 
#include <locale>
using std::wstring_convert;
#include <codecvt>
using  std::codecvt_utf8;

#include <assert.h>

// random number
#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include "cryptopp/hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

// source, sink
#include "cryptopp/filters.h"
using CryptoPP::StringSink; // output
using CryptoPP::StringSource; // input
using CryptoPP::ArraySink;
using CryptoPP::SignatureVerificationFilter;
using CryptoPP::SignerFilter;

// file input output
#include "cryptopp/files.h"
using CryptoPP::FileSource;
using CryptoPP::FileSink;

//integer algo
#include <cryptopp/integer.h>
using CryptoPP::Integer;

// hash func
#include "cryptopp/sha.h"
using CryptoPP::SHA256;

//ecc curve, ECDSA
#include "cryptopp/eccrypto.h"
using CryptoPP::DL_GroupParameters_EC;
using CryptoPP::ECDSA;
using CryptoPP::ECP;
#include "cryptopp/oids.h"
using CryptoPP::OID;

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
void LoadPrivateKey(const string &filename, ECDSA<ECP, SHA256>::PrivateKey &key);
void LoadPublicKey(const string &filename, ECDSA<ECP, SHA256>::PublicKey &key);

//In các parameter của key
void PrintParameters(const DL_GroupParameters_EC<ECP> &parameters);

/* Sign */
string goSign(const ECDSA<ECP, SHA256>::PrivateKey &pri_key, const string &message);
void Sign();

/* Verify */
bool goVerify(const ECDSA<ECP, SHA256>::PublicKey &pub_key, const string &mess, const string &signature);
void Verify();

int main(int argc, char* argv[]){
    // support tiếng việt
	#ifdef __linux__
	setlocale(LC_ALL,"");
	#elif _WIN32
	_setmode(_fileno(stdin), _O_U16TEXT);
 	_setmode(_fileno(stdout), _O_U16TEXT);
	#else
	#endif

    int option;
    wcout << L"1. Sign message.txt file\n";
    wcout << L"2. Verify signature.txt file\n";
    wcout << L"Chọn: ";
    wcin >> option;
    switch (option)
    {
        case 1:
            Sign();
            wcout << L"Kí thành công!";
            break;
        case 2:
            Verify();
            wcout << L"Xác thực thành công!";
            break;
        default:
            wcout << L"Nhập sai yêu cầu !";
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

void LoadPrivateKey(const string &filename, ECDSA<ECP, SHA256>::PrivateKey &key)
{
	key.Load(FileSource(filename.c_str(), true).Ref());
}

void LoadPublicKey(const string &filename, ECDSA<ECP, SHA256>::PublicKey &key)
{
	key.Load(FileSource(filename.c_str(), true).Ref());
}

//In các thành phần của khóa
void PrintParameters(const DL_GroupParameters_EC<ECP> &parameters)
{
    wcout << "Modulus = ";
    wcout << in2ws(parameters.GetCurve().GetField().GetModulus()) << endl;
    wcout << "Coefficient A = ";
    wcout << in2ws(parameters.GetCurve().GetA()) << endl;
    wcout << "Coefficient B = ";
    wcout << in2ws(parameters.GetCurve().GetB()) << endl;
    wcout << "Base x = " << in2ws(parameters.GetSubgroupGenerator().x) << endl;
    wcout << "Base y = " << in2ws(parameters.GetSubgroupGenerator().y) << endl;
    wcout << "Subgroup Order = ";
    wcout << in2ws(parameters.GetSubgroupOrder()) << endl;
    wcout << "Cofactor = ";
    wcout << in2ws(parameters.GetCofactor()) << endl;
}

string goSign(const ECDSA<ECP, SHA256>::PrivateKey &pri_key, const string &message) 
{
    AutoSeededRandomPool prng;
    string signature = "";
    signature.clear();
    // sử dụng SignerFilter để kí và hàm băm SHA-256 cho private key
    StringSource(message, true, 
        new SignerFilter(prng,ECDSA<ECP, SHA256>::Signer(pri_key), 
            new StringSink(signature)
        )
    );
    return signature;
}

void Sign()
{
    ECDSA<ECP, SHA256>::PrivateKey pri_key;
    // Lấy private key 
    LoadPrivateKey("eccPrivate.key", pri_key);

    // Lấy message từ file message.txt
    string message = "";
    #ifdef _WIN32
        FileSource fmess("message.txt", true, new StringSink(message));
    #elif __linux__
        FileSource fmess("./message.txt", true, new StringSink(message));
    #endif

    string signature;
    double runtime = 0;
    int time_start = 0, time_stop = 0;
    for (int i = 0; i < 10000; i++)        
    {
        time_start = clock();
        // Thực hiện kí
        signature = goSign(pri_key, message);
        // check kí có thành công không
        if (signature.empty()) 
        {
            wcout << "Error!";
            exit(1);
        }
        time_stop = clock();
        runtime += double(time_stop - time_start) / CLOCKS_PER_SEC;
    }

    // lưu vào  signature file signature.txt
    StringSource s(signature, true, new FileSink("signature.txt"));

    // In privatekey parameters
    PrintParameters(pri_key.GetGroupParameters());
    wcout << "Private Exponent = ";
    wcout << in2ws(pri_key.GetPrivateExponent()) << endl;

    // In runtime
    wcout << L"Thời gian chạy trung bình: " << 1000 * runtime / 10000 << "ms\n";
}

bool goVerify(const ECDSA<ECP, SHA256>::PublicKey &pub_key, const string &mess, const string &signature) 
{
    bool result = false;
    StringSource(signature + mess, true, 
        new SignatureVerificationFilter(ECDSA<ECP, SHA256>::Verifier(pub_key),
            new ArraySink((CryptoPP::byte *)&result, sizeof(result)
            )
        )
    );
    return result;
}

void Verify()
{
    ECDSA<ECP, SHA256>::PublicKey pub_key;
    // Lấy private key 
    LoadPublicKey("eccPublic.key", pub_key);

    // Lấy message từ file message.txt
    string message = "";
    #ifdef _WIN32
        FileSource fmess("message.txt", true, new StringSink(message));
    #elif __linux__
        FileSource fmess("./message.txt", true, new StringSink(message));
    #endif

    // Lấy signature từ file signature.txt
    string signature = "";
    #ifdef _WIN32
        FileSource fsign("signature.txt", true, new StringSink(signature));
    #elif __linux__
        FileSource fsign("./signature.txt", true, new StringSink(signature));
    #endif

    double runtime = 0;
    int time_start = 0, time_stop = 0;
    for (int i = 0; i < 10000; i++)        
    {
        time_start = clock();
        // check verify có thành công không
        if(goVerify(pub_key, message, signature) == false)
		{
			wcout << "Error!" << endl;
			exit(1);
		}
        time_stop = clock();
        runtime += double(time_stop - time_start) / CLOCKS_PER_SEC;
    }

    // In publickey parameters
    PrintParameters(pub_key.GetGroupParameters());
    wcout << "Pub x = " << in2ws(pub_key.GetPublicElement().x) << endl;
    wcout << "Pub y = " << in2ws(pub_key.GetPublicElement().y) << endl;

    // In runtime
    wcout << L"Thời gian chạy trung bình: " << 1000 * runtime / 10000 << "ms\n";
}