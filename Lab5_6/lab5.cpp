#include <iostream>
using std::cerr;
using std::endl;
using std::wcin;
using std::wcout;
using namespace std;

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
#include "cryptopp/base64.h"
using CryptoPP::Base64Encoder;
using CryptoPP::Base64Decoder;

//integer algo
#include <cryptopp/integer.h>
#include <cryptopp/nbtheory.h>

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

#include "cryptopp/osrng.h"
using CryptoPP::byte;



// Set _setmode()
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

int main(int argc, char* argv[])
{
    #ifdef __linux__
	setlocale(LC_ALL,"");
	#elif _WIN32
	_setmode(_fileno(stdin), _O_U16TEXT);
 	_setmode(_fileno(stdout), _O_U16TEXT);
	#else
	#endif

    //hash func
    CryptoPP::SHAKE256 hash;
    int DigestSize = 512; //bytes

    // Hash algoritthms information
    wcout << "Name: " << s2ws(hash.AlgorithmName()) << endl;
    wcout << "Digest size: " << DigestSize << endl;
    wcout << "Block size: " << hash.BlockSize() << endl;

    // get input string
    wstring message;
    wcout << L"Nhập message: ";
    getline(wcin, message);

    // Compute disgest
    string digest;
    hash.Restart(); // xoá cái cũ 
    hash.Update((const CryptoPP::byte*)ws2s(message).data(), ws2s(message).size()); // set input
    digest.resize(DigestSize); // set ouput length
    hash.TruncatedFinal((CryptoPP::byte*)&digest[0], digest.size()); // compute ouput

  

// convert digest into hex format
    std::string encode;
    encode.clear();
    StringSource(digest, true, 
    new HexEncoder (new StringSink (encode)));
    std::wcout << "Digest string: " << s2ws(encode) << std::endl;

    // hash to Z_p 
    // length(digest) >= length(p)
    string hdigest=encode+"H";
    CryptoPP::Integer idigest(hdigest.data());
    CryptoPP::Integer p("AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308717D4D9B009BC66842AECDA12AE6A380E62881FF2F2D82C68528AA6056583A48F3H");
    wcout << "Prime number p for Z_p: "<< in2ws(p) << endl;
    wcout << "Hash digest in Z_p: " << in2ws(idigest % p) << endl; // idigest mod p
    return 0;

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
