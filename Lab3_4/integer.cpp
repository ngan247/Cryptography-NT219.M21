#include <iostream>
using std::cerr;
using std::endl;
using std::wcin;
using std::wcout;

//integer convert
#include <sstream>
using std::ostringstream;

#include <string>
using std::string;
using std::wstring;

// source, sink
#include "cryptopp/filters.h"
using CryptoPP::StringSink; // output
using CryptoPP::StringSource; // input
using CryptoPP::BufferedTransformation;
using CryptoPP::PK_EncryptorFilter; // Public key encryption
using CryptoPP::PK_DecryptorFilter; // Public key decryption

// convert string 
#include <locale>
using std::wstring_convert;
#include <codecvt>
using  std::codecvt_utf8;

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

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
// padding nay ko nen sai
using CryptoPP::RSAES_PKCS1v15_Decryptor;
using CryptoPP::RSAES_PKCS1v15_Encryptor;
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

// file input output
#include "cryptopp/files.h"
using CryptoPP::FileSource;
using CryptoPP::FileSink;

using namespace std;

/* Def function*/ 
// convert string to wstring và in ra màn hình
wstring s2ws (const std::string& str);

// convert wstring to string và in ra màn hình
string ws2s (const std::wstring& str);

// convert integer
wstring in2ws(const CryptoPP::Integer &t);
string in2s(const CryptoPP::Integer &t);


//Set mode 
#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#else
#endif

int main(int argc, char* argv[]){
	
	#ifdef __linux__
	setlocale(LC_ALL,"");
	#elif _WIN32
	_setmode(_fileno(stdin), _O_U16TEXT);
 	_setmode(_fileno(stdout), _O_U16TEXT);
	#else
	#endif


/*
	//prime
	AutoSeededRandomPool prng;
	Integer p,q,g;
	PrimeAndGenerator pg;
	pg.Generate(-1,prng,512,511); //p 512 bits, a 511 bits
	p = pg.Prime();
	q = pg.SubPrime();
	g = pg.Generator();
	
	wcout << L"code hỗ trợ tiếng việt" << endl;
	wcout << "prime number p = " << in2ws(p) << endl;
	wcout << "prime number q = " << in2ws(q) << endl;
	wcout << "generator g = " << in2ws(g) << endl;

	ModularArithmetic ma(p); // mod p

	Integer x1;
	Integer x("1958569211444031162104289660421262539500678100766128832735.");
	Integer y("2858569211444031162104289660421262539500678100766128765412.");
	wcout << "x+y mod p: " << in2ws(ma.Add(x, y)) << endl;
	wcout << "x-y mod p: " << in2ws(ma.Subtract(x, y)) << endl;
	wcout << "x*y mod p: " << in2ws(ma.Multiply(x, y)) << endl;
	wcout << "x/y mod p: " << in2ws(ma.Divide(x, y)) << endl;
	wcout << "x%y mod p: " << in2ws(ma.Reduce(x, y)) << endl;
	wcout << "x^y mod p: " << in2ws(ma.Exponentiate(x, y)) << endl;
	wcout << "x1=x^-1 mod p: " << in2ws(ma.Divide(1, x)) << endl;
	x1 = ma.Divide(1, x);
	wcout << "x*x1 mod p: " << in2ws(ma.Multiply(x, x1)) << endl;


	//hex
	wcout << "x*y mod p: " << std::hex << in2ws(a_times_b_mod_c(x,y,p)) << endl;
	wcout << "x^y mod p: " << std::hex << in2ws(a_exp_b_mod_c(x,y,p)) << endl; 

	// convert wstring to integer
	wstring ss;
	string encode;
	wcout << L"Nhập input: ";
	getline(wcin,ss);
	encode.clear();
	StringSource(ws2s(ss), true, new HexEncoder(new StringSink (encode)));
	encode = encode + "H";
	wcout << "string to hex: " << s2ws(encode) << endl;
	Integer h(encode.data());
	wcout << "wstring h: " << in2ws(h) << endl;
	*/
	// Tạo key cách 1
	AutoSeededRandomPool prng;
	RSA::PrivateKey rsaPrivateKey;
	rsaPrivateKey.GenerateRandomWithKeySize(prng, 3072);
	RSA::PublicKey rsaPublicKey(rsaPrivateKey); // !!!! public e luôn là 17
	

	/* tạo key cách 2 
	// Generate Parameters
	AutoSeededRandomPool prng;
	InvertibleRSAFunction params;
	params.GenerateRandomWithKeySize(prng, 3072);
	// Create Keys
	RSA::PrivateKey rsaPrivateKey(params);
	RSA::PublicKey rsaPublicKey(params);
	*/

	// pretty print
	Integer modul =  rsaPrivateKey.GetModulus();
	Integer prime1 =  rsaPrivateKey.GetPrime1(); // prime p
	Integer prime2 =  rsaPrivateKey.GetPrime2(); // prime q
	wcout << "modul n = p.q: " << in2ws(modul) << endl;
	wcout << "prime p: " << in2ws(prime1) << endl;
	wcout << "prime q: " << in2ws(prime2) << endl;
	/*secret exponent d; public exponent e*/
	Integer SK = rsaPrivateKey.GetPrivateExponent();
	Integer PK = rsaPublicKey.GetPublicExponent();
	wcout << "secret d: " << in2ws(SK) << endl;
	wcout << "public e: " << in2ws(PK) << endl;
	// check 
	ModularArithmetic ma;
	Integer check = ma.Multiply(prime1, prime2);
	wcout << "check: " << in2ws(check) << endl;

	

	/*encryp*/
	// input
	wstring wplain;
	string plain, cipher, encode, recover;
	wcout << L"Nhập input: ";
	getline(wcin, wplain);
	plain = ws2s(wplain);
	wcout << "Plaintext: " << wplain << endl;
	// enrypt
	RSAES_OAEP_SHA_Encryptor e(rsaPublicKey);
	StringSource (plain, true, 
		new PK_EncryptorFilter(prng, e,
			new StringSink(cipher)
		));
	// pretty print
	encode.clear();
	StringSource(cipher, true, 
		new HexEncoder(
			new StringSink(encode)
		));
	wcout << "ciphertext: " << s2ws(encode) << endl;

	/*decrypt*/
	// derypt
	RSAES_OAEP_SHA_Decryptor d(rsaPrivateKey);
	StringSource (cipher, true, 
		new PK_DecryptorFilter(prng, d,
			new StringSink(recover)
		));
	// pretty print
	wcout << "recoverdtext: " << s2ws(recover);


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
