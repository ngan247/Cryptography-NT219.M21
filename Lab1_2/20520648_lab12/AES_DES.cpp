/* internal lib */
#include <iostream>
using std::cerr;
using std::cin;
using std::cout;
using std::endl;
using std::wcin;
using std::wcout;

#include <string>
using std::string;
using std::wstring;

// convert string 
#include <locale>
using std::wstring_convert;
#include <codecvt>
using  std::codecvt_utf8;

#include <cstdlib>
using std::exit;

// comparision_tìm lỗi
#include <assert.h>

/* Set mode */ 
#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#else
#endif

/* external header lib */
// crypto lib
#include "cryptopp/cryptlib.h"
using CryptoPP::byte;
using CryptoPP::Exception;

// string trans
#include "cryptopp/filters.h"
using CryptoPP::StringSink; // output
using CryptoPP::StringSource; // input
using CryptoPP::StreamTransformationFilter;
using CryptoPP::Redirector; // string to bytes
using CryptoPP::ArraySink;
using CryptoPP::AuthenticatedDecryptionFilter;
using CryptoPP::AuthenticatedEncryptionFilter;

// file input output
#include "cryptopp/files.h"
using CryptoPP::FileSource;
using CryptoPP::FileSink;
using CryptoPP::BufferedTransformation;

//hex trans
#include "cryptopp/hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

//base64 trans
#include "cryptopp/base64.h"
using CryptoPP::Base64Encoder;
using CryptoPP::Base64Decoder;

// tao randomnumber
#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;
using CryptoPP::byte;

// kiểu SecByteBlock cho key, IV
#include "cryptopp/secblock.h"
using CryptoPP::SecByteBlock;

// block cipher
#include "cryptopp/aes.h"
using CryptoPP::AES;
#include "cryptopp/des.h"
using CryptoPP::DES;

/* mode of operation */
//CBC,ECB,OFB, CFB, CTR
#include "cryptopp/modes.h"
using CryptoPP::CBC_Mode;
using CryptoPP::ECB_Mode;
using CryptoPP::CFB_Mode;
using CryptoPP::CTR_Mode;
using CryptoPP::OFB_Mode;
// XTS
#include "cryptopp/xts.h"
using CryptoPP::XTS;
// CCM
#include "cryptopp/ccm.h"
using CryptoPP::CCM;
// GCM
#include "cryptopp/gcm.h"
using CryptoPP::GCM;

using namespace std;

/* Def function*/ 
// convert string to wstring và in ra màn hình
wstring s2ws (const std::string& str);

// convert wstring to string và in ra màn hình
string ws2s (const std::wstring& str);

// chuyển SecByteBlock thành hex wstring và in ra màn hình
void PrettyPrint(SecByteBlock byte_block);

// chuyển string thành Base64 wstring và in ra màn hình
void PrettyPrint(string str);

//chuyển Cryptopp::byte array thành hex wstring và in ra màn hình
void PrettyPrint(CryptoPP::byte *bytes_array);

//convert ciphertext to base64 và trả về string base64 để xuất file
string PrinterForFile(string str);

//Check nhập số có đúng yêu cầu không.
bool Check(int a, int limit);

// Chọn thuật toán AES / DES từ màn hình
int ChosenAlgorithm();

// Chọn mode từ màn hình
int ChosenMode(int algo);

// Chọn Encrypt hay Decrypt
int Encrypt_Decrypt();

// Size cho key và iv
void KeyIV_Size(int algo, int mode, int &key_size, int &iv_size);

// Tạo key và iv
void GenerateSecByteBlock(SecByteBlock &block, int block_size, int algo, wstring which, bool isDe);

// Get input from random/ screen/ file
void Input(SecByteBlock &key, int key_size, SecByteBlock &iv, int iv_size, string &plaintext, 
string &ciphertext, int en_de, int algo);

//Encrypt và Decrypt
//dùng template cho các mode
template <class Mode> 
void Encrypt(const string &plaintext, Mode &m, string &cipher);
template <class Mode> 
void Decrypt(const string &cipher, Mode &m, string &recovered);

//Hàm mã hóa cho mode từ 1 đến 6
//trả về thời gian thực hiện mã 1 lần.
//tham chiếu ciphertext
template <class Encryption>
double Encrypt_pro(const SecByteBlock &key, const SecByteBlock &iv, string plaintext,
string &ciphertext, string &recovered, bool isIV);

//Hàm giải mã cho mode từ 1 đến 6
//trả về thời gian thực hiện mã 1 lần.
//tham chiếu recovered
template <class Decryption>
double Decrypt_pro(const SecByteBlock &key, const SecByteBlock &iv, string plaintext,
string &ciphertext, string &recovered, bool isIV) ;

// hàm mã hoá cho mode 7,8
//trả về thời gian thực hiện mã 1 lần.
//tham chiếu cipher
template <class Mode>
double Encrypt_pro_Au(string &cipher, string &plaintext, SecByteBlock key, SecByteBlock iv);

// hàm mã hoá cho mode 7,8
//trả về thời gian thực hiện mã 1 lần.
//tham chiếu recovered
template <class Mode>
double Decrypt_pro_Au(string &cipher, string &recovered, SecByteBlock key, SecByteBlock iv);

//Hàm trả về thời gian chạy 10000 lần 
//Xác định và gán các giá trị Mode cho các hàm giải mã và mã hóa
//Biến isDe để xác định mã hóa hoặc giải mã, biến type là algorithm+mode
//tham số ciphertext hoặc recovered là để trả về kết quả sau khi thực hiện.
double *Timing(bool isDe, string type,const SecByteBlock &key, const SecByteBlock &iv, string plaintext, string &ciphertext, string &recovered);

int main(int argc, char* argv[]){
	#ifdef __linux__
	setlocale(LC_ALL,"");
	#elif _WIN32
	_setmode(_fileno(stdin), _O_U16TEXT);
 	_setmode(_fileno(stdout), _O_U16TEXT);
	#else
	#endif

	//Khai báo
	CryptoPP::SecByteBlock key;
	CryptoPP::SecByteBlock iv;
	int key_size, iv_size;
	string plaintext, ciphertext, recoveredtext;
	int algorithm, mode, en_de;
	double *etime = new double[2];

	wcout << L"Ciphertext ở dạng Base64." << endl;
	wcout << L"Key và IV ở dạng Hex." << endl;
    wcout << L"DES: Key size = 16, iv size = 8" << endl;
	wcout << L"AES: Key size = 32, iv size = 16" << endl;
	wcout << L"AES, mode CCM, GCM: Key size = 32, iv size = 12" << endl; 

    algorithm = ChosenAlgorithm();
	mode = ChosenMode(algorithm);
	en_de = Encrypt_Decrypt();
	KeyIV_Size(algorithm, mode, key_size, iv_size);
	Input(key, key_size, iv, iv_size, plaintext, ciphertext, en_de, algorithm);

	// Tính thời gian chạy 10000 lần và thực hiện mã hoá/ giải mã theo đúng thuật toán và mode 
	// isDe trong hàm Timing là bool, với 0 là encrypt(1) và 1 là decrypt(2) nên isDe = en_de - 1 

	switch (algorithm) 
	{
		case 1: 
		{
			switch (mode)
			{
			case 1:
				etime = Timing(en_de - 1, "DES_ECB",key, iv, plaintext, ciphertext, recoveredtext);
				break;
			case 2:
				etime = Timing(en_de - 1, "DES_CBC",key, iv, plaintext, ciphertext, recoveredtext);
				break;
			case 3:
				etime = Timing(en_de - 1, "DES_OFB",key, iv, plaintext, ciphertext, recoveredtext);
				break;
			case 4:
				etime = Timing(en_de - 1, "DES_CFB",key, iv, plaintext, ciphertext, recoveredtext);
				break;
			case 5:
				etime = Timing(en_de - 1, "DES_CTR",key, iv, plaintext, ciphertext, recoveredtext);
				break;
			}
			break;
		}
		case 2: 
		{
			switch (mode) 
			{
				case 1:
					etime = Timing(en_de - 1, "AES_ECB",key, iv, plaintext, ciphertext, recoveredtext);
					break;
				case 2:
					etime = Timing(en_de - 1, "AES_CBC",key, iv, plaintext, ciphertext, recoveredtext);
					break;
				case 3:
					etime = Timing(en_de - 1, "AES_OFB",key, iv, plaintext, ciphertext, recoveredtext);
					break;
				case 4:
					etime = Timing(en_de - 1, "AES_CFB",key, iv, plaintext, ciphertext, recoveredtext);
					break;
				case 5:
					etime = Timing(en_de - 1, "AES_CTR",key, iv, plaintext, ciphertext, recoveredtext);
					break;
				case 6:
					etime = Timing(en_de - 1, "AES_XTS",key, iv, plaintext, ciphertext, recoveredtext);
					break;
				case 7:
					etime = Timing(en_de - 1, "AES_CCM",key, iv, plaintext, ciphertext, recoveredtext);
					break;
				case 8:
					etime = Timing(en_de - 1, "AES_GCM",key, iv, plaintext, ciphertext, recoveredtext);
					break;
			}
		}
	}

	//Sử dụng switch case để xuất kết quả encrypt hoặc decrypt
	switch (en_de) {
		case 1: {
			wcout << L"Ciphertext: ";
			PrettyPrint(ciphertext);
			wcout << L"Thời gian chạy 10000 lần: " << etime[0] << L" ms";
			break;
		}
		case 2: {
			wcout << L"Recoveredtext: ";
			wcout << s2ws(recoveredtext) << '\n';
			wcout << L"Thời gian chạy 10000 lần: " << etime[1] << L" ms";
			break;
		}
	}
	
	if (en_de == 1)
	{
		ofstream outFile;
		outFile.open("./cipher.txt");
		string encoded = PrinterForFile(ciphertext);
		outFile << encoded;
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

void PrettyPrint(SecByteBlock byte_block)
{
	// Convert byte_block to a hex
	string hexstring;
	StringSource(byte_block, byte_block.size(), true, new HexEncoder(new StringSink(hexstring)));
	wcout << s2ws(hexstring) << endl;
}

void PrettyPrint(string str)
{
	// Convert string to a base64
	string base64string;
	StringSource(str, true, new Base64Encoder(new StringSink(base64string)));
	wcout << s2ws(base64string) << endl;
}
void PrettyPrint(CryptoPP::byte *bytes_array)
{
	// Convert bytes_array to a hex wstring
	string encoded_string;
	StringSource(bytes_array, sizeof(bytes_array), true, new HexEncoder(new StringSink(encoded_string)));
	wcout << s2ws(encoded_string) << endl;
}

string PrinterForFile(string str)
{
	string encodedCode;
	StringSource(str, true,
				 new Base64Encoder(
					 new StringSink(encodedCode)));
	return encodedCode;
}
bool Check(int a, int max) {
	return(a > 0 && a <= max);
}

int ChosenAlgorithm()
{
	int algo;
	wcout << L"Chọn thuật toán (1_DES, 2_AES): ";
	wcin >> algo;
	if (!Check(algo,2)) {
		wcout << L"Nhập sai";
		exit(1);
	}
	return algo;
}

int ChosenMode(int algo)
{
	int mode;
	wcout << L"Chọn mode ";
	wcout << "1_ECB, 2_CBC, 3_OFB, 4_CFB, 5_CTR "; //DES có 5 mode
	if (algo == 2)
	{
		wcout << "6_XTS, 7_CCM, 8_GCM " << endl;  //AES có 8 mode
		wcout << "mode: ";
		wcin >> mode;
		if (!Check(mode, 8))
		{
			wcout << L"Nhập sai";
			exit(1);
		}
	}
	else
	{
		wcout << endl << "mode: ";
		wcin >> mode;
		if (!Check(mode, 5)) 
		{
			wcout << L"Nhập sai";
			exit(1);
		}
	}
	return mode;
}

int Encrypt_Decrypt()
{
	int e_d;
	wcout << L"Chọn 1_Encrypt, 2_Decrypt: ";
	wcin >> e_d;
	if (!Check(e_d, 2)) 
	{
		wcout << L"Nhập sai";
		exit(1);
	}
	else 
		return e_d;
}

void KeyIV_Size(int algo, int mode, int &key_size, int &iv_size)
{
	if (algo == 2) //AES
	{
		if (mode < 7) 
		{
			key_size = 32;
			iv_size = 16;
		} 
		else 
		{
			key_size = 32;
			iv_size = 12;
		}
	}
	else if (algo == 1)// DES
	{
		key_size = DES::DEFAULT_KEYLENGTH;
		iv_size = DES::BLOCKSIZE;
	}

}

void GenerateSecByteBlock(SecByteBlock &block, int block_size, int algo, wstring which, bool isDe) {
	wcout << L"Chọn cách tạo " << which << endl;
	if (isDe == 0) wcout << L" 1_Random, 2_Nhập từ màn hình, 3_Nhập từ file:  ";
	else wcout << L" 2_Nhập từ màn hình, 3_Nhập từ file:  ";
	
	int option;
	block = SecByteBlock(block_size);
	try
	{
		wcin >> option;
		// không tạo random key, iv cho decrypt
		if (option == 1 && !isDe)
		{
			AutoSeededRandomPool prng;
			prng.GenerateBlock(block, block_size);
			//Ghi key ra file voi des
			if(which == L"key" && algo == 1)
			{
				#ifdef _WIN32
					StringSource sskey(block, block.size(), true, new FileSink("des_fkey.key"));
				#elif __linux__
					StringSource sskey(block, block.size(), true, new FileSink("./des_fkey.key"));
				#endif
			}
			//Ghi iv ra file voi des
			else if(which == L"IV" && algo == 1)
			{
				#ifdef _WIN32
					StringSource ssiv(block, block.size(), true, new FileSink("des_fiv.key"));
				#elif __linux__
					StringSource ssiv(block, block.size(), true, new FileSink("./des_fiv.key"));
				#endif
			}
			//Ghi key ra file voi aes
			else if(which == L"key" && algo == 2)
			{
				#ifdef _WIN32
					StringSource sskey(block, block.size(), true, new FileSink("aes_fkey.key"));
				#elif __linux__
					StringSource sskey(block, block.size(), true, new FileSink("./aes_fkey.key"));
				#endif
			}
			//Ghi iv ra file voi aes
			else if(which == L"IV" && algo == 2)
			{
				#ifdef _WIN32
					StringSource ssiv(block, block.size(), true, new FileSink("aes_fiv.key"));
				#elif __linux__
					StringSource ssiv(block, block.size(), true, new FileSink("./aes_fiv.key"));
				#endif
			}
		} 
		//Nhập từ màn hình
		else if (option == 2) 
		{
			try 
			{
				//Nhập string từ màn hình
				wstring winput;
				wcout << L"Nhập " << which << ": ";
				#ifdef _WIN32
					fflush(stdin);
				#elif __linux__
					getline(wcin, winput);
				#endif
					getline(wcin,winput);
				//chuyển đổi sang string
				string input = ws2s(winput);
			
				//Thực hiện Decoder vì input ở dạng Hex
				StringSource(input,true,new HexDecoder (new CryptoPP::ArraySink(block,block_size)));
			} 
			catch (exception &e) 
			{
				wcout << L"Đã xảy ra lỗi trong quá trình nhập!" << endl;
				exit(1);
			}
		} 
		//Nhập từ file 
		else if (option == 3) 
		{
			try 
			{
				//Đọc key từ file voi des
				if (which == L"key" && algo == 1) 
				{
					#ifdef _WIN32
						FileSource fs("des_fkey.key", false);
						ArraySink bytes_block(block, block_size);
						fs.Detach(new Redirector(bytes_block));
						fs.Pump(block_size);
					#elif __linux__ //chạy trên linux
						FileSource fs("./des_fkey.key", false);
						ArraySink bytes_block(block, block_size);
						fs.Detach(new Redirector(bytes_block));
						fs.Pump(block_size);
					#endif
				} 
				//Đọc iv từ file voi des
				else if (which == L"IV" && algo == 1) 
				{
					#ifdef _WIN32
						FileSource fs("des_fiv.key", false);
						ArraySink bytes_block(block, block_size);
						fs.Detach(new Redirector(bytes_block));
						fs.Pump(block_size);
					#elif __linux__ //chạy trên linux
						FileSource fs("./des_fiv.key", false);
						ArraySink bytes_block(block, block_size);
						fs.Detach(new Redirector(bytes_block));
						fs.Pump(block_size);
					#endif
				}
				//Đọc key từ file voi aes
				else if (which == L"key" && algo == 2) 
				{
					#ifdef _WIN32
						FileSource fs("aes_fkey.key", false);
						ArraySink bytes_block(block, block_size);
						fs.Detach(new Redirector(bytes_block));
						fs.Pump(block_size);
					#elif __linux__ //chạy trên linux
						FileSource fs("./aes_fkey.key", false);
						ArraySink bytes_block(block, block_size);
						fs.Detach(new Redirector(bytes_block));
						fs.Pump(block_size);
					#endif
				} 
				//Đọc iv từ file voi aes
				else if (which == L"IV" && algo == 2) 
				{
					#ifdef _WIN32
						FileSource fs("aes_fiv.key", false);
						ArraySink bytes_block(block, block_size);
						fs.Detach(new Redirector(bytes_block));
						fs.Pump(block_size);
					#elif __linux__ //chạy trên linux
						FileSource fs("./aes_fiv.key", false);
						ArraySink bytes_block(block, block_size);
						fs.Detach(new Redirector(bytes_block));
						fs.Pump(block_size);
					#endif
				}
			} 
			catch (exception &e) 
			{
				wcout << e.what() << '\n';
				exit(1);
			}
		} 
		else {
			wcout << L"Nhập sai";
			exit(1);
		}	
	}
	catch(exception &e) {
		wcout << e.what() << '\n';
		exit(1);
	}
}

void Input(SecByteBlock &key, int key_size, SecByteBlock &iv, int iv_size, string &plaintext,
string &ciphertext, int en_de, int algo) 
{
	wstring wplaintext, wciphertext;
	int option;

	if (en_de == 1) // encrypt
	{
		// hàm tạo key, iv 
		GenerateSecByteBlock(key, key_size, algo, L"key", 0);
		GenerateSecByteBlock(iv, iv_size, algo, L"IV", 0);
		plaintext.clear();
		//Chọn nhập input từ file hoặc  từ màn hình		
		wcout << L"Chọn cách nhập input" << endl;	
		wcout << L"1_Nhập input từ màn hình, 2_Nhập input từ file: ";
		wcin >> option;
		//Input nhập từ màn hình
		if (option == 1) 
		{
			wcout << L"Plaintext: ";
			#ifdef _WIN32
				fflush(stdin);
			#elif linux
				getline(wcin, wplaintext);
			#endif
				//Nhập input
				getline(wcin, wplaintext);
			//Chuyển đổi thành string
			plaintext = ws2s(wplaintext);
		} 
		//input được nhập từ file do người dùng tạo 
		else if (option == 2) 
		{
			FileSource("plaintext153KB.txt", true, new StringSink(plaintext));
		} 
		else 
		{
			wcout << L"Nhập sai.";
			exit(1);
		}
	} 
		// Decrypt
	else
	{
		//Gọi hàm tạo key, iv, tham số isDe = 1 để không tạo key và iv random
		GenerateSecByteBlock(key, key_size, algo, L"key", 1);
		GenerateSecByteBlock(iv, iv_size, algo, L"IV", 1);
		ciphertext.clear();
		//Cho phép chọn nhập input bằng file hoặc nhập từ màn hình
		wcout << L"Chọn cách nhập input" << endl;
		wcout << L"1_Nhập input từ màn hình, 2_Nhập input từ file: ";
		wcin >> option;
		 //Input từ màn hình (base64)
		if (option == 1) 
		{
			wcout << "Ciphertext: \n";
			#ifdef _WIN32
				fflush(stdin);
			#elif linux
				getline(wcin, wciphertext);
			#endif
				getline(wcin, wciphertext);
			//convert cinphertext to string
			string sciphertext = ws2s(wciphertext);
			//Giải mã từ base64
			StringSource(sciphertext, true, new Base64Decoder(new StringSink(ciphertext)));
		}
		//input nhập từ file do người dùng tự tạo giá trị (Định dạng base64)
		else if (option == 2) 
		{
			FileSource("cipher.txt", true, new Base64Decoder(new StringSink(ciphertext)));

		} 
		else 
		{
			wcout << L"Nhập sai";
			exit(1);
		}
	}
	//Xuất ra màn hình key và iv 
	wcout << "Key: ";
	PrettyPrint(key);
	wcout << "IV: ";
	PrettyPrint(iv);
}

template <class Mode> 
void Encrypt(const string &plaintext, Mode &m, string &cipher) 
{
	cipher.clear(); 
	try 
	{
		// StreamTransformationFilter để mã hóa theo mode m
		StringSource s(plaintext, true, new StreamTransformationFilter(m, new StringSink(cipher)));
	}
	catch (const CryptoPP::Exception &e) 
	{
		wcout << e.what() << endl;
		exit(1);
	}
}
template <class Mode>
void Decrypt(const string &cipher, Mode &m, string &recovered)
{
	recovered.clear();
	try
	{
		// StreamTransformationFilter để giải mã theo mode modee
		StringSource s(cipher, true, new StreamTransformationFilter(m, new StringSink(recovered)));
	}
	catch (const CryptoPP::Exception &e)
	{
		wcout << e.what() << endl;
		exit(1);
	}
}

template <class Encryption>
double Encrypt_pro(const SecByteBlock &key, const SecByteBlock &iv, string plaintext,
string &ciphertext, string &recovered, bool isIV) 
{
	ciphertext.clear();
	Encryption en;
	//Biến đo thời gian chạy
	int time_start = 0, time_stop = 0;
	//Nếu isIV = 1 thì mode yêu cầu iv.
	if (isIV == 1) 
	{
		try
		{
			// time_start là thời gian bắt đầu mã hóa.
			time_start = clock();
			//Set key và IV
			en.SetKeyWithIV(key, key.size(), iv);
			//Mã hóa theo mode đã chọn
			Encrypt<Encryption>(plaintext, en, ciphertext);
			// time_stop là thời gian kết thúc mã hóa
			time_stop = clock();
		}
		catch (const CryptoPP::Exception &ex)
		{
			wcout << ex.what() << endl;
			exit(1);
		} 
	}
	// mode không cần IV
	else if (isIV == 0) 
	{
		try
		{
			// time_start là thời gian bắt đầu mã hóa.
			time_start = clock();
			//Set key 
			en.SetKey(key,key.size());
			//Mã hóa theo mode đã chọn
			Encrypt<Encryption>(plaintext, en, ciphertext);
			// time_stop là thời gian kết thúc hàm mã hóa
			time_stop = clock();
		}
		catch (const CryptoPP::Exception &ex)
		{
			wcout << ex.what() << endl;
			exit(1);
		}
	} 
	//Hàm thay đổi giá trị của ciphertext (tham chiếu)
	//Trả về thời gian thực hiện 1 lần 
	return(double(time_stop - time_start) / CLOCKS_PER_SEC * 1000);
}

template <class Decryption>
double Decrypt_pro(const SecByteBlock &key, const SecByteBlock &iv, string plaintext,
string &ciphertext, string &recovered, bool isIV) 
{
	recovered.clear();
	Decryption de;
	//Biến đo thời gian chạy
	int time_start = 0, time_stop = 0;
	//Nếu isIV = 1 thì mode yêu cầu iv.
	if (isIV == 1) 
	{
		try
		{
			// time_start là thời gian bắt đầu giải mã.
			time_start = clock();
			//Set key và IV
			de.SetKeyWithIV(key, key.size(), iv);
			//Giải mã theo mode đã chọn
			Decrypt<Decryption>(ciphertext, de, recovered);
			// time_stop là thời gian kết thúc giải mã.
			time_stop = clock();
		}
		catch (const CryptoPP::Exception &ex)
		{
			wcout << ex.what() << endl;
			exit(1);
		} 
	}
	// mode không cần IV
	else if (isIV == 0) 
	{
		try
		{
			// time_start là thời gian bắt đầu giải mã.
			time_start = clock();
			//Set key 
			de.SetKey(key,key.size());
			//Mã hóa theo mode đã chọn
			Decrypt<Decryption>(ciphertext, de, recovered);
			// time_stop là thời gian kết thúc giải mã.
			time_stop = clock();
		}
		catch (const CryptoPP::Exception &ex)
		{
			wcout << ex.what() << endl;
			exit(1);
		}
	} 
	//Hàm thay đổi giá trị của recoveredtext (tham chiếu)
	//Trả về thời gian thực hiện 1 lần 
	return(double(time_stop - time_start) / CLOCKS_PER_SEC * 1000);
}

template <class Mode>
double Encrypt_pro_Au(string &cipher, string &plaintext, SecByteBlock key, SecByteBlock iv)
{
	cipher.clear();
	//Biến đo thời gian chạy
	int time_start = 0, time_stop = 0;
	try
	{
		time_start = clock();
		//Khai báo m ứng mode đã chọn
		Mode m;
		m.SetKeyWithIV(key, sizeof(key),iv);
		m.SpecifyDataLengths( 0, plaintext.size(), 0 ); //cho mode CCM
		//hàm AuthenticatedEncryptionfilter để mã hóa theo mode m
		StringSource s(plaintext, true, new AuthenticatedEncryptionFilter(m, new StringSink(cipher)));
		time_stop = clock();
	}
	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}
	return(double (time_stop - time_start) / CLOCKS_PER_SEC * 1000);
}

template <class Mode>
double Decrypt_pro_Au(string &cipher, string &recovered, SecByteBlock key, SecByteBlock iv)
{
	recovered.clear();
	//Biến đo thời gian chạy
	int time_start = 0, time_stop = 0;
	try
	{
		time_start = clock();
		//Khai báo m ứng mode đã chọn
		Mode m;
		m.SetKeyWithIV(key, sizeof(key),iv);
		m.SpecifyDataLengths( 0, cipher.size() - 8, 0 ); //cho mode CCM
		//hàm AuthenticatedEncryptionfilter để mã hóa theo mode m
		//Lưu kết quả bằng StringSink trong tham biến cipher truyền ra ngoài
		StringSource s(cipher, true, new AuthenticatedEncryptionFilter(m, new StringSink(recovered)));
		time_stop = clock();
	}
	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}
	return(double (time_stop - time_start) / CLOCKS_PER_SEC * 1000);
}

//Hàm trả về thời gian chạy 10000 lần 
//Xác định và gán các giá trị Mode cho các hàm giải mã và mã hóa
//Biến isDe để xác định giữa giải mã và mã hóa, biến type để định dạng mode
//ciphertext và recovered là tham số để trả về kết quả sau khi thực hiện mã hóa hoặc giải mã.
double *Timing(bool isDe, string type,const SecByteBlock &key, const SecByteBlock &iv, string plaintext, string &ciphertext, string &recovered) {
	//Khởi tạo giá trị etime để lưu giá trị thời gian chạy 10000 lần của các hàm
	double *etime = new double[2];

	//Chọn DES và mode ECB, không sử dụng iv biến isIV = 0
	if ( type == "DES_ECB") 
	{
		for (int i = 1; i<=10000; i++) 
		{
			if (!isDe) etime[0] += Encrypt_pro<ECB_Mode<DES>::Encryption>(key, iv, plaintext, ciphertext, recovered,0);
			else etime[1] += Decrypt_pro<ECB_Mode<DES>::Decryption>(key, iv, plaintext, ciphertext, recovered,0);
		}
	} 
	//Chọn DES và mode CBC
	else if ( type == "DES_CBC") 
	{
		for (int i = 1; i<=10000; i++) 
		{
			if (!isDe) etime[0] += Encrypt_pro<CBC_Mode<DES>::Encryption>(key, iv, plaintext, ciphertext, recovered,1);
			else etime[1] += Decrypt_pro<CBC_Mode<DES>::Decryption>(key, iv, plaintext, ciphertext, recovered,1);
		}
	} 
	//Chọn scheme DES và mode OFB
	else if ( type == "DES_OFB") 
	{
		for (int i = 1; i<=10000; i++)
		{
			if (!isDe) etime[0] += Encrypt_pro<OFB_Mode<DES>::Encryption>(key, iv, plaintext, ciphertext, recovered,1);
			else etime[1] += Decrypt_pro<OFB_Mode<DES>::Decryption>(key, iv, plaintext, ciphertext, recovered,1);
		}
	}
	//Chọn scheme DES và mode CFB
	else if ( type == "DES_CFB") 
	{
		for (int i = 1; i<=10000; i++) 
		{
			if (!isDe) etime[0] += Encrypt_pro<CFB_Mode<DES>::Encryption>(key, iv, plaintext, ciphertext, recovered,1);
			else etime[1] += Decrypt_pro<CFB_Mode<DES>::Decryption>(key, iv, plaintext, ciphertext, recovered,1);
		}
	} 
	//Chọn scheme DES và mode CTR
	else if ( type == "DES_CTR") 
	{
		for (int i = 1; i<=10000; i++) 
		{
			if (!isDe) etime[0] += Encrypt_pro<CTR_Mode<DES>::Encryption>(key, iv, plaintext, ciphertext, recovered,1);
			else etime[1] += Decrypt_pro<CTR_Mode<DES>::Decryption>(key, iv, plaintext, ciphertext, recovered,1);
		}
	} 
	//Chọn AES và mode ECB, không sử dụng iv biến isIV = 0
	else if ( type == "AES_ECB") 
	{
		for (int i = 1; i<=10000; i++) 
		{
			if (!isDe) etime[0] += Encrypt_pro<ECB_Mode<AES>::Encryption>(key, iv, plaintext, ciphertext, recovered,0);
			else etime[1] += Decrypt_pro<ECB_Mode<AES>::Decryption>(key, iv, plaintext, ciphertext, recovered,0);
		}
	} 
	//Chọn AES và mode CBC
	else if ( type == "AES_CBC" )
	{
		for (int i = 1; i<=10000; i++) 
		{
			if (!isDe) etime[0] += Encrypt_pro<CBC_Mode<AES>::Encryption>(key, iv, plaintext, ciphertext, recovered,1);
			else etime[1] += Decrypt_pro<CBC_Mode<AES>::Decryption>(key, iv, plaintext, ciphertext, recovered,1);
		}
	} 
	//Chọn AES và mode OFB
	else if (type ==  "AES_OFB") 
	{ 
		for (int i = 1; i<=10000; i++) 
		{
			if (!isDe) etime[0] += Encrypt_pro<OFB_Mode<AES>::Encryption>(key, iv, plaintext, ciphertext, recovered,1);
			else etime[1] += Decrypt_pro<OFB_Mode<AES>::Decryption>(key, iv, plaintext, ciphertext, recovered,1);
		}
	}
	//Chọn AES và mode CFB
	else if ( type == "AES_CFB") 
	{
		for (int i = 1; i<=10000; i++) 
		{
			if (!isDe) etime[0] += Encrypt_pro<CFB_Mode<AES>::Encryption>(key, iv, plaintext, ciphertext, recovered,1);
			else etime[1] += Decrypt_pro<CFB_Mode<AES>::Decryption>(key, iv, plaintext, ciphertext, recovered,1);
		}
	} 
	//Chọn AES và mode CTR
	if ( type == "AES_CTR") 
	{
		for (int i = 1; i<=10000; i++) 
		{
			if (!isDe) etime[0] += Encrypt_pro<CTR_Mode<AES>::Encryption>(key, iv, plaintext, ciphertext, recovered,1);
			else etime[1] += Decrypt_pro<CTR_Mode<AES>::Decryption>(key, iv, plaintext, ciphertext, recovered,1);
		}
	}
	//ChọnAES và mode XTS, không sử dụng iv biến isIV = 0
	if ( type == "AES_XTS") 
	{
		for (int i = 1; i<=10000; i++) 
		{
			if (!isDe) etime[0] += Encrypt_pro<ECB_Mode<AES>::Encryption>(key, iv, plaintext, ciphertext, recovered,0);
			else etime[1] += Decrypt_pro<ECB_Mode<AES>::Decryption>(key, iv, plaintext, ciphertext, recovered,0);
		}
	} 
	//Chọn AES và mode CCM, dùng Authentication gọi Encrypt_pro_Au và Decrypt_pro_Au
	if (type == "AES_CCM") 
	{
		for (int i = 1; i<=10000; i++) 
		{
			if (!isDe) etime[0] += Encrypt_pro_Au<CCM< AES, 8 >::Encryption>(ciphertext, plaintext, key, iv);
			else etime[1] += Decrypt_pro_Au<CCM< AES, 8 >::Decryption>(ciphertext, recovered, key, iv);
		}
	} 
	//Chọn AES và mode GCM, dùng Authentication gọi Encrypt_pro_Au và Decrypt_pro_Au
	if (type == "AES_GCM") 
	{
		for (int i = 1; i<=10000; i++) 
		{
			if (!isDe) etime[0] += Encrypt_pro_Au<GCM< AES, CryptoPP::GCM_64K_Tables >::Encryption>(ciphertext, plaintext, key, iv);
			else etime[1] += Decrypt_pro_Au<GCM< AES, CryptoPP::GCM_64K_Tables >::Decryption>(ciphertext, recovered, key, iv);
		}
	}
	//etime[0] lưu trữ thời gian mã hóa 10000 lần.
	//etime[1] lưu trữ thời gian giải mã 10000 lần.
	return etime;
} 
