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

#include <limits>
#include <cstdlib>
#include <string.h>
#include <sstream>
#include <fstream>

using namespace std;

// comparision_tìm lỗi
#include <assert.h>

/* Set mode */ 
#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#else
#endif

/* Khai báo biến toàn cục */
// số cột của matrix 
#define Nb 4
// số word của 32 bytes key
int Nk = 8;
// Số round với 32 bytes key
int Nr = 14;

// Mảng lưu 240 bytes (60 words)round keys.
unsigned char RoundKey[240];
// key input cho AES Program
unsigned char key[32];
// iv input cho AES Program
unsigned char iv[16];
// in - mảng lưu input
// out - mảng lưu output.
// matrix - mảng 2 chiều - ma trận 4x4, lưu giá trị tạm thời trong quá trình mã hoá
// re - mảng lưu cipher giải mã từ dạng hex.
unsigned char in[1024], out[1024], matrix[4][Nb], re[1024]; 

#define xtime(x)   ((x<<1) ^ (((x>>7) & 1) * 0x1b))
#define Multiply(x,y) (((y & 1) * x) ^ ((y>>1 & 1) * xtime(x)) ^ ((y>>2 & 1) * xtime(xtime(x))) ^ ((y>>3 & 1) * xtime(xtime(xtime(x)))) ^ ((y>>4 & 1) * xtime(xtime(xtime(xtime(x))))))

/* Def function*/ 
// convert string to wstring và in ra màn hình
wstring s2ws (const std::string& str);

// convert wstring to string và in ra màn hình
string ws2s (const std::wstring& str);

// lấy input
void GetInput(string &input, string &key, string &iv, int &en_de);

void enXorarray();
void deXorarray();

int enFillBlock (int size, char *str, unsigned char *in);
int deFillBlock (int size, unsigned char *in, int m);

//tạo round key (key qua expension)
void ExpandKey();

// // quá trình AddRoundKey XOR matrix với round key
void AddRoundKey(int round);

// Thay thế giá trị trong matrix bằng sbox
void SubBytes();
void invSubBytes(); //decyrpt

// Hàm dịch trái cho các row trong matrix
void ShiftRows();
// Hàm dịch phai cho các row trong matrix
void invShiftRows(); //decrypt

// hàm MixColumns tạo thành các cột mới trong matrix
void MixColumns();
void invMixColumns(); //decrypt

//mã hoá
void Encrypt();
//giải mã 
void Decrypt();
 
//Bảng sbox
const int sbox[256] = {
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};
//Bảng inverted sbox
const int inv_sbox[256] = {
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
};
//Bảng rcon
const int rcon[256] = {
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
    0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39,
    0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
    0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
    0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef,
    0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc,
    0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b,
    0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
    0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94,
    0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20,
    0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35,
    0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
    0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
    0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63,
    0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd,
    0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d
};

int main()
{
    #ifdef __linux__
	setlocale(LC_ALL,"");
	#elif _WIN32
	_setmode(_fileno(stdin), _O_U16TEXT);
 	_setmode(_fileno(stdout), _O_U16TEXT);
	#else
	#endif
    
    //khai bao 
    string input, key_s, iv_s;
    int en_de;
    long long unsigned int size = 0;
    GetInput(input, key_s, iv_s, en_de);    
    
    char input_c[1024];
    strcpy(input_c, input.c_str());

    std::string newString;
    for(long long unsigned int i = 0; i< key_s.length(); i+=2)
    {
        std::string byte = key_s.substr(i,2);
        char chr = (char) (int)strtol(byte.c_str(), NULL, 16);
        newString.push_back(chr);
    }
    memcpy(key, newString.data(), newString.length());
    newString.clear();

    for(long long unsigned int i = 0; i< iv_s.length(); i+=2)
    {
        std::string byte = iv_s.substr(i,2);
        char chr = (char) (int)strtol(byte.c_str(), NULL, 16);
        newString.push_back(chr);
    }
    memcpy(iv, newString.data(), newString.length());

    ExpandKey();
    switch (en_de) 
    {
        // encrypt
        case 1: 
        {
            wcout << "Ciphertext: " << endl;
            while (size < strlen(input_c)) 
            {
                size = enFillBlock (size, input_c, in);
                // Xor với iv block trước
                enXorarray();
                // encrypt _ kết quả lưu trong mảng out
                Encrypt();

                for(long long unsigned int i = 0; i < sizeof(iv); i++)
                    iv[i] = out[i];
               
                for (int i = 0 ; i < Nb*4 ; i++) 
                {
                    int x = (int)out[i];
                    if(x < 16) wcout << 0 << hex << x;
                    else wcout << hex << x; 
                } 
            }
            break;
        }
        //decrypt
        case 2: 
        {
            size = 0;
            // Convert hex to byte
            string strr(input_c);  
            string str;
            for(long long unsigned int i = 0; i < strr.length(); i+=2)
            {
                std::string byte = strr.substr(i,2);
                char chr = (char) (int)strtol(byte.c_str(), NULL, 16);
                str.push_back(chr);
            }
            memcpy(re, str.data(), str.length());
            str="";
            while (size < strr.length()/2) 
            {
                size = deFillBlock(size,in,strr.length()/2);

            // decrypted, kết quả lưu trong mảng out
            Decrypt();

            // xor với iv hoặc block trước
            deXorarray();

            for(long long unsigned int i = 0; i < sizeof(iv); i++)
               iv[i] = in[i];

            for (int i = 0 ; i < Nb*4 ; i++) str += out[i];
            }
            wcout << "Recoveredtext: " << endl;
            wcout << s2ws(str);
            break;
        }
        default: 
        {
            wcout << L"Nhập sai\n";
            exit(1);
        }
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

void GetInput(string &input, string &key, string &iv, int &en_de)
{
    wstring winput, wkey, wiv;
    int option;
    wcout << L"Chọn 1_Encryption, 2_Decryption: ";
    wcin >> option;
    if (option == 1)
    {
        en_de = 1;
        wcout << L"Nhập plaintext:" << endl;
        fflush(stdin);
        getline(wcin, winput);
        input = ws2s(winput);
    }
    else if(option == 2)
    {
        en_de = 2;
        wcout << L"Nhập ciphertext:" << endl;
        fflush(stdin);
        getline(wcin, winput);
        input = ws2s(winput);
    }
    else
    {
        wcout << L"Nhập sai!\n";
        exit(1);
    }

    // nhập key
    wcout << L"Nhập 32 bytes key: ";
    fflush(stdin);
    getline(wcin, wkey);
    key = ws2s(wkey);

    // nhập iv
    wcout << L"Nhập 16 bytes iv : ";
    fflush(stdin);
    getline(wcin, wiv);
    iv = ws2s(wiv);
}

void enXorarray()
{
    for(unsigned long long i = 0; i < sizeof(in); i++)
        in[i] ^= iv[i];
}

void deXorarray()
{
   for(unsigned long long i = 0; i < sizeof(out); i++)
      out[i] ^= iv[i];  
}

int enFillBlock (int size, char *str, unsigned char *in) 
{
    int j = 0;
    while (size < strlen(str)) 
    {
        if (j >= Nb*4) break;
        in[j++] = (unsigned char)str[size];
        size++;
    }
    // Pad 0 vào block
    if (size >= strlen(str)) for ( ; j < Nb*4 ; j++) in[j] = 0;
    return size;   
}

int deFillBlock (int size, unsigned char *in, int m) 
{
    int j = 0;
    while (size < m) 
    {
        if (j >= Nb*4) break;
        in[j++] = re[size];
        size++;
    }
   return size;   
}

void ExpandKey() 
{
   int i,j;
   unsigned char str[4],k;
   //8 word đầu tiên lấy trực tiếp từ 32 bytes key
    for (i = 0 ; i < Nk ; i++) {
        RoundKey[i*4]   = key[i*4];
        RoundKey[i*4+1] = key[i*4+1];
        RoundKey[i*4+2] = key[i*4+2];
        RoundKey[i*4+3] = key[i*4+3];
    }
   //Tạo word từ 8 đến 59
    while (i < 60) 
    {
        for (j = 0 ; j < 4 ; j++) 
        {
	        str[j] = RoundKey[(i-1) * 4 + j];
        }
      if (i % Nk == 0) {
	 // Dịch 4 bytes của word sang trái 1 đơn vị
	 // Function RotWord()
      k = str[0];
      str[0] = str[1];
      str[1] = str[2];
      str[2] = str[3];
      str[3] = k;
      // thay thế bằng sbox
      // Function Subword()
      str[0] = sbox[str[0]];
      str[1] = sbox[str[1]];
      str[2] = sbox[str[2]];
      str[3] = sbox[str[3]];
      str[0] =  str[0] ^ rcon[i/Nk];
      } 
      else if (Nk > 6 && i % Nk == 4) 
      {
      // Function Subword()
      str[0] = sbox[str[0]];
      str[1] = sbox[str[1]];
      str[2] = sbox[str[2]];
      str[3] = sbox[str[3]];
      }
      RoundKey[i*4+0] = RoundKey[(i-Nk)*4+0] ^ str[0];
      RoundKey[i*4+1] = RoundKey[(i-Nk)*4+1] ^ str[1];
      RoundKey[i*4+2] = RoundKey[(i-Nk)*4+2] ^ str[2];
      RoundKey[i*4+3] = RoundKey[(i-Nk)*4+3] ^ str[3];
      i++;
    }
}

void AddRoundKey(int round) 
{
    int i, j;
    for (i = 0 ; i < Nb ; i++) 
    {
        for (j = 0 ; j < 4 ; j++) 
        {
	    matrix[j][i] ^= RoundKey[round * Nb * 4 + i * Nb + j];
        }
    }
}

void SubBytes() 
{
    int i,j;
    for (i = 0 ; i < 4 ; i++) 
    {
        for (j = 0 ; j < Nb ; j++) 
        {
	    matrix[i][j] = sbox[matrix[i][j]];
        }
   }
}

void invSubBytes() 
{
    int i,j;
    for (i = 0 ; i < 4 ; i++)
    {
        for (j = 0 ; j < Nb ; j++) 
        {
	    matrix[i][j] = inv_sbox[matrix[i][j]];
        }
    }
}

void ShiftRows() 
{
    unsigned char str;
    // row 0 khong dịch
    // dịch trai 1 vi tri cho row 1	
    str = matrix[1][0];
    matrix[1][0] = matrix[1][1];
    matrix[1][1] = matrix[1][2];
    matrix[1][2] = matrix[1][3];
    matrix[1][3] = str;
    // dịch trai 2 vi tri cho row 2
    str = matrix[2][0];
    matrix[2][0] = matrix[2][2];
    matrix[2][2] = str;
    str = matrix[2][1];
    matrix[2][1] = matrix[2][3];
    matrix[2][3] = str;
    // dịch trai 3 vi tri cho row 3
    str = matrix[3][0];
    matrix[3][0] = matrix[3][3];
    matrix[3][3] = matrix[3][2];
    matrix[3][2] = matrix[3][1];
    matrix[3][1] = str;
}

void invShiftRows() 
{
    unsigned char str;
    // row 0 khong dịch
    // dịch phai 1 vi tri cho row 1	
    str = matrix[1][3];
    matrix[1][3] = matrix[1][2];
    matrix[1][2] = matrix[1][1];
    matrix[1][1] = matrix[1][0];
    matrix[1][0] = str;
    // row 0 khong dịch
    // dịch phai 2 vi tri cho row 2	
    str = matrix[2][0];
    matrix[2][0] = matrix[2][2];
    matrix[2][2] = str;
    str = matrix[2][1];
    matrix[2][1] = matrix[2][3];
    matrix[2][3] = str;
    // dịch phai 3 vi tri cho row 3
    str = matrix[3][0];
    matrix[3][0] = matrix[3][1];
    matrix[3][1] = matrix[3][2];
    matrix[3][2] = matrix[3][3];
    matrix[3][3] = str;
}

void MixColumns() 
{
    int i;
    unsigned char Tmp,Tm,t;
    for (i = 0 ; i < Nb ; i++) 
    {	
        t = matrix[0][i];
        Tmp = matrix[0][i] ^ matrix[1][i] ^ matrix[2][i] ^ matrix[3][i] ;
        Tm = matrix[0][i] ^ matrix[1][i] ; 
        Tm = xtime(Tm); 
        matrix[0][i] ^= Tm ^ Tmp ;
      
        Tm = matrix[1][i] ^ matrix[2][i] ; 
        Tm = xtime(Tm); 
        matrix[1][i] ^= Tm ^ Tmp ;

        Tm = matrix[2][i] ^ matrix[3][i] ; 
        Tm = xtime(Tm); 
        matrix[2][i] ^= Tm ^ Tmp ;

        Tm = matrix[3][i] ^ t ; 
        Tm = xtime(Tm); 
        matrix[3][i] ^= Tm ^ Tmp ;
    }
}

void invMixColumns() 
{
    int i;
    unsigned char a,b,c,d;
    for (i = 0 ; i < Nb ; i++)
    {
        a = matrix[0][i];
        b = matrix[1][i];
        c = matrix[2][i];
        d = matrix[3][i];
		
        matrix[0][i] = Multiply(a, 0x0e) ^ Multiply(b, 0x0b) ^ 
	    Multiply(c, 0x0d) ^ Multiply(d, 0x09);
        matrix[1][i] = Multiply(a, 0x09) ^ Multiply(b, 0x0e) ^ 
	    Multiply(c, 0x0b) ^ Multiply(d, 0x0d);
        matrix[2][i] = Multiply(a, 0x0d) ^ Multiply(b, 0x09) ^ 
	    Multiply(c, 0x0e) ^ Multiply(d, 0x0b);
        matrix[3][i] = Multiply(a, 0x0b) ^ Multiply(b, 0x0d) ^ 
	    Multiply(c, 0x09) ^ Multiply(d, 0x0e);
    }
}

void Encrypt() 
{
    int i, j, round = 0;
    //Copy input PlainText vào mảng matrix.
    for (i = 0 ; i < Nb ; i++) 
    {
        for (j = 0 ; j < 4 ; j++)     
        {
	        matrix[j][i] = in[i*4 + j];
        }
   }
    // thực hiện ark trước khi vào round 1
    AddRoundKey(0); 
    // thực hiện 4 hàm cho mỗi round trừ round cuối
    for (round=1 ; round < Nr ; round++) {
        SubBytes();
        ShiftRows();
        MixColumns();
        AddRoundKey(round);
    }
    // round cuối không có mix columns
    SubBytes();
    ShiftRows();
    AddRoundKey(Nr);
    // Copy mảng matrix vào mảng output
    for (i = 0 ; i < Nb ; i++) 
    {
        for (j = 0 ; j < 4 ; j++) 
        {
	        out[i*4+j] = matrix[j][i];
        }
    }
}

void Decrypt() 
{
    int i,j,round = 0;
    //Copy input CipherText vào mảng matrix.
    for (i = 0 ; i < Nb ; i++) {
        for (j = 0 ; j < 4 ; j++) {
	    matrix[j][i] = in[i*4 + j];
        }
    }
    // thực hiện ark trước khi vào round 1
    AddRoundKey(Nr); 
    // thực hiện 4 hàm cho mỗi round trừ round cuối.
    for (round = Nr-1 ; round > 0 ; round--) 
    {
        invShiftRows();
        invSubBytes();
        AddRoundKey(round);
        invMixColumns();
    }
    // round cuối không có mix columns.
    invShiftRows();
    invSubBytes();
    AddRoundKey(0);
    // Copy mảng matrix vào mảng output
    for(i = 0 ; i < Nb ; i++) 
    {
        for(j = 0 ; j < 4 ; j++) 
        {
	    out[i*4+j] = matrix[j][i];
        } 
    }
}

