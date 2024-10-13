#ifdef _WIN32 //dèine code window
#include <io.h>
#include <fcntl.h>
#endif

//Nhập xuất ra màn hình
#include <iostream> // thư viện nhập xuất
using std::wcin;
using std::wcout;

//Sử dụng string và wstring
#include <string> // thư viện chuỗi
using std::string;
using std::wstring;

//Bắt lỗi
#include <exception> 
using std::exception; // xử lý các ngoại lệ

//Hỗ trở tiếng việt
#include <codecvt>
#include <locale>
#include <cstdlib>
#include <assert.h>
#include <limits>
#include <iomanip>

//Input, Output file
#include "cryptopp/files.h"
using CryptoPP::FileSink;
using CryptoPP::FileSource;

//Encryp, Decryp RSA
#include "cryptopp/rsa.h"
using CryptoPP::InvertibleRSAFunction;
using CryptoPP::RSA;
using CryptoPP::RSAES_OAEP_SHA_Decryptor;
using CryptoPP::RSAES_OAEP_SHA_Encryptor;

#include "cryptopp/sha.h"
using CryptoPP::SHA512;

//filter cho các hàm stream cipher
#include "cryptopp/filters.h"
using CryptoPP::PK_DecryptorFilter;
using CryptoPP::PK_EncryptorFilter;
using CryptoPP::StringSink;
using CryptoPP::StringSource;

//Input, Output file
#include "cryptopp/files.h"
using CryptoPP::FileSink;
using CryptoPP::FileSource;

//Random number generation
#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

//Lưu byte string
#include <cryptopp/queue.h> 
using CryptoPP::ByteQueue;

#include "cryptopp/cryptlib.h"
using CryptoPP::BufferedTransformation; 
using CryptoPP::DecodingResult;
using CryptoPP::Exception;

//Hex converted
#include "cryptopp/hex.h"
using CryptoPP::HexDecoder;
using CryptoPP::HexEncoder;

//Thư viện xử lí số lớn, modulus
#include "cryptopp/nbtheory.h"
#include "cryptopp/modarith.h"
#include "cryptopp/integer.h"
using CryptoPP::Integer;

using CryptoPP::DECRYPTION;
using CryptoPP::ENCRYPTION;

//Support Vietnamese
//Setup
void SupportVietnamese() {
	#ifdef __linux__
	setlocale(LC_ALL,"");
	#elif _WIN32
	_setmode(_fileno(stdin), _O_U16TEXT);
 	_setmode(_fileno(stdout), _O_U16TEXT);
	#else
	#endif
}
//Chuyển đổi string to wstring + wstring to string
wstring s2ws (const std::string& str)
{
    std::wstring_convert<std::codecvt_utf8<wchar_t> > towstring;
    return towstring.from_bytes(str);
}
string ws2s (const std::wstring& str)
{
    std::wstring_convert<std::codecvt_utf8<wchar_t> > tostring;
    return tostring.to_bytes(str);
}

 //Chuyển đổi int to wstring
wstring i2ws(const CryptoPP::Integer &t)
    {
        std::ostringstream oss;
        oss.str("");
        oss.clear();
        oss << t;                       // pumb t to oss
        std::string encoded(oss.str()); // to string
        std::wstring_convert<std::codecvt_utf8<wchar_t>> towstring;
        return towstring.from_bytes(encoded); // string to wstring
    }
//Chạy test 10000 lần.
#define nconst 10000

//Kiểm tra người dùng có nhập số từ menu đúng yêu cầu hay không.
bool CheckInput(int a, int limit) {
	return(a>0 && a<=limit);
}

//Chuyển đổi từ byte string sang Hex sang wstring và in ra màn hình
void PrettyPrint(string str)
{
	// Convert byte string to a hex wstring,
	// and print to console.
	string encoded_string;
	StringSource(str, true, new HexEncoder(new StringSink(encoded_string)));
	wstring wstr = s2ws(encoded_string);
	wcout << wstr << endl;
}

//Chuyển đổi từ string sang pointer char
char *s2ptrc(string str)
    {
        char *c = new char[str.size() + 1];
        for (int i = 0; i < str.size(); ++i)
        {
            c[i] = str[i];
        }
        c[str.size()] = '\0';
        return c;
    }

//Thực hiện lấy key từ 1 file.
void LoadKeyFromFile(const string &filename, BufferedTransformation &b) {
    FileSource f(filename.c_str(), true);
    f.TransferTo(b);
    b.MessageEnd(); //Đọc đến khi hết file
}

//Hàm lấy key từ file, dùng template để chia private key và public key
template <class PriOrPub>
void KeyFromFile(PriOrPub &Key, string filepath) {
    //Khai báo
    ByteQueue bq; 
    AutoSeededRandomPool prng;

    //Key sẽ được lấy từ file trong đường dẫn filepath, sau đó lưu vào ByteQueue bq là load vào key
    //Lấy key xong sẽ kiểm tra key hợp lệ hay không
    try {
        LoadKeyFromFile(filepath,bq);
        Key.Load(bq);
        bq.Clear();
        if (!Key.Validate(prng,3)) {
            throw "Validate error";
        }
    } //Bắt lỗi (Không thể mở file, không thể load key vào bq,...) 
    catch (CryptoPP::Exception  &error) {
        wcout << (error.what()) << '\n';
    }
}

//Hàm lấy key vào, chia 2 phần linux và windows do đường dẫn khác nhau
//filepath mặc định của key là RSAPrivateKey và RSAPublickey
void GetInputKey(RSA::PrivateKey &RSAPri, RSA::PublicKey &RSAPub) { 
    wcout << L"Note: Public key bắt buộc phải >= 3072 bits\n" 
    << L"Private key sẽ được load từ file RSAPricateKey.key\n"
    << L"Public key sẽ được load từ file RSAPublicKey.key\n";
    wcout << L"Nhập Private Key và Public Key từ file.\n"; 

    #ifdef _WIN32
        KeyFromFile<RSA::PrivateKey>(RSAPri,".\\RSAPrivateKey.key");
        KeyFromFile<RSA::PublicKey>(RSAPub,".\\RSAPublicKey.key");
    #elif __linux__
        KeyFromFile<RSA::PrivateKey>(RSAPri,"./RSAPrivateKey.key");
        KeyFromFile<RSA::PublicKey>(RSAPub,"./RSAPublicKey.key");
    #endif
}

//Hàm lấy input (plaintext, ciphertext) từ file.
//EnDe sẽ xác định cần lấy plaintext hay ciphertext.
void GetInputFromFile(string &plaintext, string &ciphertext, int EnDe) {
    if (EnDe == 1) {
        FileSource f("plaintext.txt", true, new StringSink(plaintext));
    } else if (EnDe == 2) {
        FileSource f("ciphertext.txt", true, new StringSink(ciphertext));
    }
}

//Hàm lấy input (plaintext, ciphertext) từ màn hình
void GetInputFromScreen(string &input) {
    wstring winput;
    fflush(stdin);
    getline(wcin, winput);
    input = ws2s(winput);
}

//Hàm in key để kiểm tra.
void PrintKeys(RSA::PrivateKey &RSAPri, RSA::PublicKey &RSAPub) {
    wcout << "Public modulo n = " << i2ws(RSAPub.GetModulus()) << '\n';
    wcout << "Private prime number p = " << i2ws(RSAPri.GetPrime1()) << '\n';
    wcout << "Private prime number q = " << i2ws(RSAPri.GetPrime2()) << '\n';
    wcout << "Public exponent e = " << i2ws(RSAPub.GetPublicExponent()) << '\n';
    wcout << "Private exponent d = " << i2ws(RSAPri.GetPrivateExponent()) << '\n';
}

//Hàm trình bày menu và lấy toàn bộ các giá trị đầu vào cần thiết.
void GetInput(string &plaintext, string &ciphertext, RSA::PrivateKey &RSAPri, RSA::PublicKey &RSAPub, int &EnDe) {
    //Đảm bảo ciphertext và plaintext trống trước khi thực hiện
    plaintext.clear();
    ciphertext.clear();

    try {
        //Menu nhập yêu cầu
        wcout << L"Nhập yêu cầu:" << '\n' 
        << L"1. Encryption." << '\n'
        << L"2. Decryption." << '\n';
        wcin >> EnDe;
        //Kiểm tra yêu cầu
        if (!CheckInput(EnDe, 2)) throw L"Vui lòng nhập đúng yêu cầu menu.";
        //Menu chọn cách nhập input
        wcout << L"Chọn cách nhập input." << '\n'
        << L"1. Nhập từ màn hình." << '\n'
        << L"2. Nhập từ File.\n";
        int ninput = 0;
        wcin >> ninput;
        //Kiểm tra yêu cầu
        if (!CheckInput(ninput, 2)) throw L"Vui lòng nhập đúng yêu cầu menu.";
        switch (EnDe) {
            case 1:
                wcout << L"Nhập plaintext:\n";
                if (ninput == 1) GetInputFromScreen(plaintext); //Nhập plaintext nên truyền vào tham số plaintext
                else if (ninput == 2) GetInputFromFile(plaintext, ciphertext, 1);
                wcout << L"Plaintext:\n" << s2ws(plaintext) << '\n';
                break;
            case 2:
                wcout << L"Nhập ciphertext:\n";
                if (ninput == 1) GetInputFromScreen(ciphertext); //Nhập plaintext nên truyền vào tham số plaintext
                else if (ninput == 2) GetInputFromFile(plaintext, ciphertext, 2);
                wcout << L"Ciphertext:\n" << s2ws(ciphertext) << '\n';
                break;
        }
        //Thực hiện nhập key từ file.
        GetInputKey(RSAPri, RSAPub);
        //In key để kiểm tra.
        PrintKeys(RSAPri, RSAPub);
    }
    catch (CryptoPP::Exception error) {
        wcout << error.what();
    }
}

//Hàm Encryp, kết quả mã hóa sẽ được trả về thông qua tham số ciphertext.
void Encryp(string &plaintext, string &ciphertext, RSA::PrivateKey RSAPri, RSA::PublicKey RSAPub) {
    //Khai báo
    AutoSeededRandomPool prng;
    double runtime = 0;

    try {
        for (int i = 0; i < nconst; i++) {
            //clear ciphertext trước khi thực hiện
            ciphertext.clear();
            int starttime = clock(); //bắt đầu đo thời gian
            //Thực hiện Encryption bằng public key
            RSAES_OAEP_SHA_Encryptor encryptor(RSAPub);
            //StringSource với đầu vào là plaintext, sử dụng PK_EncryptorFilter để mã hóa, sau đó lưu vào ciphertext.
            StringSource(plaintext, true, new PK_EncryptorFilter(prng, encryptor, new StringSink(ciphertext)));
            int endtime = clock(); //Kết thúc đo thời gian.
            runtime += double(endtime - starttime) / CLOCKS_PER_SEC;
        }
    } catch (CryptoPP::Exception error) {
        wcout << error.what() << '\n';
    }
    wcout << L"Ciphertext: ";
    //In ciphertext được dạng Hex.
    PrettyPrint(ciphertext); 
    wcout << '\n' << L"Thời gian trung bình: " << 1000 *runtime / nconst << L"ms." << '\n';
}

//Hàm Decryp, kết quả giải mã sẽ được trả về thông qua tham số plaintext.
void Decryp(string &plaintext, string &ciphertext, RSA::PrivateKey RSAPri, RSA::PublicKey RSAPub) {
    //Khai báo
    AutoSeededRandomPool prng;
    string cipher;
    cipher.clear();
    double runtime = 0;
    //Hàm StringSource với đầu vào là ciphertext, sử dụng HexDecoder để giải mã và lưu kết quả vào biến cipher.
    StringSource(ciphertext, true, new HexDecoder(new StringSink(cipher)));
    
    try {
        for (int i = 0; i < 1; i++) {
            plaintext.clear();
            int starttime = clock(); //Bắt đầu đo thời gian
            //Bắt đầu giải mã với private key
            RSAES_OAEP_SHA_Decryptor decryptor(RSAPri);
            //Hàm StringSource với đầu vào là cipher, sử dụng PK_DecryptorFilter để giải mã và lưu kết quả vào plaintext.
            StringSource(cipher, true, new PK_DecryptorFilter(prng, decryptor, new StringSink(plaintext)));
            int endtime = clock(); //Kết thúc đo thời gian
            runtime += double(endtime - starttime) / CLOCKS_PER_SEC;
        }
    } catch (Exception error) {
        wcout << error.what() << '\n';
    }
    wcout << L"Recovered text: ";
    wcout << s2ws(plaintext) << '\n';
    wcout << '\n' << L"Thời gian trung bình: " << 1000 *runtime / nconst << L"ms." << '\n';
}

int main() {
    //Set up hỗ trợ tiếng việt.
    SupportVietnamese();

    //Khai báo các biến cần dùng.
    string plaintext = "", ciphertext = "";
    RSA::PrivateKey RSAPri;
    RSA::PublicKey RSAPub;
    int EnDe = 0;

    //Thực hiện việc lấy các giá trị đầu vào
    GetInput(plaintext, ciphertext, RSAPri, RSAPub, EnDe);
    //Switch case các yêu cầu
    switch (EnDe) {
        case 1:
            Encryp(plaintext, ciphertext, RSAPri, RSAPub);
            break;
        case 2:
            Decryp(plaintext, ciphertext, RSAPri, RSAPub);
            break;
        default:
            throw L"Vui lòng nhập đúng yêu cầu menu.";
    }
    return 0;
}