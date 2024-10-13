#include <bits/stdc++.h>// thư viện tổng

using namespace std;
// thêm các thư viện crypto liên quan để thực hiện chạy
#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include "cryptopp/integer.h"
using CryptoPP::Integer;

#include "cryptopp/sha.h"
using CryptoPP::SHA256;

#include "cryptopp/filters.h"
using CryptoPP::ArraySink;
using CryptoPP::SignatureVerificationFilter;
using CryptoPP::SignerFilter;
using CryptoPP::StringSink;
using CryptoPP::StringSource;

#include "cryptopp/files.h"
using CryptoPP::FileSink;
using CryptoPP::FileSource;

#include "cryptopp/eccrypto.h"
using CryptoPP::DL_GroupParameters_EC;
using CryptoPP::ECDSA;
using CryptoPP::ECP;

#include "cryptopp/oids.h"
using CryptoPP::OID;

#include "cryptopp/hex.h"
using CryptoPP::HexDecoder;
using CryptoPP::HexEncoder;

#define nValue 10000

// Hàm dùng để hỗ trợ tiếng việt
void setUpVietnamese()
{
#ifdef _WIN32
	_setmode(_fileno(stdin), _O_U16TEXT); // Hàm dùng để điều chỉnh chế độ dịch cho văn bản cho trước
	_setmode(_fileno(stdout), _O_U16TEXT);// O_U16TEXT chế độ unocode
	// đầu ra ký tự xuất dữ liệu Unicode một cách chính xác sang bảng điều khiển Windows
}

// chuyển đổi wstring thành string
wstring s2ws(const std::string &str)
{
	using convert_type = std::codecvt_utf8<wchar_t>;// dùng để chuyển wstring thành string
	std::wstring_convert<convert_type, wchar_t> converter;
	return converter.from_bytes(str);
	// trả về byte là dạng UTF-8, byte có thể ghi được vào tệp văn bản
}

// chuyển đổi wstring thành string
string ws2s(const std::wstring &wstr)
{
	using convert_type = std::codecvt_utf8<wchar_t>; // dùng để chuyển string thành wstring
	std::wstring_convert<convert_type, wchar_t> converter;// convert thành wstring
	return converter.to_bytes(wstr);
	//trả về mảng số nguyên được biểu diễn bằng độ dài byte
}

// chuyển từ integer thành wstring
wstring in2ws(const CryptoPP::Integer &t)
{
	std::ostringstream oss; // hỗ trợ tạo bản sao string
	oss.str(""); // khỏi tạo một chuỗi rỗng
	oss.clear();
	oss << t; 
	std::string encoded(oss.str());// lấy chuỗi đã mã hoá
	std::wstring_convert<codecvt_utf8<wchar_t>> towstring; // chuyển đổi kiểu dữ liệu wstring
	return towstring.from_bytes(encoded);
}

// chuyển đổi byte string thành hex wstring cryptopp::byte (file)
wstring BeautifulPrinterForFile(string byteString)
{
	string encodedCode = ""; // khởi tạo một chuỗi rỗng làm đầu vào
	StringSource(byteString, true,
				 new HexEncoder( // tạo HexEncoder đã mã hóa byte thành dữ liệu dưới dạng hệ 16.
					 new StringSink(encodedCode)));// tạo một StringSink mới để nhận tham chiếu đến chuỗi mã hoá
	wstring wstr = s2ws(encodedCode); // gọi hàm s2ws để chuyển kiểu dữ liệu sang string
	return wstr;
	// trả về chuỗi dữ liệu mã hoá
}

//lấy plaintxt từ file
string getPlaintextFromFile(string filename)
{
	string plaintext; // thực hiện khởi tạo một chuỗi mới 
	ifstream file(filename); // ifstream là lớp giúp nhập dữ liệu từ File
	if (file.is_open()) // trường hợp ta mở file
	{
		getline(file, plaintext); // ghi dữ liệu trong file thành chuỗi plaintext
		file.close(); // thực hiện đóng file
	}
	else
	{
		wcout << L"Can not open file!" << endl; // trường hợp không mở được file thì sẽ thông báo không mở được
		exit(1);
	}
	return plaintext;
}

//hàm để lấy chữ ký từ file
void getSignatureFromFile(string filename, string &signature)
{
    ifstream fin(filename);//thực hiện lấy dữ liệu file 
    if (fin.is_open()) // Trường hợp ta mở được file
    {
        string line; // tao 1 chuỗi liên để chưa cái ký tự trong chữ ký
        while (fin.good())//sử dụng good () để kiểm tra xem luồng có đủ tốt để hoạt động hay không và không có phát sinh lỗi
        {
            getline(fin, line); // thực hiện ghi dữ liệu lên
            signature += line;
        }
        fin.close();
    }
    else // trường jopwj còng lại là không mở được file
    {
        wcout << "Can't open File " << s2ws(filename) << "!" << endl;
        exit(1);
    }
}

//Hàm để tạo menu cho người dùng
int selectWork()
{
	int choice; // tạo biến để ngta có thể nhập vào sự chọn chạy từ 1 tới 3
	wcout << L"1. Generate keys and write to files" << endl;
	wcout << L"2. Sign a file" << endl;
	wcout << L"3. Verify a file" << endl;
	wcout << L"Enter your choice: ";
	try
	{
		wcin >> choice; // chọn ngoài 1 2 3 thì sẽ bị bảo lỗi
		if (choice < 1 || choice > 3)
		{
			wcout << L"Wrong choice!" << endl;
			exit(1);
		}
	}
	catch (const std::exception &e)
	{
		wcout << e.what() << '\n';
		exit(1);
	}
	return choice;
}

//hàm tạo khoá secrect
bool generatePrivateKey(const OID &oid, ECDSA<ECP, SHA256>::PrivateKey &key)
// Đầu vào ECDSA<ECP là phương thức xác thực ECDSA-256 with curve secp256rl đang được dùng với độ dài là 256 bit
// sử dụng SHA256 ở đây là hàm băm đi kèm theo phương thức xác thực ECDSA<ECP
{//OID Kiểu như constructor khởi tạo nó thành một cái ObjectID mới.
	AutoSeededRandomPool prng; // hàm random giá trị của khoá
	key.Initialize(prng, oid); // khỏi tạo khoá với thành objectid mới với giá trị đã random
	return key.Validate(prng, 3); // Trả về khoá
}

//Hàm tạo khoá công khai
bool generatePublicKey(const ECDSA<ECP, SHA256>::PrivateKey &privateKey, ECDSA<ECP, SHA256>::PublicKey &publicKey)
{
	// đưa vào 2 đầu vào trong để tao khoá public, và khoá public với private phải có liên kết với nhau
	AutoSeededRandomPool prng; // hàm random
	privateKey.MakePublicKey(publicKey);
	return publicKey.Validate(prng, 3);
}

//Hàm xuất ra thông số
void printDomainParameters(const DL_GroupParameters_EC<ECP> &parameters)
{ //đầu vào DL_GroupParameters_EC<ECP> sử dụng các tham số đường cong có sẳn của ECDSA
	wcout << endl;
	wcout << "M:" << endl;
	wcout << " " << in2ws(parameters.GetCurve().GetField().GetModulus()) << endl;//gọi hàm in2ws để chuyển các tham số đường cong thành wstring
	//
	wcout << "Coefficient A:" << endl;
	wcout << " " << in2ws(parameters.GetCurve().GetA()) << endl;

	wcout << "Coefficient B:" << endl;
	wcout << " " << in2ws(parameters.GetCurve().GetB()) << endl;

	wcout << "Base Point:" << endl;
	wcout << " X: " << in2ws(parameters.GetSubgroupGenerator().x) << endl;
	wcout << " Y: " << in2ws(parameters.GetSubgroupGenerator().y) << endl;

	wcout << "Subgroup Order:" << endl;
	wcout << " " << in2ws(parameters.GetSubgroupOrder()) << endl;

	wcout << "Cofactor:" << endl;
	wcout << " " << in2ws(parameters.GetCofactor()) << endl;
}

//hàm in ra thông số kèm theo khoá riêng tư 
void printDomainParameters(const ECDSA<ECP, SHA256>::PrivateKey &key)
{
	printDomainParameters(key.GetGroupParameters());
}

//hàm in ra thông số kèm theo khoá công khai
void printDomainParameters(const ECDSA<ECP, SHA256>::PublicKey &key)
{
	printDomainParameters(key.GetGroupParameters());
}

//Hàm in ra khoá riêng tư
void printPrivateKey(const ECDSA<ECP, SHA256>::PrivateKey &key)
{
	wcout << "Private Exponent:" << endl;
	wcout << " " << in2ws(key.GetPrivateExponent()) << endl;
}

//Hàm in ra khoá công khai
void printPublicKey(const ECDSA<ECP, SHA256>::PublicKey &key)
{
	wcout << "Public Element:" << endl;
	wcout << " X: " << in2ws(key.GetPublicElement().x) << endl;
	wcout << " Y: " << in2ws(key.GetPublicElement().y) << endl;
}

//Hàm xuất ra key
void printKey(const ECDSA<ECP, SHA256>::PrivateKey &privateKey, const ECDSA<ECP, SHA256>::PublicKey &publicKey)
{
	//gọi các hàmin ra thông số về khoá private, public và tham số đường cong
	printDomainParameters(privateKey);
	printPrivateKey(privateKey);
	printPublicKey(publicKey);
}

//Hàm xác thực lại khoá
bool generateKey(const OID &oid, string filePrivateKey, string filePublicKey)
{
	// hàm thực hiện cơ chế xách thực lại khoá để đầu vào có file Privatelkey và file Publickey nơi lưu giá trị của 2 khoá
	ECDSA<ECP, SHA256>::PrivateKey privateKey; 
	ECDSA<ECP, SHA256>::PublicKey publicKey;

	if (generatePrivateKey(oid, privateKey) == false || generatePublicKey(privateKey, publicKey) == false)
	{// xét điều kiện 1 trong 2 khoá bị sai thì đều sẽ tả về kết quả là false
		return false;
	}

	privateKey.Save(FileSink(filePrivateKey.c_str(), true).Ref());// kiểm tra nếu đúng thì ta thực hiện lưu vào các tệp tạm thời
	publicKey.Save(FileSink(filePublicKey.c_str(), true).Ref());
	printKey(privateKey, publicKey); // sau đó in ra giá trị khoá bao gồm private và public

	return true;
}

//Hàm ký tên
string signMessage(const string &message, const ECDSA<ECP, SHA256>::PrivateKey &privateKey)
{
	AutoSeededRandomPool prng;// thực hiện random giá trị
	string signature;// tạo 1 chuỗi chữ ký
	signature.clear(); 

	StringSource(message, true, // tạo một file chưa chữ ký tạm kết hợp với phương thức 
				 new SignerFilter(prng,
								  ECDSA<ECP, SHA256>::Signer(privateKey),
								  new StringSink(signature)));// file tạm chưa chữ ký
	return signature;
}
//hàm để set up chữ ký
void setUpSignature(string filePrivateKey, string fileMessage, string& signature)
{
	// đầu vào đưa khoá private, nội dung và chữ ký dưới dạng chuỗi
	ECDSA<ECP, SHA256>::PrivateKey privateKey; // sử dụng phương thức ECDSA<ECP kèm theo hàm băm SHA256

	loadPrivateKey(filePrivateKey, privateKey); // gọi hàm loadPrivateKey để lấy khoá private từ file

	string message = getPlaintextFromFile(fileMessage); // khởi tạo chuỗi thông điệp là chuỗi plaintext lấy lên từ file
	double timeCounter = 0.0;

	for (int i = 0; i < nValue; ++i)
	{
		double startTime = clock(); // dùng để kiểm tra thời gian bắt đầu thực thi của các dòng lệnh trong for
		signature = signMessage(message, privateKey);
		if (signature.empty())
		{
			wcout << L"Signature is empty!" << endl;
			exit(1);
		}
		double endTime = clock();
		timeCounter += (endTime - startTime);// tính thời gian thực thi của đoạn lệnh để đánh khả năng chạy
	}
	printDomainParameters(privateKey); 
	printPrivateKey(privateKey);
	wcout << L"Signature: ";
	BeautifulPrinter(signature);
	wcout << L"Average time: " << timeCounter / nValue << " ms" << endl;
}


// Hàm đẩy chữ ký vào file
void putSignatureToFile(string filename, const string& signature)
{
	ofstream file(filename); // ofstream dùng để ghi dữ liệu vào file
	try
	{
		file << signature; // thực hiện hàm xử lý ngoại lệ
		file.close(); // nếu dữ liệu được ghi vào thì ta sẽ ghi vào file bởi dòng lệnh file << signature sau đó sẽ đóng file lại
	}
	catch (const std::exception& e)
	{
		wcout << e.what() << '\n'; // việc thực hiện ghi lại không được thì sẽ gây ra ngoại lệ, lúc đó ta sẽ gọi hàm what
		exit(1);
	}
//Tải dử liệu khoá riêng tư từ File
void loadPrivateKey(const string &filename, ECDSA<ECP, SHA256>::PrivateKey &key)
{
	key.Load(FileSource(filename.c_str(), true).Ref());
}

//Tải dử liệu khoá công khai từ File
void loadPublicKey(const string &filename, ECDSA<ECP, SHA256>::PublicKey &key)
{
	key.Load(FileSource(filename.c_str(), true).Ref());
}


}
// Hàm tiền sử lý xác nhận thông điệp
void setUpVerification(string filePublicKey, string fileMessage, string fileSignature)
{ // đầu đưa vào bao gôm chuỗi giá trị khoá công khai, thông điệp, chữ ký
	ECDSA<ECP, SHA256>::PublicKey publicKey;

	loadPublicKey(filePublicKey, publicKey);//gọi hàm để lấy khoá public từ file lên

	string message = getPlaintextFromFile(fileMessage);
	string signature;
	getSignatureFromFile(fileSignature, signature);
	double timeCounter = 0.0;

	for (int i = 0; i < nValue; ++i)
	{
		double startTime = clock();
		if (verifyMessage(publicKey, message, signature) == false)
		{
			wcout << L"Verification failed!" << endl;
			exit(1);
		}
		double endTime = clock();
		timeCounter += (endTime - startTime);
	}
	printDomainParameters(publicKey);
	printPublicKey(publicKey);
	wcout << L"Signature: ";
	BeautifulPrinter(signature);
	wcout << L"Average time: " << timeCounter / nValue << " ms" << endl;
}


//Hàm xác thực thông điệp
bool verifyMessage(const ECDSA<ECP, SHA256>::PublicKey &publicKey, const string &message, const string &signature)
{
	bool result = false;
	StringSource(signature + message, true,// thông điệp ở đây phải bao gôm nội dung thông điệp kèm theo chữ ký ngừi gửi
				 new SignatureVerificationFilter(
					 ECDSA<ECP, SHA256>::Verifier(publicKey), // gọi phương thức ECDSA<ECP và hàm băm SHA256
					 new ArraySink((CryptoPP::byte *)&result, sizeof(result)))); // tạo một mảng tạm dưới dạng bytes để xác thực
	return result;
}
int main(int argc, char **argv)
{
	// Lần lượt gọi các hàm chạy
	setUpVietnamese();

	int choice = selectWork();// gọi hàm để chạy menu cho người dùng chọn chức năng
	string signature;
	string slash;

#ifdef _WIN32
	slash = '\\';
#endif

	string filePublicKey ;
	string filePrivateKey;
	string fileMessage ;
	string fileSignature;

	switch (choice)
	{ // th1
	case 1:
		try
		{
			if (generateKey(CryptoPP::ASN1::secp256r1(), filePrivateKey, filePublicKey) == true)
			{
				wcout << L"Keys generated successfully!" << endl;
			}
			else
			{
				wcout << L"Keys generation failed!" << endl;
			}
		}
		catch (const std::exception &e)
		{
			wcout << L"Error when generating keys!" << endl;
			wcout << e.what() << endl;
			exit(1);
		}
		break;

	case 2://th2
		try
		{
			setUpSignature(filePrivateKey, fileMessage, signature);
			putSignatureToFile(fileSignature, signature);
			wcout << L"Signature saved successfully!" << endl;
		}
		catch (const CryptoPP::Exception &e)
		{
			wcout << L"Error when signing message!" << endl;
			wcout << e.what() << endl;
			exit(1);
		}
		break;

	case 3://th3
		try
		{
			setUpVerification(filePublicKey, fileMessage, fileSignature);
			wcout << L"Message verified successfully!" << endl;
		}
		catch (const CryptoPP::Exception &e)
		{
			wcout << L"Error when verifying signature!" << endl;
			wcout << e.what() << endl;
			exit(1);
		}
		break;
		
	default:
		wcout << "Invalid choice!" << endl;// nếu ngoài các case trên thì báDo lỗi
		break;
	}
	return 0;
}