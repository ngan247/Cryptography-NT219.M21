#include <iostream>
using std::cout;
using std::cin;

using namespace std;
#include <string>
#include <cstdlib>
using std::exit;

#include "cryptopp/cryptlib.h"
#include "cryptopp/x509cert.h"
#include "cryptopp/secblock.h"
#include <cryptopp/files.h>
#include "cryptopp/filters.h"
#include "cryptopp/rsa.h"
#include "cryptopp/pem.h"
#include "cryptopp/sha.h"
#include "cryptopp/hex.h"

int main(int argc, char* argv[])
{
    string pemCertificate;
    using namespace CryptoPP;
    cout << "(1) file PEM\n";
    cout << "(2) file DER\n";
    cout << "Choose: ";
    int option;
    cin >> option;

    X509Certificate cert;
    if (option == 1 )
    {
        #ifdef _WIN32
            FileSource f("cert.pem", true, new StringSink(pemCertificate));
        #elif __linux__
            FileSource f("./cert.pem", true, new StringSink(pemCertificate));
        #endif
        StringSource ss(pemCertificate, true);
        PEM_Load(ss, cert);
    }
    else if (option == 2)
    {
        #ifdef _WIN32
            FileSource f("cert.der", true, new StringSink(pemCertificate));
        #elif __linux__
            FileSource f("./cert.der", true, new StringSink(pemCertificate));
        #endif
        StringSource ss(pemCertificate, true);
        PEM_Load(ss, cert);
    }
    else
    {
        cout << "Error";
        exit(1);
    }

    const SecByteBlock &signature = cert.GetCertificateSignature();
    const SecByteBlock &toBeSigned = cert.GetToBeSigned();
    const X509PublicKey &publicKey = cert.GetSubjectPublicKey();

    RSASS<PKCS1v15, SHA256>::Verifier verifier(publicKey);
    bool result = verifier.VerifyMessage(toBeSigned, toBeSigned.size(), signature, signature.size());
    if (result)
        cout << "Verified certificate" << endl;
    else
        cout << "Failed to verify certificate" << endl;

    cout << "The information of the certificate" << endl;
    cout << "Version: " << cert.GetVersion() << endl;
    cout << "Serial Number: " << cert.GetSerialNumber() << endl;
    cout << "Not Before: " << cert.GetNotBefore() << endl;
    cout << "Not After: " << cert.GetNotAfter() << endl;
    cout << "Subject Identities:\n" << cert.GetSubjectIdentities() << endl;
    cout << "Issuer Identities: " << cert.GetIssuerDistinguishedName() << endl;
    cout << "Subject Key Identities: " << cert.GetSubjectKeyIdentifier() << endl;
    cout << "Authority Key Identities: " << cert.GetAuthorityKeyIdentifier() << endl;
    cout << "Sign Algorithm: " << cert.GetCertificateSignatureAlgorithm() << endl;
    cout << "Subject Public Key Algorithm: " << cert.GetSubjectPublicKeyAlgorithm() << endl;
    cout << "Signature: ";
    StringSource(signature, signature.size(), true, new HexEncoder(new FileSink(std::cout)));
    cout << endl;
    cout << "To Be Signed: ";
    StringSource(toBeSigned, toBeSigned.size(), true, new HexEncoder(new FileSink(std::cout)));
    return 0;
    /*
    using namespace CryptoPP;

    StringSource ss(pemCertificate, true);
    X509Certificate cert;
    PEM_Load(ss, cert);

    const SecByteBlock& signature = cert.GetCertificateSignature();
    const SecByteBlock& toBeSigned = cert.GetToBeSigned();
    const X509PublicKey& publicKey = cert.GetSubjectPublicKey();
    
    // đã xác định thuật toán
    RSASS<PKCS1v15, SHA256>::Verifier verifier(publicKey); // cần coding trực tiếp

    bool result = verifier.VerifyMessage(toBeSigned, toBeSigned.size(), signature, signature.size());

    if (result)
        cout << "Verified certificate" << endl;
    else
        cout << "Failed to verify certificate" << endl;

    string encode;
    encode.clear();
    cout << "Signature: ";
    //size_t size = min(signature.size(), (size_t)30);
    StringSource(signature, signature.size(), true, new HexEncoder(new StringSink (encode)));
    cout << encode << endl;
    
    encode.clear();
    cout << "To Be Signed: ";
    //size = min(signature.size(), (size_t)30);
    StringSource(toBeSigned, toBeSigned.size(), true, new HexEncoder(new StringSink (encode)));
    cout << encode << endl;
    return 0;*/
}
/*
const string pemCertificate =
    "-----BEGIN CERTIFICATE-----\r\n"
    "MIIEZTCCA02gAwIBAgIUTrRCySQFQNRYcWKYxhHVNsult3cwDQYJKoZIhvcNAQEL\r\n"
    "BQAwfzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk5ZMREwDwYDVQQHDAhOZXcgWW9y\r\n"
    "azEVMBMGA1UECgwMRXhhbXBsZSwgTExDMRgwFgYDVQQDDA9FeGFtcGxlIENvbXBh\r\n"
    "bnkxHzAdBgkqhkiG9w0BCQEWEHRlc3RAZXhhbXBsZS5jb20wHhcNMTkxMDAxMDYx\r\n"
    "NzE0WhcNMjAwOTMwMDYxNzE0WjB/MQswCQYDVQQGEwJVUzELMAkGA1UECAwCTlkx\r\n"
    "ETAPBgNVBAcMCE5ldyBZb3JrMRUwEwYDVQQKDAxFeGFtcGxlLCBMTEMxGDAWBgNV\r\n"
    "BAMMD0V4YW1wbGUgQ29tcGFueTEfMB0GCSqGSIb3DQEJARYQdGVzdEBleGFtcGxl\r\n"
    "LmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL1tC7yUK8h7L/dg\r\n"
    "THkoQGYLhBI/jNIoN+HJUP6fnEIrhaYnH3bbFoXKcarOqZusKmhhRIsgGeeT2NG6\r\n"
    "0nWgkRbBUH2Ic1gNqzIhQsF8eirUGchaCyXuuueBvQUrnkJjVG9yyJ5XFdjjx4kX\r\n"
    "y9IMxAM80W3GmMxXkKlS1vYVqKmRNf/NUne5h/U/kRtkGqjDQpIG/y9et8+mY3CV\r\n"
    "vjh4AiFAIswPB5beUqSVuq+vx+VCo3vZw9KptuEwqphZMC8YVuSHi3/hQXuaBlG1\r\n"
    "sAfVR05KIl3tKVp428tQPZZZjreVZTBfWCwI/marlFFxkC9bWuIAzpy8tTPsB21r\r\n"
    "LDvXof8CAwEAAaOB2DCB1TAdBgNVHQ4EFgQUgrdpzgQ4EeZk2VRdMDXPeSPCvGsw\r\n"
    "HwYDVR0jBBgwFoAUgrdpzgQ4EeZk2VRdMDXPeSPCvGswDAYDVR0TAQH/BAIwADAL\r\n"
    "BgNVHQ8EBAMCBaAwSgYDVR0RBEMwQYILZXhhbXBsZS5jb22CD3d3dy5leGFtcGxl\r\n"
    "LmNvbYIQbWFpbC5leGFtcGxlLmNvbYIPZnRwLmV4YW1wbGUuY29tMCwGCWCGSAGG\r\n"
    "+EIBDQQfFh1PcGVuU1NMIEdlbmVyYXRlZCBDZXJ0aWZpY2F0ZTANBgkqhkiG9w0B\r\n"
    "AQsFAAOCAQEAn5fSk9UK+N4MDAFytzIpfUoSobiVvvNT//+dticgJyySyPThXeZ+\r\n"
    "+I+C6FSykkr0+wq4DZidygpHydS1/E2Dvlsa2XHQbgTyfiBdpEcbu6bVNeBRAtyP\r\n"
    "kWe0pO7/rha94dcFMDN88d4qMIragWh+yJk0rIofLxQe5qWounTYBetutz5dFOiJ\r\n"
    "lwvGeY1HTnElkxaXULtoz+QPcgidQX8sEKhHNwKiae5gj0YeWowVoAnaHhwYiRMa\r\n"
    "VdUKKD1CiSkFNaKSUW0ee8dpVr3rWtt+X1K0+B46lUPGUG5QtN33dtisqrY3X8q7\r\n"
    "g0NwwUKAWL9DE1uadKjJI+X1AL0ft6Nj4Q==\r\n"
    "-----END CERTIFICATE-----\r\n";*/