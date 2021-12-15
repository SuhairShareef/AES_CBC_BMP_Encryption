// Libraries includes
#include <iostream>
#include <cstdlib>
#include <string>
#include <fstream>
#include <chrono>
#include <opencv2/opencv.hpp>
#include "opencv2/imgcodecs.hpp"
#include "opencv2/core/saturate.hpp"


// Header files includes
#include "osrng.h"
#include "cryptlib.h"
#include "hex.h"
#include "aes.h"
#include "ccm.h"
#include "eax.h"
#include "filters.h"


// Namespaces
using namespace std;
using namespace CryptoPP;
using namespace chrono;
using namespace cv;


ifstream img;
ofstream cipher_img;
ofstream recovered_img;
ofstream key_file;

// Initialize images data
Mat original_image = imread("lena_gray.bmp", IMREAD_UNCHANGED);
Mat cipher_image = original_image.clone();
Mat restored_image = original_image.clone();
int rows = original_image.rows;
int cols = original_image.cols;
byte key[AES::DEFAULT_KEYLENGTH];	// 128 bit
byte iv[AES::BLOCKSIZE];

void AES_enc_dec(int dynamic_key, string plain, int row, int col, int channel);
string AES_encryption(string plain, int row, int col, int channel);
void AES_decryption(string cipher, int row, int col, int channel);


void Init_key(byte* genkey, size_t size);


int main(int argc, char* argv[])
{
	// initializing timer
	auto start = high_resolution_clock::now();

	cout << "rows: " << rows << endl;
	cout << "cols: " << cols << endl;

	if (original_image.empty())
	{
		cout << "Cannot load image!" << endl;
		return -1;
	}

	// encrypt every 128 block
	string plain = "";
	int dynamic_key = rand();
	int row_start, col_start, channel_start;
	int rounds = 0;


	for (int row = 0; row < rows; row++)
	{
		for (int col = 0; col < cols; col++)
		{
			for (int channel = 0; channel < 3; channel++) {
				char ch = saturate_cast<char>(original_image.at<Vec3b>(row, col)[channel]);
				if (plain == "") {
					row_start = row;
					col_start = col;
					channel_start = channel;
				}
				plain += ch;
				if (plain.length() == 128) {
					AES_enc_dec(dynamic_key, plain, row_start, col_start, channel_start);
					rounds++;
					plain = "";
				}
			}
		}
	}

	// print the duration of the encryption and dycreption
	auto stop = high_resolution_clock::now();
	auto duration = duration_cast<microseconds>(stop - start);

	cout << "Excution Duration: " << duration.count() << " microsecond" << endl;

	imshow("Original image", original_image);

	imshow("Decrypted image", cipher_image);

	imshow("Restored image", restored_image);
	waitKey(0);


	return 0;
}

void AES_enc_dec(int dynamic_key, string plain, int row, int col, int channel)
{
	// Plain recieved is 128 bytes or less which will go through 16 rounds
	// Define the random key generator
	byte key[AES::DEFAULT_KEYLENGTH];	// 128 bit
	byte iv[AES::BLOCKSIZE];

	// Initializing RC4
	int key_length = sizeof(key);
	int* s = new int[256];
	int* T = new int[256];
	for (int i = 0; i < 256; i++)
	{
		s[i] = i;
		T[i] = dynamic_key;
	}
	int temp = 0;
	for (int j = 0; j < 256; j++)
	{
		temp = (temp + s[j] + T[j]) % 256;
		swap(s[j], s[temp]);
	}

	int rounds = plain.length() / 16;
	int plain_start = 0;
	int* val = new int[key_length];

	while (rounds) {
		// the beginning of the current block
		string curr_plain = plain.substr(plain_start, 16);

		// initialive IV
		Init_key(iv, sizeof(iv));

		int i = 0;
		int j = 0;
		int z = 0;
		int pp = key_length;

		// Construct key from the dynamic key
		while (pp)
		{
			i = (i + 1) % key_length;
			j = (j + s[i]) % key_length;
			swap(s[i], s[j]);
			int t = (s[i] + s[j]) % key_length;
			val[z] = s[t];
			key[z] = (char)val[z];
			z++;
			pp -= 1;
		}

		string cipher = AES_encryption(curr_plain, row, col, channel);
		AES_decryption(cipher, row, col, channel);

		// Move row to the next 16 byte block
		int count = 0;
		while (count < 16) {
			channel++;
			if (channel > 2) {
				channel = 0;
				col++;
			}
			if (col > cols) {
				col = 0;
				row++;
			}
			count++;
		}

		rounds--;
		plain_start += 16;

	}
}

string AES_encryption(string plain, int row, int col, int channel) {
	string cipher = "";
	try
	{
		// Encrypting every 8 bytes
		CBC_Mode<AES>::Encryption e;
		e.SetKeyWithIV(key, sizeof(key), iv);

		// The StreamTransformationFilter removes padding as required.
		StringSource s(plain, true, new StreamTransformationFilter(e, new StringSink(cipher)));

		// Add to cipher matrix
		int count = 0;
		while (count < 16) {
			//unsigned char ch = (uchar)cipher[count];
			cipher_image.at<Vec3b>(row, col)[channel] = (uchar)cipher[count];
			channel++;
			if (channel > 2) {
				channel = 0;
				col++;
			}
			if (col > cols) {
				col = 0;
				row++;
			}
			count++;
		}

#if 0
		StreamTransformationFilter filter(e);
		filter.Put((const byte*)plain.data(), plain.size());
		filter.MessageEnd();
		const size_t ret = filter.MaxRetrievable();
		cipher.resize(ret);
		filter.Get((byte*)cipher.data(), cipher.size());
#endif

	}
	catch (const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		cout << "error here" << endl;
		exit(1);
	}
	return cipher;
}

void AES_decryption(string cipher, int row, int col, int channel) {
	string recovered;
	try
	{
		// Decryption
		CBC_Mode<AES>::Decryption d;
		d.SetKeyWithIV(key, sizeof(key), iv);
		// The StreamTransformationFilter removes
		// padding as required.
		StringSource s(cipher, true, new StreamTransformationFilter(d, new StringSink(recovered)));

		// Recovery
		// Add to restored matrix
		int count = 0;
		while (count < 16) {
			//unsigned char ch = (uchar)cipher[count];
			restored_image.at<Vec3b>(row, col)[channel] = (uchar)recovered[count];
			channel++;
			if (channel > 2) {
				channel = 0;
				col++;
			}
			if (col > cols) {
				col = 0;
				row++;
			}
			count++;
		}
#if 0
		StreamTransformationFilter filter(d);
		filter.Put((const byte*)cipher.data(), cipher.size());
		filter.MessageEnd();
		const size_t ret = filter.MaxRetrievable();
		recovered.resize(ret);
		filter.Get((byte*)recovered.data(), recovered.size());
#endif

	}

	catch (const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}

}

void Init_key(byte* genkey, size_t size) {
	// Initialization of key data
	for (size_t i = 0; i < size; ++i) {
		genkey[i] = rand();
	}
}