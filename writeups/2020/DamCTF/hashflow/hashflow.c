#include <openssl/aes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <linux/seccomp.h>
#include <sys/prctl.h>

void read_flag();
void read_key();
static void sign();
static void verify();

AES_KEY key;

void read_key()
{
	unsigned char key_buf[16];

	FILE* urandom = fopen("/dev/urandom", "rb");
	if (!urandom) exit(EXIT_FAILURE);
	if (fread(key_buf, 16, 1, urandom) != 1) exit(EXIT_FAILURE);
	if (fclose(urandom)) exit(EXIT_FAILURE);

	AES_set_encrypt_key(key_buf, 128, &key);
}

typedef struct
{
	unsigned char data[16];
} digest;

digest hash(unsigned char* buffer, size_t len)
{
	const unsigned long p = 18446744073709551557ul;
	unsigned long h = 0;
	unsigned long a = 1;
	for (size_t i = 0; i < len; i += sizeof(unsigned long))
	{
		unsigned long x = 0;
		if (sizeof(unsigned long) < len - i)
			memcpy(&x, buffer + i, sizeof(unsigned long));
		else
			memcpy(&x, buffer + i, len - i);

		h += a*x;
		a *= p;
	}

	digest d;
	memset(d.data, 0, sizeof(d.data));
	memcpy(d.data + 8, &h, sizeof(h));
	return d;
}

digest mac(unsigned char* buffer, size_t len)
{
	digest d = hash(buffer, len);

	digest mac;
	AES_encrypt(d.data, mac.data, &key);

	return mac;
}

static void sign()
{
	printf("Message: ");
	unsigned char buffer[0100];
	size_t len = read(STDIN_FILENO, buffer, 0100);
	digest m = mac(buffer, len);

	printf("Signature: ");
	for (unsigned int j = 0; j < sizeof(m.data); j++)
		printf("%02x", m.data[j]);
	printf("\n");
}

static void verify()
{
	unsigned char buffer[0100];
	memset(buffer, 0, sizeof(buffer));

	printf("Message: ");
	size_t len = read(STDIN_FILENO, buffer, 0x100);
	digest m = mac(buffer, len);

	printf("Signature: ");
	digest sig;
	for (unsigned int j = 0; j < sizeof(sig.data); j++)
		scanf("%02hhx", &sig.data[j]);

	if (memcmp(sig.data, m.data, sizeof(sig.data)))
	{
		printf("Invalid signature!\n");
		exit(EXIT_FAILURE);
	}

	printf("Verified message: %s\n", buffer);
}

void menu()
{
	printf("0: Sign a message\n");
	printf("1: Verify a message\n");

	while (true)
	{
		int option;
		printf("Pick an option: ");
		scanf("%d", &option);

		if (option == 0)
			sign();
		else if (option == 1)
			verify();
		else
			break;
	}
}

void sys_exit(int status, void* arg)
{
	syscall(SYS_exit, status);
}

int main()
{
	setbuf(stdin, NULL);
	setbuf(stdout, NULL);

	read_key();

	fopen("flag", "r");

	// libc calls exit_group instead of exit by default, but that system call is
	// disabled by seccomp. Use exit instead.
	on_exit(sys_exit, NULL);
	prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT);

	menu();

	return EXIT_SUCCESS;
}
