#include<stdio.h>
#include<time.h>
#include<string.h>
#include<memory.h>
#include<stdlib.h>
#include<stdint.h>

//bn.h

#define WORD_SIZE 16
#define MAX_MODULUS_BITS 512
#define MAX_MODULUS_LENGTH (MAX_MODULUS_BITS/WORD_SIZE)
#define MAX_PRIME_BITS (MAX_MODULUS_BITS/2)
#define MAX_PRIME_LENGTH (MAX_PRIME_BITS/WORD_SIZE)
#define DTYPE uint16_t
#define T_DTYPE uint32_t
#define MAX_VAL (uint16_t)0xffff
#define BN_MSB(x) (uint16_t)((x & 0x8000) >> (WORD_SIZE-1)) //most significant bit of x
#define BN_LSB(x) (uint16_t)(x & 0x0001) //least significant bit of x
#define STD_FORMAT_STR "%04x"

typedef struct{
    int flag;
    DTYPE length;
    DTYPE *bn;
}sm; //signed multiprecision integer

//print multiprecision integer in hex format
void BN_print_hex(DTYPE *data, DTYPE data_length);

void BN_printToFile(DTYPE *data, DTYPE data_length, FILE *fp);

//transform string to hex format
void string_to_hex(DTYPE *hex, char *str);

//transform hex to string
void hex_to_string(char *str, DTYPE *hex);

//init data to zero
void BN_init(DTYPE *data, DTYPE data_length);

//data>>=digit
void BN_right_shift(DTYPE *data, DTYPE data_length, int digit);

//data<<=digit
void BN_left_shift(DTYPE *data, DTYPE data_length, int digit);

//if data=1, return 1; else return 0
int BN_isEqualOne(DTYPE *data, DTYPE data_length);

//if data=0, return 1; else return 0
int BN_isEqualZero(DTYPE *data, DTYPE data_length);

//set data to 1
void BN_setOne(DTYPE *data, DTYPE data_length);

void BN_inc(DTYPE *data, DTYPE data_length); //increasa 1

void BN_dec(DTYPE *data, DTYPE data_length); //decrease 1

//return loc of the first non-zero number
int BN_valid_pos(DTYPE *BN, DTYPE BN_length);

int BN_valid_bits(DTYPE *m, DTYPE length);

//a>b=>1, a<b=>-1, a=b=>0
int BN_cmp(DTYPE *a, DTYPE a_length, DTYPE *b, DTYPE b_length);

//assign b to a
void BN_assign(DTYPE *a, DTYPE *b, DTYPE b_length);

//exchange values of a and b
void BN_exchange(DTYPE *a, DTYPE *b, DTYPE length);

//r=a+b a_length>=b_length by default, r_length=a_length+1
void BN_add(DTYPE *r, DTYPE r_length, DTYPE *a, DTYPE a_length, DTYPE *b, DTYPE b_length);

//r=a-b a_length>=b_length by default, r_length=a_length
void BN_sub(DTYPE *r, DTYPE r_length, DTYPE *a, DTYPE a_length, DTYPE *b, DTYPE b_length);

//r=a*a r_length=a_length*2
void BN_square(DTYPE *r, DTYPE *a, DTYPE a_length);

//r=a*b r_length=a_leng+b_length
void BN_mul(DTYPE *r, DTYPE *a, DTYPE a_length, DTYPE *b, DTYPE b_length);

//r=a(mod n) r_length=n_length, a_length>=n_length
void BN_mod(DTYPE *r, DTYPE *a, DTYPE a_length, DTYPE *n, DTYPE n_length);

//r=a*b(mod n) default r_length=n_length
//method - multiply then reduce
void BN_mod_mul(DTYPE *r, DTYPE *a, DTYPE a_length, DTYPE *b, DTYPE b_length, DTYPE *n, DTYPE n_length);

//r=a*b(mod n) using Blakley's Method
void BN_mod_mul2(DTYPE *r, DTYPE *a, DTYPE a_length, DTYPE *b, DTYPE b_length, DTYPE *n, DTYPE n_length);

//compute a_inv, a_inv*a=1(mod n)
void BN_mod_inv(DTYPE *a_inv, DTYPE *a, DTYPE a_length, DTYPE *n, DTYPE n_length);

//compute a_inv(a DTYPE), a_inv*a=1(mod 2^WORD_SIZE)
void BN_MonMod_inv(DTYPE *a_inv, DTYPE *a, DTYPE a_length);

//compute Montgomery Product of a and b with modulus n
void BN_MonPro(DTYPE *r, DTYPE *a, DTYPE a_length, DTYPE *b, DTYPE b_length, DTYPE *n, DTYPE n_length, DTYPE n_inv);

//r=a^e(mod n) using Montgomery Method
void BN_MonExp(DTYPE *result, DTYPE *a, DTYPE a_length, DTYPE *e, DTYPE e_length, DTYPE *n, DTYPE n_length, DTYPE *r, DTYPE inv);

//a_length=e_length=n_length=MAX_PRIME_LENGTH
void BN_pow_mod(DTYPE *result, DTYPE *a, DTYPE *e, DTYPE *n);

void signBN_init(sm *r, DTYPE len);

void BN_signAddShift(sm *a, DTYPE *n, DTYPE *tmp);

void signBN_init_assign(sm *r, DTYPE *a, DTYPE a_length);

//r->length=a->length=c->length
void BN_sign_sub(sm *r, sm *a, sm *c);

//bn.c

void BN_print_hex(DTYPE *data, DTYPE data_length)
{
	int i=0;
	while(data[i]==0 && i < data_length-1)
	{
		i++;
	}
	for(; i < data_length; i++)
	{
		printf(STD_FORMAT_STR, data[i]);
	}
	printf("\n");
}

void BN_printToFile(DTYPE *data, DTYPE data_length, FILE *fp)
{
	int i=BN_valid_pos(data, data_length);
	for(; i < data_length; i++)
	{
		fprintf(fp, STD_FORMAT_STR, data[i]);
	}
}

//transform string(ascii) to hex format
//hex_len=strlen/2
void string_to_hex(DTYPE *hex, char *str)
{
	int i;
	int j=MAX_MODULUS_LENGTH-1;
	for(i=strlen(str)-1; i >= 1; i-=2)
	{
		hex[j--]=(str[i-1] << 8) | str[i];
	}
	if(i==0)
	{
		hex[j--]=str[i];
	}
	while (j >= 0)
	{
		hex[j--]=0;
	}
}

//transform hex to string(ascii)
void hex_to_string(char *str, DTYPE *hex)
{
	int i=BN_valid_pos(hex, MAX_MODULUS_LENGTH);
	int j=0;
	for(; i<MAX_MODULUS_LENGTH; i++)
	{
		if(j==0 && ((hex[i] & 0xff00) >> 8 == 0))
		{
			str[j]=(hex[i] & 0x00ff);
			j+=1;
		}
		else
		{
			str[j]=(hex[i] & 0xff00) >> 8;
			str[j+1]=(hex[i] & 0x00ff);
			j+=2;
		}
	}
	str[j]='\0';
}

//set data to zero
void BN_init(DTYPE *data, DTYPE data_length)
{
	int i;
	for(i=0; i < data_length; i++)
	{
		data[i]=0;
	}
}

//to clarify, digit=1, means data>>1 in bit
void BN_right_shift(DTYPE *data, DTYPE data_length, int digit)
{
	int i=0;
	int j;
	DTYPE former;
	while(i<digit)
	{
		former=0;
		for(j=data_length-1; j>=0; j--)
		{
			if(j>0)
			{
				former=BN_LSB(data[j-1]) << (WORD_SIZE-1);
				data[j]>>=1;
				data[j]+=former;
			}
			else
			{
				data[j]>>=1;
			}
		}
		i++;
	}
}

//to clarify, digit=1, means data<<1 in bit
void BN_left_shift(DTYPE *data, DTYPE data_length, int digit)
{
	int i=0;
	int j;
	DTYPE back;
	while(i<digit)
	{
		back=0;
		for(j=0; j<data_length; j++)
		{
			if(j<data_length-1)
			{
				back=BN_MSB(data[j+1]);
				data[j]<<=1;
				data[j]+=back;
			}
			else
			{
				data[j]<<=1;
			}
		}
		i++;
	}
}

//return if data is equal to 1, with 1 as is, 0 as isn't
int BN_isEqualOne(DTYPE *data, DTYPE data_length)
{
	int i;
	if(data[data_length-1]==1)
	{
		for(i=data_length-2; i>=0; i--)
		{
			if(data[i]!=0) return 0;
			else continue;
		}
		return 1;
	}
	else return 0;
}

//return if data is equal to 0, with 1 as is, 0 as isn't
int BN_isEqualZero(DTYPE *data, DTYPE data_length)
{
	int i;
	for(i=data_length-1; i>=0; i--)
	{
		if(data[i]!=0) return 0;
		else continue;
	}
	return 1;
}

void BN_setOne(DTYPE *data, DTYPE data_length)
{
	int i;
	for(i=0; i<data_length-1; i++)
	{
		data[i]=0;
	}
	data[i]=1;
}

void BN_inc(DTYPE *data, DTYPE data_length)
{
	int i=data_length-1, Carry=0;
	data[i]+=1;
	if(data[i]==0)
	{
		Carry=1;
		for(i=data_length-2; i>=0; i++)
		{
			if(Carry==1) data[i]=data[i]+Carry;
			if(data[i]==0) Carry=1;
			else break;
		}
	}
} //increasa 1

void BN_dec(DTYPE *data, DTYPE data_length)
{
	int i=data_length-1, Borrow=0;
	data[i]-=1;
	if(data[i]==MAX_VAL)
	{
		Borrow=1;
		for(i=data_length-2; i>=0; i++)
		{
			if(Borrow==1) data[i]=data[i]-Borrow;
			if(data[i]==MAX_VAL) Borrow=1;
			else break;
		}
	}
} //decrease 1

//return loc of the first non-zero number
int BN_valid_pos(DTYPE *BN, DTYPE BN_length)
{
	int i;
	for(i=0; i<BN_length; i++)
	{
		if(BN[i]==0) continue;
		else return i;
	}
	return BN_length-1;
}

int BN_valid_bits(DTYPE *m, DTYPE length)
{
	int i=0, j=0;
	while(m[i]==0)
	{
		i++;
	}
	DTYPE m0=m[i];
	while(BN_MSB(m0)!=1)
	{
		m0 <<= 1;
		j++;
	}
	return ((length-i)*WORD_SIZE-j);
}

//a>b return 1, a<b return -1, a=b return 0
int BN_cmp(DTYPE *a, DTYPE a_length, DTYPE *b, DTYPE b_length)
{
	int i, j;
	int pos_a=a_length-BN_valid_pos(a, a_length);
	int pos_b=b_length-BN_valid_pos(b, b_length);
	if(pos_a > pos_b) return 1;
	else if(pos_a < pos_b) return -1;
	else
	{
		pos_a=a_length-pos_a;
		pos_b=b_length-pos_b;
		if(a[pos_a]>b[pos_b]) return 1;
		else if(a[pos_a]<b[pos_b]) return -1;
		else
		{
			for(i=pos_a, j=pos_b; i<a_length && j<b_length; i++, j++)
			{
				if(a[i]==b[j]) continue;
				else if(a[i]>b[j]) return 1;
				else return -1;
			}
			return 0;
		}
	}
}

//assign b to a, a_length=b_length
void BN_assign(DTYPE *a, DTYPE *b, DTYPE b_length)
{
	int i;
	for(i=0; i<b_length; i++)
	{
		a[i]=b[i];
	}
}

//exchange values of a and b
void BN_exchange(DTYPE *a, DTYPE *b, DTYPE length)
{
	DTYPE tmp;
	int i;
	for(i=0; i<length; i++)
	{
		tmp=b[i];
		b[i]=a[i];
		a[i]=tmp;
	}
}

//default a_length>=b_length, r_length=a_length+1
void BN_add(DTYPE *r, DTYPE r_length, DTYPE *a, DTYPE a_length, DTYPE *b, DTYPE b_length)
{
	int i, j, k=r_length-1, Carry=0;
	T_DTYPE two_dtype_sum=0;
	for(i=a_length-1, j=b_length-1; j>=0; i--, j--)
	{
		two_dtype_sum=a[i]+b[j]+Carry;
		r[k--]=two_dtype_sum & 0x0000ffff;
		Carry=(two_dtype_sum & 0xffff0000)>>WORD_SIZE;
	}
	for(; i>=0; i--)
	{
		two_dtype_sum=a[i]+Carry;
		r[k--]=two_dtype_sum & 0x0000ffff;
		Carry=(two_dtype_sum & 0xffff0000)>>WORD_SIZE;
	}
	r[k]=Carry;
}

//r=a-b a_length>=b_length by default, r_length=a_length
void BN_sub(DTYPE *r, DTYPE r_length, DTYPE *a, DTYPE a_length, DTYPE *b, DTYPE b_length)
{
	int Borrow=0, i, j, k=r_length-1;
	for(i=a_length-1, j=b_length-1; i>=0 && j>=0; i--, j--)
	{
		if(a[i]<b[j]+Borrow)
		{
			r[k--]=a[i]-b[j]+MAX_VAL+1-Borrow;
			Borrow=1;
		}
		else
		{
			r[k--]=a[i]-b[j]-Borrow;
			Borrow=0;
		}
	}
	for(; i>=0; i--)
	{
		if(a[i]<Borrow)
		{
			r[k--]=a[i]+MAX_VAL+1-Borrow;
			Borrow=1;
		}
		else
		{
			r[k--]=a[i]-Borrow;
			Borrow=0;
		}
	}
}

//r=a*a default r_length=a_length*2
void BN_square(DTYPE *s, DTYPE *a, DTYPE a_length)
{
	int i, j;
	DTYPE d, e;
	T_DTYPE C_and_S;
	for(i=a_length-1; i>=0; i--)
	{
		C_and_S=s[i+i+1]+a[i]*a[i];
		s[i+i+1]=(C_and_S & 0x0000ffff);
		d=(C_and_S & 0xffff0000) >> WORD_SIZE;
		e=0;
		for(j=i-1; j>=0; j--)
		{
			C_and_S=s[i+j+1]+a[i]*a[j]+d;
			s[i+j+1]=(C_and_S & 0x0000ffff);
			d=(C_and_S & 0xffff0000) >> WORD_SIZE;
			C_and_S=s[i+j+1]+a[i]*a[j]+e;
			s[i+j+1]=(C_and_S & 0x0000ffff);
			e=(C_and_S & 0xffff0000) >> WORD_SIZE;
		}
		C_and_S=d+e;
		d=(C_and_S & 0x0000ffff);
		e=(C_and_S & 0xffff0000) >> WORD_SIZE;
		C_and_S=s[i]+d;
		s[i]=(C_and_S & 0x0000ffff);
		if(i>=1) s[i-1]=e+((C_and_S & 0xffff0000) >> WORD_SIZE);
	}
}

//r=a*b r_length=a_leng+b_length
void BN_mul(DTYPE *r, DTYPE *a, DTYPE a_length, DTYPE *b, DTYPE b_length)
{
	if(a_length==b_length && BN_cmp(a, a_length, b, b_length)==0)
	{
		BN_square(r, a, a_length);
		return;
	}

	int i, j;
	DTYPE len=a_length+b_length, Carry;
	T_DTYPE multi_tmp;

	BN_init(r, len); //set result to 0

	for(i=b_length-1; i>=0; i--)
	{
		Carry=0;
		for(j=a_length-1; j>=0; j--)
		{
			multi_tmp=r[i+j+1]+(T_DTYPE)b[i]*a[j]+Carry;
			Carry=(multi_tmp & 0xffff0000) >> WORD_SIZE;
			r[i+j+1]=(multi_tmp & 0x0000ffff);
		}
		r[i]=Carry;
	}
}

//r=a(mod n) r_length=n_length, a_length>=n_length
void BN_mod(DTYPE *r, DTYPE *a, DTYPE a_length, DTYPE *n, DTYPE n_length)
{
	int i, j;
	if(BN_cmp(a, a_length, n, n_length)==-1)
	{
		for(i=n_length-1, j=a_length-1; i>=0 && j>=0; i--, j--)
		{
			r[i]=a[j];
		}
		return;
	}

	DTYPE *a_copy=(DTYPE *)malloc(sizeof(DTYPE)*a_length);
	DTYPE *aligned_n=(DTYPE *)malloc(sizeof(DTYPE)*a_length);
	if(a_copy == NULL || aligned_n == NULL)
	{
		printf("Wrong with malloc\n");
		exit(-1);
	}
	BN_assign(a_copy, a, a_length);
	BN_init(aligned_n, a_length);
	if(a_length == n_length)
	{
		BN_assign(aligned_n, n, n_length);
	}
	else //a_length>n_length
	{
		for(i=n_length-1; i>=0; i--)
		{
			aligned_n[a_length-n_length+i]=n[i];
		}
	}

	int ba=BN_valid_bits(a, a_length);
	int bn=BN_valid_bits(n, n_length);
	if(ba>bn) BN_left_shift(aligned_n, a_length, ba-bn);
	for(i=0; i<=(ba-bn); i++)
	{
		if(BN_cmp(a_copy, a_length, aligned_n, a_length)!=-1)
		{
			BN_sub(a_copy, a_length, a_copy, a_length, aligned_n, a_length);
		}
		BN_right_shift(aligned_n, a_length, 1);
	}
	for(j=a_length-1; j+n_length-a_length>=0; j--)
	{
		r[j+n_length-a_length]=a_copy[j];
	}

	if(a_copy!=NULL) free(a_copy);
	if(aligned_n!=NULL) free(aligned_n);
}

//r=a*b(mod n) default r_length=n_length use multiply then reduce method
void BN_mod_mul(DTYPE *r, DTYPE *a, DTYPE a_length, DTYPE *b, DTYPE b_length, DTYPE *n, DTYPE n_length)
{
	DTYPE *rr=(DTYPE *)malloc(sizeof(DTYPE)*(a_length+b_length));
	if(rr == NULL)
	{
		printf("Wrong with malloc");
		exit(-1);
	}
	BN_mul(rr, a, a_length, b, b_length);
	BN_mod(r, rr, a_length+b_length, n, n_length);
	if(rr!=NULL) free(rr);
}

//r=a*(b mod n)(mod n) using Blakley's Method
void BN_mod_mul2(DTYPE *r, DTYPE *a, DTYPE a_length, DTYPE *b, DTYPE b_length, DTYPE *n, DTYPE n_length)
{
	int i, j, k, q, len=2*MAX_MODULUS_LENGTH+1;
	DTYPE a0;
	DTYPE R[2*MAX_MODULUS_LENGTH+1]={0};
	DTYPE *b_mod_n=(DTYPE *)malloc(sizeof(DTYPE)*n_length);
	if(b_mod_n == NULL)
	{
		printf("Wrong with malloc\n");
		exit(-1);
	}
	BN_mod(b_mod_n, b, b_length, n, n_length);

	for(i=BN_valid_pos(a, a_length); i < a_length; i++)
	{
		a0=a[i];
		for(j=0; j<WORD_SIZE; j++)
		{
			BN_left_shift(R, len, 1);
			if(BN_cmp(R, len, n, n_length)>=0)
			{
				BN_sub(R, len, R, len, n, n_length);
			}
			for(k=n_length-1, q=len-1; k>=0; k--, q--)
			{
				r[k]=R[q];
			}
			if(BN_MSB(a0)==1)
			{
				BN_add(R, len, r, n_length, b_mod_n, n_length);
			}
			if(BN_cmp(R, len, n, n_length)>=0)
			{
				BN_sub(R, len, R, len, n, n_length);
			}
			if(BN_cmp(R, len, n, n_length)>=0)
			{
				BN_sub(R, len, R, len, n, n_length);
			}
			for(k=n_length-1, q=len-1; k>=0; k--, q--)
			{
				r[k]=R[q];
			}
			a0 <<= 1;
		}
	}
	if(b_mod_n!=NULL) free(b_mod_n);
}

//compute a_inv, a_inv*a=1(mod n) use Binary Extended gcd Algorithm
void BN_mod_inv(DTYPE *a_inv, DTYPE *a, DTYPE a_length, DTYPE *n, DTYPE n_length)
{
	int i, j;
	sm u, v, A, B, C, D, a_copy;
	signBN_init_assign(&u, a, a_length); //u=a
	signBN_init_assign(&v, n, n_length); //v=n
	signBN_init(&A, n_length+1);
	A.bn[n_length]=1; //A=1
	signBN_init(&B, a_length+1); //B=0
	signBN_init(&C, n_length+1); //C=0
	signBN_init(&D, a_length+1);
	D.bn[a_length]=1; //D=1
	signBN_init(&a_copy, a_length+1);
	for(i=0; i<a_length; i++){
		a_copy.bn[i+1]=a[i];
	} //a_copy=a;

	DTYPE *ntmp=(DTYPE *)malloc(sizeof(DTYPE)*(n_length+2));
	if(ntmp==NULL)
	{
		printf("Wrong with malloc\n");
		exit(-1);
	}
	BN_init(ntmp, n_length+2);

	while(BN_isEqualZero(u.bn, a_length)==0)
	{
		while(BN_LSB(u.bn[a_length-1])==0)
		{
			BN_right_shift(u.bn, a_length, 1);
			if(BN_LSB(A.bn[n_length])==0 && BN_LSB(B.bn[a_length])==0)
			{
				BN_right_shift(A.bn, n_length+1, 1);
				BN_right_shift(B.bn, a_length+1, 1);
			}
			else
			{
				BN_signAddShift(&A, n, ntmp);
				BN_sign_sub(&B, &B, &a_copy);
				BN_right_shift(B.bn, a_length+1, 1);
			}
		}
		while(BN_LSB(v.bn[n_length-1])==0)
		{
			BN_right_shift(v.bn, n_length, 1);
			if(BN_LSB(C.bn[n_length])==0 && BN_LSB(D.bn[a_length])==0)
			{
				BN_right_shift(C.bn, n_length+1, 1);
				BN_right_shift(D.bn, a_length+1, 1);
			}
			else
			{
				BN_signAddShift(&C, n, ntmp);
				BN_sign_sub(&D, &D, &a_copy);
				BN_right_shift(D.bn, a_length+1, 1);
			}
		}
		if(BN_cmp(u.bn, a_length, v.bn, n_length)!=-1)
		{
			if(n_length>a_length)
			{
				DTYPE *u_BN=(DTYPE *)malloc(sizeof(DTYPE)*n_length);
				if(u_BN == NULL)
				{
					printf("Wrong with malloc\n");
					exit(-1);
				}
				BN_init(u_BN, n_length);
				for(i=n_length-1, j=a_length-1; i>=0 && j>=0; i--, j--)
				{
					u_BN[i]=u.bn[j];
				}
				BN_sub(u_BN, n_length, u_BN, n_length, v.bn, n_length);
				for(i=n_length-1, j=a_length-1; i>=0 && j>=0; i--, j--)
				{
					u.bn[j]=u_BN[i];
				}
				if(u_BN != NULL) free(u_BN);
			}
			else
			{
				BN_sub(u.bn, a_length, u.bn, a_length, v.bn, n_length);
			}
			BN_sign_sub(&A, &A, &C);
			BN_sign_sub(&B, &B, &D);
		}
		else
		{
			BN_sub(v.bn, n_length, v.bn, n_length, u.bn, a_length);
			BN_sign_sub(&C, &C, &A);
			BN_sign_sub(&D, &D, &B);
		}
	}

	for(j=n_length-1; j>=0; j--)
	{
		a_inv[j]=C.bn[j+1];
	}
	if(C.flag==0)
	{
		BN_sub(a_inv, n_length, n, n_length, a_inv, n_length);
	}
	while(BN_cmp(a_inv, n_length, n, n_length)==1)
	{
	 	BN_sub(a_inv, n_length, a_inv, n_length, n, n_length);
	}

	if(ntmp!=NULL) free(ntmp);
}

//compute a_inv, a_inv*a=1(mod 2^WORD_SIZE)
//a_inv and a is a DTYPE
void BN_MonMod_inv(DTYPE *a_inv, DTYPE *a, DTYPE a_length)
{
	DTYPE y[2]={ 0, 1 }, modulus[2]={ 0, 2 }, r_tmp[2]={ 0 }, tmp[3]={0};
	int i;

	for(i=2; i<=WORD_SIZE; i++)
	{
		BN_left_shift(modulus, 2, 1);
		BN_mod_mul(r_tmp, y, 2, a, a_length, modulus, 2);
		// BN_mod_mul2(r_tmp, y, 2, a, a_length, modulus, 2);
		BN_right_shift(modulus, 2, 1);
		if(BN_cmp(r_tmp, 2, modulus, 2)==1)
		{
			BN_add(tmp, 3, y, 2, modulus, 2);
			y[0]=tmp[1];
			y[1]=tmp[2];
		}
		BN_left_shift(modulus, 2, 1);
	}
	*a_inv=y[1];
}

//special case: compute Montgomery Product with n as pk->n
void BN_MonPro_n(DTYPE *r, DTYPE *a, DTYPE *b, DTYPE *n, DTYPE n_inv)
{
    int i, j;
    DTYPE m[2]={0}, mm, Carry=0, Sum=0;
	DTYPE t[2*MAX_MODULUS_LENGTH]={0};
	DTYPE u[2*MAX_MODULUS_LENGTH+1]={0};
	DTYPE r_tmp[MAX_MODULUS_LENGTH+1]={0};
	T_DTYPE tmp=0;
	T_DTYPE modulus=0x00010000, mul;

	BN_mul(t, a, MAX_MODULUS_LENGTH, b, MAX_MODULUS_LENGTH);
    for(i=2*MAX_MODULUS_LENGTH-1; i>=MAX_MODULUS_LENGTH; i--)
	{
        Carry=0;
		mul=(t[i]*n_inv)%modulus;
		mm=(mul & 0x0000ffff);
        for(j=MAX_MODULUS_LENGTH-1; j>=0; j--)
		{
            tmp=t[i+j-MAX_MODULUS_LENGTH+1]+mm*n[j]+Carry;
            Carry=(tmp & 0xffff0000) >> WORD_SIZE;
			t[i+j-MAX_MODULUS_LENGTH+1]=(tmp & 0x0000ffff);
        }
        for(j=i-MAX_MODULUS_LENGTH; j>=0; j--)
		{
            tmp=t[j]+Carry;
            Carry=(tmp & 0xffff0000) >> WORD_SIZE;
            t[j]=(tmp & 0x0000ffff);
        }
    }
    u[0]=Carry;
	for(i=1; i<2*MAX_MODULUS_LENGTH+1; i++)
	{
		u[i]=t[i-1];
	}

    int bits=BN_valid_bits(n, MAX_MODULUS_LENGTH);
	if(bits==MAX_MODULUS_BITS)
	{
		for(i=MAX_MODULUS_LENGTH, j=MAX_MODULUS_LENGTH; i>=0 && j>=0; i--, j--)
		{
			r_tmp[j]=u[i];
		}
		if(BN_cmp(r_tmp, MAX_MODULUS_LENGTH+1, n, MAX_MODULUS_LENGTH)==1)
		{
			BN_sub(r_tmp, MAX_MODULUS_LENGTH+1, r_tmp, MAX_MODULUS_LENGTH+1, n, MAX_MODULUS_LENGTH);
		}
		for(i=MAX_MODULUS_LENGTH, j=MAX_MODULUS_LENGTH-1; i>=0 && j>=0; i--, j--)
		{
			r[j]=r_tmp[i];
		}
	}
	else
	{
		BN_right_shift(u, 2*MAX_MODULUS_LENGTH+1, bits);
		for(i=2*MAX_MODULUS_LENGTH, j=MAX_MODULUS_LENGTH; i>=0 && j>=0; i--, j--)
		{
			r_tmp[j]=u[i];
		}
		while(BN_cmp(r_tmp, MAX_MODULUS_LENGTH+1, n, MAX_MODULUS_LENGTH)==1)
		{
			BN_sub(r_tmp, MAX_MODULUS_LENGTH+1, r_tmp, MAX_MODULUS_LENGTH+1, n, MAX_MODULUS_LENGTH);
		}
		for(i=MAX_MODULUS_LENGTH, j=MAX_MODULUS_LENGTH-1; i >= 0 && j >= 0; i--, j--)
		{
			r[j]=r_tmp[i];
		}
	}
}

//special case: compute Montgomery Product with n as sk->p, sk->q
void BN_MonPro_p(DTYPE *r, DTYPE *a, DTYPE *b, DTYPE *n, DTYPE n_inv)
{
	int i, j;
	DTYPE m[2]={ 0 }, mm, Carry=0, Sum=0;
	DTYPE t[2  *MAX_PRIME_LENGTH]={ 0 };
	DTYPE u[2  *MAX_PRIME_LENGTH+1]={ 0 };
	DTYPE r_tmp[MAX_PRIME_LENGTH+1]={ 0 };
	T_DTYPE tmp=0;
	T_DTYPE modulus=0x00010000, mul;

	BN_mul(t, a, MAX_PRIME_LENGTH, b, MAX_PRIME_LENGTH);
	for(i=2*MAX_PRIME_LENGTH-1; i>=MAX_PRIME_LENGTH; i--)
	{
		Carry=0;
		mul=(t[i]*n_inv)%modulus;
		mm=(mul & 0x0000ffff);
		for(j=MAX_PRIME_LENGTH-1; j >= 0; j--)
		{
			tmp=t[i+j-MAX_PRIME_LENGTH+1]+mm*n[j]+Carry;
			Carry=(tmp & 0xffff0000) >> WORD_SIZE;
			t[i+j-MAX_PRIME_LENGTH+1]=(tmp & 0x0000ffff);
		}
		for(j=i-MAX_PRIME_LENGTH; j >= 0; j--)
		{
			tmp=t[j]+Carry;
			Carry=(tmp & 0xffff0000) >> WORD_SIZE;
			t[j]=(tmp & 0x0000ffff);
		}
	}
	u[0]=Carry;

	for(i=1; i<2  *MAX_PRIME_LENGTH+1; i++)
	{
		u[i]=t[i-1];
	}
	for(i=MAX_PRIME_LENGTH; i>=0; i--)
	{
		r_tmp[i]=u[i];
	}
	if(BN_cmp(r_tmp, MAX_PRIME_LENGTH+1, n, MAX_PRIME_LENGTH)!=-1)
	{
		BN_sub(r_tmp, MAX_PRIME_LENGTH+1, r_tmp, MAX_PRIME_LENGTH+1, n, MAX_PRIME_LENGTH);
	}
	for(i=MAX_PRIME_LENGTH-1; i>=0; i--)
	{
		r[i]=r_tmp[i+1];
	}
}

void BN_MonPro(DTYPE *r, DTYPE *a, DTYPE a_length, DTYPE *b, DTYPE b_length, DTYPE *n, DTYPE n_length, DTYPE n_inv)
{
	if(n_length == MAX_MODULUS_LENGTH) BN_MonPro_n(r, a, b, n, n_inv);
	else BN_MonPro_p(r, a, b, n, n_inv);
}

void BN_MonExp_n(DTYPE *result, DTYPE *a, DTYPE *e, DTYPE *n, DTYPE *r, DTYPE inv)
{
	int bits;
	DTYPE e_copy[MAX_PRIME_LENGTH]={0};
	DTYPE a_r[MAX_MODULUS_LENGTH]={0};
	DTYPE x_r[MAX_MODULUS_LENGTH]={0};
	DTYPE one[MAX_MODULUS_LENGTH]={0};
	one[MAX_MODULUS_LENGTH-1]=1;
	BN_assign(e_copy, e, MAX_PRIME_LENGTH);
	BN_assign(x_r, r, MAX_MODULUS_LENGTH);
	// BN_mod_mul2(a_r, a, MAX_MODULUS_LENGTH, x_r, MAX_MODULUS_LENGTH, n, MAX_MODULUS_LENGTH);
	BN_mod_mul(a_r, a, MAX_MODULUS_LENGTH, x_r, MAX_MODULUS_LENGTH, n, MAX_MODULUS_LENGTH);
	bits=BN_valid_bits(e, MAX_PRIME_LENGTH);
	while(BN_MSB(e_copy[0])!=1)
	{
		BN_left_shift(e_copy, MAX_PRIME_LENGTH, 1);
	}
	while(bits>0)
	{
		BN_MonPro_n(x_r, x_r, x_r, n, inv);
		if(BN_MSB(e_copy[0]) == 1)
		{
			BN_MonPro_n(x_r, a_r, x_r, n, inv);
		}
		BN_left_shift(e_copy, MAX_PRIME_LENGTH, 1);
		bits--;
	}
	BN_MonPro_n(result, x_r, one, n, inv);
}

//Montgomery Method to compute result=a^e(mod n)
void BN_MonExp_p(DTYPE *result, DTYPE *a, DTYPE *e, DTYPE *n, DTYPE *r, DTYPE inv)
{
	int bits;
	DTYPE e_copy[MAX_PRIME_LENGTH]={0};
	DTYPE a_r[MAX_PRIME_LENGTH]={0};
	DTYPE x_r[MAX_PRIME_LENGTH]={0};
	DTYPE one[MAX_PRIME_LENGTH]={0};
	one[MAX_PRIME_LENGTH-1]=1;
	BN_assign(e_copy, e, MAX_PRIME_LENGTH);
	BN_assign(x_r, r, MAX_PRIME_LENGTH);
	// BN_mod_mul2(a_r, a, MAX_MODULUS_LENGTH, x_r, MAX_PRIME_LENGTH, n, MAX_PRIME_LENGTH);
	BN_mod_mul(a_r, a, MAX_MODULUS_LENGTH, x_r, MAX_PRIME_LENGTH, n, MAX_PRIME_LENGTH);
	bits=BN_valid_bits(e, MAX_PRIME_LENGTH);
	while(BN_MSB(e_copy[0])!=1)
	{
		BN_left_shift(e_copy, MAX_PRIME_LENGTH, 1);
	}
	while(bits>0)
	{
		BN_MonPro_p(x_r, x_r, x_r, n, inv);
		if(BN_MSB(e_copy[0]) == 1)
		{
			BN_MonPro_p(x_r, a_r, x_r, n, inv);
		}
		BN_left_shift(e_copy, MAX_PRIME_LENGTH, 1);
		bits--;
	}
	BN_MonPro_p(result, x_r, one, n, inv);
}

void BN_MonExp(DTYPE *result, DTYPE *a, DTYPE a_length, DTYPE *e, DTYPE e_length, DTYPE *n, DTYPE n_length, DTYPE *r, DTYPE inv)
{
	if(n_length == MAX_MODULUS_LENGTH) BN_MonExp_n(result, a, e, n, r, inv);
	else  BN_MonExp_p(result, a, e, n, r, inv);
}

//a_length=e_length=n_length=MAX_PRIME_LENGTH
void BN_pow_mod(DTYPE *result, DTYPE *a, DTYPE *e, DTYPE *n)
{
	int i, bits=BN_valid_bits(e, MAX_PRIME_LENGTH);
	DTYPE ee[MAX_PRIME_LENGTH];
	BN_assign(ee, e, MAX_PRIME_LENGTH);
	while(BN_MSB(ee[0])!=1)
	{
		BN_left_shift(ee, MAX_PRIME_LENGTH, 1);
	}
	BN_assign(result, a, MAX_PRIME_LENGTH);
	for(i=0; i<bits-1; i++)
	{
		BN_left_shift(ee, MAX_PRIME_LENGTH, 1);
		//BN_mod_mul2(result, result, MAX_PRIME_LENGTH, result, MAX_PRIME_LENGTH, n, MAX_PRIME_LENGTH);
		BN_mod_mul(result, result, MAX_PRIME_LENGTH, result, MAX_PRIME_LENGTH, n, MAX_PRIME_LENGTH);
		if(BN_MSB(ee[0])==1)
		{
			//BN_mod_mul2(result, result, MAX_PRIME_LENGTH, a, MAX_PRIME_LENGTH, n, MAX_PRIME_LENGTH);
			BN_mod_mul(result, result, MAX_PRIME_LENGTH, a, MAX_PRIME_LENGTH, n, MAX_PRIME_LENGTH);
		}
	}
}

void signBN_init(sm *r, DTYPE len)
{
	int i;
	r->flag=1;
	r->length=len;
	r->bn=(DTYPE *)malloc(sizeof(DTYPE)*len);
	if(r->bn == NULL)
	{
		printf("Wrong with malloc\n");
		exit(-1);
	}
	for(i=0; i<len; i++)
	{
		r->bn[i]=0;
	}
}

void signBN_init_assign(sm *r, DTYPE *a, DTYPE a_length)
{
	r->flag=1;
	r->length=a_length;
	r->bn=(DTYPE *)malloc(sizeof(DTYPE)*a_length);
	if(r->bn == NULL)
	{
		printf("Wrong with malloc\n");
		exit(-1);
	}
	BN_assign(r->bn, a, a_length);
}

void BN_signAddShift(sm *a, DTYPE *n, DTYPE *tmp)
{
	int i;
	if(a->flag==1)
	{
		BN_add(tmp, a->length+1, a->bn, a->length, n, a->length-1);
		BN_right_shift(tmp, a->length+1, 1);
		for(i=0; i<a->length; i++)
		{
			a->bn[i]=tmp[i+1];
		}
	}
	else
	{
		if(BN_cmp(a->bn, a->length, n, a->length-1)==1)
		{
			BN_sub(a->bn, a->length, a->bn, a->length, n, a->length-1);
		}
		else
		{
			DTYPE *nc=(DTYPE *)malloc(sizeof(DTYPE)*a->length);
			if(nc==NULL)
			{
				printf("Wrong with malloc\n");
				exit(-1);
			}
			nc[0]=0;
			for(i=1; i<a->length; i++)
			{
				nc[i]=n[i-1];
			}
			BN_sub(a->bn, a->length, nc, a->length, a->bn, a->length);
			a->flag=1;
			if(nc!=NULL) free(nc);
		}
		BN_right_shift(a->bn, a->length, 1);
	}
	BN_init(tmp, a->length+1);
}

//r=a-c
void BN_sign_sub(sm *r, sm *a, sm *c)
{
	int len=a->length;
	if(a->flag==1 && c->flag==1)
	{
		if(BN_cmp(a->bn, len, c->bn, len)>=0)
		{
			BN_sub(r->bn, len, a->bn, len, c->bn, len);
			r->flag=1;
		}
		else
		{
			BN_sub(r->bn, len, c->bn, len, a->bn, len);
			r->flag=0;
		}
	}
	else if(a->flag==1 && c->flag==0)
	{
		BN_add(r->bn, len, a->bn, len, c->bn, len);
		r->flag=1;
	}
	else if(a->flag==0 && c->flag==1)
	{
		BN_add(r->bn, len, a->bn, len, c->bn, len);
		r->flag=0;
	}
	else if(a->flag==0 && c->flag==0)
	{
		if(BN_cmp(c->bn, len, a->bn, len)>=0)
		{
			BN_sub(r->bn, len, c->bn, len, a->bn, len);
			r->flag=1;
		}
		else
		{
			BN_sub(r->bn, len, a->bn, len, c->bn, len);
			r->flag=0;
		}
	}
}

//Key.h
typedef struct pk{
	DTYPE n[MAX_MODULUS_LENGTH];
	DTYPE e[MAX_PRIME_LENGTH];
	DTYPE r_mod[MAX_MODULUS_LENGTH]; //r_mod=2^MAX_MODULUS_BITS(mod n)
	DTYPE n_inv; //-n_inv*n=1(mod 2^word_size)
}rsa_pk;

typedef struct sk{
	DTYPE n[MAX_MODULUS_LENGTH];
	DTYPE p[MAX_PRIME_LENGTH];
	DTYPE q[MAX_PRIME_LENGTH];
	DTYPE phi_n[MAX_MODULUS_LENGTH]; //phi_n=(p-1)*(q-1)
	DTYPE d[MAX_MODULUS_LENGTH]; //e*d=1(mod fi_n)
	DTYPE d1[MAX_PRIME_LENGTH]; //d1=d mod(p-1)
	DTYPE d2[MAX_PRIME_LENGTH]; //d2=d mod(q-1) 
	DTYPE p_inv[MAX_PRIME_LENGTH]; //p_inv*p=1(mod q)
	DTYPE r_mod[MAX_MODULUS_LENGTH]; //r_mod=2^MAX_MODULUS_BITS(mod n)
	DTYPE p_mod[MAX_PRIME_LENGTH]; //p_mod=2^MAX_PRIME_BITS(mod p)
	DTYPE q_mod[MAX_PRIME_LENGTH]; //q_mod=2^MAX_PRIME_BITS(mod q)
	DTYPE n_inv; //-n_inv*n=1(mod 2^word_size)
	DTYPE p0_inv; //-p0_inv*p=1(mod 2^word_size)
	DTYPE q0_inv; //-q0_inv*q=1(mod 2^word_size)
}rsa_sk;

//Key.c

#define S_LENGTH 54
#define TRUE 1
#define FALSE 0

const int SP = 14;
DTYPE S[S_LENGTH] = {2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251};

void seive(DTYPE *p, DTYPE *S, DTYPE *w)
{
	int i, j, flag=0;

	//first generate an odd number
	for(i=MAX_PRIME_LENGTH-1; i>=0; i--)
	{
		srand(time(NULL) * 1000 + (clock() % 1000) + i);
		p[i] = (DTYPE)rand(); 
		// p[i] = (DTYPE)rand() % MAX_VAL;
		if(i==MAX_PRIME_LENGTH-1) p[i] = (p[i] | 0x0001); //p is odd
		if(i==0) p[i] = (p[i] | 0x8000); //the most significant bit of p is 1
	}
	for(i=0; i<S_LENGTH; i++)
	{
		BN_mod(&w[i], p, MAX_PRIME_LENGTH, &S[i], 1);
	}
	
	while(flag==0)
	{
		for(i=0; i<S_LENGTH; i++)
		{
			if(w[i]==0)
			{
				for(j=0; j<S_LENGTH; j++)
				{
					w[j]=(w[j]+2)%S[j];
				}
				//p=p+2
				BN_inc(p, MAX_PRIME_LENGTH);
				BN_inc(p, MAX_PRIME_LENGTH);
				break;
			}
			else continue;
		}
		if(i==S_LENGTH) flag = 1;
	}
}

//running Miller-Rabin Probable Primality Test, length of n is MAX_PRIME_lENGTH
int probable_prime_test(DTYPE *n, DTYPE SecurityParam)
{
	int i, j, s=0, flag=0;
	DTYPE n_sub_1[MAX_PRIME_LENGTH]={0}, n_sub[MAX_PRIME_LENGTH]={0}, y[MAX_PRIME_LENGTH]={0};
	DTYPE a[2*MAX_PRIME_LENGTH]={0};
	DTYPE r[MAX_PRIME_LENGTH+1]={0}, r_mod[MAX_PRIME_LENGTH]={0};
	DTYPE inv, n0;

	BN_assign(n_sub_1, n, MAX_PRIME_LENGTH);
	BN_dec(n_sub_1, MAX_PRIME_LENGTH);
	BN_assign(n_sub, n_sub_1, MAX_PRIME_LENGTH); //n_sub = n-1

	for(i=2*MAX_PRIME_LENGTH-1, j=MAX_PRIME_LENGTH-1; i>=0 && j>=0; i--, j--)
	{
		a[i] = n_sub[j];
	} //a=n-1

	r[0]=1;
	BN_mod(r_mod, r, MAX_PRIME_LENGTH+1, n, MAX_PRIME_LENGTH);

	n0=n[MAX_PRIME_LENGTH-1];
	n0 = MAX_VAL-n0;
	n0 += 1;
	BN_MonMod_inv(&inv, &n0, 1);

	while(BN_LSB(n_sub_1[MAX_PRIME_LENGTH-1])!=1)
	{
		BN_right_shift(n_sub_1, MAX_PRIME_LENGTH, 1);
		s++;
	}

	for(i=1; i<=SecurityParam; i++)
	{
		BN_dec(a, 2*MAX_PRIME_LENGTH);
		BN_MonExp(y, a, 2*MAX_PRIME_LENGTH, n_sub_1, MAX_PRIME_LENGTH, n, MAX_PRIME_LENGTH, r_mod, inv);
		if(BN_isEqualOne(y, MAX_PRIME_LENGTH) == 0 && BN_cmp(y, MAX_PRIME_LENGTH, n_sub, MAX_PRIME_LENGTH) != 0)
		{
			for(j=0; j<s; j++)
			{
				if(BN_cmp(y, MAX_PRIME_LENGTH, n_sub, MAX_PRIME_LENGTH) != 0)
				{
					// BN_mod_mul2(y, y, MAX_PRIME_LENGTH, y, MAX_PRIME_LENGTH, n, MAX_PRIME_LENGTH);
					BN_mod_mul(y, y, MAX_PRIME_LENGTH, y, MAX_PRIME_LENGTH, n, MAX_PRIME_LENGTH);
					if(BN_isEqualOne(y, MAX_PRIME_LENGTH) == 1 || BN_cmp(y, MAX_PRIME_LENGTH, n_sub, MAX_PRIME_LENGTH) != 0) return FALSE;
				} //end of if
			} //end of for
		} //end of if
	} //end of for
	return TRUE;
}

//generate prime with length of MAX_PRIME_LENGTH, order=0->sk->p, order=1->sk->q
void prime_generate(rsa_sk *sk, int order)
{
	DTYPE p[MAX_PRIME_LENGTH], w[S_LENGTH]={0};

	do{
		seive(p, S, w);
	}while(probable_prime_test(p, SP)==FALSE); //SP, number of iterations in Miller Rabin Test

	if(order==0) BN_assign(sk->p, p, MAX_PRIME_LENGTH);
	else BN_assign(sk->q, p, MAX_PRIME_LENGTH);
}

//generate keys in RSA
void rsa_key_generation(rsa_pk *pk, rsa_sk *sk)
{
	BN_init(pk->e, MAX_PRIME_LENGTH);
	BN_init(pk->n, MAX_MODULUS_LENGTH);
	BN_init(sk->n, MAX_MODULUS_LENGTH);
	BN_init(sk->p, MAX_PRIME_LENGTH);
	BN_init(sk->q, MAX_PRIME_LENGTH);
	BN_init(sk->phi_n, MAX_MODULUS_LENGTH);
	BN_init(sk->d, MAX_MODULUS_LENGTH);
	BN_init(sk->d1, MAX_PRIME_LENGTH);
	BN_init(sk->d2, MAX_PRIME_LENGTH);
	BN_init(sk->p_inv, MAX_PRIME_LENGTH);
	BN_init(sk->r_mod, MAX_MODULUS_LENGTH);
	BN_init(sk->p_mod, MAX_PRIME_LENGTH);
	BN_init(sk->q_mod, MAX_PRIME_LENGTH);

	//e=2^16+1
	pk->e[MAX_PRIME_LENGTH - 2] = 1;
	pk->e[MAX_PRIME_LENGTH - 1] = 1;

	prime_generate(sk, 0); //sk->p
	prime_generate(sk, 1); //sk->q
	
	if(BN_cmp(sk->q, MAX_PRIME_LENGTH, sk->p, MAX_PRIME_LENGTH)==1)
	{
		BN_exchange(sk->q, sk->p, MAX_PRIME_LENGTH);
	} //if q is bigger than p, exchange them
	
	BN_mul(pk->n, sk->p, MAX_PRIME_LENGTH, sk->q, MAX_PRIME_LENGTH); //pk->n
	BN_assign(sk->n, pk->n, MAX_MODULUS_LENGTH); //sk->n

	DTYPE n0=pk->n[MAX_MODULUS_LENGTH-1];
	n0 = MAX_VAL-n0;
	n0 += 1;
	BN_MonMod_inv(&pk->n_inv, &n0, 1); //pk->n_inv
	sk->n_inv = pk->n_inv; //sk->n_inv

	DTYPE r[MAX_MODULUS_LENGTH+1] = {0};
	int bits = BN_valid_bits(pk->n, MAX_MODULUS_LENGTH);
	if(bits==MAX_MODULUS_BITS) r[0]=1;
	else
	{
		r[MAX_MODULUS_LENGTH] = 1;
		BN_left_shift(r, MAX_MODULUS_LENGTH + 1, bits);
	}
	BN_mod(pk->r_mod, r, MAX_MODULUS_LENGTH+1, pk->n, MAX_MODULUS_LENGTH); //pk->r_mod
	BN_assign(sk->r_mod, pk->r_mod, MAX_MODULUS_LENGTH); //sk->r_mod

	DTYPE p_dec[MAX_PRIME_LENGTH], q_dec[MAX_PRIME_LENGTH];
	BN_assign(p_dec, sk->p, MAX_PRIME_LENGTH);
	BN_assign(q_dec, sk->q, MAX_PRIME_LENGTH);
	BN_dec(p_dec, MAX_PRIME_LENGTH);
	BN_dec(q_dec, MAX_PRIME_LENGTH);
	BN_mul(sk->phi_n, p_dec, MAX_PRIME_LENGTH, q_dec, MAX_PRIME_LENGTH); //sk->phi_n
	BN_mod_inv(sk->d, pk->e, MAX_PRIME_LENGTH, sk->phi_n, MAX_MODULUS_LENGTH); //sk->d
	BN_mod(sk->d1, sk->d, MAX_MODULUS_LENGTH, p_dec, MAX_PRIME_LENGTH); //sk->d1
	BN_mod(sk->d2, sk->d, MAX_MODULUS_LENGTH, q_dec, MAX_PRIME_LENGTH); //sk->d2

	DTYPE p_mod_q[MAX_PRIME_LENGTH]={0};
	BN_sub(p_mod_q, MAX_PRIME_LENGTH, sk->p, MAX_PRIME_LENGTH, sk->q, MAX_PRIME_LENGTH);
	BN_mod_inv(sk->p_inv, p_mod_q, MAX_PRIME_LENGTH, sk->q, MAX_PRIME_LENGTH); //sk->p_inv

	DTYPE pp[MAX_PRIME_LENGTH+1] = {0};
	pp[0]=1;
	BN_mod(sk->p_mod, pp, MAX_PRIME_LENGTH+1, sk->p, MAX_PRIME_LENGTH); //sk->p_mod

	DTYPE qq[MAX_PRIME_LENGTH + 1] = { 0 };
	qq[0] = 1;
	BN_mod(sk->q_mod, qq, MAX_PRIME_LENGTH+1, sk->q, MAX_PRIME_LENGTH); //sk->q_mod

	DTYPE p0=sk->p[MAX_PRIME_LENGTH-1];
	p0 = MAX_VAL-p0;
	p0 += 1;
	BN_MonMod_inv(&sk->p0_inv, &p0, 1); //sk->p0_inv

	DTYPE q0=sk->q[MAX_PRIME_LENGTH-1];
	q0 = MAX_VAL-q0;
	q0 += 1;
	BN_MonMod_inv(&sk->q0_inv, &q0, 1); //sk->q0_inv
}


//RSA.c
//use pk to encrypt msg, output is cipher
void rsa_encrypt(DTYPE *cipher, DTYPE cipher_len, DTYPE *msg, DTYPE msg_len, rsa_pk *pk)
{
	BN_MonExp(cipher, msg, msg_len, pk->e, MAX_PRIME_LENGTH, pk->n, MAX_MODULUS_LENGTH, pk->r_mod, pk->n_inv);
}

//use sk to decrype cipher, result is saved in output
void rsa_decrypt(DTYPE *output, DTYPE output_len, DTYPE *cipher, DTYPE cipher_len, rsa_sk *sk)
{
	int i;
	DTYPE M1[MAX_PRIME_LENGTH]={0};
	DTYPE M2[MAX_PRIME_LENGTH]={0};
	DTYPE M_tmp[MAX_PRIME_LENGTH]={0};
	DTYPE r1_tmp[MAX_PRIME_LENGTH]={0};
	DTYPE r2_tmp[MAX_MODULUS_LENGTH]={0};
	DTYPE out[MAX_MODULUS_LENGTH+1] = {0};

	BN_MonExp(M1, cipher, cipher_len, sk->d1, MAX_PRIME_LENGTH, sk->p, MAX_PRIME_LENGTH, sk->p_mod, sk->p0_inv);
	BN_MonExp(M2, cipher, cipher_len, sk->d2, MAX_PRIME_LENGTH, sk->q, MAX_PRIME_LENGTH, sk->q_mod, sk->q0_inv);
	if(BN_cmp(M2, MAX_PRIME_LENGTH, M1, MAX_PRIME_LENGTH)>=0) //M2>=M1
	{
		BN_sub(M_tmp, MAX_PRIME_LENGTH, M2, MAX_PRIME_LENGTH, M1, MAX_PRIME_LENGTH);
	}
	else //M1>M2
	{
		BN_sub(M_tmp, MAX_PRIME_LENGTH, M1, MAX_PRIME_LENGTH, M2, MAX_PRIME_LENGTH);
		BN_mod(M_tmp, M_tmp, MAX_PRIME_LENGTH, sk->q, MAX_PRIME_LENGTH);
		BN_sub(M_tmp, MAX_PRIME_LENGTH, sk->q, MAX_PRIME_LENGTH, M_tmp, MAX_PRIME_LENGTH);
	}
	// BN_mod_mul2(r1_tmp, M_tmp, MAX_PRIME_LENGTH, sk->p_inv, MAX_PRIME_LENGTH, sk->q, MAX_PRIME_LENGTH);
	BN_mod_mul(r1_tmp, M_tmp, MAX_PRIME_LENGTH, sk->p_inv, MAX_PRIME_LENGTH, sk->q, MAX_PRIME_LENGTH);
	BN_mul(r2_tmp, r1_tmp, MAX_PRIME_LENGTH, sk->p, MAX_PRIME_LENGTH);
	BN_add(out, MAX_MODULUS_LENGTH+1, r2_tmp, MAX_MODULUS_LENGTH, M1, MAX_PRIME_LENGTH);
	
	for(i=0; i<MAX_MODULUS_LENGTH; i++)
	{
		output[i] = out[i+1];
	}
}

int main(void)
{
	rsa_pk pk;
	rsa_sk sk;

	clock_t key_s, key_e, rsa_s, rsa_e;
	double key_t, rsa_t;

	DTYPE msg[MAX_MODULUS_LENGTH] = { 0 };
	DTYPE cipher[MAX_MODULUS_LENGTH] = { 0 };
	DTYPE plaintext[MAX_MODULUS_LENGTH] = { 0 };

    char message[MAX_MODULUS_LENGTH * 2];
    char ciphertext[MAX_MODULUS_LENGTH * 4 + 1];
	char plainmsg[MAX_MODULUS_LENGTH * 2 + 1];

	char *m = "message.txt";
	char *c = "ciphertext.txt";
	char *p = "plaintext.txt";
	char *pkey = "publicKey.txt";
	char *skey = "privateKey.txt";

	FILE *fp;

	printf("Key generation starts...\n");
    key_s = clock();
	rsa_key_generation(&pk, &sk);
    key_e = clock();
	printf("Key generation done...\n\n");
    key_t = (key_e - key_s) / CLOCKS_PER_SEC;

    //write public keys into file
    fp = fopen(pkey, "w");
    fclose(fp);
    fp = fopen(pkey, "a");
    BN_printToFile(pk.n, MAX_MODULUS_LENGTH, fp);
    fputc('\n', fp);
    BN_printToFile(pk.e, MAX_PRIME_LENGTH, fp);
    fclose(fp);

    //write private keys into file
    fp = fopen(skey, "w");
    fclose(fp);
    fp = fopen(skey, "a");
    BN_printToFile(sk.p, MAX_PRIME_LENGTH, fp);
    fputc('\n', fp);
    BN_printToFile(sk.q, MAX_PRIME_LENGTH, fp);
    fputc('\n', fp);
    BN_printToFile(sk.d, MAX_MODULUS_LENGTH, fp);
    fclose(fp);

    //read message from file
    fp = fopen(m , "r");
    if(fp==NULL){
        printf("Cannot open file %s\n", m);
        return 0;
    }
    fgets(message, MAX_MODULUS_LENGTH * 2, fp);
    fclose(fp);
    string_to_hex(msg, message);
	
	printf("Encryption starts...\n");
    rsa_s = clock();
	rsa_encrypt(cipher, MAX_MODULUS_LENGTH, msg, MAX_MODULUS_LENGTH, &pk);
    rsa_e = clock();
    rsa_t = (double)(rsa_e-rsa_s) / CLOCKS_PER_SEC;
    printf("Encryption done...\n\n");

    //write ciphertext into file
    fp = fopen(c, "w");
    BN_printToFile(cipher, MAX_MODULUS_LENGTH, fp);
    fclose(fp);

    printf("Decryption starts...\n");
    rsa_s = clock();
    rsa_decrypt(plaintext, MAX_MODULUS_LENGTH, cipher, MAX_MODULUS_LENGTH, &sk);
    rsa_e = clock();
    printf("Decryption done...\n\n");
	rsa_t += (double)(rsa_e-rsa_s) / CLOCKS_PER_SEC;
    
    //write plaintext into file
    hex_to_string(plainmsg, plaintext);
    fp = fopen(p, "w");
    fputs(plainmsg, fp);
    fclose(fp);

	if(BN_cmp(msg, MAX_MODULUS_LENGTH, plaintext, MAX_MODULUS_LENGTH)==0)
    {
		printf("\nAfter decryption, plaintext equal to message.\n");
	}
	else
    {
		printf("\nAfter decryption, wrong answer.\n");
	}

	printf("\n%f seconds to generate keys, %f seconds to encrypt and decrypt\n", key_t, rsa_t);

	return 0;
}
