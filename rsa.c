/******************************************************************************

                            Online C Compiler.
                Code, Compile, Run and Debug C program online.
Write your code in this editor and press "Run" button to compile and execute it.

*******************************************************************************/

#include <stdio.h>
#include <math.h>
#include <stdlib.h>
#include <time.h>
// Recursive function to return gcd of a and b  
int gcd (int a, int b)
{
  if (a == 0)
    return b;
  return gcd (b % a, a);
}

// Function to return LCM of two numbers  
int lcm (int a, int b)
{
  return (a / gcd (a, b)) * b;
}

int modInverse (int a, int m)
{
  for (int x = 1; x < m; x++)
    if (((a % m) * (x % m)) % m == 1)
      return x;
}

int power (int x, unsigned int y, int p)
{
  int res = 1;			// Initialize result 
  x = x % p;			// Update x if it is more than or 
  // equal to p 
  while (y > 0)
    {
      // If y is odd, multiply x with result 
      if (y & 1)
	res = (res * x) % p;

      // y must be even now 
      y = y >> 1;		// y = y/2 
      x = (x * x) % p;
    }
  return res;
}

// This function is called for all k trials. It returns 
// false if n is composite and returns false if n is 
// probably prime. 
// d is an odd number such that d*2<sup>r</sup> = n-1 
// for some r >= 1 
int miillerTest (int d, int n)
{
  // Pick a random number in [2..n-2] 
  // Corner cases make sure that n > 4 
  int a = 2 + rand () % (n - 4);

  // Compute a^d % n 
  int x = power (a, d, n);

  if (x == 1 || x == n - 1)
    return 1;

  // Keep squaring x while one of the following doesn't 
  // happen 
  // (i) d does not reach n-1 
  // (ii) (x^2) % n is not 1 
  // (iii) (x^2) % n is not n-1 
  while (d != n - 1)
    {
      x = (x * x) % n;
      d *= 2;

      if (x == 1)
	return 0;
      if (x == n - 1)
	return 1;
    }

  // Return composite 
  return 0;
}

// It returns false if n is composite and returns true if n 
// is probably prime. k is an input parameter that determines 
// accuracy level. Higher value of k indicates more accuracy. 
int isPrime (int n, int k)
{
  // Corner cases 
  if (n <= 1 || n == 4)
    return 0;
  if (n <= 3)
    return 1;

  // Find r such that n = 2^d * r + 1 for some r >= 1 
  int d = n - 1;
  while (d % 2 == 0)
    d /= 2;

  // Iterate given nber of 'k' times 
  for (int i = 0; i < k; i++)
    if (!miillerTest (d, n))
      return 0;

  return 1;
}
// int rand_prime(){
    // int prime = 1;
//     int number;
//     srand(time(0));
//     do{
//     int number=rand();
// }while(!isPrime(number,4));
//   return number;
unsigned long long rand_prime (int lower, int upper)
{
  // time_t t;
  unsigned long long spread = upper - lower + 1;
  srand (time (0) + (rand () % spread + 100000));
  while (1)
    {
      unsigned long long p = 1 | (rand () % spread + lower);
      if (isPrime (p, 4))
	return p;
    }
}
unsigned long long power_mod(int key,int n,int mc){
    unsigned long long k = 1;
      for(int j = 0; j < key; j++)
      {
         k = k * mc;
         k = k % n;
      }
      return k;
}
int main ()
{
  int p, q, n, e, d, m, ct, c;
  unsigned long long int r;
  p = rand_prime (2, 1000000000);			//generate random prime number 907
  q = rand_prime (2, 1000000000);			//generate random prime number 773
  n = p * q;
  ct = lcm (p - 1, q - 1);	//lcm 
  printf ("%d\n", ct);
  printf("%d\n",gcd(11,ct));
  e = 11;			//choose between 1 and ct, generally 65,537 (rand() % (ct - 1 + 1)) + 1; -> gcd should be 1
  m = 4;			//message
  // c = (int)pow (m, e) % n;	// m power e mod n is ciphertext
  c = power_mod(e,n,m);
  printf ("%d\n", c);
  d = modInverse(e, ct);
  printf ("Modular multiplicative inverse is %d\n", d);
  // r = (unsigned long long int)pow (c, d) % n;
  r = power_mod(d,n,c);
  printf ("Decrypt %llu\n", r);
  printf ("\n%llu", rand_prime (2, 1000000000));
  printf ("\n%llu", rand_prime (2, 1000000000));
  return 0;
}
