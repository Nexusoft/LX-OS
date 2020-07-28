#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <math.h>
#include <nexus/timing.h>
#include <nexus/util.h>
#include <nexus/Debug.interface.h>
#include <nexus/hashtree.h>


#define DBGHT_OPT 0
#define VERBOSEHT 0

#define HASHSIZE 20

#define round(a) ((((a) * 10) + 5)/10)


#define EPSILON      .00000000000000001
#define INITIALGUESS 256

static void overflow(double x, int line){
  
  if(isnan(x)){
    printf("nan in line %d\n", line);
    exit(-1);
  }
  if(isinf(x)){
    printf("inf in line %d\n", line);
    exit(-1);
  }
}

/* rawcost computes the real cost (including middle terms) */
static double rawcost(int n, double alpha, double beta, double hashsize, double f, double b, int branch){
  double lhashes = 0, lcost = 0;
  double ihashes = 0, icost = 0;
  int i = 0;
  int d = 0;

  if(DBGHT_OPT)printf("n=%d a=%f b=%f h=%f f=%f b=%f b=%d\n", n, alpha, beta, hashsize, f, b, branch);

  lhashes = f/b * (1 - pow(1 - b/f, n));
  lcost = alpha * b + beta;
  
  d = log(f/b)/log(branch);

  ihashes = 0;
  for(i = 0; i <= d-1; i++)
    ihashes += (f/b)/(pow(branch, i + 1)) * (1 - pow(1 - ((b/f)*pow(branch, i + 1)), n));
    
  icost = alpha * hashsize + beta;
  
  return icost * ihashes + lcost * lhashes;
}

#define ALPHACHECK					\
  do{							\
    printf("checking alpha\n");				\
    overflow(alpha,__LINE__);				\
    printf("alpha is valid\n");				\
    printf("checking beta\n");				\
    overflow(beta,__LINE__);				\
    printf("beta is valid\n");				\
  }while(0)			


static double newton(int dummy, int n, double alpha, double beta, double hashsize, double f, int branch){
  if(DBGHT_OPT)printf("alpha=%llx, beta=%llx, hashsize=%llx, f=%llx\n",*(unsigned long long *)&alpha, *(unsigned long long *)&beta, *(unsigned long long *)&hashsize, *(unsigned long long *)&f);
  if(DBGHT_OPT)printf("num_updates=%d, alpha=%f, beta=%f, hsize=%f, fsize=%f, branch=%d\n", n, alpha, beta, hashsize, f, branch);
  if(DBGHT_OPT)Debug_FPUDebug();
    
  double guess;
  double eps;
  double firstderiv, seconderiv;
  double toadd;

  guess = INITIALGUESS;
  eps = 0;
  do{
    firstderiv = 0;
    seconderiv = 0;
    guess += eps;
    
    if(guess > f)
      return f;

    if(DBGHT_OPT)printf("firstderiv = %f\n", firstderiv); 
    if(DBGHT_OPT)printf("seconderiv = %f\n", seconderiv); 
    if(DBGHT_OPT)printf("guess      = %f\n", guess); 

    overflow(firstderiv, __LINE__);
    overflow(seconderiv, __LINE__);
    overflow(guess, __LINE__);
    overflow(n, __LINE__);
    overflow(alpha, __LINE__);
    overflow(beta, __LINE__);
    overflow(hashsize, __LINE__);
    overflow(f, __LINE__);
    overflow(branch, __LINE__);

    toadd = f / guess;
    overflow(toadd, __LINE__);
    toadd /= guess;
    overflow(toadd, __LINE__);
    toadd *= beta;
    overflow(toadd, __LINE__);
    firstderiv -= toadd;
    overflow(firstderiv, __LINE__);

    toadd = f  / (pow(guess, 2)) * pow(1 - guess/f, n) * beta;
    firstderiv += (toadd > EPSILON) ? toadd : 0;
    overflow(firstderiv, __LINE__);
    firstderiv += n * pow(1 - guess/f, n-1) * alpha;
    overflow(firstderiv, __LINE__);
    firstderiv += n * pow(1 - guess/f, n-1) * beta / guess;
    overflow(firstderiv, __LINE__);
    firstderiv -= n * alpha * hashsize * branch / (guess * log(branch));
    overflow(firstderiv, __LINE__);
    firstderiv -= n * beta / (guess * log(branch));
    overflow(firstderiv, __LINE__);
    if(DBGHT_OPT)printf("firstderiv = %f\n", firstderiv); 

    seconderiv += 2 * f * beta / (pow(guess, 3));
    seconderiv -= 2 * f * pow(1 - guess/f, n) * beta / (pow(guess, 3));
    seconderiv -= 2 * n * pow(1 - guess/f, n-1) * beta / (pow(guess , 2));
    seconderiv -= n * n * pow(1 - guess/f, n-2) * alpha / f;
    seconderiv -= n * n * pow(1 - guess/f, n-2) * beta / (f * guess);
    seconderiv += n * pow(1 - guess/f, n-2) * alpha / f;
    seconderiv += n * pow(1 - guess/f, n-2) * beta / (f * guess);
    seconderiv += n * alpha * hashsize * branch / (guess * guess * log(branch));
    seconderiv += n * beta / (guess * guess * log(branch));
    overflow(seconderiv, __LINE__);
    
    if(DBGHT_OPT)printf("seconderiv = %f\n", seconderiv); 
    if(DBGHT_OPT)printf("firstderiv %f seconderiv %f, f/s %f\n", firstderiv, seconderiv, firstderiv / seconderiv);

    eps = -1 * firstderiv / seconderiv;
  }while(abs(eps) > EPSILON);
       
  if (guess > f || guess < 1)
    return f;

  return guess;
}


#define GAMMA .009991288
#define ALPHA .010384 
#define BETA .621739
#define BRANCHES 2

int blocksize_get_opt(int len, int num_updates){
  double filesize = len;
  double min;
  int intmin;
  double leftcost, rightcost;
  double filesizecost;

  if(VERBOSEHT)printf("finding opt blocksize for len=%d num_updates=%d\n", len, num_updates);

  if(num_updates >= len/2)
    min = intmin = len;
  else{

    double alpha = ALPHA;
    double beta = BETA;
    int branches = BRANCHES;
    double hsize = HASHSIZE;

    if(DBGHT_OPT)Debug_FPUDebug();
    if(DBGHT_OPT)printf("num_updates=%d, alpha=%f, beta=%f, hsize=%f, fsize=%f, branch=%d\n", num_updates, alpha, beta, hsize, filesize, branches);
    min = newton(0, num_updates, alpha, beta, hsize, filesize, branches);  
  
    /* the SHA is really a step function due to the 64 byte blocksize it
     * uses.  We use the best of the step edges around the optimal on
     * the smooth curve. 55 119 183 247 311 375 439 503 567 631...*/
    intmin = (int)round(min);

    intmin -= (intmin % 64);
    intmin -= 9; /* the fixed length of the sha size block */
    intmin = max(intmin, 0);

    if(DBGHT_OPT)printf("leftargs n=%d a=%f b=%f h=%d f=%f b=%d b=%d\n", num_updates, ALPHA, BETA, HASHSIZE, filesize, intmin, BRANCHES);
    leftcost  = rawcost(num_updates, ALPHA, BETA, HASHSIZE, filesize, intmin, BRANCHES);

    if(DBGHT_OPT)printf("rightargs n=%d a=%f b=%f h=%d f=%f b=%d b=%d\n", num_updates, ALPHA, BETA, HASHSIZE, filesize, intmin + 64, BRANCHES);
    rightcost = rawcost(num_updates, ALPHA, BETA, HASHSIZE, filesize, intmin + 64, BRANCHES);

    if(DBGHT_OPT)printf("choosing between %d(%d) and %d(%d)\n",intmin,(int)leftcost, intmin+64,(int)rightcost);

#if 0
    if(leftcost > rightcost){
      intmin += 64;
      leftcost = rightcost;
    }
#else
    /* if rawcost was returning the right values it would always round up in the 64MB
     * case, as seen by running min_gamma on linux. */
    intmin += 64;
    leftcost = rightcost;
#endif

    filesizecost = GAMMA * filesize;
    if(leftcost > filesizecost){
      intmin = filesize;
    }
  }

  if(VERBOSEHT)printf("USING OPTIMAL OF %d %f %f\n", (int)round(min), ALPHA, BETA);

  return intmin;
}
