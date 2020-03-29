/*-----------------------------------------------------------------------------+
 |  Extended Memory Semantics (EMS)                            Version 1.4.0   |
 |  Synthetic Semantics       http://www.synsem.com/       mogill@synsem.com   |
 +-----------------------------------------------------------------------------+
 |  Copyright (c) 2011-2014, Synthetic Semantics LLC.  All rights reserved.    |
 |  Copyright (c) 2015-2016, Jace A Mogill.  All rights reserved.              |
 |                                                                             |
 | Redistribution and use in source and binary forms, with or without          |
 | modification, are permitted provided that the following conditions are met: |
 |    * Redistributions of source code must retain the above copyright         |
 |      notice, this list of conditions and the following disclaimer.          |
 |    * Redistributions in binary form must reproduce the above copyright      |
 |      notice, this list of conditions and the following disclaimer in the    |
 |      documentation and/or other materials provided with the distribution.   |
 |    * Neither the name of the Synthetic Semantics nor the names of its       |
 |      contributors may be used to endorse or promote products derived        |
 |      from this software without specific prior written permission.          |
 |                                                                             |
 |    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS      |
 |    "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT        |
 |    LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR    |
 |    A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL SYNTHETIC         |
 |    SEMANTICS LLC BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,   |
 |    EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,      |
 |    PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR       |
 |    PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF   |
 |    LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING     |
 |    NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS       |
 |    SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.             |
 |                                                                             |
 +-----------------------------------------------------------------------------*/
#ifndef EMSPROJ_EMS_H
#define EMSPROJ_EMS_H
#define __STDC_FORMAT_MACROS 1
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <inttypes.h>
#include <sys/mman.h>
#include <math.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <stdbool.h>

#if !defined _GNU_SOURCE
#  define _GNU_SOURCE
#endif
#include <sched.h>

//==================================================================
// EMS init flags
//
#define EMS_USE_MAP             0b00000000100000000000000000000000
#define EMS_PERSIST             0b00000001000000000000000000000000
#define EMS_CLEAR               0b00000010000000000000000000000000
#define EMS_FILL                0b00000100000000000000000000000000
#define EMS_FILL_JSON           0b00001100000000000000000000000000
#define EMS_SET_E               0b00010000000000000000000000000000
#define EMS_SET_F               0b00110000000000000000000000000000
#define EMS_PIN_THREADS         0b01000000000000000000000000000000
#define EMS_MLOCK_PCT_MASK      0b00000000000000000000000001111111

//==================================================================
// EMS Full/Empty Tag States
//
#define EMS_TAG_ANY       ((unsigned char)4)  // Never stored, used for matching
#define EMS_TAG_RW_LOCK   ((unsigned char)3)
#define EMS_TAG_BUSY      ((unsigned char)2)
#define EMS_TAG_EMPTY     ((unsigned char)1)
#define EMS_TAG_FULL      ((unsigned char)0)


//==================================================================
// EMS Data types
//
#ifdef EMS_TYPE_0_INVALID
  #define EMS_TYPE_INVALID      ((unsigned char)0)
  #define EMS_TYPE_BOOLEAN      ((unsigned char)1)
  #define EMS_TYPE_STRING       ((unsigned char)2)
  #define EMS_TYPE_FLOAT        ((unsigned char)3)
  #define EMS_TYPE_INTEGER      ((unsigned char)4)
  #define EMS_TYPE_UNDEFINED    ((unsigned char)5)
  #define EMS_TYPE_JSON         ((unsigned char)6)  // Catch-all for JSON arrays and Objects
  #define EMS_TYPE_BUFFER       ((unsigned char)7)  // Catch-all for JSON arrays and Objects
#else
  #define EMS_TYPE_UNDEFINED    ((unsigned char)0)
  #define EMS_TYPE_INTEGER      ((unsigned char)1)
  #define EMS_TYPE_STRING       ((unsigned char)2)
  #define EMS_TYPE_BUFFER       ((unsigned char)3)
  #define EMS_TYPE_FLOAT        ((unsigned char)4)
  #define EMS_TYPE_BOOLEAN      ((unsigned char)5)
  #define EMS_TYPE_INVALID      ((unsigned char)6)   // TODO: remove
  #define EMS_TYPE_JSON         ((unsigned char)7)  // Catch-all for JSON arrays and Objects
#endif


//==================================================================
// Control Block layout stored at the head of each EMS array
//
//        Name          Offset      Description of contents
//---------------------------------------------------------------------------------------
#define NWORDS_PER_CACHELINE  16
#define EMS_ARR_NELEM         0
  // * 0 // Maximum number of elements in the EMS array
#define EMS_ARR_HEAPSZ        16
  // * 1 // # bytes of storage for array data: strings, JSON, maps, etc.
#define EMS_ARR_Q_BOTTOM      32
  // (2 * NWORDS_PER_CACHELINE) // Current index of the queue bottom
#define EMS_ARR_STACKTOP      48
  // (3 * NWORDS_PER_CACHELINE)   // Current index of the top of the stack/queue
#define EMS_ARR_MAPBOT        64
  // (4 * NWORDS_PER_CACHELINE)   // Index of the base of the index map
#define EMS_ARR_MALLOCBOT     80
  // (5 * NWORDS_PER_CACHELINE)   // Index of the base of the heap -- malloc structs start here
#define EMS_ARR_HEAPBOT       96
  // (6 * NWORDS_PER_CACHELINE)   // Index of the base of data on the heap -- strings start here
#define EMS_ARR_MEM_MUTEX     112
  // (7 * NWORDS_PER_CACHELINE)   // Mutex lock for thememory allocator of this EMS region's
#define EMS_ARR_FILESZ        128
  // (8 * NWORDS_PER_CACHELINE)   // Total size in bytes of the EMS region
  // Tag data may follow data by as much as 8 words, so
  // A gap of at least 8 words is required to leave space for
  // the tags associated with header data
#define EMS_ARR_CB_SIZE       256
  // (16 * NWORDS_PER_CACHELINE)   // Index of the first EMS array element



//==================================================================
// EMS Control Block -- Global State for EMS
#define EMS_CB_NTHREADS     0     // Number of threads
#define EMS_CB_NBAR0        1     // Number of threads at Barrier 0
#define EMS_CB_NBAR1        2     // Number of threads at Barrier 1
#define EMS_CB_BARPHASE     3     // Current Barrier Phase (0 or 1)
#define EMS_CB_CRITICAL     4     // Mutex for critical regions
#define EMS_CB_SINGLE       5     // Number of threads passed through an execute-once region
#define EMS_LOOP_IDX        6     // Index of next iteration in a Parallel loop to schedule
#define EMS_LOOP_START      7     // Index of first iteration in a parallel loop
#define EMS_LOOP_END        8     // Index of last iteration in a parallel loop
#define EMS_LOOP_CHUNKSZ    9     // Current Number of iterations per thread
#define EMS_LOOP_MINCHUNK  10     // Smallest number of iterations per thread
#define EMS_LOOP_SCHED     11     // Parallel loop scheduling method:
#define    EMS_SCHED_GUIDED  1200
#define    EMS_SCHED_DYNAMIC 1201
#define    EMS_SCHED_STATIC  1202
#define EMS_CB_LOCKS       12     // First index of an array of locks, one lock per thread



//==================================================================
//  Pointers to mmapped EMS buffers
#define EMS_MAX_N_BUFS 4096
#define MAX_NUMBER2STR_LEN 40   // Maximum number of characters in a %d or %f format
#define MAX_FNAME_LEN 256
extern char   *emsBufs[EMS_MAX_N_BUFS];
extern size_t  emsBufLengths[EMS_MAX_N_BUFS];
extern char    emsBufFilenames[EMS_MAX_N_BUFS][MAX_FNAME_LEN];

//  Maximum number of slots to check due to conflicts
#define  MAX_OPEN_HASH_STEPS 200


//==================================================================
//  Macros to translate from EMS Data Indexes and EMS Control Block
//  indexes to offsets in the EMS shared memory
#define EMSwordSize           8 //(sizeof(size_t))
#define EMSwordSize_pow2      3 //EMSwordSize
#define EMSnWordsPerTagWord   7 //(EMSwordSize-1)
#define EMSnWordsPerLine      8 //EMSwordSize
#define EMSnWordsPerLine_pow2 3 //EMSwordSize


//==================================================================
//  Layout of EMS memory
//     Tagged Memory
//         CB:     Control Block of array state
//         Data:   Scalar user data
//         Map:    Scalar index map data
//     Untagged Memory
//         Malloc: Storage for the free/used structures
//         Heap:   Open Heap storage
#define EMSappIdx2emsIdx(idx) \
  ( (((idx) / EMSnWordsPerTagWord) << EMSnWordsPerLine_pow2) \
    + ((idx) % EMSnWordsPerTagWord) )
#define EMSappIdx2LineIdx(idx) \
  ( ((idx) / EMSnWordsPerTagWord) << EMSnWordsPerLine_pow2)
#define EMSappIdx2TagWordIdx(idx) \
  ( EMSappIdx2LineIdx(idx) + EMSnWordsPerTagWord )
#define EMSappIdx2TagWordOffset(idx) \
  ( EMSappIdx2TagWordIdx(idx) << EMSwordSize_pow2 )
#define EMSappTag2emsTag(idx) \
  ( EMSappIdx2TagWordOffset(idx) + ((idx) % EMSnWordsPerTagWord) )
#define EMScbData(idx)        EMSappIdx2emsIdx(idx)
#define EMScbTag(idx)         EMSappTag2emsTag(idx)
#define EMSdataData(idx)    ( EMSappIdx2emsIdx((idx) + EMS_ARR_CB_SIZE) )
#define EMSdataTag(idx)     ( EMSappTag2emsTag((idx) + EMS_ARR_CB_SIZE) )
#define EMSdataTagWord(idx) ( EMSappIdx2TagWordOffset((idx) + EMS_ARR_CB_SIZE) )
#define EMSmapData(idx)     ( EMSappIdx2emsIdx((idx) + EMS_ARR_CB_SIZE + bufInt64[EMScbData(EMS_ARR_NELEM)]) )
#define EMSmapTag(idx)      ( EMSappTag2emsTag((idx) + EMS_ARR_CB_SIZE + bufInt64[EMScbData(EMS_ARR_NELEM)]) )
#define EMSheapPtr(idx)     ( &bufChar[ bufInt64[EMScbData(EMS_ARR_HEAPBOT)] + (idx) ] )




//==================================================================
//  Sleep/Timeout
//  Yield the processor and sleep (using exponential decay) without
//  using resources/
//  Used within spin-loops to reduce hot-spotting

#define TIME_ms_to_ns(x) ( ((x)<<10) - ((x)<<5) + ((x)<<3) )

#define MAX_NAP_TIME  524288L // .5 (sec) == 1 << 19 (ns)

#define RESET_NAP_TIME() \
  int64_t * ems_nano_timeout_p = NULL;\
  int EMScurrentNapTime = 16; // 1 // D4

#define NANO_SET_TIMEOUT(timeout)\
  int64_t * ems_nano_timeout_p = timeout;\
  int EMScurrentNapTime = 16; // 1 // D4

#define NANOSLEEP    {\
    struct timespec     sleep_time;\
    sleep_time.tv_sec  = 0;\
    sleep_time.tv_nsec = EMScurrentNapTime;\
    nanosleep(&sleep_time, NULL);\
    EMScurrentNapTime <<= 1;\
    if(EMScurrentNapTime > MAX_NAP_TIME) {\
        EMScurrentNapTime = MAX_NAP_TIME;\
    }\
 }

#define NANO_TIMEOUT_SLEEP_CATCH \
    if (ems_nano_timeout_p == NULL ||\
       (*ems_nano_timeout_p -= EMScurrentNapTime) > 0)\
    { NANOSLEEP }\
    else

#define NANO_DID_TIMEOUT(timer_p) \
    ((timer_p != NULL) && (*timer_p < 0))



//==================================================================
// EMS alloc
//
// The block size used by the memory allocator for allocating heap space.
// May be any positive non-zero value
#define         EMS_MEM_BLOCKSZ     64
#define         EMS_MEM_BLOCKSZ_P2  6

//  Buddy allocator control structure
struct emsMem
{
    int32_t         level;
    uint8_t         tree[1];
};

struct emsMem*  emsMem_new(int level);
void            emsMem_delete(struct emsMem *);
size_t          emsMem_alloc(struct emsMem *, size_t bytesRequested);
void            ems_free(struct emsMem *, size_t offset);
size_t          emsMem_size(struct emsMem *, size_t offset);
void            emsMem_dump(struct emsMem *);
size_t          emsNextPow2(int64_t x);
size_t          emsMutexMem_alloc(
                    struct emsMem *heap,  // Base of EMS malloc structs
                    size_t len,  // Number of bytes to allocate
                    volatile char *mutex); // Pointer to mem allocator's mutex
void            emsMutexMem_free(
                    struct emsMem *heap, // Base of EMS malloc structs
                    size_t addr, // Offset of alloc'd block in EMS memory
                    volatile char *mutex); // Pointer to mem allocator's mutex

#define         EMS_MEM_MALLOCBOT(bufChar) \
                    ((struct emsMem *) &bufChar[ bufInt64[ EMScbData(EMS_ARR_MALLOCBOT)] ])

#define         EMS_ALLOC(addr, len, bufChar, errmsg, retval) \
                    addr = emsMutexMem_alloc(\
                        EMS_MEM_MALLOCBOT(bufChar),\
                        len,\
                        (char*) &bufInt64[EMScbData(EMS_ARR_MEM_MUTEX)]);\
                    if (addr < 0)  {\
                        fprintf(stderr,\
                            "%s:%d (%s) ERROR: EMS memory allocation of len(%zx) failed: %s\n",\
                            __FILE__, __LINE__, __FUNCTION__, len, errmsg);\
                        return retval;\
                    }

#define         EMS_FREE(addr) \
                    emsMutexMem_free(\
                        EMS_MEM_MALLOCBOT(bufChar), \
                        addr,\
                        (char*) &bufInt64[EMScbData(EMS_ARR_MEM_MUTEX)] )









extern int EMSmyID;   // EMS Thread ID

#define EMSisMapped \
  ( (bufInt64[EMScbData(EMS_ARR_MAPBOT)] << EMSwordSize_pow2) \
  != bufInt64[EMScbData(EMS_ARR_MALLOCBOT)] )







// --------------------------------------------------------------------------------
//  EMS Types

// Bitfields of a Tag Byte
#define     EMS_TYPE_NBITS_FE    2
#define     EMS_TYPE_NBITS_TYPE  3
#define     EMS_TYPE_NBITS_RW    3
#define     EMS_RW_NREADERS_MAX  ((1 << EMS_TYPE_NBITS_RW) - 1)
typedef union 
{
            struct
            {
                unsigned char fe   : EMS_TYPE_NBITS_FE;
                unsigned char type : EMS_TYPE_NBITS_TYPE;
                unsigned char rw   : EMS_TYPE_NBITS_RW;
            }   tags;
            unsigned char byte;
}           EMStag_t;

#define     EMS_VALUE_TYPE_INITIALIZER \
                {\
                    .length = 0,\
                    .value = NULL,\
                    .type = EMS_TYPE_INVALID\
                }


// Type-punning is now a warning in GCC, but this syntax is still okay
typedef union
{
                double d;
                uint64_t u64;
}           EMSulong_double;


// Internal EMS representation of a JSON value
typedef struct
{
                size_t length;  // Defined only for JSON and strings
                void *value;
                unsigned char type;
}           EMSvalueType;

// --------------------------------------------------------------------------------
//  Non-exposed API functions
int64_t EMSwriteIndexMap(const int mmapID, EMSvalueType *key, int64_t * timer);
int64_t EMSkey2index(void *emsBuf, EMSvalueType *key, bool is_mapped);
int64_t EMShashString(const void *key, int32_t len);


// ---------------------------------------------------------------------------------
//  External API functions
int     EMScriticalEnter(int mmapID, int timeout);
bool    EMScriticalExit(int mmapID);
int     EMSbarrier(int mmapID, int timeout);
bool    EMSsingleTask(int mmapID);
bool    EMScas(int mmapID,
            EMSvalueType *key,
            EMSvalueType *oldValue, EMSvalueType *newValue,
            EMSvalueType *returnValue);
bool    EMSfaa(int mmapID,
            EMSvalueType *key,
            EMSvalueType *value,
            EMSvalueType *returnValue);
bool    EMSloopInit(int mmapID,
            int32_t start,
            int32_t end,
            int32_t minChunk,
            int schedule_mode);
bool    EMSloopChunk(int mmapID,
            int32_t *start,
            int32_t *end);
unsigned char EMStransitionFEtag(
            EMStag_t volatile *tag,
            EMStag_t volatile *mapTag,
            unsigned char oldFE,
            unsigned char newFE,
            unsigned char oldType,
            int64_t* timer);

int EMSpush(int mmapID, EMSvalueType *value, int64_t* timer);
int EMSpop(int mmapID, EMSvalueType *returnValue, int64_t* timer);
int EMSenqueue(int mmapID, EMSvalueType *value, int64_t* timer);
int EMSdequeue(int mmapID, EMSvalueType *returnValue, int64_t* timer);
bool EMSreadRW(const int mmapID, EMSvalueType *key, EMSvalueType *returnValue);
bool EMSreadFF(const int mmapID, EMSvalueType *key, EMSvalueType *returnValue);
bool EMSreadFE(const int mmapID, EMSvalueType *key, EMSvalueType *returnValue);
bool EMSread(const int mmapID, EMSvalueType *key, EMSvalueType *returnValue);
int EMSreleaseRW(const int mmapID, EMSvalueType *key);
bool EMSwriteXF(int mmapID, EMSvalueType *key, EMSvalueType *value);
bool EMSwriteXE(int mmapID, EMSvalueType *key, EMSvalueType *value);
bool EMSwriteEF(int mmapID, EMSvalueType *key, EMSvalueType *value);
bool EMSwrite(int mmapID, EMSvalueType *key, EMSvalueType *value);
bool EMSsetTag(int mmapID, EMSvalueType *key, bool is_full);
bool ems_destroy(int mmapID, bool do_unlink);
bool EMSindex2key(int mmapID, int64_t idx, EMSvalueType *key);
bool EMSsync(int mmapID);
int EMSinitialize(int64_t nElements,     // 0
                  size_t heapSize,        // 1
                  bool useMap,            // 2
                  const char *filename,   // 3
                  bool persist,           // 4
                  bool useExisting,       // 5
                  bool doDataFill,        // 6
                  bool fillIsJSON,        // 7
                  EMSvalueType *fillValue, // 8
                  bool doSetFEtags,       // 9
                  bool setFEtagsFull,     // 10
                  int EMSmyID,            // 11
                  bool pinThreads,        // 12
                  int32_t nThreads,       // 13
                  int32_t pctMLock );     // 14

int ems_open(const char *filename);
int ems_create(
    int64_t nElements,    
    size_t heapSize,
    const char *filename,
    int32_t flags
);

#endif //EMSPROJ_EMS_H
