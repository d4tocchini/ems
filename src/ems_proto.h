/*-----------------------------------------------------------------------------+
 |  Extended Memory Semantics (EMS)                            Version 1.5.0   |
 |  Synthetic Semantics       http://www.synsem.com/       mogill@synsem.com   |
 +-----------------------------------------------------------------------------+
 |  Copyright (c) 2011-2014, Synthetic Semantics LLC.  All rights reserved.    |
 |  Copyright (c) 2015-2017, Jace A Mogill.  All rights reserved.              |
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
#include "ems_types.h"

// ---------------------------------------------------------------------------------
//  Non-exposed API functions
int64_t EMSwriteIndexMap(const int mmapID, EMSvalueType *key, int64_t * timer);
int64_t EMSkey2index(void *emsBuf, EMSvalueType *key, bool is_mapped);
int64_t EMShashString(const char *key);


// ---------------------------------------------------------------------------------
//  External API functions
int EMScriticalEnter(int mmapID, int timeout);
bool EMScriticalExit(int mmapID);
int EMSbarrier(int mmapID, int timeout);
bool EMSsingleTask(int mmapID);
bool EMScas(int mmapID, EMSvalueType *key,
            EMSvalueType *oldValue, EMSvalueType *newValue,
            EMSvalueType *returnValue);
bool EMSfaa(int mmapID, EMSvalueType *key, EMSvalueType *value, EMSvalueType *returnValue);
bool EMSloopInit(int mmapID, int32_t start, int32_t end, int32_t minChunk, int schedule_mode);
bool EMSloopChunk(int mmapID, int32_t *start, int32_t *end);

unsigned char EMStransitionFEtag(
    EMStag_t volatile *tag, EMStag_t volatile *mapTag,
    unsigned char oldFE, unsigned char newFE, unsigned char oldType,
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
bool EMSdestroy(int mmapID, bool do_unlink);
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
    int64_t nElements,     // 0
    size_t heapSize,      // 1
    const char *filename,  // 2
    int thread_id,        // 3
    int32_t nThreads,      // 4
    int32_t flags,          // 5
    EMSvalueType *fillValue// 6
);