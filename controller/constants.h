#ifndef CONSTANTS_H
#define CONSTANTS_H

#include <stdbool.h>
#include "xil_printf.h"
#include "hmac.h"



// crypto
#define PKEY_SIZE 64 //see: hmac keygen
#define UNAME_SIZE 16 //see: ectf requirements
#define SALT_SIZE 16 //see: common sense
#define PIN_SIZE 64 //see: ectf requirement

#define HASH_SIZE 64
#define CIPHER_BLOCKSIZE 64 
#define ARGON2_THREADS 1
#define ARGON2_LANES 1
#define HMAC_SIG_SIZE 64

// definition of sizes
#define SONGID_LEN 16
#define TOTAL_USERS 64
#define MAX_SHARED_USERS 64 
#define MAX_SHARED_REGIONS 32
#define REGION_NAME_SZ 64
#define MAX_QUERY_REGIONS MAX_SHARED_REGIONS /*TOTAL_REGIONS*/
#define INVALID_UID -1
#define INVALID_RID -1

// song stuffs
#define MAX_SONG_SZ (1<<25) //33554432 == 32 mib
#define SEGMENT_BUF_SIZE 32000 //32000 + 128 KB
#define CHUNK_SZ 16000
#define SONGLEN_30S (mb_state.current_song_header.len_250ms * 4 * 30)
#define SONGLEN_5S (mb_state.current_song_header.len_250ms * 4 * 5)

#define PCM_DRV_BUFFER_SIZE 16000  // 0x3e80
#define FIFO_CAP 4096*4

/*
checks to see if the shared user entry at <idx_> is in use.
*/
#define CURRENT_DRM_SHARED_EMPTY_SLOT(idx_) (mb_state.current_song_header.shared_users[idx_][0] == '\0')
#define SONG_OWNER 1 //the song is owned by the current user
#define SONG_SHARED 2 //the song is shared with the current user
#define SONG_BADREGION -1 //the region is not allowed to play the song (a 30s preview should be done instead)
#define SONG_BADUSER -2 //the user is not allowed to play the song (a 30s preview should be done instead)
#define SONG_BADSIG 0 //the song fails signature validation and should not be played.


// ADC/DAC sampling rate in Hz
#define AUDIO_SAMPLING_RATE 48000
#define BYTES_PER_SAMP 2
#define PREVIEW_SZ (PREVIEW_TIME_SEC * AUDIO_SAMPLING_RATE * BYTES_PER_SAMP)

// printing utility
#define MB_PROMPT "\r\nMB> "
#define mb_printf(...) xil_printf(MB_PROMPT __VA_ARGS__)
#define mb_printf_none() xil_printf(MB_PROMPT)
#define MB_PROMPT_DEBUG "\r\nMB_DEBUG> "
#define mb_debug(...) xil_printf(MB_PROMPT_DEBUG __VA_ARGS__)

// simulate array of 64B names without pointer indirection
#define q_region_lookup(q, i) (q.regions + (i * REGION_NAME_SZ))
#define q_user_lookup(q, i) (q.users_list + (i * UNAME_SIZE))
#define q_song_region_lookup(q,i) (q.song_regions + (i * REGION_NAME_SZ))
#define q_song_user_lookup(q, i) (q.shared_users[UNAME_SIZE][i])

#define PCM_SUBCH1_SIZE 16 //subchunk1_size for PCM audio
#define AUDIO_FMT_PCM 1 //audio_fmts


#ifndef offsetof
#define offsetof(st, m) ((size_t)&(((st *)0)->m))
#endif
#ifndef min
#define min(a,b) (((a)<(b))?(a):(b))
#endif // !min
#ifndef max
#define max(a,b) (((a)>(b))?(a):(b))
#endif // !max


#ifdef __GNUC__ //using inline asm ensures that the memset calls won't be optimized away.
#define clear_buffer(buf_) do{ memset((buf_), 0, sizeof(buf_)); __asm__ volatile ("" ::: "memory"); }while(0)
#define clear_obj(obj_) do{ memset(&(obj_), 0, sizeof(obj_)); __asm__ volatile ("" ::: "memory"); }while(0)
#else
#define clear_buffer(buf_) memset(buf_, 0, sizeof(buf_))
#define clear_obj(obj_) memset(&(obj_), 0, sizeof(obj_))
#endif

#define swap_bytes(a, b) {\
	uint8_t tmp; \
	tmp = *((uint8_t *)a); \
	*((uint8_t *)a) = *((uint8_t *)b); \
	*((uint8_t *)b) = tmp; \
}

// used for AES decryption
#define Transpose(block) {\
        swap_bytes(block + 1, block + 4); \
        swap_bytes(block + 2, block + 8); \
        swap_bytes(block + 3, block + 12); \
        swap_bytes(block + 6, block + 9); \
        swap_bytes(block + 7, block + 13); \
        swap_bytes(block + 11, block + 14); \
}

#endif // !CONSTANTS_H
