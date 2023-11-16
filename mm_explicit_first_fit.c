#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>

#include "mm.h"
#include "memlib.h"

/*********************************************************
 * NOTE TO STUDENTS: Before you do anything else, please
 * provide your team information in the following struct.
 ********************************************************/
team_t team = {
    /* Team name */
    "malloc_implicit_first_fit",
    /* First member's full name */
    "DG",
    /* First member's email address */
    "iuboost8@gmail.com",
    /* Second member's full name (leave blank if none) */
    "",
    /* Second member's email address (leave blank if none) */
    ""
};

// Basic constants and macors
#define WSIZE       4           // Word and header/footer size(bytes)
#define DSIZE       8           // Double word size (btyes)
#define CHUNKSIZE   (1 << 12)   // Extend heap by this amount (bytes)

#define MAX(x, y)   ((x) > (y) ? (x) : (y)) 

#define PACK(size, alloc)   ((size) | (alloc)) // Write size & allocated informaiton

// Read and wirte a word at address
#define GET(p)  (*(unsigned int *)(p))
#define PUT(p, val)  (*(unsigned int *)(p) = (val))

// Read the size and allocated field from address p
#define GET_SIZE(p)    (GET(p) & ~0x7) 
#define GET_ALLOC(p)   (GET(p) & 0x1) 

#define HDRP(bp)    ((char *)(bp) - WSIZE)
#define FTRP(bp)    ((char *)(bp) + GET_SIZE(HDRP(bp)) - DSIZE)

/*
*     [H][DATA][F] ¦ [H][DATA][F] ¦ [H][DATA][F]
*        ↑bp            ↑bp            ↑bp
*    [    size    ][    size     ][    size    ]
*/

#define NEXT_BLKP(bp)   (((char *)(bp) + GET_SIZE((char *)(bp) - WSIZE))) 
#define PREV_BLKP(bp)   (((char *)(bp) - GET_SIZE((char *)(bp) - DSIZE)))    

static void *heap_listp;
static void *extend_heap(size_t words);
static void *coalesce(void *bp);
static void *find_fit(size_t a_size);
static void place(void *bp, size_t a_size);

/* 
 * mm_init - initialize the malloc package.
 */
int mm_init(void)
{
    if ((heap_listp = mem_sbrk(4*WSIZE)) == (void *)-1)
        return -1;


    //  heap_listp - [ ][P.H][P.F][E.H]  // 4byte * 4

    PUT(heap_listp, 0);                             // Alignment padding
    PUT(heap_listp + (1*WSIZE), PACK(DSIZE, 1));    // Prologue header
    PUT(heap_listp + (2*WSIZE), PACK(DSIZE, 1));    // Prologue footer
    PUT(heap_listp + (3*WSIZE), PACK(0, 1));        // Epilogue header
    heap_listp += (2*WSIZE);

    // Extend the empty heap with a free block of CHUNKSIZE bytes
    if (extend_heap(CHUNKSIZE/WSIZE) == NULL)
        return -1;
        
    return 0;
}

/*
 * extend_heap - extend the heap space, if you need.
 */
static void *extend_heap(size_t words) 
{
    char *bp;
    size_t size;

    // Allocate an even number of words  to maintain alignment
    size = (words % 2) ? (words+1) * WSIZE : words * WSIZE; 
    if ((long)(bp = mem_sbrk(size)) == -1) 
        return NULL;

    // initialize free block header/footer and the epilogue header

    /*
     *     [H][DATA][F] ¦ [H][DATA][F] ¦ [H][DATA][F]
     *        ↑bp            ↑bp            ↑bp
     *    [    size    ][    size     ][    size    ]
     */

    PUT(HDRP(bp), PACK(size, 0)); // Set free block
    PUT(FTRP(bp), PACK(size, 0)); // Set free block
    PUT(HDRP(NEXT_BLKP(bp)), PACK(0, 1));

    // coalesce if the previous block was free
    return coalesce(bp);   
}

static void *coalesce(void *bp) 
{
    size_t prev_alloc = GET_ALLOC(FTRP(PREV_BLKP(bp))); // Get the allocate infomation of prev_block.
    size_t next_alloc = GET_ALLOC(HDRP(NEXT_BLKP(bp))); // Get the allocate infomation of next_block.
    size_t size = GET_SIZE(HDRP(bp));

    if (prev_alloc && next_alloc)   // Case 1 - [prev_block(allocated)] ¦ [current] ¦ [next_block(allocated)]
        return bp;
    else if (prev_alloc && !next_alloc)  // Case 2 - [prev_block(allocated)] ¦ [current] ¦ [next_block(free)]
	{
        size += GET_SIZE(HDRP(NEXT_BLKP(bp)));
        remove_free_block(NEXT_BLKP(bp));
        PUT(HDRP(bp), PACK(size, 0));
        PUT(FTRP(bp), PACK(size, 0)); 
    }
    else if (!prev_alloc && next_alloc)	 // Case 3 - [prev_block(free)] ¦ [current] ¦  [next_block(allocated)]
	{
        size += GET_SIZE(HDRP(PREV_BLKP(bp)));
        bp = PREV_BLKP(bp);
        remove_free_block(bp);
        PUT(HDRP(bp), PACK(size, 0));
        PUT(FTRP(bp), PACK(size, 0));
    }
    else  // Case 4 - [prev_block(free)] ¦ [current] ¦ [next_block(free)]
	{
         size += GET_SIZE(HDRP(PREV_BLKP(bp))) + GET_SIZE(HDRP(NEXT_BLKP(bp)));
        remove_free_block(PREV_BLKP(bp));
        remove_free_block(NEXT_BLKP(bp));
        bp = PREV_BLKP(bp);
        PUT(HDRP(bp), PACK(size, 0));
        PUT(FTRP(bp), PACK(size, 0));
    }
    return bp;
} 

/* 
 * mm_malloc - Allocate a block by incrementing the brk pointer.
 *     Always allocate a block whose size is a multiple of the alignment.
 */
void *mm_malloc(size_t size) 
{
    size_t a_size;       // adjusted block szie
    size_t extend_size;  // Amount to extend heap if no fit
    char *bp;

    // Ignore spurious requests
    if (size == 0)
        return NULL;

    // Adjust block size to include overhead and alignment reqs
    if (size <= DSIZE) 
        a_size = 2*DSIZE;
    else 
        a_size = DSIZE * ((size + DSIZE + (DSIZE-1)) / DSIZE);

    // Search the free list for a fit
    if ((bp = find_fit(a_size)) != NULL) 
	{
        place(bp, a_size);  
        return bp;
    }

    // NO fit found. Get more memory and place the block
    // extend heap size
    extend_size = MAX(a_size, CHUNKSIZE);
    if ((bp = extend_heap(extend_size/WSIZE)) == NULL)
        return NULL;

    place(bp, a_size);
    return bp;
}

static void *find_fit(size_t a_size)
{
    void *bp;

    for (bp = free_listp; GET_ALLOC(HDRP(bp)) == 0; bp = NEXT_FRBLKP(bp))
    {
        if (a_size <= GET_SIZE(HDRP(bp)))
            return bp;
    }
    return NULL; // NO fit
}

static void place(void *bp, size_t a_size) 
{
    size_t c_size = GET_SIZE(HDRP(bp));

    if ((c_size - a_size) >= (2*DSIZE)) 
	{
        PUT(HDRP(bp), PACK(a_size, 1));
        PUT(FTRP(bp), PACK(a_size, 1));
        remove_free_block(bp);
        
        c_sieze -= a_size;
        bp = NEXT_BLKP(bp);
        PUT(HDRP(bp), PACK(c_size, 0));
        PUT(FTRP(bp), PACK(c_size, 0));
        coalesce(bp);
    }
    else 
	{
        PUT(HDRP(bp), PACK(c_size, 1));
        PUT(FTRP(bp), PACK(c_size, 1));
        remove_free_block(bp);
    }
}

/*
 * mm_free - Freeing a block does nothing.
 */
void mm_free(void *bp)
{
    size_t size = GET_SIZE(HDRP(bp));

    PUT(HDRP(bp), PACK(size, 0));
    PUT(FTRP(bp), PACK(size, 0));
    coalesce(bp);
}

void *mm_realloc(void *bp, size_t size) // size is pure Data size.
{
    size_t old_size = GET_SIZE(HDRP(bp));
    size_t new_size = size + (DSIZE); // size + Header + Footer.

    if (new_size <= old_size)
        return bp;
    else 
	{
        size_t next_alloc = GET_ALLOC(HDRP(NEXT_BLKP(bp)));
        size_t current_size = old_size + GET_SIZE(HDRP(NEXT_BLKP(bp)));

        if (!next_alloc && (current_size >= new_size)) 
		{
            PUT(HDRP(bp), PACK(current_size, 1));
            PUT(FTRP(bp), PACK(current_size, 1));
            return bp;
        }
        else 
		{
            void *new_bp = mm_malloc(new_size);
            place(new_bp, new_size);
            memcpy(new_bp, bp, new_size);  
            mm_free(bp);
            return new_bp;
        }
    }
}

static void remove_free_block(void *bp)
{
	if(PREV_FRBLKP(bp))
        NEXT_FRBLKP(PREV_FRBLKP(bp)) = NEXT_FRBLKP(bp);
    else
        free_listp = NEXT_FRBLKP(bp);
    PREV_FRBLKP(NEXT_FRBLKP(bp)) = PREV_FRBLKP(bp);
}
