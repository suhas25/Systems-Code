* 
 * Simple, 32-bit and 64-bit clean allocator based on an implicit free list,
 * first fit placement, and boundary tag coalescing, as described in the
 * CS:APP3e text.  Blocks are aligned to double-word boundaries.  This
 * yields 8-byte aligned blocks on a 32-bit processor, and 16-byte aligned
 * blocks on a 64-bit processor.  However, 16-byte alignment is stricter
 * than necessary; the assignment only requires 8-byte alignment.  The
 * minimum block size is four words.
 *
 * This allocator uses the size of a pointer, e.g., sizeof(void *), to
 * define the size of a word.  This allocator also uses the standard
 * type uintptr_t to define unsigned integers that are the same size
 * as a pointer, i.e., sizeof(uintptr_t) == sizeof(void *).
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "memlib.h"
#include "mm.h"

/*********************************************************
 * NOTE TO STUDENTS: Before you do anything else, please
 * provide your team information in the following struct.
 ********************************************************/
team_t team = {
	/* Team name */
	" Kozaky ",
	/* First member's full name */
	" Yuliia Suprun ",
	/* First member's NetID */
	" ys70 ",
	/* Second member's full name (leave blank if none) */
	" Davyd Fridman ",
	/* Second member's NetID (leave blank if none) */
	" df21 "
};

/* Basic constants and macros: */
#define WSIZE      sizeof(void *) /* Word and header/footer size (bytes) */
#define DSIZE      (2 * WSIZE)    /* Doubleword size (bytes) */
#define CHUNKSIZE  (1 << 6)      /* Extend heap by this amount (bytes) */
#define ASIZE 	    8
#define MAX(x, y)  ((x) > (y) ? (x) : (y))  
#define NUM_LISTS  14

/* Pack a size and allocated bit into a word. */
#define PACK(size, alloc)  ((size) | (alloc))

/* Read and write a word at address p. */
#define GET(p)       (*(uintptr_t *)(p))
#define PUT(p, val)  (*(uintptr_t *)(p) = (val))

/* Read the size and allocated fields from address p. */
#define GET_SIZE(p)   (GET(p) & ~(ASIZE - 1))
#define GET_ALLOC(p)  (GET(p) & 0x1)

/* Given block ptr bp, compute address of its header and footer. */
#define HDRP(bp)  ((char *)(bp) - WSIZE)
#define FTRP(bp)  ((char *)(bp) + GET_SIZE(HDRP(bp)) - DSIZE)

/* Given block ptr bp, compute address of next and previous blocks. */
#define NEXT_BLKP(bp)  ((char *)(bp) + GET_SIZE(((char *)(bp) - WSIZE)))
#define PREV_BLKP(bp)  ((char *)(bp) - GET_SIZE(((char *)(bp) - DSIZE)))

/* Global variables: */
static char *heap_listp; 		/* Pointer to first block */  
static struct free_list *array_of_heads; /* Pointer to the beginning of the
array of dummy headers. */
static bool first_realloc = true;	/* Boolean is set to true, meaning that
no realloc() calls were made. */


/* Function prototypes for internal helper routines: */
static void *coalesce(void *bp);
static void *extend_heap(size_t words);
static void *find_fit(size_t asize);
static void place(void *bp, size_t asize);
static int create_arr_headers();
static void add_free_block(void *block_ptr);
static void insert_free_list(struct free_list *new_block, struct free_list *target);
static void remove_block(struct free_list *block);
static int get_index(int n);
static int log2n(int n); 
static int ceil_log2n(int n);
static int ceil_pow2(int n);

/* Function prototypes for heap consistency checker routines: */
static void checkblock(void *bp);
static void checkheap(bool verbose);
static void printblock(void *bp); 

/* Structure that encapsulates the pointers to the next and previous elements
of the given block in the explicit free list. */
struct free_list {
	struct free_list *next;
	struct free_list *prev;
};

/* 
 * Requires:
 *   None.
 *
 * Effects:
 *   Initialize the memory manager.  Returns 0 if the memory manager was
 *   successfully initialized and -1 otherwise.
 */
int
mm_init(void) 
{    
	// Create array for holding the dummy headers.
	if (create_arr_headers())
		return (-1);
	/* Create the initial empty heap. */
	if ((heap_listp = mem_sbrk(3 * WSIZE)) == (void *)-1)
		return (-1);

	PUT(heap_listp + (0 * WSIZE), PACK(DSIZE, 1)); /* Prologue header */
	PUT(heap_listp + (1 * WSIZE), PACK(DSIZE, 1)); /* Prologue footer */ 
	PUT(heap_listp + (2 * WSIZE), PACK(0, 1));     /* Epilogue header */
	heap_listp += (1 * WSIZE);
	/* Make the space for allocation of small blocks in the beginning of
	the heap. Set this extra space to 288 bytes. */
	void* free_block = extend_heap(2 * (144 / WSIZE));
	if (free_block == NULL)
		return (-1);
	/* Set the boolean value to true, meaning that the realloc function (if
	called) would be called for the first time. */
	first_realloc = true;

	/* Add the newly created free block to the explicit free list. */
	add_free_block(free_block);
	
	//checkheap(false);

	return (0);
}

/*
 * Requires:
 *   "bp" - pointer to the free block to add to an explicit free list.
 *  
 * Effects:
 *   Adds a block pointed at by "bp" to and explicit free list.
 */
static void
add_free_block(void *block_ptr) {
	
	// Get the size of the block.
	size_t size = GET_SIZE(HDRP(block_ptr));
	// An allocation bit LSB is already set to 0.
	// Find the appropriate header.
	int index = get_index(size);
	struct free_list *new_block = (struct free_list *)(block_ptr);

	// Insert the new block to the free list of the appropriate size range.
	// We use the LIFO principle within each free list.
	insert_free_list(new_block, &array_of_heads[index]);
}

/*
 * Requires:
 *  Nothing.
 *
 * Effects:
 *  Inserts new_block into a circular doubly linked list after target.
 */
static void
insert_free_list(struct free_list *new_block, struct free_list *target)
{
	new_block->prev = target;
	new_block->next = target->next;
	target->next->prev = new_block;
	target->next = new_block;
}

/*
 * Requires:
 *  Nothing.
 *
 * Effects:
 *  Removes free_block from a circular doubly linked list.
 *  The fields next and prev of free_block are set to NULL before return.
 */
static void
remove_block(struct free_list *block)
{
	block->prev->next = block->next;
	block->next->prev = block->prev;
	block->next = NULL;
	block->prev = NULL;
}

/*
 * Requires: 
 *   None.
 *
 * Effects:
 *   Return the pointer to the beginning of the array of dummy headers.
 */
static int
create_arr_headers()
{
	// Create an array of NUM_LISTS = 14 explicit free lists.
	// NUM_LISTS is a number of words needed to store NUM_LISTS pointers.
	if ((heap_listp = mem_sbrk(NUM_LISTS * sizeof(struct free_list))) == (void *)-1)
		return (-1);
	
	array_of_heads = (struct free_list*)heap_listp;
	// Set each dummy head's prev and next fields to its own address.
	for(int i = 0; i < NUM_LISTS; i++) {	
		array_of_heads[i].next = &array_of_heads[i];
		array_of_heads[i].prev = &array_of_heads[i];
	}
	return (0);
}

/* 
 * Requires:
 *   None.
 *
 * Effects:
 *   Allocate a block with at least "size" bytes of payload, unless "size" is
 *   zero.  Returns the address of this block if the allocation was successful
 *   and NULL otherwise.
 */
void *
mm_malloc(size_t size) 
{
	size_t asize;      /* Adjusted block size */
 	size_t extendsize; /* Amount to extend heap if no fit */
	void *bp;	   /* Pointer to the allocated memory block. */

	/* Ignore spurious requests. */
	if (size == 0)
  		return (NULL);

  	/* Adjust block size to include overhead and alignment reqs. 
	  The minimum size of the payload is 2*ASIZE since we need to store the
	  pointers to prev and next in each free block, which requires 2*ASIZE
	  bytes.*/
  	if (size <= 2 * ASIZE)
  		asize = 2 * ASIZE + DSIZE;
	else if (size <= 3 * ASIZE)
		asize = 3 * ASIZE + DSIZE;
	else if (size <= 2800) // Threshold found by the trial-and-error method.
		/*  Take the minimum power of 2 that exceeds or is equal to
		"size", and add DSIZE. */
		asize = ceil_pow2(size) + DSIZE;
	else 
		/*  Take the ceiling of size if divided by 8, and add DSIZE. */
		asize = DSIZE + ASIZE * ((size + (ASIZE - 1)) / ASIZE);
  	/* Search the free list for a fit. */
  	if ((bp = find_fit(asize)) != NULL) {
    		place(bp, asize);
		//checkheap(false);
		return (bp);
  	}

  	/* No fit found.  Get more memory and place the block. */
  	extendsize = MAX(asize, CHUNKSIZE);
  	if ((bp = extend_heap(extendsize / WSIZE)) == NULL)  
    		return (NULL);
	place(bp, asize);
	//checkheap(false);
  	return (bp);
}


/* 
 * Requires:
 *   "bp" is either the address of an allocated block or NULL.
 *
 * Effects:
 *   Free a block.
 */
void
mm_free(void *bp)
{
	size_t size;

	/* Ignore spurious requests. */
	if (bp == NULL)
		return;

	/* Free and coalesce the block. */
	size = GET_SIZE(HDRP(bp));
	PUT(HDRP(bp), PACK(size, 0));
	PUT(FTRP(bp), PACK(size, 0));
	// Get the pointer to the newly coalesced free block.
	bp = coalesce(bp); 
	// Add the freed and coalesced block to the free lists array.
	add_free_block(bp);
	
	//checkheap(false);
}

/*
 * Requires:
 *   "ptr" is either the address of an allocated block or NULL.
 *
 * Effects:
 *   Reallocates the block "ptr" to a block with at least "size" bytes of
 *   payload, unless "size" is zero.  If "size" is zero, frees the block
 *   "ptr" and returns NULL.  If the block "ptr" is already a block with at
 *   least "size" bytes of payload, then "ptr" may optionally be returned.
 *   Otherwise, a new block is allocated and the contents of the old block
 *   "ptr" are copied to that new block.  Returns the address of this new
 *   block if the allocation was successful and NULL otherwise.
 */
void *
mm_realloc(void *ptr, size_t size)
{
        size_t oldsize;
        void *newptr;

        /* If size == 0 then this is just free, and we return NULL. */
        if (size == 0) {
                mm_free(ptr);
                return (NULL);
        }

        /* If oldptr is NULL, then this is just malloc. */
        if (ptr == NULL)
                return (mm_malloc(size));

        /* Adjust the new size. It has to be 8-byte aligned, and it has to
	   contain enough space for header and footer. */
        if (size <= 2 * ASIZE)
                size = 2 * ASIZE + DSIZE;
        else 
                size = DSIZE + ASIZE * ((size + (ASIZE - 1)) / ASIZE);
        // Get the old size.
        oldsize = GET_SIZE(HDRP(ptr));

        if (size <= oldsize) {
                // Current block can fit a new size. 
		PUT(HDRP(ptr), PACK(oldsize, 0));
                PUT(FTRP(ptr), PACK(oldsize, 0));
		place(ptr, size);
                return ptr;
        } else {
                // Current block can't fit a new size.
                // Find the size of the next block.
                size_t next_size = GET_SIZE(HDRP(NEXT_BLKP(ptr)));

                /* Case 1: the next block is allocated and non-empty
		(it's not an epilogue). */
                if (GET_ALLOC(HDRP(NEXT_BLKP(ptr))) && next_size != 0) {
                        // Copy the old data to a new location.
                        // Allocate enough memory for new payload size.
                        newptr = mm_malloc(size);
                        if (newptr == NULL)
                                return (NULL);
                        // Copy the old data.
                        memcpy(newptr, ptr, oldsize);
                        // Free the old block.
                        mm_free(ptr);
			//checkheap(false);
                        return (newptr);
                } else {
                        /* Case 2: the next block is an epilogue or a little
			free block. */
                        if (next_size < (size - oldsize)) {
                                /* extend_heap coalesces the "old" next and
				   newly created free blocks if needed. */
                                newptr = extend_heap((size - oldsize - next_size) / WSIZE);
                                if (newptr == NULL)
                                        return (NULL);
                                PUT(HDRP(ptr), PACK(size, 0));
                                PUT(FTRP(ptr), PACK(size, 0));
                        
                        // Case 3: the next block is free of a sufficient size.
                        } else {
                                remove_block((struct free_list *)NEXT_BLKP(ptr));
                                /* Put the new size to the current block's
				header and the next block's footer. */
                                PUT(HDRP(ptr), PACK(oldsize + next_size, 0));
                                PUT(FTRP(ptr), PACK(oldsize + next_size, 0));
                        }
			// No need to copy the data.
                        // Place the new size into this new merged block.
                        place(ptr, size);
			// checkheap(false);
                        return ptr;
                }
        }
}

/*
 * The following routines are internal helper routines.
 */

/*
 * Requires:
 *   "bp" is the address of a newly freed block.
 *
 * Effects:
 *   Perform boundary tag coalescing.  Returns the address of the coalesced
 *   block.
 */
static void *
coalesce(void *bp) 
{
	if (first_realloc) {
		// Return right away and do not coalesce (for realloc).
		first_realloc = false;
		return bp;
	}
	size_t size = GET_SIZE(HDRP(bp));
	bool prev_alloc = GET_ALLOC(FTRP(PREV_BLKP(bp)));
	bool next_alloc = GET_ALLOC(HDRP(NEXT_BLKP(bp)));
	// Have to delete the neighboring blocks from free list.
	if (!prev_alloc) {
		remove_block((struct free_list *)(PREV_BLKP(bp)));
	}
	if (!next_alloc) {
		remove_block((struct free_list *)(NEXT_BLKP(bp)));
	}

	if (prev_alloc && next_alloc) {
		return (bp); 				/* Case 1 */
	} else if (prev_alloc && !next_alloc) {         /* Case 2 */
		size += GET_SIZE(HDRP(NEXT_BLKP(bp)));
		PUT(HDRP(bp), PACK(size, 0));
		PUT(FTRP(bp), PACK(size, 0));
	} else if (!prev_alloc && next_alloc) {         /* Case 3 */
		size += GET_SIZE(HDRP(PREV_BLKP(bp)));
		PUT(FTRP(bp), PACK(size, 0));
		PUT(HDRP(PREV_BLKP(bp)), PACK(size, 0));
		bp = PREV_BLKP(bp);
	} else {                                        /* Case 4 */
		size += GET_SIZE(HDRP(PREV_BLKP(bp))) + 
		    GET_SIZE(FTRP(NEXT_BLKP(bp)));
		PUT(HDRP(PREV_BLKP(bp)), PACK(size, 0));
		PUT(FTRP(NEXT_BLKP(bp)), PACK(size, 0));
		bp = PREV_BLKP(bp);
	}
	return (bp);
}

/* 
 * Requires:
 *   None.
 *
 * Effects:
 *   Extend the heap with a free block and return that block's address.
 */
static void *
extend_heap(size_t words) 
{
	size_t size;
	void *bp;
	
	/* Find the size of the block to be allocated. */
	size = words * WSIZE;
	if ((bp = mem_sbrk(size)) == (void *)-1)  
		return (NULL); 

	/* Initialize the free block's header and footer.
	   Initialize the epilogue header. */
	PUT(HDRP(bp), PACK(size, 0));         /* Free block header */
	PUT(FTRP(bp), PACK(size, 0));         /* Free block footer */
	PUT(HDRP(NEXT_BLKP(bp)), PACK(0, 1)); /* New epilogue header */

	/* Coalesce if the previous block was free. */
	return (coalesce(bp));
}

/*
 * Requires:
 *   None.
 *
 * Effects:
 *   Find a fit for a block with "asize" bytes.  Returns that block's address
 *   or NULL if no suitable block was found. 
 */
static void *
find_fit(size_t asize)
{
	/* Find the index of the appropriate range. */
	int index = get_index(asize);
	struct free_list* header;
	/* Search for the first fit. */
	while (index <  NUM_LISTS) {
		// Find the dummy header of the appropriate list.
		header = &array_of_heads[index];
		// Find the first non-dummy block in this list.
		struct free_list *block = header->next;

		while (block != header) {
			// Check if the size is sufficient.
			if (GET_SIZE(HDRP(block)) >= asize) {
				// Remove the block from the free list.
				remove_block(block);
				return block;
			}
			block = block->next;
		}
		// No appropriate block was found in the given range.
		index++;
	}
	return (NULL);
}

/* 
 * Requires:
 *   "bp" is the address of a free block that is at least "asize" bytes.
 *
 * Effects:
 *   Place a block of "asize" bytes at the start of the free block "bp" and
 *   split that block if the remainder would be at least the minimum block
 *   size. 
 */
static void
place(void *bp, size_t asize)
{
	// We already removed block bp from the explicit free list.
	// Get size of the given block.
	size_t csize = GET_SIZE(HDRP(bp));   
	// If the difference is sufficient to create a new free block.
	if ((csize - asize) >= ((2 * ASIZE) + DSIZE)) { 
		// Allocate the block of the provided size.
		PUT(HDRP(bp), PACK(asize, 1));
		PUT(FTRP(bp), PACK(asize, 1));
		bp = NEXT_BLKP(bp);
		// Free the remaining part of the block.
		PUT(HDRP(bp), PACK(csize - asize, 0));
		PUT(FTRP(bp), PACK(csize - asize, 0));
		// Insert the remaining free part of block to the free list.
		add_free_block(bp);
	} else {
		// We can't extract the "independent" valid block.
		// Allocate the whole given block.
		PUT(HDRP(bp), PACK(csize, 1));
		PUT(FTRP(bp), PACK(csize, 1));
	}
}

/* 
 * The remaining routines are heap consistency checker routines. 
 */

/*
 * Requires:
 *   "bp" is the address of a block. 
 *
 * Effects:
 *   Perform a minimal check on the block "bp".
 */
static void
checkblock(void *bp) 
{

	if ((uintptr_t)bp % ASIZE)
		printf("Error: %p is not doubleword aligned\n", bp);
	if (GET(HDRP(bp)) != GET(FTRP(bp)))
		printf("Error: header does not match footer\n");
}

/* 
 * Requires:
 *   None.
 *
 * Effects:
 *   Perform a minimal check of the heap for consistency. 
 */
void
checkheap(bool verbose) 
{
	void *bp;

	if (verbose)
		printf("Heap (%p):\n", heap_listp);

	if (GET_SIZE(HDRP(heap_listp)) != DSIZE ||
	    !GET_ALLOC(HDRP(heap_listp)))
		printf("Bad prologue header\n");
	checkblock(heap_listp);

	for (bp = heap_listp; GET_SIZE(HDRP(bp)) > 0; bp = NEXT_BLKP(bp)) {
		if (verbose)
			printblock(bp);
		checkblock(bp);
	}
	// Is every block in free list marked as free?
	for (int i = 0; i < 10; i++) {
		struct free_list* header = &array_of_heads[i];
		struct free_list* curr_block = header->next; 
		while (curr_block != header) {
			if (GET_ALLOC(HDRP(curr_block))) {
				printf("Error: block is in free_list, but it's allocated\n");
			}
			curr_block = curr_block->next;
		}
	}

	// Are there any contigous free blocks that somehow escaped coalescing?
	if (!first_realloc)
		for (bp = heap_listp; GET_SIZE(HDRP(bp)) > 0; bp = NEXT_BLKP(bp)) {
			if (!GET_ALLOC(HDRP(bp))) { //if the block is free, we can check its neighbors 
				bool next_alloc = GET_ALLOC(HDRP(NEXT_BLKP(bp)));
				if (!next_alloc)
					printf("Error: contiguous free blocks that escaped coalescing\n");
			}

		}
	// Is every free block actually in the free list?
	bool not_in_free = false;
	for (bp = heap_listp; GET_SIZE(HDRP(bp)) > 0; bp = NEXT_BLKP(bp)) {
		if (!GET_ALLOC(HDRP(bp))) { 
			// If the block is free, we can check its neighbors.
			// Find if it's in a free list.
			not_in_free = true;
			for (int i = 0; i < NUM_LISTS; i++) {
				struct free_list *header = &array_of_heads[i];
				struct free_list *curr_block = header->next;
				while (curr_block != header) {
					if (bp == curr_block)
						not_in_free = false;
					curr_block = curr_block->next;
				}
			}
			if (not_in_free)
				printf("Error: not every free block is in the free list\n");
		}
	}
	// Do any allocated blocks overlap?
	for (bp = heap_listp; GET_SIZE(HDRP(NEXT_BLKP(bp))) > 0; bp = NEXT_BLKP(bp)) {
		// Check that the footer of the current block comes before the 
		// header of the next block.
		void *curr_block_ftr = FTRP(bp);
		void *next_block_header = HDRP(NEXT_BLKP(bp));
		if (curr_block_ftr >= next_block_header)
			printf("Error: allocated blocks overlap\n");
	}
	// Do the pointers in a heap block point to valid heap addresses?
	for (bp = heap_listp; GET_SIZE(HDRP(bp)) > 0; bp = NEXT_BLKP(bp)) {
		if (bp < mem_heap_lo() || bp > mem_heap_hi()) 
			printf("Error: pointers in a heap block do not point to a valid address\n");
	}
	
	if (verbose)
		printblock(bp);
	if (GET_SIZE(HDRP(bp)) != 0 || !GET_ALLOC(HDRP(bp)))
		printf("Bad epilogue header\n");
	
}

/*
 * Requires:
 *   "bp" is the address of a block.
 *
 * Effects:
 *   Print the block "bp".
 */
static void
printblock(void *bp) 
{
	size_t hsize, fsize;
	bool halloc, falloc;

	checkheap(false);
	hsize = GET_SIZE(HDRP(bp));
	halloc = GET_ALLOC(HDRP(bp));  
	fsize = GET_SIZE(FTRP(bp));
	falloc = GET_ALLOC(FTRP(bp));  

	if (hsize == 0) {
		printf("%p: end of heap\n", bp);
		return;
	}

	printf("%p: header: [%zu:%c] footer: [%zu:%c]\n", bp, 
	    hsize, (halloc ? 'a' : 'f'), 
	    fsize, (falloc ? 'a' : 'f'));
}

/*
 * Requires:
 *   Nothing.
 *
 * Effects:
 *   Returns the index of the free list that conatins the appropriate size
 *   range for the provided size.
 */
static int 
get_index(int size) 
{
  	// Formula for index-size relationship:
  	// [0] entry contains size 32 = 16 + 8*2
  	// [1] entry contains size 40 = 16 + 8*3
  	// [i] entry contains size range (16 + 8*2^(i), 16 + 8*2^(i+1)]

	int nwords = (size - DSIZE) / ASIZE;
	// nwords can't be less than 2.
	if (nwords < 5) {
		return nwords - 2;
	} else if (nwords > 4096){
		return NUM_LISTS - 1;
	}
	else {
		return ceil_log2n(nwords);
	}
}  

/*
 * Requires:
 *   Nothing.
 *
 * Effects:
 *   Returns the floor of the logarithm based 2 of the given integer.
 */
static int 
log2n(int n)
{
	return 31 - __builtin_clz(n | 1);
}

/*
 * Requires:
 *   Nothing.
 *
 * Effects:
 *   Returns the ceiling of the logarithm based 2 of the given integer.
 */
static int
ceil_log2n(int n)
{
  // If the total number of 0s is 31, then the integer is a power of 2.
  if(__builtin_clz(n|1) + __builtin_ctz(n) == 31)
  	return log2n(n);
  else
  	return log2n(n) + 1;
}

/*
 * Requires:
 *   Nothing.
 *
 * Effects:
 *   Returns the minimum power of two that is greater than or equal 
 *   to the given integer.
 */
static int
ceil_pow2(int n)
{
  // If the total number of 0s is 31, then the integer is a power of 2.
  if(__builtin_clz(n|1) + __builtin_ctz(n) == 31)
  	return 1 << (log2n(n));
  else
  	return 1 << (log2n(n) + 1);
}