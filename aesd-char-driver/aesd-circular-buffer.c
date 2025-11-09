/**
 * @file aesd-circular-buffer.c
 * @brief Functions and data related to a circular buffer imlementation
 *
 * @author Dan Walkes
 * @date 2020-03-01
 * @copyright Copyright (c) 2020
 *
 */

#ifdef __KERNEL__
#include <linux/string.h>
#else
#include <string.h>
#endif

#include "aesd-circular-buffer.h"

/**
 * @param buffer the buffer to search for corresponding offset.  Any necessary locking must be performed by caller.
 * @param char_offset the position to search for in the buffer list, describing the zero referenced
 *      character index if all buffer strings were concatenated end to end
 * @param entry_offset_byte_rtn is a pointer specifying a location to store the byte of the returned aesd_buffer_entry
 *      buffptr member corresponding to char_offset.  This value is only set when a matching char_offset is found
 *      in aesd_buffer.
 * @return the struct aesd_buffer_entry structure representing the position described by char_offset, or
 * NULL if this position is not available in the buffer (not enough data is written).
 */
struct aesd_buffer_entry *
aesd_circular_buffer_find_entry_offset_for_fpos(struct aesd_circular_buffer *buffer,
            size_t char_offset, size_t *entry_offset_byte_rtn)
{
    if (!buffer || !entry_offset_byte_rtn)
        return NULL;

    size_t accumulated_size = 0;
    unsigned int idx = buffer->out_offs;
    unsigned int traversed = 0;

    /* If buffer is empty return NULL */
    if (!buffer->full && buffer->in_offs == buffer->out_offs) {
        return NULL;
    }

    /* Walk through entries in-order from oldest (out_offs) to newest */
    while (traversed < AESDCHAR_MAX_CIRCULAR_BUFFER_SIZE) {

        struct aesd_buffer_entry *e = &buffer->entry[idx];
        /* If this entry is empty, stop search */
        if (!e->buffptr || e->size == 0) {
            return NULL;
        }

        if (char_offset < accumulated_size + e->size) {
            *entry_offset_byte_rtn = char_offset - accumulated_size;

            pr_info("CIRC_FIND_OK: idx=%u entry_offset_byte_rtn=%zu\n", idx, *entry_offset_byte_rtn);

            return e;
        }

        accumulated_size += e->size;
        idx = (idx + 1) % AESDCHAR_MAX_CIRCULAR_BUFFER_SIZE;
        traversed++;

        /* stop if we've reached in_offs when buffer isn't full */
        if (!buffer->full && idx == buffer->in_offs)
            break;
    }

    return NULL;
}


/**
* Adds entry @param add_entry to @param buffer in the location specified in buffer->in_offs.
* If the buffer was already full, overwrites the oldest entry and advances buffer->out_offs to the
* new start location.
* Any necessary locking must be handled by the caller
* Any memory referenced in @param add_entry must be allocated by and/or must have a lifetime managed by the caller.
*/
void aesd_circular_buffer_add_entry(struct aesd_circular_buffer *buffer, const struct aesd_buffer_entry *add_entry)
{
    pr_info("CIRC_ADD: entry in=%u out=%u full=%d adding_ptr=%p size=%zu\n",
        buffer->in_offs, buffer->out_offs, buffer->full,
        add_entry->buffptr, add_entry->size);

    if (!buffer || !add_entry)
        return;

    /* Copy pointer and size into the slot at in_offs.
       Caller is responsible for freeing overwritten entries if buffer->full. */
    buffer->entry[buffer->in_offs].buffptr = add_entry->buffptr;
    buffer->entry[buffer->in_offs].size = add_entry->size;

    /* advance in_offs */
    buffer->in_offs = (buffer->in_offs + 1) % AESDCHAR_MAX_CIRCULAR_BUFFER_SIZE;

    /* if advance wrapped to equal out_offs then buffer is now full */
    if (buffer->in_offs == buffer->out_offs) {
        buffer->full = true;
    }

    pr_info("CIRC_ADD_DONE: entry in=%u out=%u full=%d\n",
        buffer->in_offs, buffer->out_offs, buffer->full);

}



/**
* Initializes the circular buffer described by @param buffer to an empty struct
*/
void aesd_circular_buffer_init(struct aesd_circular_buffer *buffer)
{
    memset(buffer,0,sizeof(struct aesd_circular_buffer));
}
