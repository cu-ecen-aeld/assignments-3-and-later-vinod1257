/*
 * aesdchar.h
 *
 *  Created on: Oct 23, 2019
 *      Author: Dan Walkes
 */

#ifndef AESDCHAR_H
#define AESDCHAR_H

#include <linux/cdev.h>
#include <linux/mutex.h>
#include "aesd-circular-buffer.h"

#define AESDCHAR_MAX_WRITE 1024

/* TODO: add any defines you need */

/* Device structure for this driver */
struct aesd_dev {
    struct cdev cdev;                     /* Char device structure */
    struct aesd_circular_buffer circ_buf; /* Circular buffer of entries */
    struct mutex lock;                    /* Mutex to protect the buffer */

    /* buffer for an in-progress (unterminated) write */
    char *write_buf;                      /* accumulated bytes for current write */
    size_t write_buf_size;                /* number of bytes stored in write_buf */

    /* TODO: add any other device-specific fields you need */
};

#endif /* AESDCHAR_H */
