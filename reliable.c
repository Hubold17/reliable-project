#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stddef.h>
#include <assert.h>
#include <poll.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <math.h>
#include "rlib.h"
#include "buffer.h"

#define max(a,b) \
   ({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
     _a > _b ? _a : _b; })

#define min(a,b) \
   ({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
     _a < _b ? _a : _b; })
 

long get_time_ms() {
    struct timeval now;
    gettimeofday(&now, NULL);
    return now.tv_sec * 1000 + now.tv_usec/1000;
}

struct reliable_state {

    rel_t *next;			/* Linked list for traversing all connections */
    rel_t **prev;

    conn_t *c;			    /* This is the connection object */

    buffer_t* send_buffer;  /* Storing all send packets, that were not ACKed yet*/
    buffer_t* rec_buffer;   /* Storing all received packets, that were not send to application layer yet*/
    
    uint32_t snd_una;       /* Oldest packet number, that was not ACKed yet. Equal to snd_nxt if all are ACKed*/
    uint32_t snd_nxt;       /* next packet number to send if we move forward*/
    uint32_t rcv_nxt;       /* next expected packet number */
    uint32_t wnd_size;      /* max sliding window size on both receiver and sender side*/
    long timeout;

    int readEOFfromInput;
    int readEOFfromConnection;
    int output_ready;       /* 0 iff. there are received packets, that were only send partially to application layer*/
};




/** Sends the latest valid ACK, considering
 * received packets as well as if all data has been
 * sent to conn_output yet.
 * 
 * @param r connection object
 * @returns on failure, when output is not ready or success
**/
void send_ack(rel_t *r) {
    if (!r) return;
    if (!r->output_ready) {
        return;
    }

    packet_t ack_pkt = {
        .cksum  = 0,
        .len    = htons(8),
        .ackno  = htonl(r->rcv_nxt)
    };
    ack_pkt.cksum = cksum (&ack_pkt, (int) 8);

    if (conn_sendpkt(r->c, &ack_pkt, 8) == -1) {
        fprintf(stderr, "Exception :: while sending ACK. \n");
        return;
    }
}

rel_t *rel_list;

/** Creates a new reliable protocol session
 * 
* @param ss is always NULL 
* @returns created and setup connection, NULL on failure
*/
rel_t *
rel_create (conn_t *c, const struct sockaddr_storage *ss,
const struct config_common *cc)
{
    rel_t *r;
    r = xmalloc (sizeof (*r));
    memset (r, 0, sizeof (*r));

    if (!c) {
        c = conn_create (r, ss);
        if (!c) {
            free (r);
            return NULL;
        }
    }

    r->c = c;
    r->next = rel_list;
    r->prev = &rel_list;
    if (rel_list)
    rel_list->prev = &r->next;
    rel_list = r;

    r->send_buffer = xmalloc(sizeof(buffer_t));
    r->send_buffer->head = NULL;
    r->rec_buffer = xmalloc(sizeof(buffer_t));
    r->rec_buffer->head = NULL;

    r->snd_una = 1;
    r->snd_nxt = 1;
    r->rcv_nxt = 1;
    r->wnd_size = cc->window;
    r->timeout = cc->timeout;
    r->readEOFfromConnection = 0;
    r->readEOFfromInput = 0;
    r->output_ready = 1;

    return r;
}


/** Closes given connection, including the memory.
 * Only call function if one of these occured:
 * 1) received EOF from the other side (payload len 12).
 * 2) read EOF from input (conn_input returned -1).
 * 3) all send packets are acknowledged (send_buf is empty).
 * 4) finished writing all output with conn_output, including the EOF packet with len 0.
 * 
 * This function only destroys the connection, if conditions 1 to 4 are fulfilled. It not,
 * the function returns and waits to be called again.
 * @param r connection object
*/
void
rel_destroy (rel_t *r)
{ 
    // implements checks 1-4
    if (!r->readEOFfromConnection 
        || !r->readEOFfromInput
        || buffer_get_first(r->send_buffer) != NULL 
        || buffer_get_first(r->rec_buffer) != NULL) {

        return;
    }

    // destroy connection
    if (r->next) {
        r->next->prev = r->prev;
    }
    *r->prev = r->next;
    conn_destroy (r->c);


    buffer_clear(r->send_buffer);
    free(r->send_buffer);
    r->send_buffer = NULL;
    buffer_clear(r->rec_buffer);
    free(r->rec_buffer);
    r->rec_buffer = NULL;
}


/**
 * Handles incoming packets. Checks for corruption and correctnes. Sends ACKs if needed.
 * @param r connection object
 * @param pkt packet (even if it it may be invalid)
 * @param  n   expected length of pkt
 * @returns if the packets are invalid or the packet was handled.
*/
void rel_recvpkt (rel_t *r, packet_t *pkt, size_t n)
{
    // corruption tests
    if (!pkt || !r) return;

    uint16_t len = ntohs(pkt->len);
    if (len != n) return;

    uint16_t ackno = ntohl(pkt->ackno);
    uint16_t seqno = ntohl(pkt->seqno);

    uint16_t seen_cksum = pkt->cksum;
    pkt->cksum = 0;
    uint16_t calc_cksum = cksum(pkt, (int) len);
    if (calc_cksum != seen_cksum) return;

    if (len == 8) {
        // ACK, SENDER
        r->snd_una = max(r->snd_una, min(r->snd_nxt, ackno));

        int pkts_acked = buffer_remove(r->send_buffer, ackno);
        if (pkts_acked > 0) {
            // more space available
            rel_read(r); 
        }
        rel_destroy(r);

    } else {
        // data packet, RECEIVER

        if (seqno >= r->rcv_nxt + r->wnd_size) return; // drop frame
        if (len == 12) r->readEOFfromConnection = 1;
        
        // if seqno is smaller than next expected than it was already processed
        if  (seqno >= r->rcv_nxt && !buffer_contains(r->rec_buffer, seqno)) {
            buffer_insert(r->rec_buffer, pkt, 0);
        }

        if (seqno == r->rcv_nxt) {
            // expected packet, release data to application layer
            buffer_node_t *curr = buffer_get_first(r->rec_buffer);
            while (curr != NULL) {
                if (ntohl(curr->packet.seqno) == r->rcv_nxt) {
                    r->rcv_nxt++;
                } 
            curr = curr->next;
            }
            rel_output(r); // includes send_ack() if successful

        } else {
            send_ack(r);
        }

        
    }
}
/**  Sends data from conn_input in max sizes of 500 bytes.
 * If there is nothing to send or the window is reached, it returns and waits to be called again.
 * Expects to be called if the window moved or new data arrived.
 * 
 * @param s connection object
**/
void
rel_read (rel_t *s)
{
    uint32_t snd_wnd = s->wnd_size - (s->snd_nxt - s->snd_una);
    if (snd_wnd <= 0 || s->readEOFfromInput) {
        return;
    }

    // has space
    char data[500];
    uint16_t datalen;
    uint32_t seqno = s->snd_nxt;

    int inp_state = conn_input(s->c, &data, 500);
    if (inp_state == -1) { 
        // EOF
        s->readEOFfromInput = 1;
        datalen = 0;


    } else if (inp_state == 0) {
        // waiting for input
        return;

    } else {
        datalen = inp_state;
    }

    uint16_t pktlen = datalen + 12;
    packet_t pkt = {
        .cksum  = 0, 
        .len    = htons(pktlen), 
        .ackno  = htonl(0), 
        .seqno  = htonl(seqno)
    };
    memcpy(pkt.data, data, datalen);
    pkt.cksum = cksum (&pkt, (int) pktlen); 

    s->snd_nxt++;

    // add packet to send queue
    long now_ms = get_time_ms();
    buffer_insert(s->send_buffer, &pkt, now_ms);
    if (conn_sendpkt(s->c, &pkt, pktlen) == -1) {
        fprintf(stderr, "Exception :: Send unsuccessful by conn_sendpkt in rel_read! \n");
        return;
    }

    s->snd_una = ntohl(buffer_get_first(s->send_buffer)->packet.seqno);
    
    if (snd_wnd > 1) {
        rel_read(s); // call again if space available
        return;
    }
}

/** Outputs received packets in-order to application layer.
 * Should be called after receiving a data packet or the application layer has buffer ready.
 * If no space is available in the application, it waits to get called again, while resetting output_ready. 
 * Sends ACK and checks for EOF iff. the end of the packet was send to the application. Try's to destroy
 * the connection when appropriate (see rel_destroy)
 * 
 * @param r connection object
**/
void
rel_output (rel_t *r)
{
    buffer_node_t *curr = buffer_get_first(r->rec_buffer);
    while (curr != NULL) {
        if (ntohl(curr->packet.seqno) >= r->rcv_nxt) {
            // not in order yet
            break;
        }

        // the next is free to output
        int space_avail = conn_bufspace(r->c);
        uint16_t data_len = ntohs(curr->packet.len)-12;
        
        if ((int) data_len <= space_avail) {
            send_ack(r);
            conn_output(r->c, curr->packet.data, data_len);
            buffer_remove_first(r->rec_buffer);
            curr = buffer_get_first(r->rec_buffer);
            r->output_ready = 1;
            rel_destroy(r);
            continue;

        } else if (space_avail > 0) {
            // split up
            conn_output(r->c, curr->packet.data, space_avail);
            memmove(curr->packet.data, &curr->packet.data[space_avail], data_len- (uint16_t)space_avail);
            curr->packet.len = htons(data_len - (uint16_t)space_avail + 12);
            r->output_ready = 0;
            return;

        } else {
            return;
        }  
    } 
}

/**
 * Goes over all reliable senders, and have them send out all packets whose respective timeout has been reached.
 * Needs to be called at regular intervals.
 * */
void
rel_timer ()
{
    rel_t *s = rel_list;
    while (s != NULL) {
        buffer_node_t *buf = buffer_get_first(s->send_buffer);
        long time_ms = get_time_ms();

        while (buf != NULL) {
            if (buf->last_retransmit + s->timeout < time_ms) {
                // Timeout
                conn_sendpkt(s->c, &buf->packet, ntohs(buf->packet.len));
                buf->last_retransmit = get_time_ms();
            }
            buf = buf->next;
        }
        s = s->next;
    }
}


