/* Copyright 2013 Freescale Semiconductor, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *	 notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *	 notice, this list of conditions and the following disclaimer in the
 *	 documentation and/or other materials provided with the distribution.
 *     * Neither the name of Freescale Semiconductor nor the
 *	 names of its contributors may be used to endorse or promote products
 *	 derived from this software without specific prior written permission.
 *
 *
 * ALTERNATIVELY, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") as published by the Free Software
 * Foundation, either version 2 of that License or (at your option) any
 * later version.
 *
 * THIS SOFTWARE IS PROVIDED BY Freescale Semiconductor ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL Freescale Semiconductor BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include "qman.h"

/* packets send to SEC4.0 per core */
__PERCPU uint32_t pkts_to_sec;
/* number of encrypted frame(s) returned from SEC4.0 per core*/
__PERCPU uint32_t enc_pkts_from_sec;
/* number of decrypted frame(s) returned from SEC4.0 per core*/
__PERCPU uint32_t dec_pkts_from_sec;

struct qm_fd fd[BUFF_NUM];	/* storage for frame descriptor */

static __PERCPU struct fqs_t enc_fqs;

static __PERCPU struct fqs_t dec_fqs;

/* callback handler for dequeued frames and fq's(from SEC40) state change */
const struct qman_fq_cb sec40_rx_cb = {
	.dqrr = cb_dqrr,
	.fqs = cb_fqs
};

/* callback handler for fq's(to SEC40) state change */
const struct qman_fq_cb sec40_tx_cb = {
	.ern = cb_ern,
	.fqs = cb_fqs
};

/*
 * brief	Create a compound frame descriptor understood by SEC 4.0
 * param[in]	buf_num - number of buffers
 * param[in]	output_buf_size
 * param[in]	input_buf_capacity
 * param[in]	input_buf_length
 * return	0 on success, otherwise -ve value
 */
int create_compound_fd(unsigned int buf_num, uint32_t output_buf_size,
		       uint32_t input_buf_capacity, uint32_t input_buf_length)
{
	uint8_t *in_buf, *out_buf;
	struct sg_entry_priv_t *sg_priv_and_data;
	struct qm_sg_entry *sg;
	/* Total size of sg entry, i/p and o/p buffer required */
	uint32_t total_size;
	uint32_t ind;

	for (ind = 0; ind < buf_num; ind++) {

		/* Allocate memory for scatter-gather entry and
		   i/p & o/p buffers */
		total_size = sizeof(struct sg_entry_priv_t) + output_buf_size
		    + input_buf_capacity;

		sg_priv_and_data =
		    __dma_mem_memalign(L1_CACHE_BYTES, total_size);

		if (unlikely(!sg_priv_and_data)) {
			fprintf(stderr, "error: Unable to allocate memory"
				" for buffer!\n");
			return -EINVAL;
		}
		memset(sg_priv_and_data, 0, total_size);

		/* Get the address of output and input buffers */
		out_buf = (uint8_t *) (sg_priv_and_data)
		    + sizeof(struct sg_entry_priv_t);
		in_buf = (uint8_t *) sg_priv_and_data + (total_size
							 - input_buf_capacity);

		sg = (struct qm_sg_entry *)sg_priv_and_data;

		/* output buffer */
		qm_sg_entry_set64(sg, __dma_mem_vtop(out_buf));
		sg->length = output_buf_size;

		/* input buffer */
		sg++;
		qm_sg_entry_set64(sg, __dma_mem_vtop(in_buf));
		sg->length = input_buf_length;
		sg->final = 1;
		sg--;

		/* Frame Descriptor */
		qm_fd_addr_set64(&fd[ind], __dma_mem_vtop(sg));
		fd[ind]._format1 = qm_fd_compound;
		fd[ind].length29 = 2 * sizeof(struct qm_sg_entry);

		sg_priv_and_data->index = ind;
	}
	return 0;
}

/*
 * brief	Create SEC frame queues
 * param[in]	fq_id - frame queue id
 * param[in]	ctxt_a_addr - context A pointer
 * param[in]	ctx_b - context B
 * return	struct qman_fq * - pointer to frame queue structure
 */
struct qman_fq *create_sec_frame_queue(uint32_t fq_id,
				       dma_addr_t ctxt_a_addr, uint32_t ctx_b)
{
	struct qm_mcc_initfq fq_opts;
	struct qman_fq *fq;
	uint32_t flags;

	/* Clear FQ options */
	memset(&fq_opts, 0x00, sizeof(struct qm_mcc_initfq));

	fq = __dma_mem_memalign(L1_CACHE_BYTES, sizeof(struct qman_fq));

	if (unlikely(NULL == fq)) {
		fprintf(stderr, "error: dma_mem_memalign failed in create_fqs"
			" for FQ ID:%u\n", fq_id);
		return NULL;
	}
	memset(fq, 0, sizeof(struct qman_fq));

	if (ctxt_a_addr) {
		flags = QMAN_FQ_FLAG_LOCKED | QMAN_FQ_FLAG_TO_DCPORTAL;
		fq->cb = sec40_tx_cb;
	} else {
		flags = QMAN_FQ_FLAG_LOCKED | QMAN_FQ_FLAG_NO_ENQUEUE;
		fq->cb = sec40_rx_cb;
	}

	if (unlikely(qman_create_fq(fq_id, flags, fq) != 0)) {
		fprintf(stderr, "error: qman_create_fq failed for FQ ID: %u\n",
			fq_id);
		return NULL;
	}

	flags = QMAN_INITFQ_FLAG_SCHED;
	fq_opts.we_mask = QM_INITFQ_WE_DESTWQ | QM_INITFQ_WE_CONTEXTA;

	if (ctxt_a_addr) {
		fq_opts.we_mask |= QM_INITFQ_WE_CONTEXTB;
		qm_fqd_context_a_set64(&fq_opts.fqd, ctxt_a_addr);
		fq_opts.fqd.context_b = ctx_b;
		fq_opts.fqd.dest.channel = qm_channel_caam;
		fq_opts.fqd.dest.wq = 0;
	} else {
		flags |= QMAN_INITFQ_FLAG_LOCAL;
		fq_opts.fqd.fq_ctrl = QM_FQCTRL_CTXASTASHING;
		fq_opts.we_mask |= QM_INITFQ_WE_FQCTRL;
		fq_opts.fqd.context_a.stashing.exclusive =
		    QM_STASHING_EXCL_DATA | QM_STASHING_EXCL_CTX;
		fq_opts.fqd.context_a.stashing.data_cl = 1;
		fq_opts.fqd.context_a.stashing.context_cl = 1;
	}

	if (unlikely(qman_init_fq(fq, flags, &fq_opts) != 0)) {
		fprintf(stderr, "error: qm_init_fq failed for fq_id: %u\n",
			fq_id);
		return NULL;
	}

	return fq;
}

/*
 * brief	Initialize SEC Frame Queues
 * param[in]	mode - Encrypt/Decrypt
 * param[in]	struct fqs_t * - pointer to frame queues structure
 * param[in]	crypto_param - pointer to test parameters
 * param[in]	crypto_cb - test specific callbacks
 * return	0 - if status is correct (i.e. 0)
 *		-1 - if SEC returned an error status (i.e. non 0)
 */
int init_sec_frame_queues(enum SEC_MODE mode, struct fqs_t *fqs,
			  void *crypto_param, struct test_cb crypto_cb)
{
	uint32_t frame_q_base;
	uint32_t fq_from_sec, fq_to_sec;
	struct qman_fq **fq_from_sec_ptr, **fq_to_sec_ptr;
	void *ctxt_a;
	dma_addr_t addr;
	int i;

	frame_q_base = fqs->base;
	fq_from_sec_ptr = fqs->from_sec;
	fq_to_sec_ptr = fqs->to_sec;

	for (i = 0; i < FQ_PER_CORE; i++) {
		ctxt_a = crypto_cb.set_sec_descriptor(mode, crypto_param);
		if (0 == ctxt_a) {
			fprintf(stderr, "error: %s: Initializing shared"
				" descriptor failure!\n", __func__);
			return -1;
		}
		addr = __dma_mem_vtop(ctxt_a);

		fq_from_sec = frame_q_base + 2 * i;
		fq_to_sec = fq_from_sec + 1;

		fq_from_sec_ptr[i] = create_sec_frame_queue(fq_from_sec, 0, 0);
		if (!fq_from_sec_ptr[i]) {
			fprintf(stderr, "error: %s : Encrypt FQ(from SEC)"
				" couldn't be allocated, ID = %d\n", __func__,
				fq_from_sec);
			return -1;
		}

		fq_to_sec_ptr[i] =
		    create_sec_frame_queue(fq_to_sec, addr, fq_from_sec);
		if (!fq_to_sec_ptr[i]) {
			fprintf(stderr, "error: %s : Encrypt FQ(to SEC)"
				" couldn't be allocated, ID = %d\n",
				__func__, fq_to_sec);
			return -1;
		}
	}
	return 0;
}

/*
 * brief	Initialize frame queues to enqueue and dequeue frames to SEC
 *		and from SEC respectively
 * param[in]	cpu_index
 * param[in]	crypto_param - pointer to test parameters
 * param[in]	crypto_cb - test specific callbacks
 * return	0 on success, otherwise -ve value
 */
int init_sec_fq(uint32_t cpu_index, void *crypto_param,
		struct test_cb crypto_cb)
{
	enc_fqs.base = SEC40_FQ_BASE;
	dec_fqs.base =
	    SEC40_FQ_BASE + 2 * FQ_PER_CORE * sysconf(_SC_NPROCESSORS_ONLN);

	/* Each core now has its own FQ base id for encrypt and decrypt */
	enc_fqs.base += 2 * cpu_index * FQ_PER_CORE;
	dec_fqs.base += 2 * cpu_index * FQ_PER_CORE;

	if (init_sec_frame_queues(ENCRYPT, &enc_fqs, crypto_param, crypto_cb)) {
		fprintf(stderr, "error: %s: couldn't Initialize SEC 4.0 Encrypt"
			" Queues\n", __func__);
		return -1;
	}

	if (!crypto_cb.requires_authentication())
		if (init_sec_frame_queues
		    (DECRYPT, &dec_fqs, crypto_param, crypto_cb)) {
			fprintf(stderr,
				"error: %s: couldn't Initialize SEC 4.0"
				" Decrypt Queues\n", __func__);
			return -1;
		}

	return 0;
}

/*
 * brief	Enqueue frames to SEC 4.0 on Encrypt/Decrypt FQ's
 * param[in]	mode - Encrypt/Decrypt
 * param[in]	cpu_index
 * param[in]	ncpus - total number of cpus
 * param[in]	buf_num	- number of buffers per test
 * return	0 on success, otherwise -ve value
 */
void do_enqueues(enum SEC_MODE mode, uint32_t cpu_index, long ncpus,
		 unsigned int buf_num)
{
	struct qman_fq *fq_to_sec;
	uint32_t ret;
	int fd_ind;
	int i = 0;

	do {
		if (i >= pkts_to_sec)
			return;

		fd_ind = (i * ncpus + cpu_index) % buf_num;

		if (ENCRYPT == mode)
			fq_to_sec = enc_fqs.to_sec[i % FQ_PER_CORE];
		else
			fq_to_sec = dec_fqs.to_sec[i % FQ_PER_CORE];

		pr_debug("%s mode: Enqueue packet ->%d\n", mode ? "Encrypt" :
			 "Decrypt\n", fd_ind);

loop:
		ret = qman_enqueue(fq_to_sec, (struct qm_fd *)&fd[fd_ind], 0);
		if (unlikely(ret)) {
			uint64_t now, then = mfatb();
			do {
				now = mfatb();
			} while (now < (then + QMAN_WAIT_CYCLES));
			goto loop;
		}

		i++;
	} while (1);
}

/*
 * brief	Free memory allocated for frame descriptors
 * param[in]	buf_num - number of buffers
 * return	None
 */
void free_fd(unsigned int buf_num)
{
	dma_addr_t addr;
	uint8_t *buf;
	uint32_t ind;

	for (ind = 0; ind < buf_num; ind++) {
		addr = qm_fd_addr_get64(&fd[ind]);
		buf = __dma_mem_ptov(addr);
		__dma_mem_free(buf);
	}
}

/*
 * brief	Poll qman DQCR for encrypted frames
 * param[in]	None
 * param[out]	None
 */
void enc_qman_poll(void)
{
	while (enc_pkts_from_sec < pkts_to_sec)
		qman_poll();
	return;
}

/*
 * brief	Poll qman DQCR for decrypted frames
 * param[in]	None
 * param[out]	None
 */
void dec_qman_poll(void)
{
	while (dec_pkts_from_sec < pkts_to_sec)
		qman_poll();
	return;
}

/*
 * brief	Callback handler for dequeued frames; Counts number of
 *		dequeued packets returned by SEC 4.0 on Encrypt/Decrypt FQ's
 * param[in]	mode - Encrypt/Decrypt
 * return	None
 */
enum qman_cb_dqrr_result cb_dqrr(struct qman_portal *qm, struct qman_fq *fq,
				 const struct qm_dqrr_entry *dqrr)
{
	enum SEC_MODE mode __maybe_unused;
	struct sg_entry_priv_t *sgentry_priv;
	dma_addr_t addr;

	if ((dqrr->fqid >= enc_fqs.base)
	    && (dqrr->fqid < enc_fqs.base + 2 * FQ_PER_CORE)) {
		enc_pkts_from_sec++;
		mode = ENCRYPT;
	} else if ((dqrr->fqid >= dec_fqs.base)
		   && (dqrr->fqid < dec_fqs.base + 2 * FQ_PER_CORE)) {
		dec_pkts_from_sec++;
		mode = DECRYPT;
	} else {
		fprintf(stderr, "error: %s: Invalid Frame Queue ID Returned"
			" by SEC = %d\n", __func__, dqrr->fqid);
		abort();
	}

	pr_debug("%s mode: Packet dequeued ->%d\n", mode ? "Encrypt" :
		 "Decrypt", mode ? enc_pkts_from_sec : dec_pkts_from_sec);

	addr = qm_fd_addr_get64(&(dqrr->fd));
	sgentry_priv = __dma_mem_ptov(addr);
	fd[sgentry_priv->index].status = dqrr->fd.status;

	return qman_cb_dqrr_consume;
}

/*
 * brief	Enqueue Rejection Notification Handler for SEC Tx FQ
 * param[in]	struct qm_mr_entry * - Message Ring entry to be processed
 * param[in]	struct qman_portal * - Pointer to qman_portal
 * param[in]	struct qman_fq * - Pointer to the Frame Descriptor
 * param[out]	None
 */
void cb_ern(struct qman_portal *qm, struct qman_fq *fq,
	    const struct qm_mr_entry *msg)
{
	fprintf(stderr, "error: %s: RC = %x, seqnum = %x\n", __func__,
		msg->ern.rc, msg->ern.seqnum);
	/* TODO Add handling */
	return;
}

/*
 * brief
 * param[in]	struct qm_mr_entry * - Message Ring entry to be processed
 * param[in]	struct qman_portal * - Pointer to qman_portal
 * param[in]	struct qman_fq * - Pointer to the Frame Descriptor
 * param[out]	None
 */
void cb_fqs(struct qman_portal *qm, struct qman_fq *fq,
	    const struct qm_mr_entry *msg)
{
	uint32_t fqid;
	uint32_t rem, offset;

	fqid = fq->fqid;

	if ((fqid >= enc_fqs.base)
	    && (fqid < enc_fqs.base + 2 * FQ_PER_CORE)) {
		offset = fqid - enc_fqs.base;
		rem = offset % 2;
		if (!rem)
			enc_fqs.from_sec_retire[offset / 2] = true;
		else
			enc_fqs.to_sec_retire[offset / 2] = true;
	} else if ((fqid >= dec_fqs.base)
		   && (fqid < (dec_fqs.base + 2 * FQ_PER_CORE))) {
		offset = fqid - dec_fqs.base;
		rem = offset % 2;
		if (!rem)
			dec_fqs.from_sec_retire[offset / 2] = true;
		else
			dec_fqs.to_sec_retire[offset / 2] = true;
	}
}

/*
 * brief	Checks if the status received in FD from CAAM block is valid
 * param[in]	buf_num - number of buffers
 * return	0 - if status is correct (i.e. 0)
 *		-1 - if CAAM returned an error status (i.e. non 0)
 */
int check_fd_status(unsigned int buf_num)
{
	uint32_t ind;

	for (ind = 0; ind < buf_num; ind++) {
		if (fd[ind].status) {
			fprintf(stderr, "error: Bad status return from SEC\n");
			print_frame_desc(&fd[ind]);
			return -1;
		}
	}
	return 0;
}

/*
 * brief	Free memory allocated for frame descriptors
 * param[in]	fq - sec frame queues
 * param[in]	fq_retire_flag
 * return	0 - if status is correct (i.e. 0)
 *		-1 - if SEC returned an error status (i.e. non 0)
 */
int free_sec_frame_queues(struct qman_fq *fq[], bool fq_retire_flag[])
{
	int res, i;
	uint32_t flags;

	for (i = 0; i < FQ_PER_CORE; i++) {
		res = qman_retire_fq(fq[i], &flags);
		if (0 > res) {
			fprintf(stderr, "error: qman_retire_fq failed for"
				" fq %d\n", i);
			return -EINVAL;
		}

		while (!fq_retire_flag[i])
			qman_poll();

		if (flags & QMAN_FQ_STATE_BLOCKOOS) {
			fprintf(stderr, "error: leaking frames for"
				" fq %d\n", i);
			return -1;
		}
		if (qman_oos_fq(fq[i])) {
			fprintf(stderr, "error: qman_oos_fq failed for"
				" fq %d\n", i);
			return -EINVAL;
		}
		qman_destroy_fq(fq[i], 0);
	}
	return 0;
}

/*
 * brief	Free memory allocated for frame descriptors
 * param[in]	authnct - frames were only authenticated/required decryption
 * return	0 - if status is correct (i.e. 0)
 *		-1 - if SEC returned an error status (i.e. non 0)
 */
int free_sec_fq(uint8_t authnct)
{
	if (unlikely(free_sec_frame_queues(enc_fqs.from_sec,
					   enc_fqs.from_sec_retire) != 0)) {
		fprintf(stderr, "error: free_sec_frame_queues failed for"
			" enc_fq_from_sec\n");
		return -1;
	}

	if (unlikely(free_sec_frame_queues(enc_fqs.to_sec,
					   enc_fqs.to_sec_retire) != 0)) {
		fprintf(stderr, "error: free_sec_frame_queues failed for"
			" enc_fq_to_sec\n");
		return -1;
	}

	if (!authnct) {
		if (unlikely(free_sec_frame_queues(dec_fqs.from_sec,
						   dec_fqs.from_sec_retire) !=
			     0)) {
			fprintf(stderr,
				"error: free_sec_frame_queues failed"
				" for dec_fq_from_sec\n");
			return -1;
		}

		if (unlikely(free_sec_frame_queues(dec_fqs.to_sec,
						   dec_fqs.to_sec_retire) !=
			     0)) {
			fprintf(stderr,
				"error: free_sec_frame_queues failed"
				" for dec_fq_to_sec\n");
			return -1;
		}
	}
	return 0;
}

/*
 * brief
 * param[in]	buf_num - number of buffers per run
 * param[in]	cpu_index
 * param[in]	ncpus - total number of cpus per run
 * return	None
 */
void get_pkts_to_sec(unsigned int buf_num, uint32_t cpu_index, long ncpus)
{
	int rem;
	pkts_to_sec = (buf_num / ncpus);
	rem = buf_num % ncpus;
	if (rem > cpu_index)
		pkts_to_sec++;
}

void set_enc_pkts_from_sec(void)
{
	enc_pkts_from_sec = 0;
}

void set_dec_pkts_from_sec(void)
{
	dec_pkts_from_sec = 0;
}

uint32_t get_enc_pkts_from_sec(void)
{
	return enc_pkts_from_sec;
}

uint32_t get_dec_pkts_from_sec(void)
{
	return dec_pkts_from_sec;
}

struct qm_fd *get_fd_base(void)
{
	return fd;
}

/*
 * brief	Prints the Frame Descriptor on Console
 * param[in]	struct qm_fd * Pointer to the Frame Descriptor
 * return	None
 */
void print_frame_desc(struct qm_fd *frame_desc)
{
	uint8_t *v;
	dma_addr_t addr;
	uint32_t i;

	fprintf(stdout, "error: Frame Description at address %p\n",
		(void *)frame_desc);
	if (!frame_desc) {
		fprintf(stdout, "error: - NULL pointer\n");
	} else {
		fprintf(stdout, "error: - debug : %d\n", frame_desc->dd);
		fprintf(stdout, "error: - bpid	: %d\n", frame_desc->bpid);
		fprintf(stdout, "error: - address : 0x%" PRIx64 "\n",
			qm_fd_addr_get64(frame_desc));

		switch (frame_desc->format) {
		case 0:
			fprintf(stdout, "error: - format : 0"
				" - Short single buffer FD\n");
			fprintf(stdout, "error: - offset : %d\n",
				frame_desc->offset);
			fprintf(stdout, "error: - length : %d\n",
				frame_desc->length20);
			break;
		case 1:
			fprintf(stdout, "error: - format : 1 - Compound FD\n");
			fprintf(stdout, "error: - congestion weight : %d\n",
				frame_desc->cong_weight);
			break;
		case 2:
			fprintf(stdout, "error: - format : 2"
				" - Long single buffer FD\n");
			fprintf(stdout, "error: - length : %d\n",
				frame_desc->length29);
			break;
		case 4:
			fprintf(stderr, "error: - format : 4"
				" - Short multi buffer FD\n");
			fprintf(stdout, "error: - offset : %d\n",
				frame_desc->offset);
			fprintf(stdout, "error: - length : %d\n",
				frame_desc->length29);
			break;
		case 6:
			fprintf(stdout, "error: - format : 6"
				" - Long multi buffer FD\n");
			fprintf(stdout, "error: - length : %d\n",
				frame_desc->length29);
			break;
		default:
			fprintf(stderr, "error: - format : INVALID"
				" format %d\n", frame_desc->format);
		}

		fprintf(stdout, "error: - status/command : 0x%08x\n",
			frame_desc->cmd);

		if (frame_desc->format == qm_fd_compound) {
			struct qm_sg_entry *sgentry;

			addr = qm_fd_addr_get64(frame_desc);
			sgentry = __dma_mem_ptov(addr);

			fprintf(stdout, "error: - compound FD S/G list at 0x%"
				PRIx64 "\n", addr);
			addr = qm_sg_entry_get64(sgentry);
			fprintf(stdout, "error: - SG Entry\n");
			fprintf(stdout, "error:       - address	0x%"
				PRIx64 "\n", addr);
			fprintf(stdout, "error:       - F %d\n",
				sgentry->final);
			fprintf(stdout, "error:       - E %d\n",
				sgentry->extension);
			fprintf(stdout, "error:       - length %d\n",
				sgentry->length);
			fprintf(stdout, "error:       - bpid %d\n",
				sgentry->bpid);
			fprintf(stdout, "error:       - offset %d\n",
				sgentry->offset);

			v = __dma_mem_ptov(addr);
			for (i = 0; i < sgentry->length; i++)
				fprintf(stdout, "error: 0x%x\n", *v++);

			sgentry++;
			addr = qm_sg_entry_get64(sgentry);
			fprintf(stdout, "error:    - Next SG Entry\n");
			fprintf(stdout, "error:       - address	0x%"
				PRIx64 "\n", addr);
			fprintf(stdout, "error:       - F %d\n",
				sgentry->final);
			fprintf(stdout, "error:       - E %d\n",
				sgentry->extension);
			fprintf(stdout, "error:       - length %d\n",
				sgentry->length);
			fprintf(stdout, "error:       - bpid %d\n",
				sgentry->bpid);
			fprintf(stdout, "error:       - offset %d\n",
				sgentry->offset);

			v = __dma_mem_ptov(addr);
			for (i = 0; i < sgentry->length; i++)
				fprintf(stdout, "error: 0x%x\n", *v++);
		}
	}
}
