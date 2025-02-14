/* ******************************************************************************
 * Copyright (c) 2011-2021 Google, Inc.  All rights reserved.
 * Copyright (c) 2010 Massachusetts Institute of Technology  All rights
 * reserved.
 * ******************************************************************************/

/*
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * * Neither the name of VMware, Inc. nor the names of its contributors may be
 *   used to endorse or promote products derived from this software without
 *   specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL VMWARE, INC. OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

/*
 * DynamoRIO's memtrace_simple.c clinet modified report the coalescing of gather
 * and scatter instruction.
 *
 * (1) It fills a per-thread-buffer with gather and scatter instructions along
 * with the memory references they access. (2) It calls a clean call to count
 * how many different cache lines are accessed by each gather and scatter
 * instruction. (3) It prints a report with the number of gathers and scatters
 * that access a certain number of cache lines at the end.
 *
 * Each gather or scatter instruction is stored in the buffer as an instruction
 * entry followed by a sequence of loads and stores performed by that
 * instruction, if any.
 *
 * This sample uses the following DynamoRIO features:
 * - the use of drutil_expand_rep_string() to expand string loops to obtain
 *   every memory reference;
 * - the use of drx_expand_scatter_gather() to expand scatter/gather instrs
 *   into a set of functionally equivalent stores/loads;
 * - the use of drutil_opnd_mem_size_in_bytes() to obtain the size of OP_enter
 *   memory references;
 * - the use of drutil_insert_get_mem_addr() to insert instructions to compute
 *   the address of each memory reference.
 *
 * This client is a simple implementation of a memory reference tracing tool
 * without instrumentation optimization.
 */

#include <stddef.h> /* for offsetof */
#include <stdio.h>
#include <string.h>

#include "dr_api.h"
#include "drreg.h"
#include "drutil.h"
#include "drx.h"

enum {
    REF_TYPE_READ = 0,
    REF_TYPE_WRITE = 1,
};

/* Each mem_ref_t is a <type, size, addr> entry representing a memory reference
 * instruction or the reference information, e.g.:
 * - mem ref instr: { type = 0 (gather), size = 5, addr = 0x7f59c2d002d3 }
 * - mem ref info:  { type = 1 (write), size = 8, addr = 0x7ffeacab0ec8 }
 */
typedef struct _mem_ref_t {
    ushort type; /* r(0), w(1), or opcode (assuming 0/1 are invalid opcode) */
    ushort size; /* mem ref size or instr length */
    app_pc addr; /* mem ref addr or instr pc */
} mem_ref_t;

/* Max number of mem_ref a buffer can have. It should be big enough
 * to hold all entries between clean calls.
 */
#define MAX_NUM_MEM_REFS 4096
/* The maximum size of buffer for holding mem_refs. */
#define MEM_BUF_SIZE (sizeof(mem_ref_t) * MAX_NUM_MEM_REFS)

#define MAX_CLINES_PER_GATSCAT 512

/* thread private buffer and counters */
typedef struct {
    // TLS buffer to hold the instrs and their mem refs.
    byte *seg_base;
    mem_ref_t *buf_base;

    uint64 *ngats_that_access_nlines;
    uint64 *nscats_that_access_nlines;

    bool last_inst_was_gatscat;
} per_thread_t;

static client_id_t client_id;
static void *mutex;        /* for multithread support */

// Global version of per thread counters.
static uint64 *ngats_that_access_nlines;
static uint64 *nscats_that_access_nlines;;

/* Allocated TLS slot offsets */
enum {
    MEMTRACE_TLS_OFFS_BUF_PTR,
    MEMTRACE_TLS_COUNT, /* total number of TLS slots allocated */
};

static reg_id_t tls_seg;
static uint tls_offs;
static int tls_idx;
#define TLS_SLOT(tls_base, enum_val) \
    (void **)((byte *)(tls_base) + tls_offs + (enum_val))
#define BUF_PTR(tls_base) \
    *(mem_ref_t **)TLS_SLOT(tls_base, MEMTRACE_TLS_OFFS_BUF_PTR)

#define MINSERT instrlist_meta_preinsert

// The cache line size in bytes.
static int cline_bytes = 64;

// Sort memrefs by address.
static void bubble_sort_memrefs(mem_ref_t *const mem_refs, const int num_mrefs) {
    for (int i = 0; i < num_mrefs - 1; i++) {
        bool swapped = false;
        for (int j = 0; j < num_mrefs - i - 1; j++) {
            if (mem_refs[j].addr > mem_refs[j + 1].addr) {
                mem_ref_t tmp = mem_refs[j];
                mem_refs[j] = mem_refs[j + 1];
                mem_refs[j + 1] = tmp;
            }
        }

        if (!swapped) { // No need to continue.
            break;
        }
    }
}

// Function to count unique addresses in a mem_ref vector.
static int count_unique_memrefs(mem_ref_t *const mem_refs, const int num_mrefs) {
    if (num_mrefs == 0) {
        return 0;
    }

    bubble_sort_memrefs(mem_refs, num_mrefs);

    int count = 1;
    for (int i = 1; i < num_mrefs; i++) {
        if (mem_refs[i].addr != mem_refs[i - 1].addr) {
            count++;
        }
    }

    return count;
}

// Count the number of different cache lines accessed by the last gather/scatter
// instruction.
static void memtrace(void *drcontext) {
    per_thread_t *data = drmgr_get_tls_field(drcontext, tls_idx);
    mem_ref_t *buf_ptr = BUF_PTR(data->seg_base);

    const bool empty_buffer = buf_ptr == data->buf_base;
    if (empty_buffer) {
        return;
    }

    // The first element in the buffer is the instruction.
    mem_ref_t* instr = (mem_ref_t*)data->buf_base;

    const bool is_gather = instr->type == REF_TYPE_READ;

    uint64 *count_vector = is_gather ? data->ngats_that_access_nlines
                                     : data->nscats_that_access_nlines;

    mem_ref_t *first_ref = ((mem_ref_t *)data->buf_base) + 1;

    // Iterate over the memory references and set the address to the cache line.
    for (mem_ref_t *mem_ref = first_ref; mem_ref < buf_ptr; mem_ref++) {
        ptr_uint_t addr = (ptr_uint_t)mem_ref->addr;
        addr /= cline_bytes;
        mem_ref->addr = (app_pc)addr;
    }

    // Count the number of different memory addresses.
    int nlines_accessed = count_unique_memrefs(first_ref, buf_ptr - first_ref);
    count_vector[nlines_accessed]++;

    // Reset the buffer.
    BUF_PTR(data->seg_base) = data->buf_base;
}

/* clean_call dumps the memory reference info to the log file */
static void clean_call(void) {
    void *drcontext = dr_get_current_drcontext();
    memtrace(drcontext);
}

static void insert_load_buf_ptr(void *drcontext,
                                instrlist_t *ilist,
                                instr_t *where,
                                reg_id_t reg_ptr) {
    dr_insert_read_raw_tls(drcontext,
                           ilist,
                           where,
                           tls_seg,
                           tls_offs + MEMTRACE_TLS_OFFS_BUF_PTR,
                           reg_ptr);
}

static void insert_update_buf_ptr(void *drcontext,
                                  instrlist_t *ilist,
                                  instr_t *where,
                                  reg_id_t reg_ptr,
                                  int adjust) {
    MINSERT(ilist,
            where,
            XINST_CREATE_add(drcontext,
                             opnd_create_reg(reg_ptr),
                             OPND_CREATE_INT16(adjust)));
    dr_insert_write_raw_tls(drcontext,
                            ilist,
                            where,
                            tls_seg,
                            tls_offs + MEMTRACE_TLS_OFFS_BUF_PTR,
                            reg_ptr);
}

static void insert_save_type(void *drcontext,
                             instrlist_t *ilist,
                             instr_t *where,
                             reg_id_t base,
                             reg_id_t scratch,
                             ushort type) {
    scratch = reg_resize_to_opsz(scratch, OPSZ_2);
    MINSERT(ilist,
            where,
            XINST_CREATE_load_int(drcontext,
                                  opnd_create_reg(scratch),
                                  OPND_CREATE_INT16(type)));
    MINSERT(ilist,
            where,
            XINST_CREATE_store_2bytes(drcontext,
                                      OPND_CREATE_MEM16(base,
                                                        offsetof(mem_ref_t, type)),
                                      opnd_create_reg(scratch)));
}

static void insert_save_size(void *drcontext,
                             instrlist_t *ilist,
                             instr_t *where,
                             reg_id_t base,
                             reg_id_t scratch,
                             ushort size) {
    scratch = reg_resize_to_opsz(scratch, OPSZ_2);
    MINSERT(ilist,
            where,
            XINST_CREATE_load_int(drcontext,
                                  opnd_create_reg(scratch),
                                  OPND_CREATE_INT16(size)));
    MINSERT(ilist,
            where,
            XINST_CREATE_store_2bytes(drcontext,
                                      OPND_CREATE_MEM16(base,
                                                        offsetof(mem_ref_t, size)),
                                      opnd_create_reg(scratch)));
}

static void insert_save_pc(void *drcontext,
                           instrlist_t *ilist,
                           instr_t *where,
                           reg_id_t base,
                           reg_id_t scratch,
                           app_pc pc) {
    instrlist_insert_mov_immed_ptrsz(drcontext,
                                     (ptr_int_t)pc,
                                     opnd_create_reg(scratch),
                                     ilist,
                                     where,
                                     NULL,
                                     NULL);
    MINSERT(ilist,
            where,
            XINST_CREATE_store(drcontext,
                               OPND_CREATE_MEMPTR(base, offsetof(mem_ref_t, addr)),
                               opnd_create_reg(scratch)));
}

static void insert_save_addr(void *drcontext,
                             instrlist_t *ilist,
                             instr_t *where,
                             opnd_t ref,
                             reg_id_t reg_ptr,
                             reg_id_t reg_addr) {
    /* we use reg_ptr as scratch to get addr */
    bool ok = drutil_insert_get_mem_addr(drcontext, ilist, where, ref, reg_addr, reg_ptr);
    DR_ASSERT(ok);
    insert_load_buf_ptr(drcontext, ilist, where, reg_ptr);
    MINSERT(ilist,
            where,
            XINST_CREATE_store(drcontext,
                               OPND_CREATE_MEMPTR(reg_ptr, offsetof(mem_ref_t, addr)),
                               opnd_create_reg(reg_addr)));
}

/* insert inline code to add an instruction entry into the buffer */
static void instrument_instr(void *drcontext,
                             instrlist_t *ilist,
                             instr_t *where,
                             instr_t *instr,
                             bool write) {
    /* We need two scratch registers */
    reg_id_t reg_ptr, reg_tmp;
    /* we don't want to predicate this, because an instruction fetch always
     * occurs */
    instrlist_set_auto_predicate(ilist, DR_PRED_NONE);
    if (drreg_reserve_register(drcontext, ilist, where, NULL, &reg_ptr) !=
            DRREG_SUCCESS ||
        drreg_reserve_register(drcontext, ilist, where, NULL, &reg_tmp) !=
            DRREG_SUCCESS) {
        DR_ASSERT(false); /* cannot recover */
        return;
    }
    insert_load_buf_ptr(drcontext, ilist, where, reg_ptr);
    insert_save_type(drcontext,
                     ilist,
                     where,
                     reg_ptr,
                     reg_tmp,
                     write ? REF_TYPE_WRITE : REF_TYPE_READ);
    insert_save_size(drcontext,
                     ilist,
                     where,
                     reg_ptr,
                     reg_tmp,
                     (ushort)instr_length(drcontext, instr));
    insert_save_pc(drcontext, ilist, where, reg_ptr, reg_tmp, instr_get_app_pc(instr));
    insert_update_buf_ptr(drcontext, ilist, where, reg_ptr, sizeof(mem_ref_t));
    /* Restore scratch registers */
    if (drreg_unreserve_register(drcontext, ilist, where, reg_ptr) != DRREG_SUCCESS ||
        drreg_unreserve_register(drcontext, ilist, where, reg_tmp) != DRREG_SUCCESS)
        DR_ASSERT(false);
    instrlist_set_auto_predicate(ilist, instr_get_predicate(where));
}

/* insert inline code to add a memory reference info entry into the buffer */
static void instrument_mem(void *drcontext,
                           instrlist_t *ilist,
                           instr_t *where,
                           opnd_t ref,
                           bool write) {
    /* We need two scratch registers */
    reg_id_t reg_ptr, reg_tmp;
    if (drreg_reserve_register(drcontext, ilist, where, NULL, &reg_ptr) !=
            DRREG_SUCCESS ||
        drreg_reserve_register(drcontext, ilist, where, NULL, &reg_tmp) !=
            DRREG_SUCCESS) {
        DR_ASSERT(false); /* cannot recover */
        return;
    }
    /* save_addr should be called first as reg_ptr or reg_tmp maybe used in ref
     */
    insert_save_addr(drcontext, ilist, where, ref, reg_ptr, reg_tmp);
    insert_save_type(drcontext,
                     ilist,
                     where,
                     reg_ptr,
                     reg_tmp,
                     write ? REF_TYPE_WRITE : REF_TYPE_READ);
    insert_save_size(drcontext,
                     ilist,
                     where,
                     reg_ptr,
                     reg_tmp,
                     (ushort)drutil_opnd_mem_size_in_bytes(ref, where));
    insert_update_buf_ptr(drcontext, ilist, where, reg_ptr, sizeof(mem_ref_t));
    /* Restore scratch registers */
    if (drreg_unreserve_register(drcontext, ilist, where, reg_ptr) != DRREG_SUCCESS ||
        drreg_unreserve_register(drcontext, ilist, where, reg_tmp) != DRREG_SUCCESS)
        DR_ASSERT(false);
}

/* For each memory reference app instr, we insert inline code to fill the buffer
 * with an instruction entry and memory reference entries.
 */
static dr_emit_flags_t event_app_instruction(void *drcontext,
                                             void *tag,
                                             instrlist_t *bb,
                                             instr_t *where,
                                             bool for_trace,
                                             bool translating,
                                             void *user_data) {

    per_thread_t *data = drmgr_get_tls_field(drcontext, tls_idx);

    /* Insert code to add an entry for each gather/scatter app instruction. */
    /* Use the drmgr_orig_app_instr_* interface to properly handle our own use
     * of drutil_expand_rep_string() and drx_expand_scatter_gather() (as well
     * as another client/library emulating the instruction stream).
     */

    instr_t *instr_fetch = drmgr_orig_app_instr_for_fetch(drcontext);

    if (instr_fetch != NULL) {
        if (instr_is_gather(instr_fetch) || instr_is_scatter(instr_fetch)) {
            data->last_inst_was_gatscat = true;
        }
        else {
            data->last_inst_was_gatscat = false;
            return DR_EMIT_DEFAULT; // Ignore the instruction.
        }
    }
    // This is a memory reference. We only care about it if it comes after a
    // gather or scatter.
    else if (!data->last_inst_was_gatscat) {
        return DR_EMIT_DEFAULT;
    }

    // Before start processing a new instruction, finish with the last one.
    /* insert code to call clean_call for processing the buffer */
    if (/* XXX i#1698: there are constraints for code between ldrex/strex pairs,
         * so we minimize the instrumentation in between by skipping the clean
         * call. As we're only inserting instrumentation on a memory reference,
         * and the app should be avoiding memory accesses in between the
         * ldrex...strex, the only problematic point should be before the strex.
         * However, there is still a chance that the instrumentation code may
         * clear the exclusive monitor state. Using a fault to handle a full
         * buffer should be more robust, and the forthcoming buffer filling API
         * (i#513) will provide that.
         */
        instr_fetch != NULL &&
        IF_AARCHXX_OR_RISCV64_ELSE(!instr_is_exclusive_store(instr_operands), true)) {
            dr_insert_clean_call(drcontext, bb, where, (void *)clean_call, false, 0);
    }

    // Instrument the instruction.
    if (instr_fetch != NULL &&
        (instr_reads_memory(instr_fetch) || instr_writes_memory(instr_fetch))) {
        DR_ASSERT(instr_is_app(instr_fetch));
        instrument_instr(drcontext, bb, where, instr_fetch, instr_is_scatter(instr_fetch));
    }

    /* Insert code to add an entry for each memory reference opnd. */
    instr_t *instr_operands = drmgr_orig_app_instr_for_operands(drcontext);
    if (instr_operands == NULL || (!instr_reads_memory(instr_operands) &&
                                   !instr_writes_memory(instr_operands))) {
        return DR_EMIT_DEFAULT;
    }

    DR_ASSERT(instr_is_app(instr_operands));

    // Instrument memory accesses.
    for (int i = 0; i < instr_num_srcs(instr_operands); i++) {
        const opnd_t src = instr_get_src(instr_operands, i);
        if (opnd_is_memory_reference(src)) {
            instrument_mem(drcontext, bb, where, src, false);
        }
    }

    for (int i = 0; i < instr_num_dsts(instr_operands); i++) {
        const opnd_t dst = instr_get_dst(instr_operands, i);
        if (opnd_is_memory_reference(dst)) {
            instrument_mem(drcontext, bb, where, dst, true);
        }
    }

    return DR_EMIT_DEFAULT;
}

/* We transform string loops into regular loops so we can more easily
 * monitor every memory reference they make.
 */
static dr_emit_flags_t event_bb_app2app(void *drcontext,
                                        void *tag,
                                        instrlist_t *bb,
                                        bool for_trace,
                                        bool translating) {
    // Expand string loops into regular loops.
    if (!drutil_expand_rep_string(drcontext, bb)) {
        DR_ASSERT(false);
        /* in release build, carry on: we'll just miss per-iter refs */
    }
    // Expand gather and scatter instructions into a sequence of loads and stores.
    if (!drx_expand_scatter_gather(drcontext, bb, NULL)) {
        DR_ASSERT(false);
    }
    return DR_EMIT_DEFAULT;
}

static void event_thread_init(void *drcontext) {
    per_thread_t *data = dr_thread_alloc(drcontext, sizeof(per_thread_t));
    DR_ASSERT(data != NULL);
    drmgr_set_tls_field(drcontext, tls_idx, data);

    /* Keep seg_base in a per-thread data structure so we can get the TLS
     * slot and find where the pointer points to in the buffer.
     */
    data->seg_base = dr_get_dr_segment_base(tls_seg);
    data->buf_base = dr_raw_mem_alloc(MEM_BUF_SIZE,
                                      DR_MEMPROT_READ | DR_MEMPROT_WRITE,
                                      NULL);

    data->ngats_that_access_nlines = dr_thread_alloc(drcontext,
                                                     sizeof(uint64) *
                                                         MAX_CLINES_PER_GATSCAT);
    data->nscats_that_access_nlines = dr_thread_alloc(drcontext,
                                                      sizeof(uint64) *
                                                          MAX_CLINES_PER_GATSCAT);

    for (int i = 0; i < MAX_CLINES_PER_GATSCAT; i++) {
        data->ngats_that_access_nlines[i] = 0;
        data->nscats_that_access_nlines[i] = 0;
    }

    DR_ASSERT(data->seg_base != NULL && data->buf_base != NULL);
    /* put buf_base to TLS as starting buf_ptr */
    BUF_PTR(data->seg_base) = data->buf_base;
}

static void event_thread_exit(void *drcontext) {
    per_thread_t *data;
    memtrace(drcontext); /* dump any remaining buffer entries */
    data = drmgr_get_tls_field(drcontext, tls_idx);
    dr_mutex_lock(mutex);

    for (int i = 0; i < MAX_CLINES_PER_GATSCAT; i++) {
        ngats_that_access_nlines[i] += data->ngats_that_access_nlines[i];
        nscats_that_access_nlines[i] += data->nscats_that_access_nlines[i];
    }

    dr_mutex_unlock(mutex);

    dr_raw_mem_free(data->buf_base, MEM_BUF_SIZE);

    dr_thread_free(drcontext, data->ngats_that_access_nlines,
                   sizeof(uint64) * MAX_CLINES_PER_GATSCAT);
    dr_thread_free(drcontext, data->nscats_that_access_nlines,
                   sizeof(uint64) * MAX_CLINES_PER_GATSCAT);

    dr_thread_free(drcontext, data, sizeof(per_thread_t));
}

static void event_exit(void) {
    int last_non_zero = -1;
    for (int i = MAX_CLINES_PER_GATSCAT - 1; i != -1; --i) {
        if (ngats_that_access_nlines[i] != 0 || nscats_that_access_nlines[i] != 0) {
            last_non_zero = i;
            break;
        }
    }

    for (int i = 0; i <= last_non_zero; i++) {
        dr_fprintf(STDOUT,
                   "Number of gathers that access %d cache lines: %lu\n",
                   i,
                   ngats_that_access_nlines[i]);
    }

    dr_fprintf(STDOUT, "\n");

    for (int i = 0; i <= last_non_zero; i++) {
        dr_fprintf(STDOUT,
                   "Number of scatters that access %d cache lines: %lu\n",
                   i,
                   nscats_that_access_nlines[i]);
    }



    if (!dr_raw_tls_cfree(tls_offs, MEMTRACE_TLS_COUNT))
        DR_ASSERT(false);

    if (!drmgr_unregister_tls_field(tls_idx) ||
        !drmgr_unregister_thread_init_event(event_thread_init) ||
        !drmgr_unregister_thread_exit_event(event_thread_exit) ||
        !drmgr_unregister_bb_app2app_event(event_bb_app2app) ||
        !drmgr_unregister_bb_insertion_event(event_app_instruction) ||
        drreg_exit() != DRREG_SUCCESS)
        DR_ASSERT(false);

    dr_mutex_destroy(mutex);

    dr_global_free(ngats_that_access_nlines, sizeof(uint64) * MAX_CLINES_PER_GATSCAT);
    dr_global_free(nscats_that_access_nlines, sizeof(uint64) * MAX_CLINES_PER_GATSCAT);

    drutil_exit();
    drmgr_exit();
    drx_exit();
}

DR_EXPORT void dr_client_main(client_id_t id, int argc, const char *argv[]) {
    /* We need 2 reg slots beyond drreg's eflags slots => 3 slots */
    drreg_options_t ops = {sizeof(ops), 3, false};
    dr_set_client_name(
        "'GatherScatterCoalescingReport' client based on DynamoRIO",
        "https://github.com/LorienLV/gatherscatter-coalescing-report");

    if (argc > 1) {
        if (argc == 2) {
            cline_bytes = atoi(argv[1]);
            dr_fprintf(STDOUT, "Using a cache line size of: %d bytes\n", cline_bytes);
            if (cline_bytes <= 0) {
                dr_fprintf(STDERR, "Error: the cache line size must be a positive integer\n");
                dr_abort();
            }
        }
        else {
            dr_fprintf(STDERR,
                       "Error: unknown argument: only the cache line size (in "
                       "bytes) is supported\n");
            dr_abort();
        }
    }
    else {
        dr_fprintf(STDOUT, "Using the default cache line size: %d bytes\n", cline_bytes);
    }

    if (!drmgr_init() || drreg_init(&ops) != DRREG_SUCCESS || !drutil_init() ||
        !drx_init())
        DR_ASSERT(false);

    /* register events */
    dr_register_exit_event(event_exit);
    if (!drmgr_register_thread_init_event(event_thread_init) ||
        !drmgr_register_thread_exit_event(event_thread_exit) ||
        !drmgr_register_bb_app2app_event(event_bb_app2app, NULL) ||
        !drmgr_register_bb_instrumentation_event(NULL /*analysis_func*/,
                                                 event_app_instruction,
                                                 NULL))
        DR_ASSERT(false);

    client_id = id;
    mutex = dr_mutex_create();

    ngats_that_access_nlines = dr_global_alloc(sizeof(uint64) * MAX_CLINES_PER_GATSCAT);
    nscats_that_access_nlines = dr_global_alloc(sizeof(uint64) * MAX_CLINES_PER_GATSCAT);

    for (int i = 0; i < MAX_CLINES_PER_GATSCAT; i++) {
        ngats_that_access_nlines[i] = 0;
        nscats_that_access_nlines[i] = 0;
    }

    tls_idx = drmgr_register_tls_field();
    DR_ASSERT(tls_idx != -1);
    /* The TLS field provided by DR cannot be directly accessed from the code
     * cache. For better performance, we allocate raw TLS so that we can
     * directly access and update it with a single instruction.
     */
    if (!dr_raw_tls_calloc(&tls_seg, &tls_offs, MEMTRACE_TLS_COUNT, 0))
        DR_ASSERT(false);
}