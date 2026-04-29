import struct

###############################################################################
#                             CONSTANTS SECTION                               #
###############################################################################

# ==================== eBPF Size Constants ====================
BPF_W		=0x00 
BPF_H		=0x08 
BPF_B		=0x10 
BPF_DW		=0x18   

# ==================== eBPF Register Numbers ====================
BPF_REG_0  = 0
BPF_REG_1  = 1
BPF_REG_2  = 2
BPF_REG_3  = 3
BPF_REG_4  = 4
BPF_REG_5  = 5
BPF_REG_6  = 6
BPF_REG_7  = 7
BPF_REG_8  = 8
BPF_REG_9  = 9
BPF_REG_10 = 10  # Frame pointer

# ==================== eBPF Instruction Classes ====================
BPF_LD    = 0x00
BPF_LDX   = 0x01
BPF_ST    = 0x02
BPF_STX   = 0x03
BPF_ALU   = 0x04
BPF_JMP   = 0x05
BPF_JMP32 = 0x06
BPF_ALU64 = 0x07

# ==================== eBPF Source Flags ====================
BPF_K = 0x00  # Immediate value
BPF_X = 0x08  # Register value

# ==================== eBPF ALU/JMP Operations ====================
BPF_ADD  = 0x00
BPF_SUB  = 0x10
BPF_MUL  = 0x20
BPF_DIV  = 0x30
BPF_OR   = 0x40
BPF_AND  = 0x50
BPF_LSH  = 0x60
BPF_RSH  = 0x70
BPF_NEG  = 0x80
BPF_MOD  = 0x90
BPF_XOR  = 0xa0
BPF_MOV  = 0xb0
BPF_ARSH = 0xc0
BPF_END  = 0xd0

BPF_JA   = 0x00
BPF_JEQ  = 0x10
BPF_JGT  = 0x20
BPF_JGE  = 0x30
BPF_JSET = 0x40
BPF_JNE  = 0x50
BPF_JSGT = 0x60
BPF_JSGE = 0x70
BPF_CALL = 0x80
BPF_EXIT = 0x90
BPF_JLT  = 0xa0
BPF_JLE  = 0xb0
BPF_JSLT = 0xc0
BPF_JSLE = 0xd0
BPF_JCOND =	0xe0

# ==================== eBPF Memory Modes ====================
BPF_MEM    = 0x60
BPF_ATOMIC = 0xc0
BPF_MEMSX  = 0x80	# load with sign extension
BPF_XADD   = 0xc0	# exclusive add - legacy name
BPF_ABS    = 0x20
BPF_IND    = 0x40
BPF_LEN	   = 0x80
BPF_IMM    = 0x00

# ==================== eBPF Pseudo Sources ====================
BPF_PSEUDO_MAP_FD    = 1
BPF_PSEUDO_MAP_VALUE = 2
BPF_PSEUDO_CALL      = 1
BPF_PSEUDO_KFUNC_CALL = 2
# ==================== Special Purpose Constants ====================
BPF_ANC = 0x80
BPF_FETCH = 0x01  # For atomic operations
BPF_XCHG = 0xe0 | BPF_FETCH	# atomic exchange
BPF_CMPXCHG	= 0xf0 | BPF_FETCH	# atomic compare-and-write
BPF_TO_LE = 0x00  # For endian conversion
BPF_FROM_LE = BPF_TO_LE
BPF_TO_BE = 0x08  # For endian conversion
BPF_FROM_BE = BPF_TO_BE

# ==================== Version Information ====================
BPF_MAJOR_VERSION = 1
BPF_MINOR_VERSION = 0

# ==================== Flags for BPF_MAP_UPDATE_ELEM command ====================
BPF_ANY		= 0     # create new element or update existing
BPF_NOEXIST	= 1     # create new element if it didn't exist
BPF_EXIST	= 2     # update existing element
BPF_F_LOCK	= 4     # spin_lock-ed map_lookup/map_update

###############################################################################
#                             HELPER MACROS SECTION                           #
###############################################################################

def BPF_SIZE(size):
    """Helper to set size field in instruction"""
    return size& 0x18

def BPF_MODE(code):
    """Extract mode from instruction code"""
    return code & 0xe0


def BPF_SRC(code):
    """Extract source from instruction code"""
    return code & 0x08

def BPF_CLASS(code):
    """Extract class from instruction code"""
    return code & 0x07

def BPF_OP(op):
    """Helper to set operation field in instruction"""
    return op 

###############################################################################
#                         INSTRUCTION GENERATION SECTION                      #
###############################################################################

# ==================== MOV Instructions ====================
def BPF_MOV64_IMM(dst, imm):
    """Move 32-bit immediate into 64-bit register"""
    return struct.pack('<BBHI', 0xb7, dst, 0, imm & 0xFFFFFFFF)

def BPF_MOV64_REG(dst, src):
    """Move 64-bit register to register"""
    return struct.pack('<BBHI', 0xbf, (src << 4) | dst, 0, 0)

def BPF_MOV32_IMM(dst, imm):
    """Move 32-bit immediate into 32-bit register"""
    return struct.pack('<BBHI', BPF_ALU | BPF_MOV | BPF_K, dst , 0, imm & 0xFFFFFFFF)

def BPF_MOV32_REG(dst, src):
    """Move 32-bit register to register"""
    return struct.pack('<BBHI', BPF_ALU | BPF_MOV | BPF_X, (src << 4) | dst, 0, 0)

def BPF_MOVSX64_REG(dst, src, off):
    """Move with sign extension (64-bit)"""
    return struct.pack('<BBHI', 0xbf, (src << 4) | dst, off & 0xFFFF, 0)

def BPF_MOVSX32_REG(dst, src, off):
    """Move with sign extension (32-bit)"""
    return struct.pack('<BBHI', BPF_ALU | BPF_MOV | BPF_X, (src << 4) | dst, off & 0xFFFF, 0)

def BPF_ZEXT_REG(dst):
    """Zero extend register"""
    return struct.pack('<BBHI', 0x04 | BPF_MOV | BPF_X, (dst << 4) | dst, 0, 1)

# ==================== ALU Instructions ====================
def BPF_ALU64_REG_OFF(op, dst, src, off):
    return struct.pack('<BBHI', BPF_ALU64 | BPF_OP(op) | BPF_X, (src << 4) | dst, off & 0xFFFF, 0)

def BPF_ALU64_REG(op, dst, src):
    return BPF_ALU64_REG_OFF(op, dst, src, 0)

def BPF_ALU32_REG_OFF(op, dst, src, off):
    return struct.pack('<BBHI', BPF_ALU | BPF_OP(op) | BPF_X, (src << 4) | dst, off & 0xFFFF, 0)

def BPF_ALU32_REG(op, dst, src):
    return BPF_ALU32_REG_OFF(op, dst, src, 0)

def BPF_ALU64_IMM_OFF(op, dst, imm, off):
    return struct.pack('<BBHI', BPF_ALU64 | BPF_OP(op) | BPF_K, dst , off & 0xFFFF, imm & 0xFFFFFFFF)

def BPF_ALU64_IMM(op, dst, imm):
    return BPF_ALU64_IMM_OFF(op, dst, imm, 0)

def BPF_ALU32_IMM_OFF(op, dst, imm, off):
    return struct.pack('<BBHI', BPF_ALU | BPF_OP(op) | BPF_K, dst , off & 0xFFFF, imm & 0xFFFFFFFF)

def BPF_ALU32_IMM(op, dst, imm):
    return BPF_ALU32_IMM_OFF(op, dst, imm, 0)

def BPF_ENDIAN(type, dst, len):
    """Endian conversion"""
    return struct.pack('<BBHI', BPF_ALU | BPF_END | BPF_SRC(type), dst , 0, len)

def BPF_BSWAP(dst, len):
    """Byte swap"""
    return BPF_ENDIAN(BPF_TO_LE, dst, len)

# ==================== Memory Instructions ====================
def BPF_LDX_MEM(size, dst, src, off):
    """Load from memory"""
    return struct.pack('<BBHI', BPF_LDX | BPF_SIZE(size) | BPF_MEM, (src << 4) | dst, off & 0xFFFF, 0)

def BPF_STX_MEM(size, dst, src, off):
    """Store to memory"""
    return struct.pack('<BBHI', BPF_STX | BPF_SIZE(size) | BPF_MEM, (src << 4) | dst, off & 0xFFFF, 0)

def BPF_ST_MEM(size, dst, off, imm):
    """Store immediate to memory"""
    return struct.pack('<BBHI', BPF_ST | BPF_SIZE(size) | BPF_MEM, dst, off & 0xFFFF, imm & 0xFFFFFFFF)

def BPF_LD_ABS(size, imm):
    """Absolute load"""
    return struct.pack('<BBHI', BPF_LD | BPF_SIZE(size) | BPF_ABS, 0, 0, imm & 0xFFFFFFFF)

def BPF_LD_IND(size, src, imm):
    """Indirect load"""
    return struct.pack('<BBHI', BPF_LD | BPF_SIZE(size) | BPF_IND, (src << 4), 0, imm & 0xFFFFFFFF)

def BPF_PROBE_MEM(size, dst, src, off):
    """Memory probe"""
    return struct.pack('<BBHI', BPF_LDX | BPF_SIZE(size) | BPF_PROBE_MEM, (src << 4) | dst, off & 0xFFFF, 0)

def BPF_PROBE_MEMSX(size, dst, src, off):
    """Memory probe with sign extension"""
    return struct.pack('<BBHI', BPF_LDX | BPF_SIZE(size) | BPF_PROBE_MEMSX, (src << 4) | dst, off & 0xFFFF, 0)

# ==================== Atomic Instructions ====================
def BPF_ATOMIC_OP(size, op, dst, src, off):
    """Atomic operation"""
    return struct.pack('<BBHI', BPF_STX | BPF_SIZE(size) | BPF_ATOMIC, (src << 4) | dst, off & 0xFFFF, op)

def BPF_STX_XADD(size, dst, src, off):
    """Atomic add"""
    return BPF_ATOMIC_OP(size, BPF_ADD, dst, src, off)

# ==================== Jump Instructions ====================
def BPF_JMP_IMM(op, dst, imm, off):
    """Jump with immediate"""
    return struct.pack('<BBHI', BPF_JMP | BPF_OP(op) | BPF_K, dst , off & 0xFFFF, imm & 0xFFFFFFFF)

def BPF_JMP_REG(op, dst, src, off):
    """Jump with register"""
    return struct.pack('<BBHI', BPF_JMP | BPF_OP(op), (src << 4) | dst, off & 0xFFFF, 0)

def BPF_JMP_A(off):
    """Unconditional jump"""
    return struct.pack('<BBHI', BPF_JMP | BPF_JA, 0, off & 0xFFFF, 0)

def BPF_JMP32_IMM(op, dst, imm, off):
    """32-bit jump with immediate"""
    return struct.pack('<BBHI', BPF_JMP32 | BPF_OP(op) | BPF_K, dst , off & 0xFFFF, imm & 0xFFFFFFFF)

def BPF_JMP32_REG(op, dst, src, off):
    """32-bit jump with register"""
    return struct.pack('<BBHI', BPF_JMP32 | BPF_OP(op), (src << 4) | dst, off & 0xFFFF, 0)

def BPF_JMP32_A(imm):
    """32-bit unconditional jump"""
    return struct.pack('<BBHI', BPF_JMP32 | BPF_JA, 0, 0, imm & 0xFFFFFFFF)

# ==================== Call/Exit Instructions ====================
def BPF_CALL_REL(tgt_offset):
    """Relative function call"""
    return struct.pack('<BBHI', BPF_JMP | BPF_CALL, (BPF_PSEUDO_CALL << 4), 0, tgt_offset & 0xFFFFFFFF)

def BPF_EXIT_INSN():
    """Exit program"""
    return struct.pack('<BBHI', BPF_JMP | BPF_EXIT, 0, 0, 0)

def BPF_TAIL_CALL():
    """Tail call"""
    return struct.pack('<BBHI', 0xf0, 0, 0, 0)

# ==================== Load Double Word ====================
def BPF_LD_IMM64(dst, imm64):
    """Load 64-bit immediate"""
    part1 = struct.pack('<BBHI', 0x18, dst , 0, imm64 & 0xFFFFFFFF)
    part2 = struct.pack('<I', (imm64 >> 32) & 0xFFFFFFFF) + b'\x00'*4
    return part1 + part2

def BPF_LD_IMM64_RAW_FULL(dst, src, off1, off2, imm1, imm2):
    """Raw 64-bit load with full control"""
    part1 = struct.pack('<BBHI', 0x18, (src << 4) | dst, off1 & 0xFFFF, imm1 & 0xFFFFFFFF)
    part2 = struct.pack('<BBHI', 0x00, 0x00, off2 & 0xFFFF, imm2 & 0xFFFFFFFF)
    return part1 + part2

def BPF_LD_IMM64_RAW(dst, src, imm64):
    """Raw 64-bit load with control"""
    return BPF_LD_IMM64_RAW_FULL(dst, src, 0, 0, imm64 & 0xFFFFFFFF, (imm64 >> 32) & 0xFFFFFFFF)

def BPF_MOV64_RAW(type, dst, src, imm):
    """64-bit move with type (K=immediate, X=register)"""
    if type == BPF_K:  # Immediate mode
        return struct.pack('<BBHI', 0xb7, dst , 0, imm & 0xFFFFFFFF)
    else:  # Register mode (BPF_X)
        return struct.pack('<BBHI', 0xbf, (src << 4) | dst, 0, 0)

def BPF_MOV32_RAW(type, dst, src, imm):
    """32-bit move with type (K=immediate, X=register)"""
    if type == BPF_K:  # Immediate mode
        return struct.pack('<BBHI', BPF_ALU | BPF_MOV | BPF_K, dst , 0, imm & 0xFFFFFFFF)
    else:  # Register mode (BPF_X)
        return struct.pack('<BBHI', BPF_ALU | BPF_MOV | BPF_X, dst  | (src << 4), 0, 0)

# ==================== Map Operations ====================
def BPF_LD_MAP_FD(dst, map_fd):
    """Load map file descriptor"""
    part1 = struct.pack('<BBHI', 0x18, dst  | ( BPF_PSEUDO_MAP_FD <<4 ), 0, map_fd & 0xFFFFFFFF)
    part2 = struct.pack('<BBHI', 0x00, 0x00, 0, 0)
    return part1 + part2

def BPF_LD_MAP_VALUE(dst, map_fd, value_off):
    """Load map value"""
    part1 = struct.pack('<BBHI', 0x18, dst | ( BPF_PSEUDO_MAP_VALUE << 4), 0, map_fd & 0xFFFFFFFF)
    part2 = struct.pack('<BBHI', 0x00, 0x00, 0, value_off & 0xFFFFFFFF)
    return part1 + part2

# ==================== Special Instructions ====================
def BPF_NOSPEC():
    """Speculation barrier"""
    return struct.pack('<BBHI', 0xc0, 0, 0, 0)

def BPF_CALL_ARGS():
    """Call with arguments"""
    return struct.pack('<BBHI', 0xe0, 0, 0, 0)

def BPF_RAW_INSN(code, dst, src, off, imm):
    """Raw instruction"""
    return struct.pack('<BBHI', code & 0xFF, ((src & 0xF) << 4) | (dst & 0xF), off & 0xFFFF, imm & 0xFFFFFFFF)

def BPF_EMIT_CALL(func_id):
    """Emit a call instruction to a BPF function"""
    return struct.pack('<BBHI', BPF_JMP | BPF_CALL, 0, 0, func_id & 0xFFFFFFFF)

# Special offset value for per-CPU moves
BPF_ADDR_PERCPU = -1  # Same as in filter.h

def BPF_MOV64_PERCPU_REG(dst, src):
    """Special form of mov for per-CPU addresses: dst_reg = src_reg + <percpu_base_off>
    
    Args:
        dst: Destination register number
        src: Source register number
    Returns:
        Packed instruction bytes (8 bytes)
    """
    return struct.pack('<BBHI', 
                      BPF_ALU64 | BPF_MOV | BPF_X,  # opcode
                      (src << 4) | dst,             # dst and src registers
                      BPF_ADDR_PERCPU & 0xFFFF,     # special offset
                      0)                            # imm

# ==================== Special Instructions ====================
BPF_NOSPEC = 0xc0  # Speculation barrier
BPF_CALL_ARGS = 0xe0  # Call with arguments

# ==================== Call Instructions ====================

def BPF_CALL_KFUNC(off, imm):
    """Emit a BPF kfunc call instruction.
    
    Args:
        off: Offset field
        imm: Immediate value (kfunc ID)
    
    Returns:
        bytes: The encoded kfunc call instruction
    """
    return struct.pack('<BBHI', 
                      BPF_JMP | BPF_CALL, 
                      BPF_PSEUDO_KFUNC_CALL, 
                      off & 0xFFFF, 
                      imm & 0xFFFFFFFF)

def BPF_ST_NOSPEC():
    """Emit a speculation barrier instruction (ST NOSPEC).
    
    Returns:
        bytes: The encoded speculation barrier instruction
    """
    return struct.pack('<BBHI', BPF_ST | BPF_NOSPEC, 0, 0, 0)



###############################################################################
#                             HELPER FUNCTIONS                               #
###############################################################################


BPF_FUNC_map_lookup_elem = 1
BPF_FUNC_map_update_elem = 2
BPF_FUNC_map_delete_elem = 3
BPF_FUNC_probe_read = 4
BPF_FUNC_ktime_get_ns = 5
BPF_FUNC_trace_printk = 6
BPF_FUNC_get_prandom_u32 = 7
BPF_FUNC_get_smp_processor_id = 8
BPF_FUNC_skb_store_bytes = 9
BPF_FUNC_l3_csum_replace = 10
BPF_FUNC_l4_csum_replace = 11
BPF_FUNC_tail_call = 12
BPF_FUNC_clone_redirect = 13
BPF_FUNC_get_current_pid_tgid = 14
BPF_FUNC_get_current_uid_gid = 15
BPF_FUNC_get_current_comm = 16
BPF_FUNC_get_cgroup_classid = 17
BPF_FUNC_skb_vlan_push = 18
BPF_FUNC_skb_vlan_pop = 19
BPF_FUNC_skb_get_tunnel_key = 20
BPF_FUNC_skb_set_tunnel_key = 21
BPF_FUNC_perf_event_read = 22
BPF_FUNC_redirect = 23
BPF_FUNC_get_route_realm = 24
BPF_FUNC_perf_event_output = 25
BPF_FUNC_skb_load_bytes = 26
BPF_FUNC_get_stackid = 27
BPF_FUNC_csum_diff = 28
BPF_FUNC_skb_get_tunnel_opt = 29
BPF_FUNC_skb_set_tunnel_opt = 30
BPF_FUNC_skb_change_proto = 31
BPF_FUNC_skb_change_type = 32
BPF_FUNC_skb_under_cgroup = 33
BPF_FUNC_get_hash_recalc = 34
BPF_FUNC_get_current_task = 35
BPF_FUNC_probe_write_user = 36
BPF_FUNC_current_task_under_cgroup = 37
BPF_FUNC_skb_change_tail = 38
BPF_FUNC_skb_pull_data = 39
BPF_FUNC_csum_update = 40
BPF_FUNC_set_hash_invalid = 41
BPF_FUNC_get_numa_node_id = 42
BPF_FUNC_skb_change_head = 43
BPF_FUNC_xdp_adjust_head = 44
BPF_FUNC_probe_read_str = 45
BPF_FUNC_get_socket_cookie = 46
BPF_FUNC_get_socket_uid = 47
BPF_FUNC_set_hash = 48
BPF_FUNC_setsockopt = 49
BPF_FUNC_skb_adjust_room = 50
BPF_FUNC_redirect_map = 51
BPF_FUNC_sk_redirect_map = 52
BPF_FUNC_sock_map_update = 53
BPF_FUNC_xdp_adjust_meta = 54
BPF_FUNC_perf_event_read_value = 55
BPF_FUNC_perf_prog_read_value = 56
BPF_FUNC_getsockopt = 57
BPF_FUNC_override_return = 58
BPF_FUNC_sock_ops_cb_flags_set = 59
BPF_FUNC_msg_redirect_map = 60
BPF_FUNC_msg_apply_bytes = 61
BPF_FUNC_msg_cork_bytes = 62
BPF_FUNC_msg_pull_data = 63
BPF_FUNC_bind = 64
BPF_FUNC_xdp_adjust_tail = 65
BPF_FUNC_skb_get_xfrm_state = 66
BPF_FUNC_get_stack = 67
BPF_FUNC_skb_load_bytes_relative = 68
BPF_FUNC_fib_lookup = 69
BPF_FUNC_sock_hash_update = 70
BPF_FUNC_msg_redirect_hash = 71
BPF_FUNC_sk_redirect_hash = 72
BPF_FUNC_lwt_push_encap = 73
BPF_FUNC_lwt_seg6_store_bytes = 74
BPF_FUNC_lwt_seg6_adjust_srh = 75
BPF_FUNC_lwt_seg6_action = 76
BPF_FUNC_rc_repeat = 77
BPF_FUNC_rc_keydown = 78
BPF_FUNC_skb_cgroup_id = 79
BPF_FUNC_get_current_cgroup_id = 80
BPF_FUNC_get_local_storage = 81
BPF_FUNC_sk_select_reuseport = 82
BPF_FUNC_skb_ancestor_cgroup_id = 83
BPF_FUNC_sk_lookup_tcp = 84
BPF_FUNC_sk_lookup_udp = 85
BPF_FUNC_sk_release = 86
BPF_FUNC_map_push_elem = 87
BPF_FUNC_map_pop_elem = 88
BPF_FUNC_map_peek_elem = 89
BPF_FUNC_msg_push_data = 90
BPF_FUNC_msg_pop_data = 91
BPF_FUNC_rc_pointer_rel = 92
BPF_FUNC_spin_lock = 93
BPF_FUNC_spin_unlock = 94
BPF_FUNC_sk_fullsock = 95
BPF_FUNC_tcp_sock = 96
BPF_FUNC_skb_ecn_set_ce = 97
BPF_FUNC_get_listener_sock = 98
BPF_FUNC_skc_lookup_tcp = 99
BPF_FUNC_tcp_check_syncookie = 100
BPF_FUNC_sysctl_get_name = 101
BPF_FUNC_sysctl_get_current_value = 102
BPF_FUNC_sysctl_get_new_value = 103
BPF_FUNC_sysctl_set_new_value = 104
BPF_FUNC_strtol = 105
BPF_FUNC_strtoul = 106
BPF_FUNC_sk_storage_get = 107
BPF_FUNC_sk_storage_delete = 108
BPF_FUNC_send_signal = 109
BPF_FUNC_tcp_gen_syncookie = 110
BPF_FUNC_skb_output = 111
BPF_FUNC_probe_read_user = 112
BPF_FUNC_probe_read_kernel = 113
BPF_FUNC_probe_read_user_str = 114
BPF_FUNC_probe_read_kernel_str = 115
BPF_FUNC_tcp_send_ack = 116
BPF_FUNC_send_signal_thread = 117
BPF_FUNC_jiffies64 = 118
BPF_FUNC_read_branch_records = 119
BPF_FUNC_get_ns_current_pid_tgid = 120
BPF_FUNC_xdp_output = 121
BPF_FUNC_get_netns_cookie = 122
BPF_FUNC_get_current_ancestor_cgroup_id = 123
BPF_FUNC_sk_assign = 124
BPF_FUNC_ktime_get_boot_ns = 125
BPF_FUNC_seq_printf = 126
BPF_FUNC_seq_write = 127
BPF_FUNC_sk_cgroup_id = 128
BPF_FUNC_sk_ancestor_cgroup_id = 129
BPF_FUNC_ringbuf_output = 130
BPF_FUNC_ringbuf_reserve = 131
BPF_FUNC_ringbuf_submit = 132
BPF_FUNC_ringbuf_discard = 133
BPF_FUNC_ringbuf_query = 134
BPF_FUNC_csum_level = 135
BPF_FUNC_skc_to_tcp6_sock = 136
BPF_FUNC_skc_to_tcp_sock = 137
BPF_FUNC_skc_to_tcp_timewait_sock = 138
BPF_FUNC_skc_to_tcp_request_sock = 139
BPF_FUNC_skc_to_udp6_sock = 140
BPF_FUNC_get_task_stack = 141
BPF_FUNC_load_hdr_opt = 142
BPF_FUNC_store_hdr_opt = 143
BPF_FUNC_reserve_hdr_opt = 144
BPF_FUNC_inode_storage_get = 145
BPF_FUNC_inode_storage_delete = 146
BPF_FUNC_d_path = 147
BPF_FUNC_copy_from_user = 148
BPF_FUNC_snprintf_btf = 149
BPF_FUNC_seq_printf_btf = 150
BPF_FUNC_skb_cgroup_classid = 151
BPF_FUNC_redirect_neigh = 152
BPF_FUNC_per_cpu_ptr = 153
BPF_FUNC_this_cpu_ptr = 154
BPF_FUNC_redirect_peer = 155
BPF_FUNC_task_storage_get = 156
BPF_FUNC_task_storage_delete = 157
BPF_FUNC_get_current_task_btf = 158
BPF_FUNC_bprm_opts_set = 159
BPF_FUNC_ktime_get_coarse_ns = 160
BPF_FUNC_ima_inode_hash = 161
BPF_FUNC_sock_from_file = 162
BPF_FUNC_check_mtu = 163
BPF_FUNC_for_each_map_elem = 164
BPF_FUNC_snprintf = 165
BPF_FUNC_sys_bpf = 166
BPF_FUNC_btf_find_by_name_kind = 167
BPF_FUNC_sys_close = 168
BPF_FUNC_timer_init = 169
BPF_FUNC_timer_set_callback = 170
BPF_FUNC_timer_start = 171
BPF_FUNC_timer_cancel = 172
BPF_FUNC_get_func_ip = 173
BPF_FUNC_get_attach_cookie = 174
BPF_FUNC_task_pt_regs = 175
BPF_FUNC_get_branch_snapshot = 176
BPF_FUNC_trace_vprintk = 177
BPF_FUNC_skc_to_unix_sock = 178
BPF_FUNC_kallsyms_lookup_name = 179
BPF_FUNC_find_vma = 180
BPF_FUNC_loop = 181
BPF_FUNC_strncmp = 182
BPF_FUNC_get_func_arg = 183
BPF_FUNC_get_func_ret = 184
BPF_FUNC_get_func_arg_cnt = 185
BPF_FUNC_get_retval = 186
BPF_FUNC_set_retval = 187
BPF_FUNC_xdp_get_buff_len = 188
BPF_FUNC_xdp_load_bytes = 189
BPF_FUNC_xdp_store_bytes = 190
BPF_FUNC_copy_from_user_task = 191
BPF_FUNC_skb_set_tstamp = 192
BPF_FUNC_ima_file_hash = 193
BPF_FUNC_kptr_xchg = 194
BPF_FUNC_map_lookup_percpu_elem = 195
BPF_FUNC_skc_to_mptcp_sock = 196
BPF_FUNC_dynptr_from_mem = 197
BPF_FUNC_ringbuf_reserve_dynptr = 198
BPF_FUNC_ringbuf_submit_dynptr = 199
BPF_FUNC_ringbuf_discard_dynptr = 200
BPF_FUNC_dynptr_read = 201
BPF_FUNC_dynptr_write = 202
BPF_FUNC_dynptr_data = 203
BPF_FUNC_tcp_raw_gen_syncookie_ipv4 = 204
BPF_FUNC_tcp_raw_gen_syncookie_ipv6 = 205
BPF_FUNC_tcp_raw_check_syncookie_ipv4 = 206
BPF_FUNC_tcp_raw_check_syncookie_ipv6 = 207
BPF_FUNC_ktime_get_tai_ns = 208
BPF_FUNC_user_ringbuf_drain = 209
BPF_FUNC_cgrp_storage_get = 210
BPF_FUNC_cgrp_storage_delete = 211




def assemble(prog_list):
    """Assemble a list of instructions into bytecode"""
    return b''.join(prog_list)