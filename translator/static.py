from bpf_proto import *
import re
import os 
import json

BPF_SIZE = {
    0x00: 'BPF_W',
    0x08: 'BPF_H',
    0x10: 'BPF_B',
    0x18: 'BPF_DW',
}
# regs
BPF_REG=[
    'BPF_REG_0',
    'BPF_REG_1',
    'BPF_REG_2',
    'BPF_REG_3',
    'BPF_REG_4',
    'BPF_REG_5',
    'BPF_REG_6',
    'BPF_REG_7',
    'BPF_REG_8',
    'BPF_REG_9',
    'BPF_REG_10'
]

BPF_OP_ALU = {
    0x00: 'BPF_ADD',
    0x10: 'BPF_SUB',
    0x20: 'BPF_MUL',
    0x30: 'BPF_DIV',
    0x40: 'BPF_OR',
    0x50: 'BPF_AND',
    0x60: 'BPF_LSH',
    0x70: 'BPF_RSH',
    0x80: 'BPF_NEG',
    0x90: 'BPF_MOD',
    0xa0: 'BPF_XOR',
    0xb0: 'BPF_MOV',
    0xc0: 'BPF_ARSH',
    0xd0: 'BPF_END',
}

# helpers
BPF_FUNC=[
    "BPF_FUNC_unspec",
    "BPF_FUNC_map_lookup_elem",
    "BPF_FUNC_map_update_elem",
    "BPF_FUNC_map_delete_elem",
    "BPF_FUNC_probe_read",
    "BPF_FUNC_ktime_get_ns",
    "BPF_FUNC_trace_printk",
    "BPF_FUNC_get_prandom_u32",
    "BPF_FUNC_get_smp_processor_id",
    "BPF_FUNC_skb_store_bytes",
    "BPF_FUNC_l3_csum_replace",
    "BPF_FUNC_l4_csum_replace",
    "BPF_FUNC_tail_call",
    "BPF_FUNC_clone_redirect",
    "BPF_FUNC_get_current_pid_tgid",
    "BPF_FUNC_get_current_uid_gid",
    "BPF_FUNC_get_current_comm",
    "BPF_FUNC_get_cgroup_classid",
    "BPF_FUNC_skb_vlan_push",
    "BPF_FUNC_skb_vlan_pop",
    "BPF_FUNC_skb_get_tunnel_key",
    "BPF_FUNC_skb_set_tunnel_key",
    "BPF_FUNC_perf_event_read",
    "BPF_FUNC_redirect",
    "BPF_FUNC_get_route_realm",
    "BPF_FUNC_perf_event_output",
    "BPF_FUNC_skb_load_bytes",
    "BPF_FUNC_get_stackid",
    "BPF_FUNC_csum_diff",
    "BPF_FUNC_skb_get_tunnel_opt",
    "BPF_FUNC_skb_set_tunnel_opt",
    "BPF_FUNC_skb_change_proto",
    "BPF_FUNC_skb_change_type",
    "BPF_FUNC_skb_under_cgroup",
    "BPF_FUNC_get_hash_recalc",
    "BPF_FUNC_get_current_task",
    "BPF_FUNC_probe_write_user",
    "BPF_FUNC_current_task_under_cgroup",
    "BPF_FUNC_skb_change_tail",
    "BPF_FUNC_skb_pull_data",
    "BPF_FUNC_csum_update",
    "BPF_FUNC_set_hash_invalid",
    "BPF_FUNC_get_numa_node_id",
    "BPF_FUNC_skb_change_head",
    "BPF_FUNC_xdp_adjust_head",
    "BPF_FUNC_probe_read_str",
    "BPF_FUNC_get_socket_cookie",
    "BPF_FUNC_get_socket_uid",
    "BPF_FUNC_set_hash",
    "BPF_FUNC_setsockopt",
    "BPF_FUNC_skb_adjust_room",
    "BPF_FUNC_redirect_map",
    "BPF_FUNC_sk_redirect_map",
    "BPF_FUNC_sock_map_update",
    "BPF_FUNC_xdp_adjust_meta",
    "BPF_FUNC_perf_event_read_value",
    "BPF_FUNC_perf_prog_read_value",
    "BPF_FUNC_getsockopt",
    "BPF_FUNC_override_return",
    "BPF_FUNC_sock_ops_cb_flags_set",
    "BPF_FUNC_msg_redirect_map",
    "BPF_FUNC_msg_apply_bytes",
    "BPF_FUNC_msg_cork_bytes",
    "BPF_FUNC_msg_pull_data",
    "BPF_FUNC_bind",
    "BPF_FUNC_xdp_adjust_tail",
    "BPF_FUNC_skb_get_xfrm_state",
    "BPF_FUNC_get_stack",
    "BPF_FUNC_skb_load_bytes_relative",
    "BPF_FUNC_fib_lookup",
    "BPF_FUNC_sock_hash_update",
    "BPF_FUNC_msg_redirect_hash",
    "BPF_FUNC_sk_redirect_hash",
    "BPF_FUNC_lwt_push_encap",
    "BPF_FUNC_lwt_seg6_store_bytes",
    "BPF_FUNC_lwt_seg6_advert_srh",
    "BPF_FUNC_lwt_seg6_action",
    "BPF_FUNC_rc_repeat",
    "BPF_FUNC_rc_keydown",
    "BPF_FUNC_skb_cgroup_id",
    "BPF_FUNC_get_current_cgroup_id",
    "BPF_FUNC_get_local_storage",
    "BPF_FUNC_sk_select_reuseport",
    "BPF_FUNC_skb_ancestor_cgroup_id",
    "BPF_FUNC_sk_lookup_tcp",
    "BPF_FUNC_sk_lookup_udp",
    "BPF_FUNC_sk_release",
    "BPF_FUNC_map_push_elem",
    "BPF_FUNC_map_pop_elem",
    "BPF_FUNC_map_peek_elem",
    "BPF_FUNC_msg_push_data",
    "BPF_FUNC_msg_pop_data",
    "BPF_FUNC_rc_pointer_rel",
    "BPF_FUNC_spin_lock",
    "BPF_FUNC_spin_unlock",
    "BPF_FUNC_sk_fullsock",
    "BPF_FUNC_tcp_sock",
    "BPF_FUNC_skb_ecn_set_ce",
    "BPF_FUNC_get_listener_sock",
    "BPF_FUNC_skc_lookup_tcp",
    "BPF_FUNC_tcp_check_syncookie",
    "BPF_FUNC_sysctl_get_name",
    "BPF_FUNC_sysctl_get_current_value",
    "BPF_FUNC_sysctl_get_new_value",
    "BPF_FUNC_sysctl_set_new_value",
    "BPF_FUNC_strtol",
    "BPF_FUNC_strtoul",
    "BPF_FUNC_sk_storage_get",
    "BPF_FUNC_sk_storage_delete",
    "BPF_FUNC_send_signal",
    "BPF_FUNC_tcp_gen_syncookie",
    "BPF_FUNC_skb_output",
    "BPF_FUNC_probe_read_user",
    "BPF_FUNC_probe_read_kernel",
    "BPF_FUNC_probe_read_user_str",
    "BPF_FUNC_probe_read_kernel_str",
    "BPF_FUNC_tcp_send_ack",
    "BPF_FUNC_send_signal_thread",
    "BPF_FUNC_jiffies64",
    "BPF_FUNC_read_branch_records",
    "BPF_FUNC_get_ns_current_pid_tgid",
    "BPF_FUNC_xdp_output",
    "BPF_FUNC_get_netns_cookie",
    "BPF_FUNC_get_current_ancestor_cgroup_id",
    "BPF_FUNC_sk_assign",
    "BPF_FUNC_ktime_get_boot_ns",
    "BPF_FUNC_seq_printf",
    "BPF_FUNC_seq_write",
    "BPF_FUNC_sk_cgroup_id",
    "BPF_FUNC_sk_ancestor_cgroup_id",
    "BPF_FUNC_ringbuf_output",
    "BPF_FUNC_ringbuf_reserve",
    "BPF_FUNC_ringbuf_submit",
    "BPF_FUNC_ringbuf_discard",
    "BPF_FUNC_ringbuf_query",
    "BPF_FUNC_csum_level",
    "BPF_FUNC_skc_to_tcp6_sock",
    "BPF_FUNC_skc_to_tcp_sock",
    "BPF_FUNC_skc_to_tcp_timewait_sock",
    "BPF_FUNC_skc_to_tcp_request_sock",
    "BPF_FUNC_skc_to_udp6_sock",
    "BPF_FUNC_get_task_stack",
    "BPF_FUNC_load_hdr_opt",
    "BPF_FUNC_store_hdr_opt",
    "BPF_FUNC_reserve_hdr_opt",
    "BPF_FUNC_inode_storage_get",
    "BPF_FUNC_inode_storage_delete",
    "BPF_FUNC_d_path",
    "BPF_FUNC_copy_from_user",
    "BPF_FUNC_snprintf_btf",
    "BPF_FUNC_seq_printf_btf",
    "BPF_FUNC_skb_cgroup_classid",
    "BPF_FUNC_redirect_neigh",
    "BPF_FUNC_per_cpu_ptr",
    "BPF_FUNC_this_cpu_ptr",
    "BPF_FUNC_redirect_peer",
    "BPF_FUNC_task_storage_get",
    "BPF_FUNC_task_storage_delete",
    "BPF_FUNC_get_current_task_btf",
    "BPF_FUNC_bprm_opts_set",
    "BPF_FUNC_ktime_get_coarse_ns",
    "BPF_FUNC_ima_inode_hash",
    "BPF_FUNC_sock_from_file",
    "BPF_FUNC_check_mtu",
    "BPF_FUNC_for_each_map_elem",
    "BPF_FUNC_snprintf",
    "BPF_FUNC_sys_bpf",
    "BPF_FUNC_btf_find_by_name_kind",
    "BPF_FUNC_sys_close",
    "BPF_FUNC_timer_init",
    "BPF_FUNC_timer_set_callback",
    "BPF_FUNC_timer_start",
    "BPF_FUNC_timer_cancel",
    "BPF_FUNC_get_func_ip",
    "BPF_FUNC_get_attach_cookie",
    "BPF_FUNC_task_pt_regs",
    "BPF_FUNC_get_branch_snapshot",
    "BPF_FUNC_trace_vprintk",
    "BPF_FUNC_skc_to_unix_sock",
    "BPF_FUNC_kallsyms_lookup_name",
    "BPF_FUNC_find_vma",
    "BPF_FUNC_loop",
    "BPF_FUNC_strncmp",
    "BPF_FUNC_get_func_arg",
    "BPF_FUNC_get_func_ret",
    "BPF_FUNC_get_func_arg_cnt",
    "BPF_FUNC_get_retval",
    "BPF_FUNC_set_retval",
    "BPF_FUNC_xdp_get_buff_len",
    "BPF_FUNC_xdp_load_bytes",
    "BPF_FUNC_xdp_store_bytes",
    "BPF_FUNC_copy_from_user_task",
    "BPF_FUNC_skb_set_tstamp",
    "BPF_FUNC_ima_file_hash",
    "BPF_FUNC_kptr_xchg",
    "BPF_FUNC_map_lookup_percpu_elem",
    "BPF_FUNC_skc_to_mptcp_sock",
    "BPF_FUNC_dynptr_from_mem",
    "BPF_FUNC_ringbuf_reserve_dynptr",
    "BPF_FUNC_ringbuf_submit_dynptr",
    "BPF_FUNC_ringbuf_discard_dynptr",
    "BPF_FUNC_dynptr_read",
    "BPF_FUNC_dynptr_write",
    "BPF_FUNC_dynptr_data",
    "BPF_FUNC_tcp_raw_gen_syncookie_ipv4",
    "BPF_FUNC_tcp_raw_gen_syncookie_ipv6",
    "BPF_FUNC_tcp_raw_check_syncookie_ipv4",
    "BPF_FUNC_tcp_raw_check_syncookie_ipv6",
    "BPF_FUNC_ktime_get_tai_ns",
    "BPF_FUNC_user_ringbuf_drain",
    "BPF_FUNC_cgrp_storage_get",
    "BPF_FUNC_cgrp_storage_delete"
]

BPF_OP_ALU = {
    0x00: 'BPF_ADD',
    0x10: 'BPF_SUB',
    0x20: 'BPF_MUL',
    0x30: 'BPF_DIV',
    0x40: 'BPF_OR',
    0x50: 'BPF_AND',
    0x60: 'BPF_LSH',
    0x70: 'BPF_RSH',
    0x80: 'BPF_NEG',
    0x90: 'BPF_MOD',
    0xa0: 'BPF_XOR',
    0xb0: 'BPF_MOV',
    0xc0: 'BPF_ARSH',
    0xd0: 'BPF_END',
}

BPF_OP_JMP = {
    0x00: 'BPF_JA',
    0x10: 'BPF_JEQ',
    0x20: 'BPF_JGT',
    0x30: 'BPF_JGE',
    0x40: 'BPF_JSET',
    0x50: 'BPF_JNE',
    0x60: 'BPF_JSGT',
    0x70: 'BPF_JSGE',
    0x80: 'BPF_CALL',
    0x90: 'BPF_EXIT',
    0xa0: 'BPF_JLT',
    0xb0: 'BPF_JLE',
    0xc0: 'BPF_JSLT',
    0xd0: 'BPF_JSLE',
}


def BPF_ALU64_INSN(code, dst, src, off, imm):
    op = code & 0xF0
    src_type = code & 0x08
    op_str = BPF_OP_ALU.get(op, 'BPF_UNKNOWN_ALU_OP')
    if op == BPF_MOV:
        '''
        MOV64 instruction
        BPF_MOV64_REG
        BPF_MOV64_IMM
        BPF_MOV64_PERCPU_REG
        BPF_MOVSX64_REG
        '''
        if src_type == BPF_K:
            return f"BPF_MOV64_IMM({BPF_REG[dst]}, 0x{imm:x})"
        elif src_type == BPF_X:
            if off==0 and imm==0:
                return f"BPF_MOV64_REG({BPF_REG[dst]}, {BPF_REG[src]})"
            elif off!=0 and imm==0:
                if off==BPF_ADDR_PERCPU:
                    return f"BPF_MOV64_PERCPU_REG({BPF_REG[dst]}, {BPF_REG[src]})"
                else:
                    return f"BPF_MOVSX64_REG(BPF_REG[{dst}], BPF_REG[{src}], {off})"
    elif op == BPF_END:
        '''
        BPF_BSWAP
        '''
        return f"BPF_BSWAP({BPF_REG[dst]}, 0x{imm:x})"
    else:
        '''
        BPF_ALU64_REG_OFF
        BPF_ALU64_REG
        BPF_ALU64_IMM
        BPF_ALU64_IMM_OFF

        '''
        if src_type == BPF_K:
            if off == 0:
                return f"BPF_ALU64_IMM({op_str}, {BPF_REG[dst]}, 0x{imm:x})"
            else:
                return f"BPF_ALU64_IMM_OFF({op_str}, {BPF_REG[dst]}, {off}, 0x{imm:x})"
        elif src_type == BPF_X:
            if off == 0:
                return f"BPF_ALU64_REG({op_str}, {BPF_REG[dst]}, {BPF_REG[src]})"
            else:
                return f"BPF_ALU64_REG_OFF({op_str}, {BPF_REG[dst]}, {BPF_REG[src]}, {off})"
    
def BPF_JMP32_INSN(code, dst, src, off, imm):
    op = code & 0xF0  # Extract opcode
    src_type = code & 0x08  # Determine source type (BPF_X/BPF_K)
    op_str = BPF_OP_JMP.get(op, 'BPF_UNKNOWN_JMP32_OP')
    '''
    BPF_JMP32_REG
    BPF_JMP32_IMM
    BPF_JMP32_A
    '''
    
    # Handle unconditional jump
    if op == BPF_JA:
        return f"BPF_JMP32_A(0x{imm:x})"
    
    # Handle conditional jump
    if src_type == BPF_K:
        # Immediate comparison (BPF_JMP32_IMM)
        return f"BPF_JMP32_IMM({op_str}, {BPF_REG[dst]}, 0x{imm:x}, {off})"
    else:
        # Register comparison (BPF_JMP32_REG)
        return f"BPF_JMP32_REG({op_str}, {BPF_REG[dst]}, {BPF_REG[src]}, {off})"


def BPF_JMP_INSN(code, dst, src, off, imm):
    op = code & 0xF0
    src_type = code & 0x08
    op_str = BPF_OP_JMP.get(op, 'BPF_UNKNOWN_JMP_OP')
    
    # Instruction type decision tree
    if op == BPF_JA:
        return f"BPF_JMP_A({off})"
    
    elif op == BPF_CALL:
        if src == BPF_PSEUDO_CALL:
            return f"BPF_CALL_REL(0x{imm:x})"
        elif src == BPF_PSEUDO_KFUNC_CALL:
            return f"BPF_CALL_KFUNC({off}, 0x{imm:x})"
        else:
            return f"BPF_EMIT_CALL({BPF_FUNC[imm%212]})"
    
    elif op == BPF_EXIT:
        return "BPF_EXIT_INSN()"
    
    # Conditional jump handling
    elif op in (BPF_JEQ, BPF_JGT, BPF_JGE, BPF_JLT, BPF_JLE, 
                BPF_JSET, BPF_JNE, BPF_JSGT, BPF_JSGE, 
                BPF_JSLT, BPF_JSLE):
        if src_type == BPF_K:
            return f"BPF_JMP_IMM({op_str}, {BPF_REG[dst]}, 0x{imm:x}, {off})"
        else:
            # Register comparison requires checking special cases
            if off == BPF_ADDR_PERCPU and imm == 0:
                return f"BPF_JMP_PERCPU_REG({op_str}, {BPF_REG[dst]}, {BPF_REG[src]})"
            return f"BPF_JMP_REG({op_str}, {BPF_REG[dst]}, {BPF_REG[src]}, {off})"
    
    # Illegal instruction handling
    else:
        return f"BPF_JMP_ILLEGAL({code}, {dst}, {src}, {off}, 0x{imm:x})"

def BPF_ALU_INSN(code, dst, src, off, imm):
    op = code & 0xF0  # Extract main opcode
    src_type = code & 0x08  # Determine source type (BPF_X/BPF_K)
    op_str = BPF_OP_ALU.get(op, 'BPF_UNKNOWN_ALU_OP')
    
    # Special instruction handling
    if op == BPF_MOV:
        '''
        MOV32 instruction
        BPF_MOV32_REG
        BPF_MOV32_IMM
        BPF_ZEXT_REG
        BPF_MOVSX32_REG
        '''


        if src_type == BPF_K:
            return f"BPF_MOV32_IMM({BPF_REG[dst]}, 0x{imm:x})"
        elif src_type == BPF_X:
            if off == 0 and imm == 0:
                return f"BPF_MOV32_REG({BPF_REG[dst]}, {BPF_REG[src]})"
            elif off != 0 and imm == 0:
                return f"BPF_MOVSX32_REG({BPF_REG[dst]}, {BPF_REG[src]}, {off})"
            
            if dst == src and off == 0 and imm == 1:
                return f"BPF_ZEXT_REG({BPF_REG[dst]})"
    
    elif op == BPF_END:
        # END instruction behaves differently in 32-bit mode (usually for byte order conversion)
        return f"BPF_ENDIAN(BPF_TO_{'LE' if imm == 16 else 'BE'}, {BPF_REG[dst]}, {imm})"
    
    elif op == BPF_NEG:
        # 32-bit negation instruction
        return f"BPF_ALU32_REG(BPF_NEG, {BPF_REG[dst]}, 0)"
    
    # Standard ALU operations
    else:
        if src_type == BPF_K:
            if off == 0:
                return f"BPF_ALU32_IMM({op_str}, {BPF_REG[dst]}, 0x{imm:x})"
            else:
                return f"BPF_ALU32_IMM_OFF({op_str}, {BPF_REG[dst]}, {off}, 0x{imm:x})"
        elif src_type == BPF_X:
            if off == 0:
                return f"BPF_ALU32_REG({op_str}, {BPF_REG[dst]}, {BPF_REG[src]})"
            else:
                return f"BPF_ALU32_REG_OFF({op_str}, {BPF_REG[dst]}, {BPF_REG[src]}, {off})"

def BPF_STX_INSN(code, dst, src, off, imm):
    size= code & 0x18
    size_str = BPF_SIZE.get(size, 'BPF_UNKNOWN_SIZE')
    op_str = BPF_OP_ALU.get(imm, 'BPF_UNKNOWN_STX_OP')
    mode = code & 0xe0

    if mode == BPF_MEM:
        return f"BPF_STX_MEM({size_str}, {BPF_REG[dst]}, {BPF_REG[src]}, {off})"
    
    elif mode == BPF_ATOMIC:
        return f"BPF_ATOMIC_OP({size_str}, {op_str}, {BPF_REG[dst]}, {BPF_REG[src]}, {off})"




def BPF_ST_INSN(code, dst, src, off, imm):
    size= code & 0x18
    size_str = BPF_SIZE.get(size, 'BPF_UNKNOWN_SIZE')
    op_str = BPF_OP_ALU.get(imm, 'BPF_UNKNOWN_STX_OP')
    mode = code & 0xe0
    if mode == BPF_MEM:
        return f"BPF_ST_MEM({size_str}, {BPF_REG[dst]}, {off}, 0x{imm:x})"
    return f"BPF_ST_ILLEGAL({code}, {dst}, {src}, {off}, 0x{imm:x})"
    
def BPF_LDX_INSN(code, dst, src, off, imm):
    size = code & 0x18  # Extract operand size (BPF_B/BPF_H/BPF_W/BPF_DW)
    size_str = BPF_SIZE.get(size, 'BPF_UNKNOWN_SIZE')
    mode = code & 0xe0  # Extract load mode (BPF_MEM/BPF_MEMSX)
    
    
    # Regular memory load
    if mode == BPF_MEM:
        return f"BPF_LDX_MEM({size_str}, {BPF_REG[dst]}, {BPF_REG[src]}, {off})"
    
    # Memory load with sign extension
    elif mode == BPF_MEMSX:
        return f"BPF_LDX_MEMSX({size_str}, {BPF_REG[dst]}, {BPF_REG[src]}, {off})"
    
    # Illegal load mode
    else:
        return f"BPF_LDX_ILLEGAL({code}, {dst}, {src}, {off}, 0x{imm:x})"


def BPF_LD_INSN(code, dst, src, off, imm):
    # imm may be 64-bit
    mode = code & 0xE0  # Extract load mode (BPF_ABS/BPF_IND/BPF_IMM)
    size = code & 0x18  # Extract operand size (BPF_W/BPF_DW)
    size_str = BPF_SIZE.get(size, 'BPF_UNKNOWN_SIZE')
    '''
    
    BPF_LD_ABS
    BPF_LD_IND
    BPF_LD_IMM64_RAW
    BPF_LD_IMM64
    BPF_LD_MAP_FD


    '''
    
    # Absolute load (LD_ABS)
    if mode == BPF_ABS:
        return f"BPF_LD_ABS({size_str}, 0x{imm:x})"
    
    # Indirect load (LD_IND)
    elif mode == BPF_IND:
        return f"BPF_LD_IND({size_str}, {BPF_REG[src]}, 0x{imm:x})"
    
    elif mode == BPF_IMM:
        if size == BPF_DW:
            # Special handling: if imm is 0 and dst is Reg1, then it's BPF_LD_MAP_FD
            if imm ==0 and dst == 1:
                return f"BPF_LD_MAP_FD({BPF_REG[dst]}, 0x{imm:x})"
            
            
            if src == 0:
                return f"BPF_LD_IMM64({BPF_REG[dst]}, 0x{imm:x})"
            elif src == BPF_PSEUDO_MAP_FD:
                return f"BPF_LD_MAP_FD({BPF_REG[dst]}, 0x{imm:x})"
            else :
                return f"BPF_LD_IMM64_RAW({BPF_REG[dst]}, {BPF_REG[src]}, 0x{imm:x})"     
    
    else:
        return f"BPF_LD_ILLEGAL({code}, {dst}, {src}, {off}, 0x{imm:x})"

def disassemble_bpf(code, dst, src, off, imm):
    base_code = code & 0x07
    match base_code:
        case 0x07 :
            return BPF_ALU64_INSN(code, dst, src, off, imm)
        case 0x06 :
            return BPF_JMP32_INSN(code, dst, src, off, imm)
        case 0x05 :
            return BPF_JMP_INSN(code, dst, src, off, imm)
        case 0x04 :
            return BPF_ALU_INSN(code, dst, src, off, imm)
        case 0x03 :
            return BPF_STX_INSN(code, dst, src, off, imm)
        case 0x02 :
            return BPF_ST_INSN(code, dst, src, off, imm)
        case 0x01 :
            return BPF_LDX_INSN(code, dst, src, off, imm)
        case 0x00 :
            return BPF_LD_INSN(code, dst, src, off, imm)



def static(content,output_file:str = ""):
    # Statistics function to count instructions and helper functions
    # Input is in IR format
    pattern = r'(BPF_[A-Z0-9_]+\([^)]*\),)'
    instructions = re.findall(pattern, content)
    print(instructions)
    for i in range(len(instructions)):
        instructions[i] = instructions[i].split('(')[0]
    print(instructions)
    helper_func = re.findall(r'BPF_FUNC_[A-Z0-9_]+', content)
    print(helper_func)
    if output_file!="":
        with open(output_file, 'w') as f:
            json.dump(instructions, f, ensure_ascii=False, indent=4)
            print(f"Result data has been saved to {output_file}")


if __name__ == "__main__":
    # Get command line arguments
    # Input file path
    # Output file path, defaults to output.json
    content="""

    BPF_MOV64_IMM(BPF_REG_0, 0),"""
    static(content)
   

