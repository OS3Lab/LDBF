#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdio.h>
#include <stddef.h>
#include <linux/if_ether.h>
#include <linux/bpf.h>
#include "bpf_insn.h"
#include <linux/btf.h>
#include <linux/types.h>

#define BTF_INFO_ENC(kind, kind_flag, vlen) \
	((!!(kind_flag) << 31) | ((kind) << 24) | ((vlen) & BTF_MAX_VLEN))
#define BTF_TYPE_ENC(name, info, size_or_type) (name), (info), (size_or_type)
#define BTF_INT_ENC(encoding, bits_offset, nr_bits) \
	((encoding) << 24 | (bits_offset) << 16 | (nr_bits))
#define BTF_TYPE_INT_ENC(name, encoding, bits_offset, bits, sz) \
	BTF_TYPE_ENC(name, BTF_INFO_ENC(BTF_KIND_INT, 0, 0), sz), \
	BTF_INT_ENC(encoding, bits_offset, bits)
#define BTF_MEMBER_ENC(name, type, bits_offset) (name), (type), (bits_offset)
#define BTF_PARAM_ENC(name, type) (name), (type)
#define BTF_VAR_SECINFO_ENC(type, offset, size) (type), (offset), (size)
#define BTF_TYPE_FLOAT_ENC(name, sz) \
	BTF_TYPE_ENC(name, BTF_INFO_ENC(BTF_KIND_FLOAT, 0, 0), sz)
#define BTF_TYPE_DECL_TAG_ENC(value, type, component_idx) \
	BTF_TYPE_ENC(value, BTF_INFO_ENC(BTF_KIND_DECL_TAG, 0, 0), type), (component_idx)
#define BTF_TYPE_TYPE_TAG_ENC(value, type) \
	BTF_TYPE_ENC(value, BTF_INFO_ENC(BTF_KIND_TYPE_TAG, 0, 0), type)

// #define offsetof(type, member)	__builtin_offsetof(type, member)
#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))

#define BPF_NETFILTER 45
#define BPF_PROG_TYPE_NETFILTER 32

#define BPF_MAP_TYPE_UNSPEC 0
#define BPF_MAP_TYPE_HASH 1
#define BPF_MAP_TYPE_ARRAY 2
#define BPF_MAP_TYPE_PROG_ARRAY 3
#define BPF_MAP_TYPE_PERF_EVENT_ARRAY 4
#define BPF_MAP_TYPE_PERCPU_HASH 5
#define BPF_MAP_TYPE_PERCPU_ARRAY 6
#define BPF_MAP_TYPE_STACK_TRACE 7
#define BPF_MAP_TYPE_CGROUP_ARRAY 8
#define BPF_MAP_TYPE_LRU_HASH 9
#define BPF_MAP_TYPE_LRU_PERCPU_HASH 10
#define BPF_MAP_TYPE_LPM_TRIE 11
#define BPF_MAP_TYPE_ARRAY_OF_MAPS 12
#define BPF_MAP_TYPE_HASH_OF_MAPS 13
#define BPF_MAP_TYPE_DEVMAP 14
#define BPF_MAP_TYPE_SOCKMAP 15
#define BPF_MAP_TYPE_CPUMAP 16
#define BPF_MAP_TYPE_XSKMAP 17
#define BPF_MAP_TYPE_SOCKHASH 18
#define BPF_MAP_TYPE_CGROUP_STORAGE 19
#define BPF_MAP_TYPE_REUSEPORT_SOCKARRAY 20
#define BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE 21
#define BPF_MAP_TYPE_QUEUE 22
#define BPF_MAP_TYPE_STACK 23
#define BPF_MAP_TYPE_SK_STORAGE 24
#define BPF_MAP_TYPE_DEVMAP_HASH 25
#define BPF_MAP_TYPE_STRUCT_OPS 26
#define BPF_MAP_TYPE_RINGBUF 27
#define BPF_MAP_TYPE_INODE_STORAGE 28
#define BPF_MAP_TYPE_TASK_STORAGE 29
#define BPF_MAP_TYPE_BLOOM_FILTER 30
#define BPF_MAP_TYPE_USER_RINGBUF 31
#define BPF_MAP_TYPE_CGRP_STORAGE 32
#define BPF_MAP_TYPE_ARENA 33

#define BPF_F_XDP_HAS_FRAGS	(1U << 5)

#define BPF_FUNC_unspec 0
#define BPF_FUNC_map_lookup_elem 1
#define BPF_FUNC_map_update_elem 2
#define BPF_FUNC_map_delete_elem 3
#define BPF_FUNC_probe_read 4
#define BPF_FUNC_ktime_get_ns 5
#define BPF_FUNC_trace_printk 6
#define BPF_FUNC_get_prandom_u32 7
#define BPF_FUNC_get_smp_processor_id 8
#define BPF_FUNC_skb_store_bytes 9
#define BPF_FUNC_l3_csum_replace 10
#define BPF_FUNC_l4_csum_replace 11
#define BPF_FUNC_tail_call 12
#define BPF_FUNC_clone_redirect 13
#define BPF_FUNC_get_current_pid_tgid 14
#define BPF_FUNC_get_current_uid_gid 15
#define BPF_FUNC_get_current_comm 16
#define BPF_FUNC_get_cgroup_classid 17
#define BPF_FUNC_skb_vlan_push 18
#define BPF_FUNC_skb_vlan_pop 19
#define BPF_FUNC_skb_get_tunnel_key 20
#define BPF_FUNC_skb_set_tunnel_key 21
#define BPF_FUNC_perf_event_read 22
#define BPF_FUNC_redirect 23
#define BPF_FUNC_get_route_realm 24
#define BPF_FUNC_perf_event_output 25
#define BPF_FUNC_skb_load_bytes 26
#define BPF_FUNC_get_stackid 27
#define BPF_FUNC_csum_diff 28
#define BPF_FUNC_skb_get_tunnel_opt 29
#define BPF_FUNC_skb_set_tunnel_opt 30
#define BPF_FUNC_skb_change_proto 31
#define BPF_FUNC_skb_change_type 32
#define BPF_FUNC_skb_under_cgroup 33
#define BPF_FUNC_get_hash_recalc 34
#define BPF_FUNC_get_current_task 35
#define BPF_FUNC_probe_write_user 36
#define BPF_FUNC_current_task_under_cgroup 37
#define BPF_FUNC_skb_change_tail 38
#define BPF_FUNC_skb_pull_data 39
#define BPF_FUNC_csum_update 40
#define BPF_FUNC_set_hash_invalid 41
#define BPF_FUNC_get_numa_node_id 42
#define BPF_FUNC_skb_change_head 43
#define BPF_FUNC_xdp_adjust_head 44
#define BPF_FUNC_probe_read_str 45
#define BPF_FUNC_get_socket_cookie 46
#define BPF_FUNC_get_socket_uid 47
#define BPF_FUNC_set_hash 48
#define BPF_FUNC_setsockopt 49
#define BPF_FUNC_skb_adjust_room 50
#define BPF_FUNC_redirect_map 51
#define BPF_FUNC_sk_redirect_map 52
#define BPF_FUNC_sock_map_update 53
#define BPF_FUNC_xdp_adjust_meta 54
#define BPF_FUNC_perf_event_read_value 55
#define BPF_FUNC_perf_prog_read_value 56
#define BPF_FUNC_getsockopt 57
#define BPF_FUNC_override_return 58
#define BPF_FUNC_sock_ops_cb_flags_set 59
#define BPF_FUNC_msg_redirect_map 60
#define BPF_FUNC_msg_apply_bytes 61
#define BPF_FUNC_msg_cork_bytes 62
#define BPF_FUNC_msg_pull_data 63
#define BPF_FUNC_bind 64
#define BPF_FUNC_xdp_adjust_tail 65
#define BPF_FUNC_skb_get_xfrm_state 66
#define BPF_FUNC_get_stack 67
#define BPF_FUNC_skb_load_bytes_relative 68
#define BPF_FUNC_fib_lookup 69
#define BPF_FUNC_sock_hash_update 70
#define BPF_FUNC_msg_redirect_hash 71
#define BPF_FUNC_sk_redirect_hash 72
#define BPF_FUNC_lwt_push_encap 73
#define BPF_FUNC_lwt_seg6_store_bytes 74
#define BPF_FUNC_lwt_seg6_advert_srh 75
#define BPF_FUNC_lwt_seg6_action 76
#define BPF_FUNC_rc_repeat 77
#define BPF_FUNC_rc_keydown 78
#define BPF_FUNC_skb_cgroup_id 79
#define BPF_FUNC_get_current_cgroup_id 80
#define BPF_FUNC_get_local_storage 81
#define BPF_FUNC_sk_select_reuseport 82
#define BPF_FUNC_skb_ancestor_cgroup_id 83
#define BPF_FUNC_sk_lookup_tcp 84
#define BPF_FUNC_sk_lookup_udp 85
#define BPF_FUNC_sk_release 86
#define BPF_FUNC_map_push_elem 87
#define BPF_FUNC_map_pop_elem 88
#define BPF_FUNC_map_peek_elem 89
#define BPF_FUNC_msg_push_data 90
#define BPF_FUNC_msg_pop_data 91
#define BPF_FUNC_rc_pointer_rel 92
#define BPF_FUNC_spin_lock 93
#define BPF_FUNC_spin_unlock 94
#define BPF_FUNC_sk_fullsock 95
#define BPF_FUNC_tcp_sock 96
#define BPF_FUNC_skb_ecn_set_ce 97
#define BPF_FUNC_get_listener_sock 98
#define BPF_FUNC_skc_lookup_tcp 99
#define BPF_FUNC_tcp_check_syncookie 100
#define BPF_FUNC_sysctl_get_name 101
#define BPF_FUNC_sysctl_get_current_value 102
#define BPF_FUNC_sysctl_get_new_value 103
#define BPF_FUNC_sysctl_set_new_value 104
#define BPF_FUNC_strtol 105
#define BPF_FUNC_strtoul 106
#define BPF_FUNC_sk_storage_get 107
#define BPF_FUNC_sk_storage_delete 108
#define BPF_FUNC_send_signal 109
#define BPF_FUNC_tcp_gen_syncookie 110
#define BPF_FUNC_skb_output 111
#define BPF_FUNC_probe_read_user 112
#define BPF_FUNC_probe_read_kernel 113
#define BPF_FUNC_probe_read_user_str 114
#define BPF_FUNC_probe_read_kernel_str 115
#define BPF_FUNC_tcp_send_ack 116
#define BPF_FUNC_send_signal_thread 117
#define BPF_FUNC_jiffies64 118
#define BPF_FUNC_read_branch_records 119
#define BPF_FUNC_get_ns_current_pid_tgid 120
#define BPF_FUNC_xdp_output 121
#define BPF_FUNC_get_netns_cookie 122
#define BPF_FUNC_get_current_ancestor_cgroup_id 123
#define BPF_FUNC_sk_assign 124
#define BPF_FUNC_ktime_get_boot_ns 125
#define BPF_FUNC_seq_printf 126
#define BPF_FUNC_seq_write 127
#define BPF_FUNC_sk_cgroup_id 128
#define BPF_FUNC_sk_ancestor_cgroup_id 129
#define BPF_FUNC_ringbuf_output 130
#define BPF_FUNC_ringbuf_reserve 131
#define BPF_FUNC_ringbuf_submit 132
#define BPF_FUNC_ringbuf_discard 133
#define BPF_FUNC_ringbuf_query 134
#define BPF_FUNC_csum_level 135
#define BPF_FUNC_skc_to_tcp6_sock 136
#define BPF_FUNC_skc_to_tcp_sock 137
#define BPF_FUNC_skc_to_tcp_timewait_sock 138
#define BPF_FUNC_skc_to_tcp_request_sock 139
#define BPF_FUNC_skc_to_udp6_sock 140
#define BPF_FUNC_get_task_stack 141
#define BPF_FUNC_load_hdr_opt 142
#define BPF_FUNC_store_hdr_opt 143
#define BPF_FUNC_reserve_hdr_opt 144
#define BPF_FUNC_inode_storage_get 145
#define BPF_FUNC_inode_storage_delete 146
#define BPF_FUNC_d_path 147
#define BPF_FUNC_copy_from_user 148
#define BPF_FUNC_snprintf_btf 149
#define BPF_FUNC_seq_printf_btf 150
#define BPF_FUNC_skb_cgroup_classid 151
#define BPF_FUNC_redirect_neigh 152
#define BPF_FUNC_per_cpu_ptr 153
#define BPF_FUNC_this_cpu_ptr 154
#define BPF_FUNC_redirect_peer 155
#define BPF_FUNC_task_storage_get 156
#define BPF_FUNC_task_storage_delete 157
#define BPF_FUNC_get_current_task_btf 158
#define BPF_FUNC_bprm_opts_set 159
#define BPF_FUNC_ktime_get_coarse_ns 160
#define BPF_FUNC_ima_inode_hash 161
#define BPF_FUNC_sock_from_file 162
#define BPF_FUNC_check_mtu 163
#define BPF_FUNC_for_each_map_elem 164
#define BPF_FUNC_snprintf 165
#define BPF_FUNC_sys_bpf 166
#define BPF_FUNC_btf_find_by_name_kind 167
#define BPF_FUNC_sys_close 168
#define BPF_FUNC_timer_init 169
#define BPF_FUNC_timer_set_callback 170
#define BPF_FUNC_timer_start 171
#define BPF_FUNC_timer_cancel 172
#define BPF_FUNC_get_func_ip 173
#define BPF_FUNC_get_attach_cookie 174
#define BPF_FUNC_task_pt_regs 175
#define BPF_FUNC_get_branch_snapshot 176
#define BPF_FUNC_trace_vprintk 177
#define BPF_FUNC_skc_to_unix_sock 178
#define BPF_FUNC_kallsyms_lookup_name 179
#define BPF_FUNC_find_vma 180
#define BPF_FUNC_loop 181
#define BPF_FUNC_strncmp 182
#define BPF_FUNC_get_func_arg 183
#define BPF_FUNC_get_func_ret 184
#define BPF_FUNC_get_func_arg_cnt 185
#define BPF_FUNC_get_retval 186
#define BPF_FUNC_set_retval 187
#define BPF_FUNC_xdp_get_buff_len 188
#define BPF_FUNC_xdp_load_bytes 189
#define BPF_FUNC_xdp_store_bytes 190
#define BPF_FUNC_copy_from_user_task 191
#define BPF_FUNC_skb_set_tstamp 192
#define BPF_FUNC_ima_file_hash 193
#define BPF_FUNC_kptr_xchg 194
#define BPF_FUNC_map_lookup_percpu_elem 195
#define BPF_FUNC_skc_to_mptcp_sock 196
#define BPF_FUNC_dynptr_from_mem 197
#define BPF_FUNC_ringbuf_reserve_dynptr 198
#define BPF_FUNC_ringbuf_submit_dynptr 199
#define BPF_FUNC_ringbuf_discard_dynptr 200
#define BPF_FUNC_dynptr_read 201
#define BPF_FUNC_dynptr_write 202
#define BPF_FUNC_dynptr_data 203
#define BPF_FUNC_tcp_raw_gen_syncookie_ipv4 204
#define BPF_FUNC_tcp_raw_gen_syncookie_ipv6 205
#define BPF_FUNC_tcp_raw_check_syncookie_ipv4 206
#define BPF_FUNC_tcp_raw_check_syncookie_ipv6 207
#define BPF_FUNC_ktime_get_tai_ns 208
#define BPF_FUNC_user_ringbuf_drain 209
#define BPF_FUNC_cgrp_storage_get 210
#define BPF_FUNC_cgrp_storage_delete 211


struct stats {
	uint32_t uid;
	uint64_t packets;
	uint64_t bytes;
};

int load_raw_btf(const char *raw_types, size_t types_len,
			 const char *str_sec, size_t str_len,
			 int token_fd);
int btf_load(const void *btf_data, size_t btf_size);

static inline __u64 ptr_to_u64(const void *ptr)
{
	return (__u64) (unsigned long) ptr;
}


static int load_local_storage_btf(void)
{


	const char strs[] = "\0bpf_spin_lock\0val\0cnt\0l";
	__u32 types[] = {
		/* int */
		BTF_TYPE_INT_ENC(0, BTF_INT_SIGNED, 0, 32, 4),  /* [1] */

	};

	return load_raw_btf((char *)types, sizeof(types),
				     strs, sizeof(strs), 0);
}

int load_raw_btf(const char *raw_types, size_t types_len,
			 const char *str_sec, size_t str_len,
			 int token_fd)
{
	struct btf_header hdr = {
		.magic = BTF_MAGIC,
		.version = BTF_VERSION,
		.hdr_len = sizeof(struct btf_header),
		.type_len = types_len,
		.str_off = types_len,
		.str_len = str_len,
	};

	int btf_fd, btf_len;
	__u8 *raw_btf;

	btf_len = hdr.hdr_len + hdr.type_len + hdr.str_len;
	raw_btf = malloc(btf_len);
	if (!raw_btf)
		return -ENOMEM;

	memcpy(raw_btf, &hdr, sizeof(hdr));
	memcpy(raw_btf + hdr.hdr_len, raw_types, hdr.type_len);
	memcpy(raw_btf + hdr.hdr_len + hdr.type_len, str_sec, hdr.str_len);

	btf_fd = btf_load(raw_btf, btf_len);

	free(raw_btf);
	return btf_fd;
}

int btf_load(const void *btf_data, size_t btf_size){
        unsigned char log_buf[1000000] = {};

        union bpf_attr attr = {

        };
        attr.btf = ptr_to_u64(btf_data);
	attr.btf_size = btf_size;

	// attr.btf_flags = 0;
	// attr.btf_token_fd = 0;
        attr.btf_log_size = sizeof(log_buf);
        attr.btf_log_buf = (uint64_t)log_buf;
        attr.btf_log_level = 3;    
        //attr.btf_log_true_size =3; 
 
        int fd=syscall(SYS_bpf, BPF_BTF_LOAD, &attr, sizeof(attr));
        if(fd<0){
                for (int i = 0; i < sizeof(log_buf) && log_buf[i] != '\0'; i++) {
                        if (log_buf[i] != '\n') {
                                printf("%c",log_buf[i]);
                        } else {
                                printf("\n");
                        }
                }           
        }
        return fd;


}


int bpf_map_create(uint32_t map_type, uint32_t key_size,
                   uint32_t value_size, unsigned int max_entries, 
                   uint32_t map_flags, int need_btf) {
	union bpf_attr attr = {.map_type = map_type,
		.key_size = key_size,
		.value_size = value_size,
		.max_entries = max_entries,
		.map_flags = map_flags};

        
        if(need_btf!=0){
                int btf_fd = load_local_storage_btf();
                if(btf_fd<0){
                        printf("Could not load btf\n");
                        return -1;
                }else{
                        printf("btf_fd = %d\n", btf_fd);
                }
                attr.btf_fd = btf_fd;
                attr.btf_key_type_id = 1;
                attr.btf_value_type_id = 1;
        }

	return syscall(SYS_bpf, BPF_MAP_CREATE, &attr, 0x48);
}




#ifndef BPF_F_TEST_XDP_LIVE_FRAMES 
#define BPF_F_TEST_XDP_LIVE_FRAMES	(1U << 1)
#endif

int bpf_prog_test_run(int prog_fd, uint32_t data_size_in, uint64_t data_in, uint64_t * ctx_in, uint32_t flags) 
{
    	union bpf_attr attr;

	memset(&attr, 0, sizeof(attr));
	attr.test.prog_fd = prog_fd;
	attr.test.data_size_in = data_size_in;
	attr.test.data_in = data_in;
	attr.test.ctx_in = (__u64)ctx_in;
	if (attr.test.ctx_in)
		attr.test.ctx_size_in = sizeof(struct xdp_md);
	attr.test.flags = flags;

	return syscall(SYS_bpf, BPF_PROG_TEST_RUN, &attr, sizeof(attr.test));
}



// loads a prog and returns the FD
int load_prog(struct bpf_insn *instructions, size_t insn_count)
{
        unsigned char log_buf[1000000] = {};
        memset(log_buf, 0, 1000000);
        union bpf_attr attr = {};
        attr.prog_type = replace_with_prog_type;
        attr.insns = (uint64_t)instructions;
        attr.insn_cnt = insn_count;
        attr.license = (uint64_t) "GPL";
        attr.log_size = sizeof(log_buf);
        attr.log_buf = (uint64_t)log_buf;
        attr.log_level = 3;
        /*replace_with_prog_flags*/
        /*replace_with_expected_attach_type*/
        /*replace_with_btf_id*/

        // load the BPF program
        int prog_fd = syscall(SYS_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
		printf("prog_fd = %d\n", prog_fd);

        if (prog_fd < 0) {
                for (int i = 0; i < sizeof(log_buf) && log_buf[i] != '\0'; i++) {
                        if (log_buf[i] != '\n') {
                                printf("%c",log_buf[i]);
                        } else {
                                printf("\n");
                        }
                }     
                printf("%s\n", strerror(errno));
                // printf("could load program\n");

                return -1;
        }

        return prog_fd;
}

int load_run_bpf_insn(int map_fd)
{

/**
 * struct bpf_insn prog[] = {
 * BPF_MOV64_REG(BPF_REG_6, BPF_REG_1),
 * BPF_MOV64_IMM(BPF_REG_2, 0),
 * ...
 * };
 */


/*replace_with_map_create*/



/** The definition of bpf insn array Start ... **/

/** The definition of bpf insn array End ... **/

	int res;

    	int prog_fd = load_prog(prog, /*prog_len=*/sizeof(prog) / sizeof(prog[0]));
        if ( prog_fd < 0) {
                printf("Could not load program\n");
                return -1;
        }
    
        res = bpf_prog_test_run(prog_fd, 0, 0, 0, BPF_F_TEST_XDP_LIVE_FRAMES);
        printf("bpf_prog_test_run return %d", res);
    
        close(prog_fd);
        return 0;
}


int main(int argc, char **argv)
{
        setbuf(stdout, NULL);
        setbuf(stderr, NULL);
        printf("Start bpf program testing\n");
	load_run_bpf_insn(-1);
}
