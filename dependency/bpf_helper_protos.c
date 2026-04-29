 /*
 * Usage Guidelines for Helper Function Definitions
 * =================================================
 *
 * 1. Helper Function Structure (bpf_func_proto):
 *    - .func: Pointer to the actual helper function implementation
 *    - .gpl_only: Set to true if helper requires GPL license
 *    - .pkt_access: Set to true if helper can access packet data
 *    - .ret_type: Define what the helper function returns
 *    - .arg1_type to .arg5_type: Define argument types (up to 5 arguments)
 *
 * 2. Return Types:
 *    - RET_INTEGER: Function returns an integer value
 *    - RET_VOID: Function doesn't return anything
 *    - RET_PTR_TO_MAP_VALUE_OR_NULL: Returns map value pointer or NULL
 *    - RET_PTR_TO_SOCKET_OR_NULL: Returns socket pointer or NULL
 *
 * 3. Argument Types with Flags:
 *    - ARG_PTR_TO_MEM | MEM_RDONLY: Read-only memory pointer
 *    - ARG_PTR_TO_MEM | MEM_UNINIT | MEM_WRITE: Uninitialized writable memory
 *    - ARG_PTR_TO_CTX: BPF program context pointer
 *    - ARG_CONST_SIZE: Constant size value
 *    - ARG_ANYTHING: Any initialized value
 *
 * 4. Common Helper Patterns:
 *
 *    a) Map Operations:
 *       - arg1: ARG_CONST_MAP_PTR (map pointer)
 *       - arg2: ARG_PTR_TO_MAP_KEY (key pointer)
 *       - arg3: ARG_PTR_TO_MAP_VALUE (value pointer for updates)
 *
 *    b) Memory Operations:
 *       - arg1: ARG_PTR_TO_UNINIT_MEM (destination buffer)
 *       - arg2: ARG_CONST_SIZE_OR_ZERO (buffer size)
 *       - arg3: ARG_ANYTHING (source address/flags)
 *
 *    c) Context Operations:
 *       - arg1: ARG_PTR_TO_CTX (program context)
 *       - Additional arguments as needed
 *
 *    d) Socket Operations:
 *       - arg1: ARG_PTR_TO_CTX (network context)
 *       - arg2: ARG_PTR_TO_MEM | MEM_RDONLY (address buffer)
 *       - arg3: ARG_CONST_SIZE (address size)
 *
 * 5. Best Practices:
 *    - Always specify the most restrictive type that still allows valid usage
 *    - Use MEM_RDONLY for read-only memory arguments
 *    - Use MEM_UNINIT for output buffers that don't need initialization
 *    - Set gpl_only appropriately based on kernel API requirements
 *    - Document the purpose and usage of each helper function
 *
 * Example New Helper Definition:
 * ------------------------------
 * static const struct bpf_func_proto my_custom_helper_proto = {
 *     .func = my_custom_helper,
 *     .gpl_only = false,
 *     .ret_type = RET_INTEGER,
 *     .arg1_type = ARG_PTR_TO_CTX,
 *     .arg2_type = ARG_PTR_TO_MEM | MEM_RDONLY,
 *     .arg3_type = ARG_CONST_SIZE,
 * };
 */

/* Helper 1: BPF_FUNC_map_lookup_elem */
static const struct bpf_func_proto bpf_map_lookup_elem_proto = {
	.func		= bpf_map_lookup_elem,
	.gpl_only	= false,
	.pkt_access	= true,
	.ret_type	= RET_PTR_TO_MAP_VALUE_OR_NULL,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_PTR_TO_MAP_KEY,
};

/* Helper 2: BPF_FUNC_map_update_elem */
static const struct bpf_func_proto bpf_map_update_elem_proto = {
	.func		= bpf_map_update_elem,
	.gpl_only	= false,
	.pkt_access	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_PTR_TO_MAP_KEY,
	.arg3_type	= ARG_PTR_TO_MAP_VALUE,
	.arg4_type	= ARG_ANYTHING,
};

/* Helper 3: BPF_FUNC_map_delete_elem */
static const struct bpf_func_proto bpf_map_delete_elem_proto = {
	.func		= bpf_map_delete_elem,
	.gpl_only	= false,
	.pkt_access	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_PTR_TO_MAP_KEY,
};

/* Helper 4: BPF_FUNC_probe_read - Using compatibility version */
static const struct bpf_func_proto bpf_probe_read_compat_proto = {
	.func		= bpf_probe_read_compat,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_UNINIT_MEM,
	.arg2_type	= ARG_CONST_SIZE_OR_ZERO,
	.arg3_type	= ARG_ANYTHING,
};

/* Helper 5: BPF_FUNC_ktime_get_ns */
static const struct bpf_func_proto bpf_ktime_get_ns_proto = {
	.func		= bpf_ktime_get_ns,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
};

/* Helper 6: BPF_FUNC_trace_printk */
static const struct bpf_func_proto bpf_trace_printk_proto = {
	.func		= bpf_trace_printk,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_MEM | MEM_RDONLY,
	.arg2_type	= ARG_CONST_SIZE,
};

/* Helper 7: BPF_FUNC_get_prandom_u32 */
static const struct bpf_func_proto bpf_get_prandom_u32_proto = {
	.func		= bpf_user_rnd_u32,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
};

/* Helper 8: BPF_FUNC_get_smp_processor_id */
static const struct bpf_func_proto bpf_get_smp_processor_id_proto = {
	.func		= bpf_get_smp_processor_id,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
};

/* Helper 9: BPF_FUNC_skb_store_bytes */
static const struct bpf_func_proto bpf_skb_store_bytes_proto = {
	.func		= bpf_skb_store_bytes,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_PTR_TO_MEM | MEM_RDONLY,
	.arg4_type	= ARG_CONST_SIZE,
	.arg5_type	= ARG_ANYTHING,
};

/* Helper 10: BPF_FUNC_l3_csum_replace */
static const struct bpf_func_proto bpf_l3_csum_replace_proto = {
	.func		= bpf_l3_csum_replace,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_ANYTHING,
	.arg4_type	= ARG_ANYTHING,
	.arg5_type	= ARG_ANYTHING,
};

/* Helper 11: BPF_FUNC_l4_csum_replace */
static const struct bpf_func_proto bpf_l4_csum_replace_proto = {
	.func		= bpf_l4_csum_replace,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_ANYTHING,
	.arg4_type	= ARG_ANYTHING,
	.arg5_type	= ARG_ANYTHING,
};

/* Helper 12: BPF_FUNC_tail_call */
static const struct bpf_func_proto bpf_tail_call_proto = {
	.func		= NULL,
	.gpl_only	= false,
	.ret_type	= RET_VOID,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_CONST_MAP_PTR,
	.arg3_type	= ARG_ANYTHING,
};

/* Helper 13: BPF_FUNC_clone_redirect */
static const struct bpf_func_proto bpf_clone_redirect_proto = {
	.func		= bpf_clone_redirect,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_ANYTHING,
};

/* Helper 14: BPF_FUNC_get_current_pid_tgid */
static const struct bpf_func_proto bpf_get_current_pid_tgid_proto = {
	.func		= bpf_get_current_pid_tgid,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
};

/* Helper 15: BPF_FUNC_get_current_uid_gid */
static const struct bpf_func_proto bpf_get_current_uid_gid_proto = {
	.func		= bpf_get_current_uid_gid,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
};

/* Helper 16: BPF_FUNC_get_current_comm */
static const struct bpf_func_proto bpf_get_current_comm_proto = {
	.func		= bpf_get_current_comm,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_UNINIT_MEM,
	.arg2_type	= ARG_CONST_SIZE,
};

/* Helper 17: BPF_FUNC_get_cgroup_classid */
static const struct bpf_func_proto bpf_get_cgroup_classid_proto = {
	.func		= bpf_get_cgroup_classid,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
};

/* Helper 18: BPF_FUNC_skb_vlan_push */
static const struct bpf_func_proto bpf_skb_vlan_push_proto = {
	.func		= bpf_skb_vlan_push,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_ANYTHING,
};

/* Helper 19: BPF_FUNC_skb_vlan_pop */
static const struct bpf_func_proto bpf_skb_vlan_pop_proto = {
	.func		= bpf_skb_vlan_pop,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
};

/* Helper 20: BPF_FUNC_skb_get_tunnel_key */
static const struct bpf_func_proto bpf_skb_get_tunnel_key_proto = {
	.func		= bpf_skb_get_tunnel_key,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_PTR_TO_UNINIT_MEM,
	.arg3_type	= ARG_CONST_SIZE,
	.arg4_type	= ARG_ANYTHING,
};

/* Helper 21: BPF_FUNC_skb_set_tunnel_key */
static const struct bpf_func_proto bpf_skb_set_tunnel_key_proto = {
	.func		= bpf_skb_set_tunnel_key,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_PTR_TO_MEM | MEM_RDONLY,
	.arg3_type	= ARG_CONST_SIZE,
	.arg4_type	= ARG_ANYTHING,
};

/* Helper 22: BPF_FUNC_perf_event_read */
static const struct bpf_func_proto bpf_perf_event_read_proto = {
	.func		= bpf_perf_event_read,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_ANYTHING,
};

/* Helper 23: BPF_FUNC_redirect */
static const struct bpf_func_proto bpf_redirect_proto = {
	.func		= bpf_redirect,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_ANYTHING,
	.arg2_type	= ARG_ANYTHING,
};

/* Helper 24: BPF_FUNC_get_route_realm */
static const struct bpf_func_proto bpf_get_route_realm_proto = {
	.func		= bpf_get_route_realm,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
};

/* Helper 25: BPF_FUNC_perf_event_output */
static const struct bpf_func_proto bpf_perf_event_output_proto = {
	.func		= bpf_perf_event_output,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_CONST_MAP_PTR,
	.arg3_type	= ARG_ANYTHING,
	.arg4_type	= ARG_PTR_TO_MEM | MEM_RDONLY,
	.arg5_type	= ARG_CONST_SIZE_OR_ZERO,
};

/* Helper 26: BPF_FUNC_skb_load_bytes */
static const struct bpf_func_proto bpf_skb_load_bytes_proto = {
	.func		= bpf_skb_load_bytes,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_PTR_TO_UNINIT_MEM,
	.arg4_type	= ARG_CONST_SIZE,
};

/* Helper 27: BPF_FUNC_get_stackid */
static const struct bpf_func_proto bpf_get_stackid_proto = {
	.func		= bpf_get_stackid,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_CONST_MAP_PTR,
	.arg3_type	= ARG_ANYTHING,
};

/* Helper 28: BPF_FUNC_csum_diff */
static const struct bpf_func_proto bpf_csum_diff_proto = {
	.func		= bpf_csum_diff,
	.gpl_only	= false,
	.pkt_access	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_MEM | PTR_MAYBE_NULL | MEM_RDONLY,
	.arg2_type	= ARG_CONST_SIZE_OR_ZERO,
	.arg3_type	= ARG_PTR_TO_MEM | PTR_MAYBE_NULL | MEM_RDONLY,
	.arg4_type	= ARG_CONST_SIZE_OR_ZERO,
	.arg5_type	= ARG_ANYTHING,
};

/* Helper 29: BPF_FUNC_skb_get_tunnel_opt */
static const struct bpf_func_proto bpf_skb_get_tunnel_opt_proto = {
	.func		= bpf_skb_get_tunnel_opt,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_PTR_TO_UNINIT_MEM,
	.arg3_type	= ARG_CONST_SIZE,
};

/* Helper 30: BPF_FUNC_skb_set_tunnel_opt */
static const struct bpf_func_proto bpf_skb_set_tunnel_opt_proto = {
	.func		= bpf_skb_set_tunnel_opt,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_PTR_TO_MEM | MEM_RDONLY,
	.arg3_type	= ARG_CONST_SIZE,
};

/* Helper 31: BPF_FUNC_skb_change_proto */
static const struct bpf_func_proto bpf_skb_change_proto_proto = {
	.func		= bpf_skb_change_proto,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_ANYTHING,
};

/* Helper 32: BPF_FUNC_skb_change_type */
static const struct bpf_func_proto bpf_skb_change_type_proto = {
	.func		= bpf_skb_change_type,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
};

/* Helper 33: BPF_FUNC_skb_under_cgroup */
static const struct bpf_func_proto bpf_skb_under_cgroup_proto = {
	.func		= bpf_skb_under_cgroup,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_CONST_MAP_PTR,
	.arg3_type	= ARG_ANYTHING,
};

/* Helper 34: BPF_FUNC_get_hash_recalc */
static const struct bpf_func_proto bpf_get_hash_recalc_proto = {
	.func		= bpf_get_hash_recalc,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
};

/* Helper 35: BPF_FUNC_get_current_task */
static const struct bpf_func_proto bpf_get_current_task_proto = {
	.func		= bpf_get_current_task,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
};

/* Helper 36: BPF_FUNC_probe_write_user */
static const struct bpf_func_proto bpf_probe_write_user_proto = {
	.func		= bpf_probe_write_user,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_ANYTHING,
	.arg2_type	= ARG_PTR_TO_MEM | MEM_RDONLY,
	.arg3_type	= ARG_CONST_SIZE,
};

/* Helper 37: BPF_FUNC_current_task_under_cgroup */
static const struct bpf_func_proto bpf_current_task_under_cgroup_proto = {
	.func		= bpf_current_task_under_cgroup,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_ANYTHING,
};

/* Helper 38: BPF_FUNC_skb_change_tail */
static const struct bpf_func_proto bpf_skb_change_tail_proto = {
	.func		= bpf_skb_change_tail,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_ANYTHING,
};

/* Helper 39: BPF_FUNC_skb_pull_data */
static const struct bpf_func_proto bpf_skb_pull_data_proto = {
	.func		= bpf_skb_pull_data,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
};

/* Helper 40: BPF_FUNC_csum_update */
static const struct bpf_func_proto bpf_csum_update_proto = {
	.func		= bpf_csum_update,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
};

/* Helper 41: BPF_FUNC_set_hash_invalid */
static const struct bpf_func_proto bpf_set_hash_invalid_proto = {
	.func		= bpf_set_hash_invalid,
	.gpl_only	= false,
	.ret_type	= RET_VOID,
	.arg1_type	= ARG_PTR_TO_CTX,
};

/* Helper 42: BPF_FUNC_get_numa_node_id */
static const struct bpf_func_proto bpf_get_numa_node_id_proto = {
	.func		= bpf_get_numa_node_id,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
};

/* Helper 43: BPF_FUNC_skb_change_head */
static const struct bpf_func_proto bpf_skb_change_head_proto = {
	.func		= bpf_skb_change_head,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_ANYTHING,
};

/* Helper 44: BPF_FUNC_xdp_adjust_head */
static const struct bpf_func_proto bpf_xdp_adjust_head_proto = {
	.func		= bpf_xdp_adjust_head,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
};

/* Helper 45: BPF_FUNC_probe_read_str - Using compatibility version */
static const struct bpf_func_proto bpf_probe_read_str_proto = {
	.func		= bpf_probe_read_str,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_UNINIT_MEM,
	.arg2_type	= ARG_CONST_SIZE_OR_ZERO,
	.arg3_type	= ARG_ANYTHING,
};

/* Helper 46: BPF_FUNC_probe_read_str */
static const struct bpf_func_proto bpf_probe_read_compat_str_proto = {
	.func		= bpf_probe_read_compat_str,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_UNINIT_MEM,
	.arg2_type	= ARG_CONST_SIZE_OR_ZERO,
	.arg3_type	= ARG_ANYTHING,
};

/* Helper 47: BPF_FUNC_get_socket_cookie */
static const struct bpf_func_proto bpf_get_socket_cookie_proto = {
	.func		= bpf_get_socket_cookie,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
};

/* Helper 48: BPF_FUNC_get_socket_uid */
static const struct bpf_func_proto bpf_get_socket_uid_proto = {
	.func		= bpf_get_socket_uid,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
};

/* Helper 49: BPF_FUNC_set_hash */
static const struct bpf_func_proto bpf_set_hash_proto = {
	.func		= bpf_set_hash,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
};

/* Helper 50: BPF_FUNC_setsockopt - Multiple variants available */
/* Variant 1: Socket-based setsockopt */
const struct bpf_func_proto bpf_sk_setsockopt_proto = {
	.func		= bpf_sk_setsockopt,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_BTF_ID_SOCK_COMMON,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_ANYTHING,
	.arg4_type	= ARG_PTR_TO_MEM | MEM_RDONLY,
	.arg5_type	= ARG_CONST_SIZE,
};

/* Helper 51: BPF_FUNC_skb_adjust_room */
static const struct bpf_func_proto bpf_skb_adjust_room_proto = {
	.func		= bpf_skb_adjust_room,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_ANYTHING,
	.arg4_type	= ARG_ANYTHING,
};

/* Helper 52: BPF_FUNC_redirect_map */
static const struct bpf_func_proto bpf_xdp_redirect_map_proto = {
	.func		= bpf_xdp_redirect_map,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_ANYTHING,
};

/* Helper 53: BPF_FUNC_sk_redirect_map */
const struct bpf_func_proto bpf_sk_redirect_map_proto = {
	.func		= bpf_sk_redirect_map,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_CONST_MAP_PTR,
	.arg3_type	= ARG_ANYTHING,
	.arg4_type	= ARG_ANYTHING,
};

/* Helper 54: BPF_FUNC_sock_map_update */
const struct bpf_func_proto bpf_sock_map_update_proto = {
	.func		= bpf_sock_map_update,
	.gpl_only	= false,
	.pkt_access	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_CONST_MAP_PTR,
	.arg3_type	= ARG_PTR_TO_MAP_KEY,
	.arg4_type	= ARG_ANYTHING,
};

/* Helper 55: BPF_FUNC_xdp_adjust_meta */
static const struct bpf_func_proto bpf_xdp_adjust_meta_proto = {
	.func		= bpf_xdp_adjust_meta,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
};

/* Helper 56: BPF_FUNC_perf_event_read_value */
static const struct bpf_func_proto bpf_perf_event_read_value_proto = {
	.func		= bpf_perf_event_read_value,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_PTR_TO_UNINIT_MEM,
	.arg4_type	= ARG_CONST_SIZE,
};

/* Helper 57: BPF_FUNC_perf_prog_read_value */
static const struct bpf_func_proto bpf_perf_prog_read_value_proto = {
	.func		= bpf_perf_prog_read_value,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_PTR_TO_UNINIT_MEM,
	.arg3_type	= ARG_CONST_SIZE,
};

/* Helper 58: BPF_FUNC_getsockopt - Multiple variants available */
/* Variant 1: Socket-based getsockopt */
const struct bpf_func_proto bpf_sk_getsockopt_proto = {
	.func		= bpf_sk_getsockopt,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_BTF_ID_SOCK_COMMON,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_ANYTHING,
	.arg4_type	= ARG_PTR_TO_UNINIT_MEM,
	.arg5_type	= ARG_CONST_SIZE,
};

/* Helper 59: BPF_FUNC_override_return */
static const struct bpf_func_proto bpf_override_return_proto = {
	.func		= bpf_override_return,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
};

/* Helper 60: BPF_FUNC_sock_ops_cb_flags_set */
static const struct bpf_func_proto bpf_sock_ops_cb_flags_set_proto = {
	.func		= bpf_sock_ops_cb_flags_set,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
};

/* Helper 61: BPF_FUNC_msg_redirect_map */
const struct bpf_func_proto bpf_msg_redirect_map_proto = {
	.func		= bpf_msg_redirect_map,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_CONST_MAP_PTR,
	.arg3_type	= ARG_ANYTHING,
	.arg4_type	= ARG_ANYTHING,
};

/* Helper 62: BPF_FUNC_msg_apply_bytes */
static const struct bpf_func_proto bpf_msg_apply_bytes_proto = {
	.func		= bpf_msg_apply_bytes,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
};

/* Helper 63: BPF_FUNC_msg_cork_bytes */
static const struct bpf_func_proto bpf_msg_cork_bytes_proto = {
	.func		= bpf_msg_cork_bytes,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
};

/* Helper 64: BPF_FUNC_msg_pull_data */
static const struct bpf_func_proto bpf_msg_pull_data_proto = {
	.func		= bpf_msg_pull_data,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_ANYTHING,
	.arg4_type	= ARG_ANYTHING,
};

/* Helper 65: BPF_FUNC_bind */
static const struct bpf_func_proto bpf_bind_proto = {
	.func		= bpf_bind,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_PTR_TO_MEM | MEM_RDONLY,
	.arg3_type	= ARG_CONST_SIZE,
};

/* Helper 66: BPF_FUNC_xdp_adjust_tail */
static const struct bpf_func_proto bpf_xdp_adjust_tail_proto = {
	.func		= bpf_xdp_adjust_tail,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
};

/* Helper 67: BPF_FUNC_skb_get_xfrm_state */
static const struct bpf_func_proto bpf_skb_get_xfrm_state_proto = {
	.func		= bpf_skb_get_xfrm_state,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_PTR_TO_UNINIT_MEM,
	.arg4_type	= ARG_CONST_SIZE,
	.arg5_type	= ARG_ANYTHING,
};

/* Helper 68: BPF_FUNC_get_stack */
const struct bpf_func_proto bpf_get_stack_proto = {
	.func		= bpf_get_stack,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_PTR_TO_UNINIT_MEM,
	.arg3_type	= ARG_CONST_SIZE_OR_ZERO,
	.arg4_type	= ARG_ANYTHING,
};

/* Helper 69: BPF_FUNC_skb_load_bytes_relative */
static const struct bpf_func_proto bpf_skb_load_bytes_relative_proto = {
	.func		= bpf_skb_load_bytes_relative,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_PTR_TO_UNINIT_MEM,
	.arg4_type	= ARG_CONST_SIZE,
	.arg5_type	= ARG_ANYTHING,
};

/* Helper 70: BPF_FUNC_fib_lookup - SKB variant */
static const struct bpf_func_proto bpf_skb_fib_lookup_proto = {
	.func		= bpf_skb_fib_lookup,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_PTR_TO_MEM,
	.arg3_type	= ARG_CONST_SIZE,
	.arg4_type	= ARG_ANYTHING,
};

/* Helper 71: BPF_FUNC_sock_hash_update */
const struct bpf_func_proto bpf_sock_hash_update_proto = {
	.func		= bpf_sock_hash_update,
	.gpl_only	= false,
	.pkt_access	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_CONST_MAP_PTR,
	.arg3_type	= ARG_PTR_TO_MAP_KEY,
	.arg4_type	= ARG_ANYTHING,
};

/* Helper 72: BPF_FUNC_msg_redirect_hash */
const struct bpf_func_proto bpf_msg_redirect_hash_proto = {
	.func		= bpf_msg_redirect_hash,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_CONST_MAP_PTR,
	.arg3_type	= ARG_PTR_TO_MAP_KEY,
	.arg4_type	= ARG_ANYTHING,
};

/* Helper 73: BPF_FUNC_sk_redirect_hash */
const struct bpf_func_proto bpf_sk_redirect_hash_proto = {
	.func		= bpf_sk_redirect_hash,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_CONST_MAP_PTR,
	.arg3_type	= ARG_PTR_TO_MAP_KEY,
	.arg4_type	= ARG_ANYTHING,
};

/* Helper 74: BPF_FUNC_lwt_push_encap - LWT IN variant */
static const struct bpf_func_proto bpf_lwt_in_push_encap_proto = {
	.func		= bpf_lwt_in_push_encap,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_PTR_TO_MEM | MEM_RDONLY,
	.arg4_type	= ARG_CONST_SIZE,
};

/* Helper 75: BPF_FUNC_lwt_seg6_store_bytes */
static const struct bpf_func_proto bpf_lwt_seg6_store_bytes_proto = {
	.func		= bpf_lwt_seg6_store_bytes,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_PTR_TO_MEM | MEM_RDONLY,
	.arg4_type	= ARG_CONST_SIZE,
};

/* Helper 76: BPF_FUNC_lwt_seg6_action */
static const struct bpf_func_proto bpf_lwt_seg6_action_proto = {
	.func		= bpf_lwt_seg6_action,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_PTR_TO_MEM | MEM_RDONLY,
	.arg4_type	= ARG_CONST_SIZE,
};

/* Helper 77: BPF_FUNC_rc_repeat */
static const struct bpf_func_proto rc_repeat_proto = {
	.func		= bpf_rc_repeat,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
};

/* Helper 78: BPF_FUNC_rc_keydown */
static const struct bpf_func_proto rc_keydown_proto = {
	.func		= bpf_rc_keydown,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_ANYTHING,
	.arg4_type	= ARG_ANYTHING,
};

/* Helper 79: BPF_FUNC_skb_cgroup_id */
static const struct bpf_func_proto bpf_skb_cgroup_id_proto = {
	.func		= bpf_skb_cgroup_id,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
};

/* Helper 80: BPF_FUNC_get_current_cgroup_id */
const struct bpf_func_proto bpf_get_current_cgroup_id_proto = {
	.func		= bpf_get_current_cgroup_id,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
};

/* Helper 81: BPF_FUNC_get_local_storage */
const struct bpf_func_proto bpf_get_local_storage_proto = {
	.func		= bpf_get_local_storage,
	.gpl_only	= false,
	.ret_type	= RET_PTR_TO_MAP_VALUE,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_ANYTHING,
};

/* Helper 82: BPF_FUNC_sk_select_reuseport */
static const struct bpf_func_proto sk_select_reuseport_proto = {
	.func		= sk_select_reuseport,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_CONST_MAP_PTR,
	.arg3_type	= ARG_PTR_TO_MAP_KEY,
	.arg4_type	= ARG_ANYTHING,
};

/* Helper 83: BPF_FUNC_skb_ancestor_cgroup_id */
static const struct bpf_func_proto bpf_skb_ancestor_cgroup_id_proto = {
	.func		= bpf_skb_ancestor_cgroup_id,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
};

/* Helper 84: BPF_FUNC_sk_lookup_tcp */
static const struct bpf_func_proto bpf_sk_lookup_tcp_proto = {
	.func		= bpf_sk_lookup_tcp,
	.gpl_only	= false,
	.pkt_access	= true,
	.ret_type	= RET_PTR_TO_SOCKET_OR_NULL,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_PTR_TO_MEM | MEM_RDONLY,
	.arg3_type	= ARG_CONST_SIZE,
	.arg4_type	= ARG_ANYTHING,
	.arg5_type	= ARG_ANYTHING,
};

/* Helper 85: BPF_FUNC_sk_lookup_udp */
static const struct bpf_func_proto bpf_sk_lookup_udp_proto = {
	.func		= bpf_sk_lookup_udp,
	.gpl_only	= false,
	.pkt_access	= true,
	.ret_type	= RET_PTR_TO_SOCKET_OR_NULL,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_PTR_TO_MEM | MEM_RDONLY,
	.arg3_type	= ARG_CONST_SIZE,
	.arg4_type	= ARG_ANYTHING,
	.arg5_type	= ARG_ANYTHING,
};

/* Helper 86: BPF_FUNC_sk_release */
static const struct bpf_func_proto bpf_sk_release_proto = {
	.func		= bpf_sk_release,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_BTF_ID_SOCK_COMMON | OBJ_RELEASE,
};

/* Helper 87: BPF_FUNC_map_push_elem */
const struct bpf_func_proto bpf_map_push_elem_proto = {
	.func		= bpf_map_push_elem,
	.gpl_only	= false,
	.pkt_access	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_PTR_TO_MAP_VALUE,
	.arg3_type	= ARG_ANYTHING,
};

/* Helper 88: BPF_FUNC_map_pop_elem */
const struct bpf_func_proto bpf_map_pop_elem_proto = {
	.func		= bpf_map_pop_elem,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_PTR_TO_MAP_VALUE | MEM_UNINIT | MEM_WRITE,
};

/* Helper 89: BPF_FUNC_map_peek_elem */
const struct bpf_func_proto bpf_map_peek_elem_proto = {
	.func		= bpf_map_peek_elem,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_PTR_TO_MAP_VALUE | MEM_UNINIT | MEM_WRITE,
};

/* Helper 90: BPF_FUNC_msg_push_data */
static const struct bpf_func_proto bpf_msg_push_data_proto = {
	.func		= bpf_msg_push_data,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_ANYTHING,
	.arg4_type	= ARG_ANYTHING,
};

/* Helper 91: BPF_FUNC_msg_pop_data */
static const struct bpf_func_proto bpf_msg_pop_data_proto = {
	.func		= bpf_msg_pop_data,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_ANYTHING,
	.arg4_type	= ARG_ANYTHING,
};

/* Helper 92: BPF_FUNC_rc_pointer_rel */
static const struct bpf_func_proto rc_pointer_rel_proto = {
	.func		= bpf_rc_pointer_rel,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_ANYTHING,
};

/* Helper 93: BPF_FUNC_spin_lock */
const struct bpf_func_proto bpf_spin_lock_proto = {
	.func		= bpf_spin_lock,
	.gpl_only	= false,
	.ret_type	= RET_VOID,
	.arg1_type	= ARG_PTR_TO_SPIN_LOCK,
	.arg1_btf_id	= BPF_PTR_POISON,
};

/* Helper 94: BPF_FUNC_spin_unlock */
const struct bpf_func_proto bpf_spin_unlock_proto = {
	.func		= bpf_spin_unlock,
	.gpl_only	= false,
	.ret_type	= RET_VOID,
	.arg1_type	= ARG_PTR_TO_SPIN_LOCK,
	.arg1_btf_id	= BPF_PTR_POISON,
};

/* Helper 95: BPF_FUNC_sk_fullsock */
static const struct bpf_func_proto bpf_sk_fullsock_proto = {
	.func		= bpf_sk_fullsock,
	.gpl_only	= false,
	.ret_type	= RET_PTR_TO_SOCKET_OR_NULL,
	.arg1_type	= ARG_PTR_TO_SOCK_COMMON,
};

/* Helper 96: BPF_FUNC_tcp_sock */
const struct bpf_func_proto bpf_tcp_sock_proto = {
	.func		= bpf_tcp_sock,
	.gpl_only	= false,
	.ret_type	= RET_PTR_TO_TCP_SOCK_OR_NULL,
	.arg1_type	= ARG_PTR_TO_SOCK_COMMON,
};

/* Helper 97: BPF_FUNC_skb_ecn_set_ce */
static const struct bpf_func_proto bpf_skb_ecn_set_ce_proto = {
	.func		= bpf_skb_ecn_set_ce,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
};

/* Helper 98: BPF_FUNC_get_listener_sock */
static const struct bpf_func_proto bpf_get_listener_sock_proto = {
	.func		= bpf_get_listener_sock,
	.gpl_only	= false,
	.ret_type	= RET_PTR_TO_SOCKET_OR_NULL,
	.arg1_type	= ARG_PTR_TO_SOCK_COMMON,
};

/* Helper 99: BPF_FUNC_skc_lookup_tcp */
static const struct bpf_func_proto bpf_skc_lookup_tcp_proto = {
	.func		= bpf_skc_lookup_tcp,
	.gpl_only	= false,
	.pkt_access	= true,
	.ret_type	= RET_PTR_TO_SOCK_COMMON_OR_NULL,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_PTR_TO_MEM | MEM_RDONLY,
	.arg3_type	= ARG_CONST_SIZE,
	.arg4_type	= ARG_ANYTHING,
	.arg5_type	= ARG_ANYTHING,
};

/* Helper 100: BPF_FUNC_tcp_check_syncookie */
static const struct bpf_func_proto bpf_tcp_check_syncookie_proto = {
	.func		= bpf_tcp_check_syncookie,
	.gpl_only	= true,
	.pkt_access	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_BTF_ID_SOCK_COMMON,
	.arg2_type	= ARG_PTR_TO_MEM | MEM_RDONLY,
	.arg3_type	= ARG_CONST_SIZE,
	.arg4_type	= ARG_PTR_TO_MEM | MEM_RDONLY,
	.arg5_type	= ARG_CONST_SIZE,
};

/* Helper 101: BPF_FUNC_sysctl_get_name */
static const struct bpf_func_proto bpf_sysctl_get_name_proto = {
	.func		= bpf_sysctl_get_name,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_PTR_TO_MEM,
	.arg3_type	= ARG_CONST_SIZE,
	.arg4_type	= ARG_ANYTHING,
};

/* Helper 102: BPF_FUNC_sysctl_get_current_value */
static const struct bpf_func_proto bpf_sysctl_get_current_value_proto = {
	.func		= bpf_sysctl_get_current_value,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_PTR_TO_UNINIT_MEM,
	.arg3_type	= ARG_CONST_SIZE,
};

/* Helper 103: BPF_FUNC_sysctl_get_new_value */
static const struct bpf_func_proto bpf_sysctl_get_new_value_proto = {
	.func		= bpf_sysctl_get_new_value,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_PTR_TO_UNINIT_MEM,
	.arg3_type	= ARG_CONST_SIZE,
};

/* Helper 104: BPF_FUNC_sysctl_set_new_value */
static const struct bpf_func_proto bpf_sysctl_set_new_value_proto = {
	.func		= bpf_sysctl_set_new_value,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_PTR_TO_MEM | MEM_RDONLY,
	.arg3_type	= ARG_CONST_SIZE,
};

/* Helper 105: BPF_FUNC_strtol */
const struct bpf_func_proto bpf_strtol_proto = {
	.func		= bpf_strtol,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_MEM | MEM_RDONLY,
	.arg2_type	= ARG_CONST_SIZE,
	.arg3_type	= ARG_ANYTHING,
	.arg4_type	= ARG_PTR_TO_FIXED_SIZE_MEM | MEM_UNINIT | MEM_WRITE | MEM_ALIGNED,
	.arg4_size	= sizeof(s64),
};

/* Helper 106: BPF_FUNC_strtoul */
const struct bpf_func_proto bpf_strtoul_proto = {
	.func		= bpf_strtoul,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_MEM | MEM_RDONLY,
	.arg2_type	= ARG_CONST_SIZE,
	.arg3_type	= ARG_ANYTHING,
	.arg4_type	= ARG_PTR_TO_FIXED_SIZE_MEM | MEM_UNINIT | MEM_WRITE | MEM_ALIGNED,
	.arg4_size	= sizeof(u64),
};

/* Helper 107: BPF_FUNC_sk_storage_get */
const struct bpf_func_proto bpf_sk_storage_get_proto = {
	.func		= bpf_sk_storage_get,
	.gpl_only	= false,
	.ret_type	= RET_PTR_TO_MAP_VALUE_OR_NULL,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_PTR_TO_BTF_ID_SOCK_COMMON,
	.arg3_type	= ARG_PTR_TO_MAP_VALUE_OR_NULL,
	.arg4_type	= ARG_ANYTHING,
};

/* Helper 108: BPF_FUNC_sk_storage_delete */
const struct bpf_func_proto bpf_sk_storage_delete_proto = {
	.func		= bpf_sk_storage_delete,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_PTR_TO_BTF_ID_SOCK_COMMON,
};

/* Helper 109: BPF_FUNC_send_signal */
static const struct bpf_func_proto bpf_send_signal_proto = {
	.func		= bpf_send_signal,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_ANYTHING,
};

/* Helper 110: BPF_FUNC_tcp_gen_syncookie */
static const struct bpf_func_proto bpf_tcp_gen_syncookie_proto = {
	.func		= bpf_tcp_gen_syncookie,
	.gpl_only	= true,
	.pkt_access	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_BTF_ID_SOCK_COMMON,
	.arg2_type	= ARG_PTR_TO_MEM | MEM_RDONLY,
	.arg3_type	= ARG_CONST_SIZE,
	.arg4_type	= ARG_PTR_TO_MEM | MEM_RDONLY,
	.arg5_type	= ARG_CONST_SIZE,
};

/* Helper 111: BPF_FUNC_skb_output */
const struct bpf_func_proto bpf_skb_output_proto = {
	.func		= bpf_skb_event_output,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_BTF_ID,
	.arg1_btf_id	= &bpf_skb_output_btf_ids[0],
	.arg2_type	= ARG_CONST_MAP_PTR,
	.arg3_type	= ARG_ANYTHING,
	.arg4_type	= ARG_PTR_TO_MEM | MEM_RDONLY,
	.arg5_type	= ARG_CONST_SIZE_OR_ZERO,
};

/* Helper 112: BPF_FUNC_probe_read_user */
const struct bpf_func_proto bpf_probe_read_user_proto = {
	.func		= bpf_probe_read_user,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_UNINIT_MEM,
	.arg2_type	= ARG_CONST_SIZE_OR_ZERO,
	.arg3_type	= ARG_ANYTHING,
};

/* Helper 113: BPF_FUNC_probe_read_kernel */
const struct bpf_func_proto bpf_probe_read_kernel_proto = {
	.func		= bpf_probe_read_kernel,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_UNINIT_MEM,
	.arg2_type	= ARG_CONST_SIZE_OR_ZERO,
	.arg3_type	= ARG_ANYTHING,
};

/* Helper 114: BPF_FUNC_probe_read_user_str */
const struct bpf_func_proto bpf_probe_read_user_str_proto = {
	.func		= bpf_probe_read_user_str,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_UNINIT_MEM,
	.arg2_type	= ARG_CONST_SIZE_OR_ZERO,
	.arg3_type	= ARG_ANYTHING,
};

/* Helper 115: BPF_FUNC_probe_read_kernel_str */
const struct bpf_func_proto bpf_probe_read_kernel_str_proto = {
	.func		= bpf_probe_read_kernel_str,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_UNINIT_MEM,
	.arg2_type	= ARG_CONST_SIZE_OR_ZERO,
	.arg3_type	= ARG_ANYTHING,
};

/* Helper 116: BPF_FUNC_tcp_send_ack */
static const struct bpf_func_proto bpf_tcp_send_ack_proto = {
	.func		= bpf_tcp_send_ack,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_BTF_ID,
	.arg1_btf_id	= &tcp_sock_id,
	.arg2_type	= ARG_ANYTHING,
};

/* Helper 117: BPF_FUNC_send_signal_thread */
static const struct bpf_func_proto bpf_send_signal_thread_proto = {
	.func		= bpf_send_signal_thread,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_ANYTHING,
};

/* Helper 118: BPF_FUNC_jiffies64 */
const struct bpf_func_proto bpf_jiffies64_proto = {
	.func		= bpf_jiffies64,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
};

/* Helper 119: BPF_FUNC_read_branch_records */
static const struct bpf_func_proto bpf_read_branch_records_proto = {
	.func		= bpf_read_branch_records,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_PTR_TO_MEM_OR_NULL,
	.arg3_type	= ARG_CONST_SIZE_OR_ZERO,
	.arg4_type	= ARG_ANYTHING,
};

/* Helper 120: BPF_FUNC_get_ns_current_pid_tgid */
const struct bpf_func_proto bpf_get_ns_current_pid_tgid_proto = {
	.func		= bpf_get_ns_current_pid_tgid,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_ANYTHING,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_PTR_TO_UNINIT_MEM,
	.arg4_type	= ARG_CONST_SIZE,
};

/* Helper 121: BPF_FUNC_xdp_output */
const struct bpf_func_proto bpf_xdp_output_proto = {
	.func		= bpf_xdp_event_output,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_BTF_ID,
	.arg1_btf_id	= &bpf_xdp_output_btf_ids[0],
	.arg2_type	= ARG_CONST_MAP_PTR,
	.arg3_type	= ARG_ANYTHING,
	.arg4_type	= ARG_PTR_TO_MEM | MEM_RDONLY,
	.arg5_type	= ARG_CONST_SIZE_OR_ZERO,
};

/* Helper 122: BPF_FUNC_get_netns_cookie */
const struct bpf_func_proto bpf_get_netns_cookie_sock_proto = {
	.func		= bpf_get_netns_cookie_sock,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX_OR_NULL,
};

/* Helper 123: BPF_FUNC_get_current_ancestor_cgroup_id */
const struct bpf_func_proto bpf_get_current_ancestor_cgroup_id_proto = {
	.func		= bpf_get_current_ancestor_cgroup_id,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_ANYTHING,
};

/* Helper 124: BPF_FUNC_sk_assign */
const struct bpf_func_proto bpf_sk_assign_proto = {
	.func		= bpf_sk_assign,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
	.arg2_type      = ARG_PTR_TO_BTF_ID_SOCK_COMMON,
	.arg3_type	= ARG_ANYTHING,
};

/* Helper 125: BPF_FUNC_ktime_get_boot_ns */
const struct bpf_func_proto bpf_ktime_get_boot_ns_proto = {
	.func		= bpf_ktime_get_boot_ns,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
};

/* Helper 126: BPF_FUNC_seq_printf */
const struct bpf_func_proto bpf_seq_printf_proto = {
	.func		= bpf_seq_printf,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_BTF_ID,
	.arg1_btf_id	= &btf_seq_file_ids[0],
	.arg2_type	= ARG_PTR_TO_MEM | MEM_RDONLY,
	.arg3_type	= ARG_CONST_SIZE,
	.arg4_type      = ARG_PTR_TO_MEM | PTR_MAYBE_NULL | MEM_RDONLY,
	.arg5_type      = ARG_CONST_SIZE_OR_ZERO,
};

/* Helper 127: BPF_FUNC_seq_write */
const struct bpf_func_proto bpf_seq_write_proto = {
	.func		= bpf_seq_write,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_BTF_ID,
	.arg1_btf_id	= &btf_seq_file_ids[0],
	.arg2_type	= ARG_PTR_TO_MEM | MEM_RDONLY,
	.arg3_type	= ARG_CONST_SIZE_OR_ZERO,
};

/* Helper 128: BPF_FUNC_sk_cgroup_id */
const struct bpf_func_proto bpf_sk_cgroup_id_proto = {
	.func           = bpf_sk_cgroup_id,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_BTF_ID_SOCK_COMMON,
};

/* Helper 129: BPF_FUNC_sk_ancestor_cgroup_id */
const struct bpf_func_proto bpf_sk_ancestor_cgroup_id_proto = {
	.func           = bpf_sk_ancestor_cgroup_id,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_BTF_ID_SOCK_COMMON,
	.arg2_type      = ARG_ANYTHING,
};

/* Helper 130: BPF_FUNC_ringbuf_output */
const struct bpf_func_proto bpf_ringbuf_output_proto = {
	.func		= bpf_ringbuf_output,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_PTR_TO_MEM | MEM_RDONLY,
	.arg3_type	= ARG_CONST_SIZE_OR_ZERO,
	.arg4_type	= ARG_ANYTHING,
};

/* Helper 131: BPF_FUNC_ringbuf_reserve */
const struct bpf_func_proto bpf_ringbuf_reserve_proto = {
	.func		= bpf_ringbuf_reserve,
	.ret_type	= RET_PTR_TO_RINGBUF_MEM_OR_NULL,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_CONST_ALLOC_SIZE_OR_ZERO,
	.arg3_type	= ARG_ANYTHING,
};

/* Helper 132: BPF_FUNC_ringbuf_submit */
const struct bpf_func_proto bpf_ringbuf_submit_proto = {
	.func		= bpf_ringbuf_submit,
	.ret_type	= RET_VOID,
	.arg1_type	= ARG_PTR_TO_RINGBUF_MEM | OBJ_RELEASE,
	.arg2_type	= ARG_ANYTHING,
};

/* Helper 133: BPF_FUNC_ringbuf_discard */
const struct bpf_func_proto bpf_ringbuf_discard_proto = {
	.func		= bpf_ringbuf_discard,
	.ret_type	= RET_VOID,
	.arg1_type	= ARG_PTR_TO_RINGBUF_MEM | OBJ_RELEASE,
	.arg2_type	= ARG_ANYTHING,
};

/* Helper 134: BPF_FUNC_ringbuf_query */
const struct bpf_func_proto bpf_ringbuf_query_proto = {
	.func		= bpf_ringbuf_query,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_ANYTHING,
};

/* Helper 135: BPF_FUNC_csum_level */
const struct bpf_func_proto bpf_csum_level_proto = {
	.func		= bpf_csum_level,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
};

/* Helper 136: BPF_FUNC_skc_to_tcp6_sock */
const struct bpf_func_proto bpf_skc_to_tcp6_sock_proto = {
	.func			= bpf_skc_to_tcp6_sock,
	.gpl_only		= false,
	.ret_type		= RET_PTR_TO_BTF_ID_OR_NULL,
	.arg1_type		= ARG_PTR_TO_BTF_ID_SOCK_COMMON,
	.ret_btf_id		= &btf_sock_ids[BTF_SOCK_TYPE_TCP6],
};

/* Helper 137: BPF_FUNC_skc_to_tcp_sock */
const struct bpf_func_proto bpf_skc_to_tcp_sock_proto = {
	.func			= bpf_skc_to_tcp_sock,
	.gpl_only		= false,
	.ret_type		= RET_PTR_TO_BTF_ID_OR_NULL,
	.arg1_type		= ARG_PTR_TO_BTF_ID_SOCK_COMMON,
	.ret_btf_id		= &btf_sock_ids[BTF_SOCK_TYPE_TCP],
};

/* Helper 138: BPF_FUNC_skc_to_tcp_timewait_sock */
const struct bpf_func_proto bpf_skc_to_tcp_timewait_sock_proto = {
	.func			= bpf_skc_to_tcp_timewait_sock,
	.gpl_only		= false,
	.ret_type		= RET_PTR_TO_BTF_ID_OR_NULL,
	.arg1_type		= ARG_PTR_TO_BTF_ID_SOCK_COMMON,
	.ret_btf_id		= &btf_sock_ids[BTF_SOCK_TYPE_TCP_TW],
};

/* Helper 139: BPF_FUNC_skc_to_tcp_request_sock */
const struct bpf_func_proto bpf_skc_to_tcp_request_sock_proto = {
	.func			= bpf_skc_to_tcp_request_sock,
	.gpl_only		= false,
	.ret_type		= RET_PTR_TO_BTF_ID_OR_NULL,
	.arg1_type		= ARG_PTR_TO_BTF_ID_SOCK_COMMON,
	.ret_btf_id		= &btf_sock_ids[BTF_SOCK_TYPE_TCP_REQ],
};

/* Helper 140: BPF_FUNC_skc_to_udp6_sock */
const struct bpf_func_proto bpf_skc_to_udp6_sock_proto = {
	.func			= bpf_skc_to_udp6_sock,
	.gpl_only		= false,
	.ret_type		= RET_PTR_TO_BTF_ID_OR_NULL,
	.arg1_type		= ARG_PTR_TO_BTF_ID_SOCK_COMMON,
	.ret_btf_id		= &btf_sock_ids[BTF_SOCK_TYPE_UDP6],
};

/* Helper 141: BPF_FUNC_get_task_stack */
const struct bpf_func_proto bpf_get_task_stack_proto = {
	.func		= bpf_get_task_stack,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_BTF_ID,
	.arg1_btf_id	= &btf_tracing_ids[BTF_TRACING_TYPE_TASK],
	.arg2_type	= ARG_PTR_TO_UNINIT_MEM,
	.arg3_type	= ARG_CONST_SIZE_OR_ZERO,
	.arg4_type	= ARG_ANYTHING,
};

/* Helper 142: BPF_FUNC_load_hdr_opt */
const struct bpf_func_proto bpf_sock_ops_load_hdr_opt_proto = {
	.func		= bpf_sock_ops_load_hdr_opt,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_PTR_TO_MEM | MEM_WRITE,
	.arg3_type	= ARG_CONST_SIZE,
	.arg4_type	= ARG_ANYTHING,
};

/* Helper 143: BPF_FUNC_store_hdr_opt */
const struct bpf_func_proto bpf_sock_ops_store_hdr_opt_proto = {
	.func		= bpf_sock_ops_store_hdr_opt,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_PTR_TO_MEM | MEM_RDONLY,
	.arg3_type	= ARG_CONST_SIZE,
	.arg4_type	= ARG_ANYTHING,
};

/* Helper 144: BPF_FUNC_reserve_hdr_opt */
const struct bpf_func_proto bpf_sock_ops_reserve_hdr_opt_proto = {
	.func		= bpf_sock_ops_reserve_hdr_opt,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_ANYTHING,
};

/* Helper 145: BPF_FUNC_inode_storage_get */
const struct bpf_func_proto bpf_inode_storage_get_proto = {
	.func		= bpf_inode_storage_get,
	.gpl_only	= false,
	.ret_type	= RET_PTR_TO_MAP_VALUE_OR_NULL,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_PTR_TO_BTF_ID_OR_NULL,
	.arg2_btf_id	= &bpf_inode_storage_btf_ids[0],
	.arg3_type	= ARG_PTR_TO_MAP_VALUE_OR_NULL,
	.arg4_type	= ARG_ANYTHING,
};

/* Helper 146: BPF_FUNC_inode_storage_delete */
const struct bpf_func_proto bpf_inode_storage_delete_proto = {
	.func		= bpf_inode_storage_delete,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_PTR_TO_BTF_ID_OR_NULL,
	.arg2_btf_id	= &bpf_inode_storage_btf_ids[0],
};

/* Helper 147: BPF_FUNC_d_path */
const struct bpf_func_proto bpf_d_path_proto = {
	.func		= bpf_d_path,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_BTF_ID,
	.arg1_btf_id	= &bpf_d_path_btf_ids[0],
	.arg2_type	= ARG_PTR_TO_MEM,
	.arg3_type	= ARG_CONST_SIZE_OR_ZERO,
	.allowed	= bpf_d_path_allowed,
};

/* Helper 148: BPF_FUNC_copy_from_user */
const struct bpf_func_proto bpf_copy_from_user_proto = {
	.func		= bpf_copy_from_user,
	.gpl_only	= false,
	.might_sleep	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_UNINIT_MEM,
	.arg2_type	= ARG_CONST_SIZE_OR_ZERO,
	.arg3_type	= ARG_ANYTHING,
};

/* Helper 149: BPF_FUNC_snprintf_btf */
const struct bpf_func_proto bpf_snprintf_btf_proto = {
	.func		= bpf_snprintf_btf,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_MEM,
	.arg2_type	= ARG_CONST_SIZE,
	.arg3_type	= ARG_PTR_TO_MEM | MEM_RDONLY,
	.arg4_type	= ARG_CONST_SIZE,
	.arg5_type	= ARG_ANYTHING,
};

/* Helper 150: BPF_FUNC_seq_printf_btf */
const struct bpf_func_proto bpf_seq_printf_btf_proto = {
	.func		= bpf_seq_printf_btf,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_BTF_ID,
	.arg1_btf_id	= &btf_seq_file_ids[0],
	.arg2_type	= ARG_PTR_TO_MEM | MEM_RDONLY,
	.arg3_type	= ARG_CONST_SIZE_OR_ZERO,
	.arg4_type	= ARG_ANYTHING,
};

/* Helper 151: BPF_FUNC_skb_cgroup_classid */
const struct bpf_func_proto bpf_skb_cgroup_classid_proto = {
	.func		= bpf_skb_cgroup_classid,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
};

/* Helper 152: BPF_FUNC_redirect_neigh */
const struct bpf_func_proto bpf_redirect_neigh_proto = {
	.func		= bpf_redirect_neigh,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_ANYTHING,
	.arg2_type      = ARG_PTR_TO_MEM | PTR_MAYBE_NULL | MEM_RDONLY,
	.arg3_type      = ARG_CONST_SIZE_OR_ZERO,
	.arg4_type	= ARG_ANYTHING,
};

/* Helper 153: BPF_FUNC_per_cpu_ptr */
const struct bpf_func_proto bpf_per_cpu_ptr_proto = {
	.func		= bpf_per_cpu_ptr,
	.gpl_only	= false,
	.ret_type	= RET_PTR_TO_MEM_OR_BTF_ID | PTR_MAYBE_NULL | MEM_RDONLY,
	.arg1_type	= ARG_PTR_TO_PERCPU_BTF_ID,
	.arg2_type	= ARG_ANYTHING,
};

/* Helper 154: BPF_FUNC_this_cpu_ptr */
const struct bpf_func_proto bpf_this_cpu_ptr_proto = {
	.func		= bpf_this_cpu_ptr,
	.gpl_only	= false,
	.ret_type	= RET_PTR_TO_MEM_OR_BTF_ID | MEM_RDONLY,
	.arg1_type	= ARG_PTR_TO_PERCPU_BTF_ID,
};

/* Helper 155: BPF_FUNC_redirect_peer */
const struct bpf_func_proto bpf_redirect_peer_proto = {
	.func           = bpf_redirect_peer,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_ANYTHING,
	.arg2_type      = ARG_ANYTHING,
};

/* Helper 156: BPF_FUNC_task_storage_get */
const struct bpf_func_proto bpf_task_storage_get_proto = {
	.func = bpf_task_storage_get,
	.gpl_only = false,
	.ret_type = RET_PTR_TO_MAP_VALUE_OR_NULL,
	.arg1_type = ARG_CONST_MAP_PTR,
	.arg2_type = ARG_PTR_TO_BTF_ID_OR_NULL,
	.arg2_btf_id = &btf_tracing_ids[BTF_TRACING_TYPE_TASK],
	.arg3_type = ARG_PTR_TO_MAP_VALUE_OR_NULL,
	.arg4_type = ARG_ANYTHING,
};

/* Helper 157: BPF_FUNC_task_storage_delete */
const struct bpf_func_proto bpf_task_storage_delete_proto = {
	.func = bpf_task_storage_delete,
	.gpl_only = false,
	.ret_type = RET_INTEGER,
	.arg1_type = ARG_CONST_MAP_PTR,
	.arg2_type = ARG_PTR_TO_BTF_ID_OR_NULL,
	.arg2_btf_id = &btf_tracing_ids[BTF_TRACING_TYPE_TASK],
};

/* Helper 158: BPF_FUNC_get_current_task_btf */
const struct bpf_func_proto bpf_get_current_task_btf_proto = {
	.func		= bpf_get_current_task_btf,
	.gpl_only	= true,
	.ret_type	= RET_PTR_TO_BTF_ID_TRUSTED,
	.ret_btf_id	= &btf_tracing_ids[BTF_TRACING_TYPE_TASK],
};

/* Helper 159: BPF_FUNC_bprm_opts_set */
const struct bpf_func_proto bpf_bprm_opts_set_proto = {
	.func		= bpf_bprm_opts_set,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_BTF_ID,
	.arg1_btf_id	= &bpf_bprm_opts_set_btf_ids[0],
	.arg2_type	= ARG_ANYTHING,
};

/* Helper 160: BPF_FUNC_ktime_get_coarse_ns */
const struct bpf_func_proto bpf_ktime_get_coarse_ns_proto = {
	.func		= bpf_ktime_get_coarse_ns,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
};

/* Helper 161: BPF_FUNC_ima_inode_hash */
const struct bpf_func_proto bpf_ima_inode_hash_proto = {
	.func		= bpf_ima_inode_hash,
	.gpl_only	= false,
	.might_sleep	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_BTF_ID,
	.arg1_btf_id	= &bpf_ima_inode_hash_btf_ids[0],
	.arg2_type	= ARG_PTR_TO_UNINIT_MEM,
	.arg3_type	= ARG_CONST_SIZE,
	.allowed	= bpf_ima_inode_hash_allowed,
};

/* Helper 162: BPF_FUNC_sock_from_file */
const struct bpf_func_proto bpf_sock_from_file_proto = {
	.func		= bpf_sock_from_file,
	.gpl_only	= false,
	.ret_type	= RET_PTR_TO_BTF_ID_OR_NULL,
	.ret_btf_id	= &bpf_sock_from_file_btf_ids[0],
	.arg1_type	= ARG_PTR_TO_BTF_ID,
	.arg1_btf_id	= &bpf_sock_from_file_btf_ids[1],
};

/* Helper 163: BPF_FUNC_check_mtu */
const struct bpf_func_proto bpf_skb_check_mtu_proto = {
	.func		= bpf_skb_check_mtu,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
	.arg2_type      = ARG_ANYTHING,
	.arg3_type      = ARG_PTR_TO_FIXED_SIZE_MEM | MEM_WRITE | MEM_ALIGNED,
	.arg3_size	= sizeof(u32),
	.arg4_type      = ARG_ANYTHING,
	.arg5_type      = ARG_ANYTHING,
};

/* Helper 164: BPF_FUNC_for_each_map_elem */
const struct bpf_func_proto bpf_for_each_map_elem_proto = {
	.func		= bpf_for_each_map_elem,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_PTR_TO_FUNC,
	.arg3_type	= ARG_PTR_TO_STACK_OR_NULL,
	.arg4_type	= ARG_ANYTHING,
};

/* Helper 165: BPF_FUNC_snprintf */
const struct bpf_func_proto bpf_snprintf_proto = {
	.func		= bpf_snprintf,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_MEM_OR_NULL,
	.arg2_type	= ARG_CONST_SIZE_OR_ZERO,
	.arg3_type	= ARG_PTR_TO_CONST_STR,
	.arg4_type	= ARG_PTR_TO_MEM | PTR_MAYBE_NULL | MEM_RDONLY,
	.arg5_type	= ARG_CONST_SIZE_OR_ZERO,
};

/* Helper 166: BPF_FUNC_sys_bpf */
const struct bpf_func_proto bpf_sys_bpf_proto = {
	.func		= bpf_sys_bpf,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_ANYTHING,
	.arg2_type	= ARG_PTR_TO_MEM | MEM_RDONLY,
	.arg3_type	= ARG_CONST_SIZE,
};

/* Helper 167: BPF_FUNC_btf_find_by_name_kind */
const struct bpf_func_proto bpf_btf_find_by_name_kind_proto = {
	.func		= bpf_btf_find_by_name_kind,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_MEM | MEM_RDONLY,
	.arg2_type	= ARG_CONST_SIZE,
	.arg3_type	= ARG_ANYTHING,
	.arg4_type	= ARG_ANYTHING,
};

/* Helper 168: BPF_FUNC_sys_close */
const struct bpf_func_proto bpf_sys_close_proto = {
	.func		= bpf_sys_close,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_ANYTHING,
};

/* Helper 169: BPF_FUNC_timer_init */
const struct bpf_func_proto bpf_timer_init_proto = {
	.func		= bpf_timer_init,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_TIMER,
	.arg2_type	= ARG_CONST_MAP_PTR,
	.arg3_type	= ARG_ANYTHING,
};

/* Helper 170: BPF_FUNC_timer_set_callback */
const struct bpf_func_proto bpf_timer_set_callback_proto = {
	.func		= bpf_timer_set_callback,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_TIMER,
	.arg2_type	= ARG_PTR_TO_FUNC,
};

/* Helper 171: BPF_FUNC_timer_start */
const struct bpf_func_proto bpf_timer_start_proto = {
	.func		= bpf_timer_start,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_TIMER,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_ANYTHING,
};

/* Helper 172: BPF_FUNC_timer_cancel */
const struct bpf_func_proto bpf_timer_cancel_proto = {
	.func		= bpf_timer_cancel,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_TIMER,
};

/* Helper 173: BPF_FUNC_get_func_ip */
const struct bpf_func_proto bpf_get_func_ip_proto_tracing = {
	.func		= bpf_get_func_ip_tracing,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
};

/* Helper 174: BPF_FUNC_get_attach_cookie */
const struct bpf_func_proto bpf_get_attach_cookie_proto = {
	.func		= bpf_get_attach_cookie,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
};

/* Helper 175: BPF_FUNC_task_pt_regs */
const struct bpf_func_proto bpf_task_pt_regs_proto = {
	.func		= bpf_task_pt_regs,
	.gpl_only	= true,
	.arg1_type	= ARG_PTR_TO_BTF_ID,
	.arg1_btf_id	= &btf_tracing_ids[BTF_TRACING_TYPE_TASK],
	.ret_type	= RET_PTR_TO_BTF_ID,
	.ret_btf_id	= &bpf_task_pt_regs_ids[0],
};

/* Helper 176: BPF_FUNC_get_branch_snapshot */
const struct bpf_func_proto bpf_get_branch_snapshot_proto = {
	.func		= bpf_get_branch_snapshot,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_UNINIT_MEM,
	.arg2_type	= ARG_CONST_SIZE_OR_ZERO,
};

/* Helper 177: BPF_FUNC_trace_vprintk */
const struct bpf_func_proto bpf_trace_vprintk_proto = {
	.func		= bpf_trace_vprintk,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_MEM | MEM_RDONLY,
	.arg2_type	= ARG_CONST_SIZE,
	.arg3_type	= ARG_PTR_TO_MEM | PTR_MAYBE_NULL | MEM_RDONLY,
	.arg4_type	= ARG_CONST_SIZE_OR_ZERO,
};

/* Helper 178: BPF_FUNC_skc_to_unix_sock */
const struct bpf_func_proto bpf_skc_to_unix_sock_proto = {
	.func			= bpf_skc_to_unix_sock,
	.gpl_only		= false,
	.ret_type		= RET_PTR_TO_BTF_ID_OR_NULL,
	.arg1_type		= ARG_PTR_TO_BTF_ID_SOCK_COMMON,
	.ret_btf_id		= &btf_sock_ids[BTF_SOCK_TYPE_UNIX],
};

/* Helper 179: BPF_FUNC_kallsyms_lookup_name */
const struct bpf_func_proto bpf_kallsyms_lookup_name_proto = {
	.func		= bpf_kallsyms_lookup_name,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_MEM,
	.arg2_type	= ARG_CONST_SIZE_OR_ZERO,
	.arg3_type	= ARG_ANYTHING,
	.arg4_type	= ARG_PTR_TO_FIXED_SIZE_MEM | MEM_UNINIT | MEM_WRITE | MEM_ALIGNED,
	.arg4_size	= sizeof(u64),
};

/* Helper 180: BPF_FUNC_find_vma */
const struct bpf_func_proto bpf_find_vma_proto = {
	.func		= bpf_find_vma,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_BTF_ID,
	.arg1_btf_id	= &btf_tracing_ids[BTF_TRACING_TYPE_TASK],
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_PTR_TO_FUNC,
	.arg4_type	= ARG_PTR_TO_STACK_OR_NULL,
	.arg5_type	= ARG_ANYTHING,
};

/* Helper 181: BPF_FUNC_loop */
const struct bpf_func_proto bpf_loop_proto = {
	.func		= bpf_loop,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_ANYTHING,
	.arg2_type	= ARG_PTR_TO_FUNC,
	.arg3_type	= ARG_PTR_TO_STACK_OR_NULL,
	.arg4_type	= ARG_ANYTHING,
};

/* Helper 182: BPF_FUNC_strncmp */
const struct bpf_func_proto bpf_strncmp_proto = {
	.func		= bpf_strncmp,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_MEM | MEM_RDONLY,
	.arg2_type	= ARG_CONST_SIZE,
	.arg3_type	= ARG_PTR_TO_CONST_STR,
};

/* Helper 183: BPF_FUNC_get_func_arg */
const struct bpf_func_proto bpf_get_func_arg_proto = {
	.func		= get_func_arg,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_PTR_TO_FIXED_SIZE_MEM | MEM_UNINIT | MEM_WRITE | MEM_ALIGNED,
	.arg3_size	= sizeof(u64),
};

/* Helper 184: BPF_FUNC_get_func_ret */
const struct bpf_func_proto bpf_get_func_ret_proto = {
	.func		= get_func_ret,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_PTR_TO_FIXED_SIZE_MEM | MEM_UNINIT | MEM_WRITE | MEM_ALIGNED,
	.arg2_size	= sizeof(u64),
};

/* Helper 185: BPF_FUNC_get_func_arg_cnt */
const struct bpf_func_proto bpf_get_func_arg_cnt_proto = {
	.func		= get_func_arg_cnt,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
};

/* Helper 186: BPF_FUNC_get_retval */
const struct bpf_func_proto bpf_get_retval_proto = {
	.func		= bpf_get_retval,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
};

/* Helper 187: BPF_FUNC_set_retval */
const struct bpf_func_proto bpf_set_retval_proto = {
	.func		= bpf_set_retval,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_ANYTHING,
};

/* Helper 188: BPF_FUNC_xdp_get_buff_len */
const struct bpf_func_proto bpf_xdp_get_buff_len_proto = {
	.func		= bpf_xdp_get_buff_len,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
};

/* Helper 189: BPF_FUNC_xdp_load_bytes */
const struct bpf_func_proto bpf_xdp_load_bytes_proto = {
	.func		= bpf_xdp_load_bytes,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_PTR_TO_UNINIT_MEM,
	.arg4_type	= ARG_CONST_SIZE,
};

/* Helper 190: BPF_FUNC_xdp_store_bytes */
const struct bpf_func_proto bpf_xdp_store_bytes_proto = {
	.func		= bpf_xdp_store_bytes,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_PTR_TO_UNINIT_MEM,
	.arg4_type	= ARG_CONST_SIZE,
};

/* Helper 191: BPF_FUNC_copy_from_user_task */
const struct bpf_func_proto bpf_copy_from_user_task_proto = {
	.func		= bpf_copy_from_user_task,
	.gpl_only	= true,
	.might_sleep	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_UNINIT_MEM,
	.arg2_type	= ARG_CONST_SIZE_OR_ZERO,
	.arg3_type	= ARG_ANYTHING,
	.arg4_type	= ARG_PTR_TO_BTF_ID,
	.arg4_btf_id	= &btf_tracing_ids[BTF_TRACING_TYPE_TASK],
	.arg5_type	= ARG_ANYTHING,
};

/* Helper 192: BPF_FUNC_skb_set_tstamp */
const struct bpf_func_proto bpf_skb_set_tstamp_proto = {
	.func           = bpf_skb_set_tstamp,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_PTR_TO_CTX,
	.arg2_type      = ARG_ANYTHING,
	.arg3_type      = ARG_ANYTHING,
};

/* Helper 193: BPF_FUNC_ima_file_hash */
const struct bpf_func_proto bpf_ima_file_hash_proto = {
	.func		= bpf_ima_file_hash,
	.gpl_only	= false,
	.might_sleep	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_BTF_ID,
	.arg1_btf_id	= &bpf_ima_file_hash_btf_ids[0],
	.arg2_type	= ARG_PTR_TO_UNINIT_MEM,
	.arg3_type	= ARG_CONST_SIZE,
	.allowed	= bpf_ima_inode_hash_allowed,
};

/* Helper 194: BPF_FUNC_kptr_xchg */
const struct bpf_func_proto bpf_kptr_xchg_proto = {
	.func         = bpf_kptr_xchg,
	.gpl_only     = false,
	.ret_type     = RET_PTR_TO_BTF_ID_OR_NULL,
	.ret_btf_id   = BPF_PTR_POISON,
	.arg1_type    = ARG_PTR_TO_KPTR,
	.arg2_type    = ARG_PTR_TO_BTF_ID_OR_NULL | OBJ_RELEASE,
	.arg2_btf_id  = BPF_PTR_POISON,
};

/* Helper 195: BPF_FUNC_map_lookup_percpu_elem */
const struct bpf_func_proto bpf_map_lookup_percpu_elem_proto = {
	.func		= bpf_map_lookup_percpu_elem,
	.gpl_only	= false,
	.pkt_access	= true,
	.ret_type	= RET_PTR_TO_MAP_VALUE_OR_NULL,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_PTR_TO_MAP_KEY,
	.arg3_type	= ARG_ANYTHING,
};

/* Helper 196: BPF_FUNC_skc_to_mptcp_sock */
const struct bpf_func_proto bpf_skc_to_mptcp_sock_proto = {
	.func		= bpf_skc_to_mptcp_sock,
	.gpl_only	= false,
	.ret_type	= RET_PTR_TO_BTF_ID_OR_NULL,
	.arg1_type	= ARG_PTR_TO_SOCK_COMMON,
	.ret_btf_id	= &btf_sock_ids[BTF_SOCK_TYPE_MPTCP],
};

/* Helper 197: BPF_FUNC_dynptr_from_mem */
const struct bpf_func_proto bpf_dynptr_from_mem_proto = {
	.func		= bpf_dynptr_from_mem,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_UNINIT_MEM,
	.arg2_type	= ARG_CONST_SIZE_OR_ZERO,
	.arg3_type	= ARG_ANYTHING,
	.arg4_type	= ARG_PTR_TO_DYNPTR | DYNPTR_TYPE_LOCAL | MEM_UNINIT | MEM_WRITE,
};

/* Helper 198: BPF_FUNC_ringbuf_reserve_dynptr */
const struct bpf_func_proto bpf_ringbuf_reserve_dynptr_proto = {
	.func		= bpf_ringbuf_reserve_dynptr,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_ANYTHING,
	.arg4_type	= ARG_PTR_TO_DYNPTR | DYNPTR_TYPE_RINGBUF | MEM_UNINIT | MEM_WRITE,
};

/* Helper 199: BPF_FUNC_ringbuf_submit_dynptr */
const struct bpf_func_proto bpf_ringbuf_submit_dynptr_proto = {
	.func		= bpf_ringbuf_submit_dynptr,
	.ret_type	= RET_VOID,
	.arg1_type	= ARG_PTR_TO_DYNPTR | DYNPTR_TYPE_RINGBUF | OBJ_RELEASE,
	.arg2_type	= ARG_ANYTHING,
};

/* Helper 200: BPF_FUNC_ringbuf_discard_dynptr */
const struct bpf_func_proto bpf_ringbuf_discard_dynptr_proto = {
	.func		= bpf_ringbuf_discard_dynptr,
	.ret_type	= RET_VOID,
	.arg1_type	= ARG_PTR_TO_DYNPTR | DYNPTR_TYPE_RINGBUF | OBJ_RELEASE,
	.arg2_type	= ARG_ANYTHING,
};

/* Helper 201: BPF_FUNC_dynptr_read */
const struct bpf_func_proto bpf_dynptr_read_proto = {
	.func		= bpf_dynptr_read,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_UNINIT_MEM,
	.arg2_type	= ARG_CONST_SIZE_OR_ZERO,
	.arg3_type	= ARG_PTR_TO_DYNPTR | MEM_RDONLY,
	.arg4_type	= ARG_ANYTHING,
	.arg5_type	= ARG_ANYTHING,
};

/* Helper 202: BPF_FUNC_dynptr_write */
const struct bpf_func_proto bpf_dynptr_write_proto = {
	.func		= bpf_dynptr_write,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_DYNPTR | MEM_RDONLY,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_PTR_TO_MEM | MEM_RDONLY,
	.arg4_type	= ARG_CONST_SIZE_OR_ZERO,
	.arg5_type	= ARG_ANYTHING,
};

/* Helper 203: BPF_FUNC_dynptr_data */
const struct bpf_func_proto bpf_dynptr_data_proto = {
	.func		= bpf_dynptr_data,
	.gpl_only	= false,
	.ret_type	= RET_PTR_TO_DYNPTR_MEM_OR_NULL,
	.arg1_type	= ARG_PTR_TO_DYNPTR | MEM_RDONLY,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_CONST_ALLOC_SIZE_OR_ZERO,
};

/* Helper 204: BPF_FUNC_tcp_raw_gen_syncookie_ipv4 */
const struct bpf_func_proto bpf_tcp_raw_gen_syncookie_ipv4_proto = {
	.func		= bpf_tcp_raw_gen_syncookie_ipv4,
	.gpl_only	= true,
	.pkt_access	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_FIXED_SIZE_MEM,
	.arg1_size	= sizeof(struct iphdr),
	.arg2_type	= ARG_PTR_TO_MEM,
	.arg3_type	= ARG_CONST_SIZE_OR_ZERO,
};

/* Helper 205: BPF_FUNC_tcp_raw_gen_syncookie_ipv6 */
const struct bpf_func_proto bpf_tcp_raw_gen_syncookie_ipv6_proto = {
	.func		= bpf_tcp_raw_gen_syncookie_ipv6,
	.gpl_only	= true,
	.pkt_access	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_FIXED_SIZE_MEM,
	.arg1_size	= sizeof(struct ipv6hdr),
	.arg2_type	= ARG_PTR_TO_MEM,
	.arg3_type	= ARG_CONST_SIZE_OR_ZERO,
};

/* Helper 206: BPF_FUNC_tcp_raw_check_syncookie_ipv4 */
const struct bpf_func_proto bpf_tcp_raw_check_syncookie_ipv4_proto = {
	.func		= bpf_tcp_raw_check_syncookie_ipv4,
	.gpl_only	= true,
	.pkt_access	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_FIXED_SIZE_MEM,
	.arg1_size	= sizeof(struct iphdr),
	.arg2_type	= ARG_PTR_TO_FIXED_SIZE_MEM,
	.arg2_size	= sizeof(struct tcphdr),
};

/* Helper 207: BPF_FUNC_tcp_raw_check_syncookie_ipv6 */
const struct bpf_func_proto bpf_tcp_raw_check_syncookie_ipv6_proto = {
	.func		= bpf_tcp_raw_check_syncookie_ipv6,
	.gpl_only	= true,
	.pkt_access	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_FIXED_SIZE_MEM,
	.arg1_size	= sizeof(struct ipv6hdr),
	.arg2_type	= ARG_PTR_TO_FIXED_SIZE_MEM,
	.arg2_size	= sizeof(struct tcphdr),
};

/* Helper 208: BPF_FUNC_ktime_get_tai_ns */
const struct bpf_func_proto bpf_ktime_get_tai_ns_proto = {
	.func		= bpf_ktime_get_tai_ns,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
};

/* Helper 209: BPF_FUNC_user_ringbuf_drain */
const struct bpf_func_proto bpf_user_ringbuf_drain_proto = {
	.func		= bpf_user_ringbuf_drain,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_PTR_TO_FUNC,
	.arg3_type	= ARG_PTR_TO_STACK_OR_NULL,
	.arg4_type	= ARG_ANYTHING,
};

/* Helper 210: BPF_FUNC_cgrp_storage_get */
const struct bpf_func_proto bpf_cgrp_storage_get_proto = {
	.func		= bpf_cgrp_storage_get,
	.gpl_only	= false,
	.ret_type	= RET_PTR_TO_MAP_VALUE_OR_NULL,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_PTR_TO_BTF_ID_OR_NULL,
	.arg2_btf_id	= &bpf_cgroup_btf_id[0],
	.arg3_type	= ARG_PTR_TO_MAP_VALUE_OR_NULL,
	.arg4_type	= ARG_ANYTHING,
};

/* Helper 211: BPF_FUNC_cgrp_storage_delete */
const struct bpf_func_proto bpf_cgrp_storage_delete_proto = {
	.func		= bpf_cgrp_storage_delete,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_PTR_TO_BTF_ID_OR_NULL,
	.arg2_btf_id	= &bpf_cgroup_btf_id[0],
};


