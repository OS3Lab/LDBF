#ifndef _DEPENDENCY_BTF_IDS_H
#define _DEPENDENCY_BTF_IDS_H

/* ------------------------------------------------------------------------
 * Minimal self-contained BTF macro stubs (non-functional, for parsing only)
 * ------------------------------------------------------------------------ */
#ifndef BTF_ID_LIST
#define BTF_ID_LIST(name)
#endif
#ifndef BTF_ID_LIST_GLOBAL
#define BTF_ID_LIST_GLOBAL(name, n)
#endif
#ifndef BTF_ID
#define BTF_ID(prefix, typename)
#endif
#ifndef BTF_ID_UNUSED
#define BTF_ID_UNUSED
#endif
#ifndef BTF_ID_LIST_SINGLE
#define BTF_ID_LIST_SINGLE(name, prefix, typename) BTF_ID_LIST(name)
#endif
#ifndef BTF_ID_LIST_GLOBAL_SINGLE
#define BTF_ID_LIST_GLOBAL_SINGLE(name, prefix, typename) BTF_ID_LIST_GLOBAL(name, 1)
#endif
#ifndef BTF_ID_EXTERN
#define BTF_ID_EXTERN(name)
#endif

/* Helper macro to annotate index + type explicitly. */
#define BTF_ID_LIST_SINGLE_INDEXED(list, idx, prefix, typename)

/* ------------------------------------------------------------------------
 * Helper-specific BTF ID lists (expanded from kernel definitions)
 * ------------------------------------------------------------------------ */
BTF_ID_LIST_SINGLE(bpf_xdp_output_btf_ids, struct, xdp_buff)
BTF_ID_LIST_SINGLE(bpf_skb_output_btf_ids, struct, sk_buff)
BTF_ID_LIST_SINGLE(bpf_d_path_btf_ids, struct, path)
BTF_ID_LIST_SINGLE(bpf_bprm_opts_set_btf_ids, struct, linux_binprm)
BTF_ID_LIST_SINGLE(bpf_ima_file_hash_btf_ids, struct, file)
BTF_ID_LIST_SINGLE(bpf_ima_inode_hash_btf_ids, struct, inode)
BTF_ID_LIST_SINGLE(bpf_inode_storage_btf_ids, struct, inode)
BTF_ID_LIST_SINGLE(bpf_sock_from_file_btf_ids, struct, socket)
BTF_ID_LIST_SINGLE(bpf_task_pt_regs_ids, struct, pt_regs)
BTF_ID_LIST_SINGLE(bpf_cgroup_btf_id, struct, cgroup)
BTF_ID_LIST_SINGLE(btf_seq_file_ids, struct, seq_file)

/* ------------------------------------------------------------------------
 * Socket-related BTF IDs (mirrors tools/include/linux/btf_ids.h)
 * ------------------------------------------------------------------------ */
#define BTF_SOCK_TYPE_xxx                        \
	BTF_SOCK_TYPE(BTF_SOCK_TYPE_INET, inet_sock)            \
	BTF_SOCK_TYPE(BTF_SOCK_TYPE_INET_CONN, inet_connection_sock) \
	BTF_SOCK_TYPE(BTF_SOCK_TYPE_INET_REQ, inet_request_sock) \
	BTF_SOCK_TYPE(BTF_SOCK_TYPE_INET_TW, inet_timewait_sock) \
	BTF_SOCK_TYPE(BTF_SOCK_TYPE_REQ, request_sock)          \
	BTF_SOCK_TYPE(BTF_SOCK_TYPE_SOCK, sock)                 \
	BTF_SOCK_TYPE(BTF_SOCK_TYPE_SOCK_COMMON, sock_common)   \
	BTF_SOCK_TYPE(BTF_SOCK_TYPE_TCP, tcp_sock)              \
	BTF_SOCK_TYPE(BTF_SOCK_TYPE_TCP_REQ, tcp_request_sock)  \
	BTF_SOCK_TYPE(BTF_SOCK_TYPE_TCP_TW, tcp_timewait_sock)  \
	BTF_SOCK_TYPE(BTF_SOCK_TYPE_TCP6, tcp6_sock)            \
	BTF_SOCK_TYPE(BTF_SOCK_TYPE_UDP, udp_sock)              \
	BTF_SOCK_TYPE(BTF_SOCK_TYPE_UDP6, udp6_sock)            \
	BTF_SOCK_TYPE(BTF_SOCK_TYPE_UNIX, unix_sock)            \
	BTF_SOCK_TYPE(BTF_SOCK_TYPE_MPTCP, mptcp_sock)          \
	BTF_SOCK_TYPE(BTF_SOCK_TYPE_SOCKET, socket)

enum {
#define BTF_SOCK_TYPE(name, type) name,
	BTF_SOCK_TYPE_xxx
#undef BTF_SOCK_TYPE
	MAX_BTF_SOCK_TYPE,
};

BTF_ID_LIST_GLOBAL(btf_sock_ids, MAX_BTF_SOCK_TYPE)

/* Indexed entries for easier parsing */
#define BTF_SOCK_TYPE(name, type) \
	BTF_ID_LIST_SINGLE_INDEXED(btf_sock_ids, name, struct, type)
BTF_SOCK_TYPE_xxx
#undef BTF_SOCK_TYPE

/* ------------------------------------------------------------------------
 * Tracing-related BTF IDs (mirrors tools/include/linux/btf_ids.h)
 * ------------------------------------------------------------------------ */
#define BTF_TRACING_TYPE_xxx   \
	BTF_TRACING_TYPE(BTF_TRACING_TYPE_TASK, task_struct) \
	BTF_TRACING_TYPE(BTF_TRACING_TYPE_FILE, file)        \
	BTF_TRACING_TYPE(BTF_TRACING_TYPE_VMA, vm_area_struct)

enum {
#define BTF_TRACING_TYPE(name, type) name,
	BTF_TRACING_TYPE_xxx
#undef BTF_TRACING_TYPE
	MAX_BTF_TRACING_TYPE,
};

BTF_ID_LIST(btf_tracing_ids)

/* Indexed entries for easier parsing */
#define BTF_TRACING_TYPE(name, type) \
	BTF_ID_LIST_SINGLE_INDEXED(btf_tracing_ids, name, struct, type)
BTF_TRACING_TYPE_xxx
#undef BTF_TRACING_TYPE

/* ------------------------------------------------------------------------
 * Extern BTF symbols
 * ------------------------------------------------------------------------ */
BTF_ID_EXTERN(tcp_sock_id)

#endif /* _DEPENDENCY_BTF_IDS_H */
