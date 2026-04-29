/*
 * BPF Type System Definitions
 * ===========================
 * This file contains comprehensive definitions of BPF type system used by
 * the BPF verifier for type checking during program verification.
 *
 * For examples of how to use these types in helper function prototypes,
 * see bpf_helper_protos.c
 */

#ifndef _BPF_TYPES_H
#define _BPF_TYPES_H

#include <linux/types.h>

/* Basic constants and macros */
#define BIT(nr)			(1UL << (nr))
#define BPF_BASE_TYPE_BITS	8
#define BPF_TYPE_LIMIT		0xFFFF
#define BPF_BASE_TYPE_LIMIT	0xFF
#define BPF_BASE_TYPE_MASK	0xFF

/* Helper macros */
#define base_type(x) ((x) & BPF_BASE_TYPE_MASK)

/* ========================================
 * BPF Type Flags
 * ========================================
 * These flags can be combined with basic types to create extended types.
 * Used by both argument types and register types.
 */
enum bpf_type_flag {
	/* PTR may be NULL. */
	PTR_MAYBE_NULL		= BIT(0 + BPF_BASE_TYPE_BITS),
	/* MEM is read-only. When applied on bpf_arg, it indicates the arg is
	 * compatible with both mutable and immutable memory.
	 */
	MEM_RDONLY		= BIT(1 + BPF_BASE_TYPE_BITS),
	/* MEM points to BPF ring buffer reservation. */
	MEM_RINGBUF		= BIT(2 + BPF_BASE_TYPE_BITS),
	/* MEM is in user address space. */
	MEM_USER		= BIT(3 + BPF_BASE_TYPE_BITS),
	/* MEM is a percpu memory. MEM_PERCPU tags PTR_TO_BTF_ID. When tagged
	 * with MEM_PERCPU, PTR_TO_BTF_ID can be accessed by bpf_per_cpu_ptr()
	 * and bpf_this_cpu_ptr().
	 */
	MEM_PERCPU		= BIT(4 + BPF_BASE_TYPE_BITS),
	/* Indicates that the argument will be released. */
	OBJ_RELEASE		= BIT(5 + BPF_BASE_TYPE_BITS),
	/* PTR is not trusted. This is only used for arguments that are pointers
	 * to types in program BTF. This is used primarily to inform the verifier
	 * that pointers to such types do not need to be null-checked, as the
	 * kernel will never pass a NULL pointer to a kfunc or helper, and
	 * enable other optimizations. See PTR_TO_BTF_ID for more details.
	 */
	PTR_UNTRUSTED		= BIT(6 + BPF_BASE_TYPE_BITS),
	/* MEM can be uninitialized. */
	MEM_UNINIT		= BIT(7 + BPF_BASE_TYPE_BITS),
	/* DYNPTR points to memory local to the bpf program. */
	DYNPTR_TYPE_LOCAL	= BIT(8 + BPF_BASE_TYPE_BITS),
	/* DYNPTR points to a kernel-produced ringbuf record. */
	DYNPTR_TYPE_RINGBUF	= BIT(9 + BPF_BASE_TYPE_BITS),
	/* Size is known at compile time. */
	MEM_FIXED_SIZE		= BIT(10 + BPF_BASE_TYPE_BITS),
	/* MEM is of an allocated object of type in program BTF. This is used to
	 * tag PTR_TO_BTF_ID allocated using bpf_obj_new.
	 */
	MEM_ALLOC		= BIT(11 + BPF_BASE_TYPE_BITS),
	/* PTR was passed from the kernel in a trusted context and may be passed
	 * to BPF_KFUNC_CALL kfuncs or helpers.
	 */
	PTR_TRUSTED		= BIT(12 + BPF_BASE_TYPE_BITS),
	/* MEM is tagged with rcu and memory access needs rcu_read_lock protection. */
	MEM_RCU			= BIT(13 + BPF_BASE_TYPE_BITS),
	/* Used to tag PTR_TO_BTF_ID | MEM_ALLOC references which are non-owning.
	 * Currently only specifies that the reference is non-owning, but in the
	 * future support for read-only references may be added to extend this flag.
	 */
	NON_OWN_REF		= BIT(14 + BPF_BASE_TYPE_BITS),
	/* DYNPTR points to sk_buff */
	DYNPTR_TYPE_SKB		= BIT(15 + BPF_BASE_TYPE_BITS),
	/* DYNPTR points to xdp_buff */
	DYNPTR_TYPE_XDP		= BIT(16 + BPF_BASE_TYPE_BITS),
	/* Memory must be aligned on some architectures, used in combination with
	 * MEM_FIXED_SIZE.
	 */
	MEM_ALIGNED		= BIT(17 + BPF_BASE_TYPE_BITS),
	/* MEM is being written to, often combined with MEM_UNINIT. Non-presence
	 * of MEM_WRITE means that MEM is only being read. MEM_WRITE without the
	 * MEM_UNINIT means that memory needs to be initialized since it is also
	 * read.
	 */
	MEM_WRITE		= BIT(18 + BPF_BASE_TYPE_BITS),
	__BPF_TYPE_FLAG_MAX,
	__BPF_TYPE_LAST_FLAG	= __BPF_TYPE_FLAG_MAX - 1,
};

#define DYNPTR_TYPE_FLAG_MASK	(DYNPTR_TYPE_LOCAL | DYNPTR_TYPE_RINGBUF | DYNPTR_TYPE_SKB | DYNPTR_TYPE_XDP)

/* ========================================
 * BPF Register Types
 * ========================================
 * These types represent what kind of values can be stored in BPF registers.
 * The verifier uses these to track the type and state of each register.
 */
enum bpf_reg_type {
	NOT_INIT = 0,		 /* nothing was written into register */
	SCALAR_VALUE,		 /* reg doesn't contain a valid pointer */
	PTR_TO_CTX,		 /* reg points to bpf_context */
	CONST_PTR_TO_MAP,	 /* reg points to struct bpf_map */
	PTR_TO_MAP_VALUE,	 /* reg points to map element value */
	PTR_TO_MAP_KEY,		 /* reg points to a map element key */
	PTR_TO_STACK,		 /* reg == frame_pointer + offset */
	PTR_TO_PACKET_META,	 /* skb->data - meta_len */
	PTR_TO_PACKET,		 /* reg points to skb->data */
	PTR_TO_PACKET_END,	 /* skb->data + headlen */
	PTR_TO_FLOW_KEYS,	 /* reg points to bpf_flow_keys */
	PTR_TO_SOCKET,		 /* reg points to struct bpf_sock */
	PTR_TO_SOCK_COMMON,	 /* reg points to sock_common */
	PTR_TO_TCP_SOCK,	 /* reg points to struct tcp_sock */
	PTR_TO_TP_BUFFER,	 /* reg points to a writable raw tp's buffer */
	PTR_TO_XDP_SOCK,	 /* reg points to struct xdp_sock */
	PTR_TO_BTF_ID,		 /* reg points to kernel struct */
	PTR_TO_MEM,		 /* reg points to valid memory region */
	PTR_TO_BUF,		 /* reg points to a read/write buffer */
	PTR_TO_FUNC,		 /* reg points to a bpf program function */
	CONST_PTR_TO_DYNPTR,	 /* reg points to a const struct bpf_dynptr */
	__BPF_REG_TYPE_MAX,

	/* Extended reg_types. */
	PTR_TO_MAP_VALUE_OR_NULL	= PTR_MAYBE_NULL | PTR_TO_MAP_VALUE,
	PTR_TO_SOCKET_OR_NULL		= PTR_MAYBE_NULL | PTR_TO_SOCKET,
	PTR_TO_SOCK_COMMON_OR_NULL	= PTR_MAYBE_NULL | PTR_TO_SOCK_COMMON,
	PTR_TO_TCP_SOCK_OR_NULL		= PTR_MAYBE_NULL | PTR_TO_TCP_SOCK,
	PTR_TO_BTF_ID_OR_NULL		= PTR_MAYBE_NULL | PTR_TO_BTF_ID,

	/* This must be the last entry. Its purpose is to ensure the enum is
	 * wide enough to hold the higher bits reserved for bpf_type_flag.
	 */
	__BPF_REG_TYPE_LIMIT	= BPF_TYPE_LIMIT,
};

/* ========================================
 * BPF Argument Types
 * ========================================
 * These types define what kind of arguments BPF helper functions accept.
 */
enum bpf_arg_type {
	ARG_DONTCARE = 0,	/* unused argument in helper function */

	/* the following constraints used to prototype
	 * bpf_map_lookup/update/delete_elem() functions
	 */
	ARG_CONST_MAP_PTR,	/* const argument used as pointer to bpf_map */
	ARG_PTR_TO_MAP_KEY,	/* pointer to stack used as map key */
	ARG_PTR_TO_MAP_VALUE,	/* pointer to stack used as map value */

	/* Used to prototype bpf_memcmp() and other functions that access data
	 * on eBPF program stack
	 */
	ARG_PTR_TO_MEM,		/* pointer to valid memory (stack, packet, map value) */

	ARG_CONST_SIZE,		/* number of bytes accessed from memory */
	ARG_CONST_SIZE_OR_ZERO,	/* number of bytes accessed from memory or 0 */

	ARG_PTR_TO_CTX,		/* pointer to context */
	ARG_ANYTHING,		/* any (initialized) argument is ok */
	ARG_PTR_TO_SPIN_LOCK,	/* pointer to bpf_spin_lock */
	ARG_PTR_TO_SOCK_COMMON,	/* pointer to sock_common */
	ARG_PTR_TO_SOCKET,	/* pointer to bpf_sock (fullsock) */
	ARG_PTR_TO_BTF_ID,	/* pointer to in-kernel struct */
	ARG_PTR_TO_RINGBUF_MEM,	/* pointer to dynamically reserved ringbuf memory */
	ARG_CONST_ALLOC_SIZE_OR_ZERO,	/* number of allocated bytes requested */
	ARG_PTR_TO_BTF_ID_SOCK_COMMON,	/* pointer to in-kernel sock_common or bpf-mirrored bpf_sock */
	ARG_PTR_TO_PERCPU_BTF_ID,	/* pointer to in-kernel percpu type */
	ARG_PTR_TO_FUNC,	/* pointer to a bpf program function */
	ARG_PTR_TO_STACK,	/* pointer to stack */
	ARG_PTR_TO_CONST_STR,	/* pointer to a null terminated read-only string */
	ARG_PTR_TO_TIMER,	/* pointer to bpf_timer */
	ARG_PTR_TO_KPTR,	/* pointer to referenced kptr */
	ARG_PTR_TO_DYNPTR,      /* pointer to bpf_dynptr. See bpf_type_flag for dynptr type */
	__BPF_ARG_TYPE_MAX,

	/* Extended arg_types. */
	ARG_PTR_TO_MAP_VALUE_OR_NULL	= PTR_MAYBE_NULL | ARG_PTR_TO_MAP_VALUE,
	ARG_PTR_TO_MEM_OR_NULL		= PTR_MAYBE_NULL | ARG_PTR_TO_MEM,
	ARG_PTR_TO_CTX_OR_NULL		= PTR_MAYBE_NULL | ARG_PTR_TO_CTX,
	ARG_PTR_TO_SOCKET_OR_NULL	= PTR_MAYBE_NULL | ARG_PTR_TO_SOCKET,
	ARG_PTR_TO_STACK_OR_NULL	= PTR_MAYBE_NULL | ARG_PTR_TO_STACK,
	ARG_PTR_TO_BTF_ID_OR_NULL	= PTR_MAYBE_NULL | ARG_PTR_TO_BTF_ID,
	/* Pointer to memory does not need to be initialized, since helper function
	 * fills all bytes or clears them in error case.
	 */
	ARG_PTR_TO_UNINIT_MEM		= MEM_UNINIT | MEM_WRITE | ARG_PTR_TO_MEM,
	/* Pointer to valid memory of size known at compile time. */
	ARG_PTR_TO_FIXED_SIZE_MEM	= MEM_FIXED_SIZE | ARG_PTR_TO_MEM,

	/* This must be the last entry. Its purpose is to ensure the enum is
	 * wide enough to hold the higher bits reserved for bpf_type_flag.
	 */
	__BPF_ARG_TYPE_LIMIT	= BPF_TYPE_LIMIT,
};
static_assert(__BPF_ARG_TYPE_MAX <= BPF_BASE_TYPE_LIMIT);

/* ========================================
 * BPF Return Types
 * ========================================
 * These types define what BPF helper functions can return.
 */
enum bpf_return_type {
	RET_INTEGER,			/* function returns integer */
	RET_VOID,			/* function doesn't return anything */
	RET_PTR_TO_MAP_VALUE,		/* returns a pointer to map elem value */
	RET_PTR_TO_SOCKET,		/* returns a pointer to a socket */
	RET_PTR_TO_TCP_SOCK,		/* returns a pointer to a tcp_sock */
	RET_PTR_TO_SOCK_COMMON,		/* returns a pointer to a sock_common */
	RET_PTR_TO_MEM,			/* returns a pointer to memory */
	RET_PTR_TO_MEM_OR_BTF_ID,	/* returns a pointer to a valid memory or a btf_id */
	RET_PTR_TO_BTF_ID,		/* returns a pointer to a btf_id */
	__BPF_RET_TYPE_MAX,

	/* Extended ret_types. */
	RET_PTR_TO_MAP_VALUE_OR_NULL	= PTR_MAYBE_NULL | RET_PTR_TO_MAP_VALUE,
	RET_PTR_TO_SOCKET_OR_NULL	= PTR_MAYBE_NULL | RET_PTR_TO_SOCKET,
	RET_PTR_TO_TCP_SOCK_OR_NULL	= PTR_MAYBE_NULL | RET_PTR_TO_TCP_SOCK,
	RET_PTR_TO_SOCK_COMMON_OR_NULL	= PTR_MAYBE_NULL | RET_PTR_TO_SOCK_COMMON,
	RET_PTR_TO_RINGBUF_MEM_OR_NULL	= PTR_MAYBE_NULL | MEM_RINGBUF | RET_PTR_TO_MEM,
	RET_PTR_TO_DYNPTR_MEM_OR_NULL	= PTR_MAYBE_NULL | RET_PTR_TO_MEM,
	RET_PTR_TO_BTF_ID_OR_NULL	= PTR_MAYBE_NULL | RET_PTR_TO_BTF_ID,
	RET_PTR_TO_BTF_ID_TRUSTED	= PTR_TRUSTED	 | RET_PTR_TO_BTF_ID,

	/* This must be the last entry. Its purpose is to ensure the enum is
	 * wide enough to hold the higher bits reserved for bpf_type_flag.
	 */
	__BPF_RET_TYPE_LIMIT	= BPF_TYPE_LIMIT,
};
static_assert(__BPF_RET_TYPE_MAX <= BPF_BASE_TYPE_LIMIT);

/* ========================================
 * BPF Register Type Groups
 * ========================================
 * These structures group compatible register types together.
 * Used by the verifier to check argument type compatibility.
 */

struct bpf_reg_types {
	enum bpf_reg_type types[10];
	u32 *btf_id;
};

/* Socket-related types */
static const struct bpf_reg_types sock_types = {
	.types = {
		PTR_TO_SOCK_COMMON,
		PTR_TO_SOCKET,
		PTR_TO_TCP_SOCK,
		PTR_TO_XDP_SOCK,
	},
};

#ifdef CONFIG_NET
static const struct bpf_reg_types btf_id_sock_common_types = {
	.types = {
		PTR_TO_SOCK_COMMON,
		PTR_TO_SOCKET,
		PTR_TO_TCP_SOCK,
		PTR_TO_XDP_SOCK,
		PTR_TO_BTF_ID,
		PTR_TO_BTF_ID | PTR_TRUSTED,
	},
};
#endif

static const struct bpf_reg_types mem_types = {
	.types = {
		PTR_TO_STACK,
		PTR_TO_PACKET,
		PTR_TO_PACKET_META,
		PTR_TO_MAP_KEY,
		PTR_TO_MAP_VALUE,
		PTR_TO_MEM,
		PTR_TO_MEM | MEM_RINGBUF,
		PTR_TO_BUF,
		PTR_TO_BTF_ID | PTR_TRUSTED,
	},
};

static const struct bpf_reg_types spin_lock_types = {
	.types = {
		PTR_TO_MAP_VALUE,
		PTR_TO_BTF_ID | MEM_ALLOC,
	}
};

static const struct bpf_reg_types fullsock_types = { .types = { PTR_TO_SOCKET } };
static const struct bpf_reg_types scalar_types = { .types = { SCALAR_VALUE } };
static const struct bpf_reg_types context_types = { .types = { PTR_TO_CTX } };
static const struct bpf_reg_types ringbuf_mem_types = { .types = { PTR_TO_MEM | MEM_RINGBUF } };
static const struct bpf_reg_types const_map_ptr_types = { .types = { CONST_PTR_TO_MAP } };

static const struct bpf_reg_types btf_ptr_types = {
	.types = {
		PTR_TO_BTF_ID,
		PTR_TO_BTF_ID | PTR_TRUSTED,
		PTR_TO_BTF_ID | MEM_RCU,
	},
};

static const struct bpf_reg_types percpu_btf_ptr_types = {
	.types = {
		PTR_TO_BTF_ID | MEM_PERCPU,
		PTR_TO_BTF_ID | MEM_PERCPU | PTR_TRUSTED,
	}
};

static const struct bpf_reg_types func_ptr_types = { .types = { PTR_TO_FUNC } };
static const struct bpf_reg_types stack_ptr_types = { .types = { PTR_TO_STACK } };
static const struct bpf_reg_types const_str_ptr_types = { .types = { PTR_TO_MAP_VALUE } };
static const struct bpf_reg_types timer_types = { .types = { PTR_TO_MAP_VALUE } };
static const struct bpf_reg_types kptr_types = { .types = { PTR_TO_MAP_VALUE } };

static const struct bpf_reg_types dynptr_types = {
	.types = {
		PTR_TO_STACK,
		CONST_PTR_TO_DYNPTR,
	}
};

/* ========================================
 * Argument Type to Register Type Mapping
 * ========================================
 * This table maps each BPF argument type to its compatible register types.
 * Used by the verifier during helper function call validation.
 */

static const struct bpf_reg_types *compatible_reg_types[__BPF_ARG_TYPE_MAX] = {
	[ARG_PTR_TO_MAP_KEY]		= &mem_types,
	[ARG_PTR_TO_MAP_VALUE]		= &mem_types,
	[ARG_CONST_SIZE]		= &scalar_types,
	[ARG_CONST_SIZE_OR_ZERO]	= &scalar_types,
	[ARG_CONST_ALLOC_SIZE_OR_ZERO]	= &scalar_types,
	[ARG_CONST_MAP_PTR]		= &const_map_ptr_types,
	[ARG_PTR_TO_CTX]		= &context_types,
	[ARG_PTR_TO_SOCK_COMMON]	= &sock_types,
#ifdef CONFIG_NET
	[ARG_PTR_TO_BTF_ID_SOCK_COMMON]	= &btf_id_sock_common_types,
#endif
	[ARG_PTR_TO_SOCKET]		= &fullsock_types,
	[ARG_PTR_TO_BTF_ID]		= &btf_ptr_types,
	[ARG_PTR_TO_SPIN_LOCK]		= &spin_lock_types,
	[ARG_PTR_TO_MEM]		= &mem_types,
	[ARG_PTR_TO_RINGBUF_MEM]	= &ringbuf_mem_types,
	[ARG_PTR_TO_PERCPU_BTF_ID]	= &percpu_btf_ptr_types,
	[ARG_PTR_TO_FUNC]		= &func_ptr_types,
	[ARG_PTR_TO_STACK]		= &stack_ptr_types,
	[ARG_PTR_TO_CONST_STR]		= &const_str_ptr_types,
	[ARG_PTR_TO_TIMER]		= &timer_types,
	[ARG_PTR_TO_KPTR]		= &kptr_types,
	[ARG_PTR_TO_DYNPTR]		= &dynptr_types,
};

/*
 * Usage Guidelines
 * ================
 *
 * 1. Type Flags (bpf_type_flag):
 *    - Can be combined using bitwise OR (|)
 *    - Example: PTR_TO_MEM | MEM_RDONLY means read-only memory pointer
 *
 * 2. Register Types (bpf_reg_type):
 *    - Basic types: NOT_INIT, SCALAR_VALUE, PTR_TO_CTX, etc.
 *    - Extended types: Combine basic types with flags
 *    - Example: PTR_TO_MAP_VALUE_OR_NULL = PTR_MAYBE_NULL | PTR_TO_MAP_VALUE
 *
 * 3. Argument Types (bpf_arg_type):
 *    - Define what arguments helper functions accept
 *    - Can be combined with type flags for specific requirements
 *    - Example: ARG_PTR_TO_MEM | MEM_RDONLY for read-only memory argument
 *
 * 4. Return Types (bpf_return_type):
 *    - Define what helper functions can return
 *    - Can indicate nullable pointers or specific memory types
 *    - Example: RET_PTR_TO_SOCKET_OR_NULL for socket pointer that may be NULL
 *
 * 5. Type Compatibility:
 *    - The compatible_reg_types[] table maps argument types to compatible register types
 *    - The verifier uses this during helper function call validation
 *    - Each argument type points to a bpf_reg_types structure listing compatible types
 *
 * Common Type Combinations:
 * -------------------------
 * - ARG_PTR_TO_MEM | MEM_RDONLY: Read-only memory pointer
 * - ARG_PTR_TO_MEM | MEM_UNINIT | MEM_WRITE: Uninitialized writable memory
 * - PTR_TO_BTF_ID | PTR_TRUSTED: Trusted kernel structure pointer
 * - RET_PTR_TO_MAP_VALUE_OR_NULL: Map value pointer that may be NULL
 */

#endif /* _BPF_TYPES_H */