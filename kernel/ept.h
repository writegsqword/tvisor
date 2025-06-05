#pragma once

#include <linux/types.h>

// Memory Types
#define MEMORY_TYPE_UNCACHEABLE                                      0x00000000
#define MEMORY_TYPE_WRITE_COMBINING                                  0x00000001
#define MEMORY_TYPE_WRITE_THROUGH                                    0x00000004
#define MEMORY_TYPE_WRITE_PROTECTED                                  0x00000005
#define MEMORY_TYPE_WRITE_BACK                                       0x00000006
#define MEMORY_TYPE_INVALID                                          0x000000FF

typedef union _ept_pointer {
	u64 all;
	struct {
		u64 memory_type : 3;
		u64 page_walk_length : 3;
		u64 dirty_and_access_enabled : 1;
		u64 supervisor_shadow_stack : 1;
		u64 reserved1 : 4;
		u64 ept_pml4_table_address : 36;
		u64 reserved2 : 16;
	} fields;
} ept_pointer_t;

typedef union _ept_pml4e {
	u64 all;
	struct {
		u64 read : 1;
		u64 write : 1;
		u64 execute : 1;
		u64 reserved1 : 5;
		u64 accessed : 1;
		u64 ignored1 : 1; // use to determine whether it is in use or not
		u64 execute_for_user_mode : 1;
		u64 ignored2 : 1;
		u64 ept_pdpt_address : 36;
		u64 reserved2 : 4;
		u64 ignored3 : 12;
	} fields;
} ept_pml4e_t;

typedef union _ept_pdpte {
	u64 all;
	struct {
		u64 read : 1;
		u64 write : 1;
		u64 execute : 1;
		u64 reserved1 : 5;
		u64 accessed : 1;
		u64 ignored1 : 1; // use to determine whether it is in use or not
		u64 execute_for_user_mode : 1;
		u64 ignored2 : 1;
		u64 ept_pd_address : 36;
		u64 reserved2 : 4;
		u64 ignored3 : 12;
	} fields;
} ept_pdpte_t;

typedef union _ept_pde {
	u64 all;
	struct {
		u64 read : 1;
		u64 write : 1;
		u64 execute : 1;
		u64 reserved1 : 5;
		u64 accessed : 1;
		u64 ignored1 : 1; // use to determine whether it is in use or not
		u64 execute_for_user_mode : 1;
		u64 ignored2 : 1;
		u64 ept_pt_address : 36;
		u64 reserved2 : 4;
		u64 ignored3 : 12;
	} fields;
} ept_pde_t;

typedef union _ept_pde_2mb {
	u64 all;
	struct {
		u64 read : 1;
		u64 write : 1;
		u64 execute : 1;
		u64 memory_type : 3;
		u64 ignore_pat : 1;
		u64 large_page : 1;
		u64 accessed : 1;
		u64 dirty : 1;
		u64 execute_for_user_mode : 1;
		u64 reserved1 : 10;
		u64 page_address : 27;
		u64 reserved2 : 15;
		u64 suppress_ve : 1;

	} fields;

} ept_pde_2mb_t;

typedef union _ept_pte {
	u64 all;
	struct {
		u64 read : 1;
		u64 write : 1;
		u64 execute : 1;
		u64 memory_type : 3;
		u64 ignore_pat : 1;
		u64 ignored1 : 1; // use to determine whether it is in use or not
		u64 accessed : 1;
		u64 dirty : 1;
		u64 execute_for_user_mode : 1;
		u64 ignored2 : 1;
		u64 page_address : 36;
		u64 reserved : 4;
		u64 ignored3 : 8;
		u64 sss : 1;
		u64 sub_page_write_permission : 1;
		u64 ignored4 : 1;
		u64 suppress_ve : 1;
	} fields;
} ept_pte_t;

// typedef struct _ept_pml4_packed {
// 	ept_pml4e_t pml4;

// }


ept_pointer_t *create_ept_by_memsize(u64 size_mib);
void free_ept(ept_pointer_t *eptp);
u64 gphys_to_hphys(u64 gphys, ept_pointer_t *eptp);
ept_pte_t* gphys_to_pte(u64 gphys, ept_pointer_t *eptp);
ept_pde_t* gphys_to_pde(u64 gphys, ept_pointer_t *eptp);


ept_pte_t *alloc_ept_pt(void);
ept_pde_t *alloc_ept_pd(void);
void setup_pte(ept_pte_t* pte, u64 idx);