#!/bin/bash
: '
Access to this file is granted under the SCONE COMMERCIAL LICENSE V1.0 

Any use of this product using this file requires a commercial license from scontain UG, www.scontain.com.

Permission is also granted  to use the Program for a reasonably limited period of time  (but no longer than 1 month) 
for the purpose of evaluating its usefulness for a particular purpose.

THERE IS NO WARRANTY FOR THIS PROGRAM, TO THE EXTENT PERMITTED BY APPLICABLE LAW. EXCEPT WHEN OTHERWISE STATED IN WRITING 
THE COPYRIGHT HOLDERS AND/OR OTHER PARTIES PROVIDE THE PROGRAM "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, 
INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. 

THE ENTIRE RISK AS TO THE QUALITY AND PERFORMANCE OF THE PROGRAM IS WITH YOU. SHOULD THE PROGRAM PROVE DEFECTIVE, 
YOU ASSUME THE COST OF ALL NECESSARY SERVICING, REPAIR OR CORRECTION.

IN NO EVENT UNLESS REQUIRED BY APPLICABLE LAW OR AGREED ON IN WRITING WILL ANY COPYRIGHT HOLDER, OR ANY OTHER PARTY WHO MAY
MODIFY AND/OR REDISTRIBUTE THE PROGRAM AS PERMITTED ABOVE, BE LIABLE TO YOU FOR DAMAGES, INCLUDING ANY GENERAL, SPECIAL, 
INCIDENTAL OR CONSEQUENTIAL DAMAGES ARISING OUT OF THE USE OR INABILITY TO USE THE PROGRAM INCLUDING BUT NOT LIMITED TO LOSS 
OF DATA OR DATA BEING RENDERED INACCURATE OR LOSSES SUSTAINED BY YOU OR THIRD PARTIES OR A FAILURE OF THE PROGRAM TO OPERATE 
WITH ANY OTHER PROGRAMS), EVEN IF SUCH HOLDER OR OTHER PARTY HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.

Copyright (C) 2017-2018 scontain.com
'

#
# - install patched sgx driver 


set -e

# OOT Patches
oot_metrics_patch_content=$(cat << 'METRICS_PATCH_EOF'
From 25330b3c753a8314d95b379ed807fdb4302c8526 Mon Sep 17 00:00:00 2001
From: =?UTF-8?q?F=C3=A1bio=20Silva?= <fabio.fernando.osilva@gmail.com>
Date: Thu, 21 May 2020 14:21:29 -0300
Subject: [PATCH 1/1] Add performance counters

---
 sgx.h            |  2 ++
 sgx_encl.c       | 15 +++++++++++++++
 sgx_page_cache.c | 19 +++++++++++++++++++
 sgx_util.c       |  7 +++++++
 show_values.sh   | 22 ++++++++++++++++++++++
 5 files changed, 65 insertions(+)
 create mode 100755 show_values.sh

diff --git a/sgx.h b/sgx.h
index 590464d..37295bf 100644
--- a/sgx.h
+++ b/sgx.h
@@ -80,6 +80,8 @@
 
 #define SGX_VA_SLOT_COUNT 512
 
+#define PATCH_METRICS 2
+
 struct sgx_epc_page {
 	resource_size_t	pa;
 	struct list_head list;
diff --git a/sgx_encl.c b/sgx_encl.c
index 6815c43..071c5bd 100644
--- a/sgx_encl.c
+++ b/sgx_encl.c
@@ -73,6 +73,14 @@
 #include <linux/slab.h>
 #include <linux/hashtable.h>
 #include <linux/shmem_fs.h>
+#include <linux/moduleparam.h>
+
+static unsigned int sgx_nr_enclaves;
+static unsigned int sgx_nr_added_pages;
+static unsigned int sgx_init_enclaves;
+module_param(sgx_init_enclaves, uint, 0440);
+module_param(sgx_nr_added_pages, uint, 0440);
+module_param(sgx_nr_enclaves, uint, 0440);
 
 struct sgx_add_page_req {
 	struct sgx_encl *encl;
@@ -221,6 +229,8 @@ static int sgx_eadd(struct sgx_epc_page *secs_page,
 	sgx_put_page((void *)(unsigned long)pginfo.secs);
 	kunmap_atomic((void *)(unsigned long)pginfo.srcpge);
 
+	sgx_nr_added_pages++;
+
 	return ret;
 }
 
@@ -663,6 +673,8 @@ int sgx_encl_create(struct sgx_secs *secs)
 	list_add_tail(&encl->encl_list, &encl->tgid_ctx->encl_list);
 	mutex_unlock(&sgx_tgid_ctx_mutex);
 
+	sgx_nr_enclaves++;
+
 	return 0;
 out:
 	if (encl)
@@ -948,6 +960,8 @@ int sgx_encl_init(struct sgx_encl *encl, struct sgx_sigstruct *sigstruct,
 	}
 
 	encl->flags |= SGX_ENCL_INITIALIZED;
+
+	sgx_init_enclaves++;
 	return 0;
 }
 
@@ -999,4 +1013,5 @@ void sgx_encl_release(struct kref *ref)
 		fput(encl->pcmd);
 
 	kfree(encl);
+	sgx_nr_enclaves--;
 }
diff --git a/sgx_page_cache.c b/sgx_page_cache.c
index 3770ad4..d1aebf9 100644
--- a/sgx_page_cache.c
+++ b/sgx_page_cache.c
@@ -69,6 +69,7 @@
 	#include <linux/signal.h>
 #endif
 #include <linux/slab.h>
+#include <linux/moduleparam.h>
 
 #define SGX_NR_LOW_EPC_PAGES_DEFAULT 32
 #define SGX_NR_SWAP_CLUSTER_MAX	16
@@ -81,11 +82,24 @@ DEFINE_MUTEX(sgx_tgid_ctx_mutex);
 atomic_t sgx_va_pages_cnt = ATOMIC_INIT(0);
 static unsigned int sgx_nr_total_epc_pages;
 static unsigned int sgx_nr_free_pages;
+static unsigned int sgx_nr_reclaimed;
 static unsigned int sgx_nr_low_pages = SGX_NR_LOW_EPC_PAGES_DEFAULT;
 static unsigned int sgx_nr_high_pages;
+static unsigned int sgx_nr_marked_old;
+static unsigned int sgx_nr_evicted;
+static unsigned int sgx_nr_alloc_pages;
 static struct task_struct *ksgxswapd_tsk;
 static DECLARE_WAIT_QUEUE_HEAD(ksgxswapd_waitq);
 
+module_param(sgx_nr_total_epc_pages, uint, 0440);
+module_param(sgx_nr_free_pages, uint, 0440);
+module_param(sgx_nr_low_pages, uint, 0440);
+module_param(sgx_nr_high_pages, uint, 0440);
+module_param(sgx_nr_marked_old, uint, 0440);
+module_param(sgx_nr_evicted, uint, 0440);
+module_param(sgx_nr_alloc_pages, uint, 0440);
+module_param(sgx_nr_reclaimed, uint, 0440);
+
 static int sgx_test_and_clear_young_cb(pte_t *ptep,
 #if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 3, 0))
     #if( defined(RHEL_RELEASE_VERSION) && defined(RHEL_RELEASE_CODE))
@@ -104,6 +118,7 @@ static int sgx_test_and_clear_young_cb(pte_t *ptep,
 	ret = pte_young(*ptep);
 	if (ret) {
 		pte = pte_mkold(*ptep);
+		sgx_nr_marked_old++; // only statistics counter, ok not to be completely correct...
 		set_pte_at((struct mm_struct *)data, addr, ptep, pte);
 	}
 
@@ -314,6 +329,7 @@ static bool sgx_ewb(struct sgx_encl *encl,
 static void sgx_evict_page(struct sgx_encl_page *entry,
 			   struct sgx_encl *encl)
 {
+	sgx_nr_evicted++;  // races are acceptable..
 	sgx_ewb(encl, entry);
 	sgx_free_page(entry->epc_page, encl);
 	entry->epc_page = NULL;
@@ -352,11 +368,13 @@ static void sgx_write_pages(struct sgx_encl *encl, struct list_head *src)
 		list_del(&entry->list);
 		sgx_evict_page(entry->encl_page, encl);
 		encl->secs_child_cnt--;
+		sgx_nr_reclaimed++;
 	}
 
 	if (!encl->secs_child_cnt && (encl->flags & SGX_ENCL_INITIALIZED)) {
 		sgx_evict_page(&encl->secs, encl);
 		encl->flags |= SGX_ENCL_SECS_EVICTED;
+		sgx_nr_reclaimed++;
 	}
 
 	mutex_unlock(&encl->lock);
@@ -526,6 +544,7 @@ struct sgx_epc_page *sgx_alloc_page(unsigned int flags)
 		schedule();
 	}
 
+	sgx_nr_alloc_pages++; // ignore races..
 	if (sgx_nr_free_pages < sgx_nr_low_pages)
 		wake_up(&ksgxswapd_waitq);
 
diff --git a/sgx_util.c b/sgx_util.c
index 38013e2..681ef43 100644
--- a/sgx_util.c
+++ b/sgx_util.c
@@ -66,6 +66,11 @@
 #else
 	#include <linux/mm.h>
 #endif
+#include <linux/moduleparam.h>
+
+static unsigned int sgx_loaded_back;
+module_param(sgx_loaded_back, uint, 0440);
+
 int sgx_vm_insert_pfn(struct vm_area_struct *vma, unsigned long addr, resource_size_t pa)
 {
 	int rc;
@@ -220,6 +225,8 @@ int sgx_eldu(struct sgx_encl *encl,
 		ret = -EFAULT;
 	}
 
+	sgx_loaded_back++;
+
 	kunmap_atomic((void *)(unsigned long)(pginfo.pcmd - pcmd_offset));
 	kunmap_atomic((void *)(unsigned long)pginfo.srcpge);
 	sgx_put_page(va_ptr);
diff --git a/show_values.sh b/show_values.sh
new file mode 100755
index 0000000..643f7ab
--- /dev/null
+++ b/show_values.sh
@@ -0,0 +1,22 @@
+#!/bin/bash
+#
+# (C) Christof Fetzer, 2017
+
+METRICS="sgx_nr_total_epc_pages \@!-tbs-!@
+    sgx_nr_free_pages \@!-tbs-!@
+    sgx_nr_low_pages \@!-tbs-!@
+    sgx_nr_high_pages \@!-tbs-!@
+    sgx_nr_marked_old \@!-tbs-!@
+    sgx_nr_evicted \@!-tbs-!@
+    sgx_nr_alloc_pages \@!-tbs-!@
+    sgx_nr_reclaimed \@!-tbs-!@
+    sgx_init_enclaves \@!-tbs-!@
+    sgx_nr_added_pages \@!-tbs-!@
+    sgx_nr_enclaves \@!-tbs-!@
+    sgx_loaded_back \@!-tbs-!@
+    "
+MODPATH="/sys/module/isgx/parameters/"
+
+for metric in $METRICS ; do
+    echo "$metric= `cat $MODPATH/$metric`"
+done
-- 
2.25.1
METRICS_PATCH_EOF
)
oot_metrics_patch_version=2

oot_page0_patch_content=$(cat << 'PAGE0_PATCH_EOF'
From 4edf6bc51ff79a251de62adbd69ac6062c6f71e4 Mon Sep 17 00:00:00 2001
From: Chia-Che Tsai <chiache@tamu.edu>
Date: Fri, 17 May 2019 15:08:49 -0500
Subject: [PATCH 1/1] Enabling mmap for address unaligned to the enclave range

---
 sgx.h      | 2 ++
 sgx_encl.c | 7 ++++---
 sgx_main.c | 5 +++--
 3 files changed, 9 insertions(+), 5 deletions(-)

diff --git a/sgx.h b/sgx.h
index 46dfc0f..47758b5 100644
--- a/sgx.h
+++ b/sgx.h
@@ -80,6 +80,8 @@
 
 #define SGX_VA_SLOT_COUNT 512
 
+#define PATCH_PAGE0 1
+
 struct sgx_epc_page {
 	resource_size_t	pa;
 	struct list_head list;
diff --git a/sgx_encl.c b/sgx_encl.c
index a03c30a..24c0fc4 100644
--- a/sgx_encl.c
+++ b/sgx_encl.c
@@ -645,7 +645,7 @@ int sgx_encl_create(struct sgx_secs *secs)
 	}
 
 	down_read(&current->mm->mmap_sem);
-	ret = sgx_encl_find(current->mm, secs->base, &vma);
+	ret = sgx_encl_find(current->mm, secs->base + secs->size - PAGE_SIZE, &vma);
 	if (ret != -ENOENT) {
 		if (!ret)
 			ret = -EINVAL;
@@ -653,8 +653,9 @@ int sgx_encl_create(struct sgx_secs *secs)
 		goto out;
 	}
 
-	if (vma->vm_start != secs->base ||
-	    vma->vm_end != (secs->base + secs->size)
+	if (vma->vm_start < secs->base ||
+	    vma->vm_start > (secs->base + secs->size) ||
+	    vma->vm_end < (secs->base + secs->size)
 	    /* vma->vm_pgoff != 0 */) {
 		ret = -EINVAL;
 		up_read(&current->mm->mmap_sem);
diff --git a/sgx_main.c b/sgx_main.c
index 170dc8a..69a6f53 100644
--- a/sgx_main.c
+++ b/sgx_main.c
@@ -128,7 +128,7 @@ static unsigned long sgx_get_unmapped_area(struct file *file,
 					   unsigned long pgoff,
 					   unsigned long flags)
 {
-	if (len < 2 * PAGE_SIZE || (len & (len - 1)) || flags & MAP_PRIVATE)
+	if (flags & MAP_PRIVATE)
 		return -EINVAL;
 
 	/* On 64-bit architecture, allow mmap() to exceed 32-bit encl
@@ -153,7 +153,8 @@ static unsigned long sgx_get_unmapped_area(struct file *file,
 	if (IS_ERR_VALUE(addr))
 		return addr;
 
-	addr = (addr + (len - 1)) & ~(len - 1);
+	if (!(flags & MAP_FIXED))
+		addr = (addr + (len - 1)) & ~(len - 1);
 
 	return addr;
 }
-- 
2.25.1
PAGE0_PATCH_EOF
)
oot_page0_patch_version=1

oot_version_patch_content=$(cat << 'VERSION_PATCH_EOF'
From 403cb32324acaebafdf0258774b8171670fb7680 Mon Sep 17 00:00:00 2001
From: =?UTF-8?q?F=C3=A1bio=20Silva?= <fabio.fernando.osilva@gmail.com>
Date: Mon, 1 Jun 2020 12:28:02 -0300
Subject: [PATCH 1/1] Export patch information

---
 sgx_main.c | 28 ++++++++++++++++++++++++++++
 1 file changed, 28 insertions(+)

diff --git a/sgx_main.c b/sgx_main.c
index 170dc8a..ffd3a39 100644
--- a/sgx_main.c
+++ b/sgx_main.c
@@ -70,6 +70,7 @@
 #include <linux/hashtable.h>
 #include <linux/kthread.h>
 #include <linux/platform_device.h>
+#include <linux/moduleparam.h>
 
 #define DRV_DESCRIPTION "Intel SGX Driver"
 #define DRV_VERSION "2.6.0"
@@ -106,6 +107,33 @@ u32 sgx_misc_reserved;
 u32 sgx_xsave_size_tbl[64];
 bool sgx_has_sgx2;
 
+/*
+ * Patch versions
+ */
+#ifndef PATCH_PAGE0
+#define PATCH_PAGE0 0
+#endif
+
+#ifndef PATCH_METRICS
+#define PATCH_METRICS 0
+#endif
+
+#define IS_DCAP_DRIVER 0
+
+#define COMMIT_SHA "COMMIT_SHA1SUM"
+#define COMMIT_SHA_LEN (40 + 1)
+
+static unsigned int patch_page0 = PATCH_PAGE0;
+static unsigned int patch_metrics = PATCH_METRICS;
+static unsigned int dcap = IS_DCAP_DRIVER;
+static char commit[COMMIT_SHA_LEN] = COMMIT_SHA;
+
+module_param(patch_page0, uint, 0444);
+module_param(patch_metrics, uint, 0444);
+module_param(dcap, uint, 0444);
+module_param_string(commit, commit, COMMIT_SHA_LEN, 0444);
+
+
 #ifdef CONFIG_COMPAT
 long sgx_compat_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
 {
-- 
2.25.1
VERSION_PATCH_EOF
)

oot_dkms_patch_content=$(cat << 'DKMS_PATCH_EOF'
From 790ece1bb65375806fb6b66ac61fd911cc0ab011 Mon Sep 17 00:00:00 2001
From: =?UTF-8?q?F=C3=A1bio=20Silva?= <fabio.fernando.osilva@gmail.com>
Date: Mon, 8 Jun 2020 10:28:27 -0300
Subject: [PATCH 1/1] Add DKMS configuration file

---
 dkms.conf | 6 ++++++
 1 file changed, 6 insertions(+)
 create mode 100644 dkms.conf

diff --git a/dkms.conf b/dkms.conf
new file mode 100644
index 0000000..9c03f4a
--- /dev/null
+++ b/dkms.conf
@@ -0,0 +1,6 @@
+PACKAGE_NAME="isgx"
+PACKAGE_VERSION="2.6.0"
+BUILT_MODULE_NAME[0]="isgx"
+DEST_MODULE_LOCATION[0]="/kernel/drivers/intel/sgx"
+AUTOINSTALL="yes"
+MAKE[0]="'make'  KDIR=/lib/modules/${kernelver}/build"
-- 
2.25.1
DKMS_PATCH_EOF
)

# DCAP Patches
dcap_metrics_patch_content=$(cat << 'METRICS_PATCH_EOF'
From 17575a61a2667b20c1984b39014583811d83e5cf Mon Sep 17 00:00:00 2001
From: =?UTF-8?q?F=C3=A1bio=20Silva?= <fabio.fernando.osilva@gmail.com>
Date: Thu, 4 Jun 2020 15:47:09 -0300
Subject: [PATCH 1/1] Add performance counters

---
 driver/linux/driver.h       |  2 ++
 driver/linux/encl.c         | 29 +++++++++++++++++++++++++++++
 driver/linux/ioctl.c        | 11 +++++++++++
 driver/linux/main.c         |  8 ++++++++
 driver/linux/reclaim.c      |  8 ++++++++
 driver/linux/show_values.sh | 23 +++++++++++++++++++++++
 6 files changed, 81 insertions(+)
 create mode 100755 driver/linux/show_values.sh

diff --git a/driver/linux/driver.h b/driver/linux/driver.h
index c90e132..c47fd79 100644
--- a/driver/linux/driver.h
+++ b/driver/linux/driver.h
@@ -12,6 +12,8 @@
 #include "uapi/asm/sgx_oot.h"
 #include "sgx.h"
 
+#define PATCH_METRICS 1
+
 #define SGX_EINIT_SPIN_COUNT	20
 #define SGX_EINIT_SLEEP_COUNT	50
 #define SGX_EINIT_SLEEP_TIME	20
diff --git a/driver/linux/encl.c b/driver/linux/encl.c
index 96f90a1..b2cd62b 100644
--- a/driver/linux/encl.c
+++ b/driver/linux/encl.c
@@ -14,6 +14,29 @@
 #include "dcap.h"
 
 #include <linux/version.h>
+#include <linux/moduleparam.h>
+
+extern unsigned int sgx_nr_enclaves;
+static unsigned int sgx_nr_low_pages = SGX_NR_LOW_PAGES;
+static unsigned int sgx_nr_high_pages = SGX_NR_HIGH_PAGES;
+static unsigned int sgx_loaded_back = 0;
+static unsigned int sgx_nr_marked_old = 0;
+
+module_param(sgx_nr_low_pages, uint, 0440);
+module_param(sgx_nr_high_pages, uint, 0440);
+module_param(sgx_loaded_back, uint, 0440);
+module_param(sgx_nr_marked_old, uint, 0440);
+
+static int get_sgx_nr_free_pages(char *buffer, const struct kernel_param *kp)
+{
+	return sprintf(buffer, "%lu\n", sgx_nr_free_pages());
+}
+
+static struct kernel_param_ops param_ops_sgx_nr_free_pages = {
+	.get = get_sgx_nr_free_pages,
+};
+
+module_param_cb(sgx_nr_free_pages, &param_ops_sgx_nr_free_pages, NULL, 0440);
 
 static int __sgx_encl_eldu(struct sgx_encl_page *encl_page,
 			   struct sgx_epc_page *epc_page,
@@ -54,6 +77,8 @@ static int __sgx_encl_eldu(struct sgx_encl_page *encl_page,
 		ret = -EFAULT;
 	}
 
+	sgx_loaded_back++;
+
 	kunmap_atomic((void *)(unsigned long)(pginfo.metadata - b.pcmd_offset));
 	kunmap_atomic((void *)(unsigned long)pginfo.contents);
 
@@ -604,6 +629,9 @@ void sgx_encl_release(struct kref *ref)
 {
 	struct sgx_encl *encl = container_of(ref, struct sgx_encl, refcount);
 
+	if (atomic_read(&encl->flags) & SGX_ENCL_CREATED)
+		sgx_nr_enclaves--;
+
 	sgx_encl_destroy(encl);
 
 	if (encl->backing)
@@ -702,6 +730,7 @@ static int sgx_encl_test_and_clear_young_cb(pte_t *ptep,
 	ret = pte_young(*ptep);
 	if (ret) {
 		pte = pte_mkold(*ptep);
+		sgx_nr_marked_old++;
 		set_pte_at((struct mm_struct *)data, addr, ptep, pte);
 	}
 
diff --git a/driver/linux/ioctl.c b/driver/linux/ioctl.c
index 79b8c80..ce7bf47 100644
--- a/driver/linux/ioctl.c
+++ b/driver/linux/ioctl.c
@@ -18,6 +18,14 @@
 
 #include <linux/version.h>
 #include "sgx_wl.h"
+#include <linux/moduleparam.h>
+
+unsigned int sgx_init_enclaves = 0;
+unsigned int sgx_nr_enclaves = 0;
+unsigned int sgx_nr_added_pages = 0;
+module_param(sgx_init_enclaves, uint, 0440);
+module_param(sgx_nr_enclaves, uint, 0440);
+module_param(sgx_nr_added_pages, uint, 0440);
 
 /* A per-cpu cache for the last known values of IA32_SGXLEPUBKEYHASHx MSRs. */
 static DEFINE_PER_CPU(u64 [4], sgx_lepubkeyhash_cache);
@@ -223,6 +231,7 @@ static int sgx_encl_create(struct sgx_encl *encl, struct sgx_secs *secs)
 	 */
 	atomic_or(SGX_ENCL_CREATED, &encl->flags);
 
+	sgx_nr_enclaves++;
 	return 0;
 
 err_out:
@@ -344,6 +353,7 @@ static int __sgx_encl_add_page(struct sgx_encl *encl,
 	kunmap_atomic((void *)pginfo.contents);
 	put_page(src_page);
 
+	sgx_nr_added_pages++;
 	return ret ? -EIO : 0;
 }
 
@@ -690,6 +700,7 @@ static int sgx_encl_init(struct sgx_encl *encl, struct sgx_sigstruct *sigstruct,
 		ret = -EPERM;
 	} else {
 		atomic_or(SGX_ENCL_INITIALIZED, &encl->flags);
+		sgx_init_enclaves++;
 	}
 
 err_out:
diff --git a/driver/linux/main.c b/driver/linux/main.c
index 82c7b77..b2e830b 100644
--- a/driver/linux/main.c
+++ b/driver/linux/main.c
@@ -14,6 +14,7 @@
 #include <linux/module.h>
 #include "version.h"
 #include "dcap.h"
+#include <linux/moduleparam.h>
 #ifndef MSR_IA32_FEAT_CTL
 #define MSR_IA32_FEAT_CTL MSR_IA32_FEATURE_CONTROL
 #endif
@@ -24,6 +25,11 @@
 
 struct sgx_epc_section sgx_epc_sections[SGX_MAX_EPC_SECTIONS];
 int sgx_nr_epc_sections;
+static unsigned int sgx_nr_total_epc_pages = 0;
+static unsigned int sgx_nr_alloc_pages = 0;
+module_param(sgx_nr_epc_sections, int, 0440);
+module_param(sgx_nr_total_epc_pages, uint, 0440);
+module_param(sgx_nr_alloc_pages, uint, 0440);
 
 // Based on arch/x86/kernel/cpu/intel.c
 static bool detect_sgx(struct cpuinfo_x86 *c)
@@ -136,6 +142,7 @@ struct sgx_epc_page *sgx_alloc_page(void *owner, bool reclaim)
 		schedule();
 	}
 
+	sgx_nr_alloc_pages++; // ignore races..
 	if (sgx_should_reclaim(SGX_NR_LOW_PAGES))
 		wake_up(&ksgxswapd_waitq);
 
@@ -280,6 +287,7 @@ static bool __init sgx_page_cache_init(void)
 		}
 
 		sgx_nr_epc_sections++;
+		sgx_nr_total_epc_pages += (size / PAGE_SIZE);
 	}
 
 	if (!sgx_nr_epc_sections) {
diff --git a/driver/linux/reclaim.c b/driver/linux/reclaim.c
index 99ada88..99e41f6 100644
--- a/driver/linux/reclaim.c
+++ b/driver/linux/reclaim.c
@@ -14,6 +14,12 @@
 #include "driver.h"
 
 #include <linux/version.h>
+#include <linux/moduleparam.h>
+
+static unsigned int sgx_nr_reclaimed = 0;
+static unsigned int sgx_nr_evicted = 0;
+module_param(sgx_nr_reclaimed, uint, 0440);
+module_param(sgx_nr_evicted, uint, 0440);
 
 struct task_struct *ksgxswapd_tsk;
 DECLARE_WAIT_QUEUE_HEAD(ksgxswapd_waitq);
@@ -398,6 +404,7 @@ static void sgx_reclaimer_write(struct sgx_epc_page *epc_page,
 			if (ret)
 				goto out;
 
+			sgx_nr_evicted++;  // races are acceptable..
 			sgx_encl_ewb(encl->secs.epc_page, &secs_backing);
 
 			sgx_free_page(encl->secs.epc_page);
@@ -465,6 +472,7 @@ void sgx_reclaim_pages(void)
 
 		mutex_lock(&encl_page->encl->lock);
 		encl_page->desc |= SGX_ENCL_PAGE_RECLAIMED;
+		sgx_nr_reclaimed++;
 		mutex_unlock(&encl_page->encl->lock);
 		continue;
 
diff --git a/driver/linux/show_values.sh b/driver/linux/show_values.sh
new file mode 100755
index 0000000..af9e2d8
--- /dev/null
+++ b/driver/linux/show_values.sh
@@ -0,0 +1,23 @@
+#!/bin/bash
+#
+# (C) Christof Fetzer, 2017
+
+METRICS="sgx_nr_total_epc_pages \@!-tbs-!@
+    sgx_nr_free_pages \@!-tbs-!@
+    sgx_nr_low_pages \@!-tbs-!@
+    sgx_nr_high_pages \@!-tbs-!@
+    sgx_nr_marked_old \@!-tbs-!@
+    sgx_nr_evicted \@!-tbs-!@
+    sgx_nr_alloc_pages \@!-tbs-!@
+    sgx_nr_reclaimed \@!-tbs-!@
+    sgx_init_enclaves \@!-tbs-!@
+    sgx_nr_added_pages \@!-tbs-!@
+    sgx_nr_enclaves \@!-tbs-!@
+    sgx_loaded_back \@!-tbs-!@
+    sgx_nr_epc_sections \@!-tbs-!@
+    "
+MODPATH="/sys/module/intel_sgx/parameters/"
+
+for metric in $METRICS ; do
+    echo "$metric= `cat $MODPATH/$metric`"
+done
-- 
2.25.1
METRICS_PATCH_EOF
)
dcap_metrics_patch_version=1

dcap_version_patch_content=$(cat << 'VERSION_PATCH_EOF'
From d40b7b1025402f26f1b51afb92698764b4b16614 Mon Sep 17 00:00:00 2001
From: =?UTF-8?q?F=C3=A1bio=20Silva?= <fabio.fernando.osilva@gmail.com>
Date: Thu, 4 Jun 2020 18:24:35 -0300
Subject: [PATCH 1/1] Export patch information

---
 driver/linux/main.c | 28 ++++++++++++++++++++++++++++
 1 file changed, 28 insertions(+)

diff --git a/driver/linux/main.c b/driver/linux/main.c
index 82c7b77..36b4cdd 100644
--- a/driver/linux/main.c
+++ b/driver/linux/main.c
@@ -25,6 +25,34 @@
 struct sgx_epc_section sgx_epc_sections[SGX_MAX_EPC_SECTIONS];
 int sgx_nr_epc_sections;
 
+/*
+ * Patch versions
+ */
+#include <linux/moduleparam.h>
+
+#ifndef PATCH_PAGE0
+#define PATCH_PAGE0 0
+#endif
+
+#ifndef PATCH_METRICS
+#define PATCH_METRICS 0
+#endif
+
+#define IS_DCAP_DRIVER 1
+
+#define COMMIT_SHA "COMMIT_SHA1SUM"
+#define COMMIT_SHA_LEN (40 + 1)
+
+static unsigned int patch_page0 = PATCH_PAGE0;
+static unsigned int patch_metrics = PATCH_METRICS;
+static unsigned int dcap = IS_DCAP_DRIVER;
+static char commit[COMMIT_SHA_LEN] = COMMIT_SHA;
+
+module_param(patch_page0, uint, 0444);
+module_param(patch_metrics, uint, 0444);
+module_param(dcap, uint, 0444);
+module_param_string(commit, commit, COMMIT_SHA_LEN, 0444);
+
 // Based on arch/x86/kernel/cpu/intel.c
 static bool detect_sgx(struct cpuinfo_x86 *c)
 {
-- 
2.25.1
VERSION_PATCH_EOF
)

# OOT & DCAP Commits
oot_driver_commit="602374c738ca58f83a1c17574d08e5d5e6341953"
dcap_driver_commit="bfa5d8f6935238c170324cac482b04650d2db4ac"

# print the right color for each level
#
# Arguments:
# 1:  level

function msg_color {
    priority=$1
    if [[ $priority == "fatal" ]] ; then
        echo -e "\033[31m"
    elif [[ $priority == "error" ]] ; then
        echo -e "\033[34m"
    elif [[ $priority == "warning" ]] ; then
        echo -e "\033[35m"
    elif [[ $priority == "info" ]] ; then
        echo -e "\033[36m"
    elif [[ $priority == "debug" ]] ; then
        echo -e "\033[37m"
    elif [[ $priority == "default" ]] ; then
        echo -e "\033[00m"
    else
        echo -e "\033[32m";
    fi
}

function no_error_message {
    exit $? 
}

function issue_error_exit_message {
    errcode=$?
    trap no_error_message EXIT
    if [[ $errcode != 0 ]] ; then
        msg_color "fatal"
        echo -e "ERROR: installation of SGX driver failed (script=install_sgx_driver.sh, Line: ${BASH_LINENO[0]}, ${BASH_LINENO[1]})"
        msg_color "default"
    else
        msg_color "OK"
        echo "OK"
        msg_color "default"
    fi
    exit $errcode
}
trap issue_error_exit_message EXIT

function verbose
{
    echo $@
}

function log_error
{
    msg_color "error"
    echo $@
    msg_color "default"
    exit 1
}

function load_module {
    local mod_name=$1

    msg_color "warning"

    (sudo lsmod | grep $mod_name > /dev/null) && (sudo rmmod $mod_name 2> /dev/null || echo "WARNING: Unable to unload currently loaded '$mod_name' module. Please, reload '$mod_name' manually to changes take effect.")

    sudo modprobe $mod_name 2> /dev/null || echo "WARNING: Unable to load '$mod_name' module. Please, check if SGX is available on your system and enabled on BIOS."

    msg_color "default"
}

function check_oot_driver {
    if [[ ! -e /sys/module/isgx/version ]] ; then
        oot_driver_found=false
    else 
        oot_driver_found=true
        verbose "SGX-driver already installed."
        if [[ ! -e /dev/isgx ]] ; then
            log_error "SGX driver is installed but no SGX device - SGX not enabled?"
        fi
    fi
}

function check_dcap_driver {
    if [[ ! -e /sys/module/intel_sgx/version ]] ; then
        dcap_driver_found=false
    else 
        dcap_driver_found=true
        verbose "DCAP SGX-driver already installed."
        if [[ ! -e /dev/sgx ]] ; then
            log_error "DCAP SGX driver is installed but no SGX device - SGX not enabled?"
        fi
    fi
}

function check_driver {
    check_oot_driver
    check_dcap_driver

    if [[ $oot_driver_found == false && $dcap_driver_found == false ]]; then
        install_driver=true
    else
        install_driver=false
    fi
}

function install_common_dependencies {
    msg_color "info"
    echo "INFO: Installing dependencies... "
    msg_color "default"
    
    sudo apt-get update > /dev/null && \
    sudo apt-get install -y build-essential git patch linux-headers-$(uname -r) > /dev/null

    msg_color "info"
    echo "INFO: Done!"
    msg_color "default"
}

function remove_dkms_driver {
    dkms_cmd=$(which dkms)
    if [ $? == "0" ]; then
        for installed_ver in $(sudo $dkms_cmd status $1 | cut -d',' -f2 | sed 's/ //g'); do
            sudo $dkms_cmd remove $1/$installed_ver --all
        done
    fi
}

function apply_oot_patches {
    if [[ $use_dkms == "1" ]]; then
        echo "Applying DKMS patch..."
        echo "$oot_dkms_patch_content" | sed 's/\\@!-tbs-!@$/\\/g' | patch -p1
    fi
    if [[ $patch_version == "1" ]]; then
        echo "Applying version patch..."
        echo "$oot_version_patch_content" | sed "s/COMMIT_SHA1SUM/$oot_commit_sha/g" | sed 's/\\@!-tbs-!@$/\\/g' | patch -p1
    fi
    if [[ $patch_metrics == "1" ]]; then
        echo "Applying metrics patch..."
	echo "$oot_metrics_patch_content" | sed 's/\\@!-tbs-!@$/\\/g' | patch -p1
    fi
    if [[ $patch_page0 == "1" ]]; then
        echo "Applying page0 patch..."
	echo "$oot_page0_patch_content" | sed 's/\\@!-tbs-!@$/\\/g' | patch -p1
    fi
#    if [[ $patch_performance == "1" ]]; then
#        echo "Applying performance patch..."
#    fi
}

function install_oot_sgx_driver {
    if [[ $install_driver == true || $force_install ]] ; then
        install_common_dependencies

        dir=$(mktemp -d)
        cd "$dir"
        git clone https://github.com/intel/linux-sgx-driver.git driver_source

        cd driver_source/

        if [ -z $install_latest ]; then
            oot_commit_sha=$oot_driver_commit
            git checkout $oot_commit_sha
        else
            git checkout master
            oot_commit_sha="$(git rev-parse HEAD)"
        fi

        remove_dkms_driver isgx

        apply_oot_patches

        if [[ -f "/lib/modules/"`uname -r`"/kernel/drivers/intel/sgx/isgx.ko" ]]; then
            msg_color "info"
            echo "INFO: Removing \"/lib/modules/"`uname -r`"/kernel/drivers/intel/sgx/isgx.ko\" ... "
            sudo rm -rf "/lib/modules/"`uname -r`"/kernel/drivers/intel/sgx/isgx.ko"
            msg_color "default"
        fi

        if [[ $use_dkms == "1" ]]; then
            msg_color "info"
            echo -n "INFO: Installing DKMS... "

            sudo apt-get install -y dkms > /dev/null

            echo "Done!"

            msg_color "default"

            driver_ver=$(cat dkms.conf | grep PACKAGE_VERSION | cut -d'=' -f2 | sed 's/"//g')

            if [[ ${#driver_ver} == 0 ]]; then
                log_error "Unable to detect OOT driver version!"
            fi

            sudo rm -rf /usr/src/isgx-$driver_ver
            sudo mkdir -p /usr/src/isgx-$driver_ver

            sudo cp -rf * /usr/src/isgx-$driver_ver/

            sudo dkms add -m isgx -v $driver_ver --force
            sudo dkms build -m isgx -v $driver_ver --force
            sudo dkms install -m isgx -v $driver_ver --force
        else
            make
            sudo mkdir -p "/lib/modules/"`uname -r`"/kernel/drivers/intel/sgx"
            sudo cp -f isgx.ko "/lib/modules/"`uname -r`"/kernel/drivers/intel/sgx"
        fi

        sudo sh -c "cat /etc/modules | grep -Fxq isgx || echo isgx >> /etc/modules"
        sudo /sbin/depmod -a

        load_module isgx

        cd "$dir"/..
        rm -rf "$dir"
    fi
}

function apply_dcap_patches {
    if [[ $patch_version == "1" ]]; then
        echo "Applying version patch..."
        echo "$dcap_version_patch_content" | sed "s/COMMIT_SHA1SUM/$dcap_commit_sha/g" | sed 's/\\@!-tbs-!@$/\\/g' | patch -p3
    fi    
    if [[ $patch_metrics == "1" ]]; then
        echo "Applying metrics patch..."
	echo "$dcap_metrics_patch_content" | sed 's/\\@!-tbs-!@$/\\/g' | patch -p3
    fi
    if [[ $patch_page0 == "1" ]]; then
        msg_color "warning"
        verbose "WARNING: page0 patch is not available for DCAP installation"
        msg_color "default"
    fi
#    if [[ $patch_performance == "1" ]]; then
#        echo "Applying performance patch..."
#    fi
}

function install_dcap_sgx_driver {
    if [[ $install_driver == true || $force_install ]] ; then
        install_common_dependencies

        msg_color "info"
        echo -n "INFO: Installing DKMS... "

        sudo apt-get install -y dkms > /dev/null

        echo "Done!"

        msg_color "default"

        dir=$(mktemp -d)
        cd "$dir"
        git clone https://github.com/intel/SGXDataCenterAttestationPrimitives.git driver_source

        cd driver_source/driver/linux

        if [ -z $install_latest ]; then
            dcap_commit_sha=$dcap_driver_commit
            git checkout $dcap_commit_sha
        else
            git checkout master
            dcap_commit_sha="$(git rev-parse HEAD)"
        fi

        apply_dcap_patches

        driver_ver=$(cat dkms.conf | grep PACKAGE_VERSION | cut -d'=' -f2 | sed 's/"//g')

        if [[ ${#driver_ver} == 0 ]]; then
            log_error "Unable to detect DCAP driver version!"
        fi

        sudo rm -rf /usr/src/sgx-$driver_ver
        sudo mkdir -p /usr/src/sgx-$driver_ver

        sudo cp -rf * /usr/src/sgx-$driver_ver/

        remove_dkms_driver sgx
        sudo dkms add -m sgx -v $driver_ver --force
        sudo dkms build -m sgx -v $driver_ver --force
        sudo dkms install -m sgx -v $driver_ver --force

        sudo cp 10-sgx.rules /etc/udev/rules.d
        sudo groupadd -f sgx_prv
        sudo udevadm trigger

        sudo sh -c "cat /etc/modules | grep -Fxq intel_sgx || echo intel_sgx >> /etc/modules"

        sudo /sbin/depmod -a

        load_module intel_sgx

        cd "$dir"/..
        rm -rf "$dir"
    fi
}

function install_sgx_driver {
    if [[ $install_dcap == "1" ]]; then
        install_dcap_sgx_driver
    else
        install_oot_sgx_driver
    fi
}

function check_commit {
    local driver_version=$1
    local driver_commit=$2

    echo -e "Driver commit: $driver_commit"

    echo -n "Driver status: [ Checking for a newer version. Please wait... ]"

    dir=$(mktemp -d)
    cd "$dir"

    if [[ $driver_version == "DCAP" ]]; then
        git clone https://github.com/intel/SGXDataCenterAttestationPrimitives.git driver_source 2> /dev/null
    else
        git clone https://github.com/intel/linux-sgx-driver.git driver_source 2> /dev/null
    fi
    cd driver_source/
    
    local current_commit="$(git rev-parse HEAD)"

    if [[ $current_commit == $driver_commit ]]; then
        echo -e "\e[0K\rDriver status: Up to date                                      "
    else
        echo -e "\e[0K\rDriver status: Outdated - $(($(git rev-list --count $driver_commit..$current_commit) - 1)) new commit(s) available            "
        update_needed=true
    fi

    cd "$dir"/..
    rm -rf "$dir"
}

# first argument: driver_type [OOT or DCAP]
function check_dkms {
    local driver_version=$1
    
    echo -n "Use DKMS: "

    dkms_cmd=$(which dkms)
    if [ $? != "0" ]; then
        echo "No"
    else
        if [[ $driver_version == "OOT" ]]; then
            (($dkms_cmd status isgx | grep installed > /dev/null) && echo "Yes") || echo "No"
        else # DCAP always use DKMS
            echo "Yes"
        fi
    fi
}

# first argument: driver_type [OOT or DCAP]
function check_patches {
    local driver_version=$1

    if [[ $metrics_ver != "0" ]]; then
        echo -n "Patch 'metrics' version: $metrics_ver "

        if [[ $driver_version == "DCAP" ]]; then
            if [[ $metrics_ver == $dcap_metrics_patch_version ]]; then
                echo "(Up to date)"
            else
                echo "(Outdated - $(($dcap_metrics_patch_version - $metrics_ver)) newer version(s) available)"
                update_needed=true
            fi
        else
            if [[ $metrics_ver == $oot_metrics_patch_version ]]; then
                echo "(Up to date)"
            else
                echo "(Outdated - $(($oot_metrics_patch_version - $metrics_ver)) newer version(s) available)"
                update_needed=true
            fi
        fi
    else
        if [[ $patch_metrics == "1" ]]; then
            echo "Patch 'metrics' not found!"
            update_needed=true
        fi
    fi

    if [[ $page0_ver != "0" ]]; then
        echo -n "Patch 'page0' version  : $page0_ver "

        if [[ $page0_ver == $oot_page0_patch_version ]]; then
            echo "(Up to date)"
        else
            echo "(Outdated - $(($oot_page0_patch_version - $page0_ver)) newer version(s) available)"
            update_needed=true
        fi
    else
        if [[ $patch_page0 == "1" && $driver_version == "OOT" ]]; then
            echo "Patch 'page0' not found!"
            update_needed=true
        fi
    fi
}

function describe {
    driver_type=$1
    module_path=$2

    update_needed=false

    echo -e "Getting SGX Driver information:\n"
    echo "$driver_type driver detected."
    echo -e "Version: $(cat $module_path/version)\n"

    if [[ ! -e "$module_path/parameters/commit" ]]; then
        msg_color "error"
        echo "FAIL: Unable to detect 'version' patch! This patch is required for running this command."
        msg_color "default"

        echo -n "To install the driver with 'version' patch, run: ./install_sgx_driver.sh install -p version "

        if [[ $driver_type == "DCAP" ]]; then
            echo -n "--dcap "
        fi

        echo "--force"
        
        exit 1
    else
        driver_commit=$(cat "$module_path/parameters/commit")
    fi

    metrics_ver=$(cat $module_path/parameters/patch_metrics)
    page0_ver=$(cat $module_path/parameters/patch_page0)

    echo -n "Detected patches: version "

    if [[ $metrics_ver != "0" ]]; then # check if a metric is exposed
        echo -n "metrics "
        metrics_ver=$(cat $module_path/parameters/patch_metrics)
    fi

    if [[ $page0_ver != "0" ]]; then # check if a metric is exposed
        echo -n "page0 "
        page0_ver=$(cat $module_path/parameters/patch_page0)
    fi

    echo -ne "\n\n"

    check_dkms $driver_type

    echo
 
    check_commit $driver_type $driver_commit

    echo

    check_patches $driver_type 

    if [[ $update_needed == true ]]; then
        msg_color "warning"
        echo "WARNING: Update is needed!"
        msg_color "default"

        exit 1
    fi

    exit 0
}

function show_help {
    echo -e \
"Usage: install_sgx_driver.sh [COMMAND] [OPTIONS]...
Helper script to install Intel SGX driver.\n
The script supports the following commands:
  check                checks the current SGX driver status
                       (requires 'version' patch)
  install              installs the SGX driver

The following options are supported by 'install' command:
  -d, --dcap           install DCAP driver

  -p, --patch=[PATCH]  apply patches to the SGX driver. The valid values for PATCH
                       are: 'version', 'metrics', 'page0'.
      -p version       installs the version patch (recommended)
      -p metrics       installs the metrics patch
      -p page0         installs the page0 patch (not available for DCAP)

  -k, --dkms           installs the driver with DKMS (default for DCAP)

  -l, --latest         installs the latest upstream driver (not recommended)

  -f, --force          replaces existing SGX driver, if installed

The following options are supported by 'check' command:
  -p, --patch=[PATCH]  check the status of patch on current installed driver.
                       The valid values for PATCH are: 'metrics', 'page0'.
      -p metrics       check the status of 'metrics' patch
      -p page0         check the status of 'page0' patch (not available for DCAP)

Note: In case of absence or outdated driver, or absence or outdated patch, this command
will return error.

The following options are supported by both commands:
  -h, --help           display this help and exit


Usage example 1: to install the SGX driver with 'metrics' and 'page0' patches, run:

./install_sgx_driver.sh install -p metrics -p page0

Usage example 2: to check the status of driver installation and 'metrics' patch

./install_sgx_driver.sh check -p metrics

"

#     -p performance  installs the performance patch - requires access to a deployment key

    exit 0
}

function enable_patch {
    case "$1" in
        version)
        patch_version=1
        ;;

        metrics)
        patch_metrics=1
        ;;

        page0)
        patch_page0=1
        ;;

        *)
        msg_color "error"
        echo "ERROR: patch '$1' is not supported" >&2
        msg_color "default"
        exit 1
    esac
}

function parse_command {
    if [[ $1 != "install" &&\
          $1 != "check" ]]; then
          log_error "ERROR: '$1' command is not supported" >&2
    fi
}

function parse_args {
    PARAMS=""

    if [[ $# == 0 ]]; then
        show_help
    fi

    while (( "$#" )); do
    arg=$1
    case "$arg" in
        install)
        cmd_install=1
        shift
        ;;

        check)
        cmd_check=1
        shift
        ;;

        -k|--dkms)
        use_dkms=1
        shift
        ;;

        -d|--dcap)
        install_dcap=1
        shift
        ;;

        -h|--help)
        show_help
        shift
        ;;

        -f|--force)
        force_install=1
        shift
        ;;

        -l|--latest)
        msg_color "warning"
        echo "WARNING: the installation of latest upstream driver is not recommended."
        msg_color "default"
        install_latest=1
        shift
        ;;

        -p|--patch)
        if [ -n "$2" ] && [ ${2:0:1} != "-" ]; then
            if [[ $cmd_install != 1 && $cmd_check != 1 ]]; then
                msg_color "error"
                echo "ERROR: invalid arguments."
                msg_color "default"
                show_help
            fi
            enable_patch $2
            shift 2
        else
            msg_color "error"
            echo "ERROR: argument for '$1' is missing" >&2
            msg_color "default"
            exit 1
        fi
        ;;

        --patch=*)
        echo "${i#*=}"
        enable_patch "${1#*=}"
        shift
        ;;

        *) # preserve positional arguments
        msg_color "error"
        echo "ERROR: unsupported command '$1'" >&2
        msg_color "default"
        exit 1
        ;;
    esac
    done
    # set positional arguments in their proper place

    eval set -- "$PARAMS"
}

parse_args $@

parse_command $1

if [[ $cmd_install == "1" ]]; then
    if [[ -z $force_install ]]; then
        check_driver
    fi
    install_sgx_driver
    exit 0
fi

if [[ $cmd_check == "1" ]]; then
    check_driver >/dev/null

    if [[ $dcap_driver_found == true ]]; then
        describe DCAP /sys/module/intel_sgx
    fi
    
    if [[ $oot_driver_found == true ]]; then
        describe OOT /sys/module/isgx
    fi

    log_error "FAIL: No SGX driver detected!"
fi

show_help
