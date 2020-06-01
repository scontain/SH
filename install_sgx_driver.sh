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

page0_patch_content=$(cat << 'PAGE0_PATCH_EOF'
From 668a6e9a2d1aa49470d2c935862ae77553861dce Mon Sep 17 00:00:00 2001
From: Chia-Che Tsai <chiache@tamu.edu>
Date: Fri, 17 May 2019 15:08:49 -0500
Subject: [PATCH 2/2] Enabling mmap for address unaligned to the enclave range

---
 sgx_encl.c | 7 ++++---
 sgx_main.c | 5 +++--
 2 files changed, 7 insertions(+), 5 deletions(-)

diff --git a/sgx_encl.c b/sgx_encl.c
index 980a536..4162a2f 100644
--- a/sgx_encl.c
+++ b/sgx_encl.c
@@ -655,7 +655,7 @@ int sgx_encl_create(struct sgx_secs *secs)
 	}
 
 	down_read(&current->mm->mmap_sem);
-	ret = sgx_encl_find(current->mm, secs->base, &vma);
+	ret = sgx_encl_find(current->mm, secs->base + secs->size - PAGE_SIZE, &vma);
 	if (ret != -ENOENT) {
 		if (!ret)
 			ret = -EINVAL;
@@ -663,8 +663,9 @@ int sgx_encl_create(struct sgx_secs *secs)
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

metrics_patch_content=$(cat << 'METRICS_PATCH_EOF'
From 9e41fb97ee9cbf4ab6298e77448552a25a25dd72 Mon Sep 17 00:00:00 2001
From: =?UTF-8?q?F=C3=A1bio=20Silva?= <fabio.fernando.osilva@gmail.com>
Date: Thu, 21 May 2020 14:21:29 -0300
Subject: [PATCH 1/2] Add performance counters

---
 sgx_encl.c       | 15 +++++++++++++++
 sgx_page_cache.c | 19 +++++++++++++++++++
 sgx_util.c       |  6 ++++++
 show_values.sh   | 22 ++++++++++++++++++++++
 4 files changed, 62 insertions(+)
 create mode 100755 show_values.sh

diff --git a/sgx_encl.c b/sgx_encl.c
index a03c30a..980a536 100644
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
 
@@ -668,6 +678,8 @@ int sgx_encl_create(struct sgx_secs *secs)
 	list_add_tail(&encl->encl_list, &encl->tgid_ctx->encl_list);
 	mutex_unlock(&sgx_tgid_ctx_mutex);
 
+	sgx_nr_enclaves++;
+
 	return 0;
 out:
 	if (encl)
@@ -953,6 +965,8 @@ int sgx_encl_init(struct sgx_encl *encl, struct sgx_sigstruct *sigstruct,
 	}
 
 	encl->flags |= SGX_ENCL_INITIALIZED;
+
+	sgx_init_enclaves++;
 	return 0;
 }
 
@@ -1004,4 +1018,5 @@ void sgx_encl_release(struct kref *ref)
 		fput(encl->pcmd);
 
 	kfree(encl);
+	sgx_nr_enclaves--;
 }
diff --git a/sgx_page_cache.c b/sgx_page_cache.c
index ed7c6be..82d16de 100644
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
 		pgtable_t token,
@@ -98,6 +112,7 @@ static int sgx_test_and_clear_young_cb(pte_t *ptep,
 	ret = pte_young(*ptep);
 	if (ret) {
 		pte = pte_mkold(*ptep);
+		sgx_nr_marked_old++; // only statistics counter, ok not to be completely correct...
 		set_pte_at((struct mm_struct *)data, addr, ptep, pte);
 	}
 
@@ -308,6 +323,7 @@ static bool sgx_ewb(struct sgx_encl *encl,
 static void sgx_evict_page(struct sgx_encl_page *entry,
 			   struct sgx_encl *encl)
 {
+	sgx_nr_evicted++;  // races are acceptable..
 	sgx_ewb(encl, entry);
 	sgx_free_page(entry->epc_page, encl);
 	entry->epc_page = NULL;
@@ -346,11 +362,13 @@ static void sgx_write_pages(struct sgx_encl *encl, struct list_head *src)
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
@@ -520,6 +538,7 @@ struct sgx_epc_page *sgx_alloc_page(unsigned int flags)
 		schedule();
 	}
 
+	sgx_nr_alloc_pages++; // ignore races..
 	if (sgx_nr_free_pages < sgx_nr_low_pages)
 		wake_up(&ksgxswapd_waitq);
 
diff --git a/sgx_util.c b/sgx_util.c
index 25b18a9..af40961 100644
--- a/sgx_util.c
+++ b/sgx_util.c
@@ -66,6 +66,10 @@
 #else
 	#include <linux/mm.h>
 #endif
+#include <linux/moduleparam.h>
+
+static unsigned int sgx_loaded_back;
+module_param(sgx_loaded_back, uint, 0440);
 
 struct page *sgx_get_backing(struct sgx_encl *encl,
 			     struct sgx_encl_page *entry,
@@ -195,6 +199,8 @@ int sgx_eldu(struct sgx_encl *encl,
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

function check_driver {
    if [[ ! -e /sys/module/isgx/version ]] ; then
        install_driver=true
    else 
        install_driver=false
        verbose "SGX-driver already installed."
        if [[ ! -e /dev/isgx ]] ; then
            log_error "SGX driver is installed but no SGX device - SGX not enabled?"
        fi
    fi
}

function apply_patches {
    
    if [[ $patch_metrics == "1" ]]; then
        echo "Applying metrics patch..."
	echo "$metrics_patch_content" | sed 's/\\@!-tbs-!@$/\\/g' | patch -p1
    fi
    if [[ $patch_page0 == "1" ]]; then
        echo "Applying page0 patch..."
	echo "$page0_patch_content" | sed 's/\\@!-tbs-!@$/\\/g' | patch -p1
    fi
#    if [[ $patch_performance == "1" ]]; then
#        echo "Applying performance patch..."
#    fi
}

function install_sgx_driver {
    commit_sha=95eaa6f6693cd86c35e10a22b4f8e483373c987c
    if [[ $install_driver == true || $force_install ]] ; then
        dir=$(mktemp -d)
        cd "$dir"
        rm -rf linux-sgx-driver
        git clone https://github.com/intel/linux-sgx-driver.git

        cd linux-sgx-driver/
        git checkout $commit_sha

        apply_patches

        sudo apt-get update
        sudo apt-get install -y build-essential
        sudo apt-get install -y linux-headers-$(uname -r)

        make 

        sudo mkdir -p "/lib/modules/"`uname -r`"/kernel/drivers/intel/sgx"    
        sudo cp -f isgx.ko "/lib/modules/"`uname -r`"/kernel/drivers/intel/sgx"    

        sudo sh -c "cat /etc/modules | grep -Fxq isgx || echo isgx >> /etc/modules"    
        sudo /sbin/depmod
        sudo /sbin/modprobe isgx

        cd ..
    fi
}

function show_help {
    echo -e \
"Usage: install_sgx_driver.sh [OPTION]...
Helper script to install Intel SGX driver.\n
The script supports the following commands:
  help     display this help and exit
  install  installs the current Intel out of branch driver if not SGX driver is installed
      -p metrics      installs the metrics patch
      -p page0        installs the page0 patch
  force   same as 'install' but will replace existing SGX driver (if installed)"
#     -p performance  installs the performance patch - requires access to a deployment key

    exit 0
}

function parse_args {
    PARAMS=""

    while (( "$#" )); do
    case "$1" in
        help)
        show_help
        shift
        ;;

        force)
        force_install=1
        shift
        ;;

        install)
        arg_install=1
        shift
        ;;

        -p)
        if [ -n "$2" ] && [ ${2:0:1} != "-" ]; then
	    if [[ $force_install != 1 && $arg_install != 1 ]]; then
                msg_color "error"
                "ERROR: invalid arguments."
                msg_color "default"
                show_help
            fi
            case "$2" in
                metrics)
                patch_metrics=1
                ;;

                page0)
                patch_page0=1
                ;;

                performance)
                patch_performance=1
                ;;

                *)
                msg_color "error"
                echo "ERROR: patch '$2' is not supported" >&2
                msg_color "default"
                exit 1
            esac
            shift 2
        else
            msg_color "error"
            echo "ERROR: argument for '$1' is missing" >&2
            msg_color "default"
            exit 1
        fi
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

if [[ $force_install == "1" ]]; then
    install_sgx_driver
    exit 0
fi

if [[ $arg_install == "1" ]]; then
    check_driver
    install_sgx_driver
    exit 0
fi

show_help
