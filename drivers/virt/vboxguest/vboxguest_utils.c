/*
 * vboxguest vmm-req and hgcm-call code, VBoxGuestR0LibHGCMInternal.cpp,
 * VBoxGuestR0LibGenericRequest.cpp and RTErrConvertToErrno.cpp in vbox svn.
 *
 * Copyright (C) 2006-2016 Oracle Corporation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * The contents of this file may alternatively be used under the terms
 * of the Common Development and Distribution License Version 1.0
 * (CDDL) only, in which case the provisions of the CDDL are applicable
 * instead of those of the GPL.
 *
 * You may elect to license modified versions of this file under the
 * terms and conditions of either the GPL or the CDDL or both.
 */

#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/sizes.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <linux/vbox_err.h>
#include <linux/vbox_utils.h>
#include "vboxguest_core.h"

/* Get the pointer to the first parameter of a HGCM call request. */
#define VMMDEV_HGCM_CALL_PARMS(a) \
	((struct vmmdev_hgcm_function_parameter *)( \
		(u8 *)(a) + sizeof(struct vmmdev_hgcm_call)))

/* The max parameter buffer size for a user request. */
#define VBG_MAX_HGCM_USER_PARM		(24 * SZ_1M)
/* The max parameter buffer size for a kernel request. */
#define VBG_MAX_HGCM_KERNEL_PARM	(16 * SZ_1M)

#define VBG_DEBUG_PORT			0x504

/* This protects vbg_log_buf and serializes VBG_DEBUG_PORT accesses */
static DEFINE_SPINLOCK(vbg_log_lock);
static char vbg_log_buf[128];

#define VBG_LOG(name, pr_func) \
void name(const char *fmt, ...)						\
{									\
	unsigned long flags;						\
	va_list args;							\
	int i, count;							\
									\
	va_start(args, fmt);						\
	spin_lock_irqsave(&vbg_log_lock, flags);			\
									\
	count = vscnprintf(vbg_log_buf, sizeof(vbg_log_buf), fmt, args);\
	for (i = 0; i < count; i++)					\
		outb(vbg_log_buf[i], VBG_DEBUG_PORT);			\
									\
	pr_func("%s", vbg_log_buf);					\
									\
	spin_unlock_irqrestore(&vbg_log_lock, flags);			\
	va_end(args);							\
}									\
EXPORT_SYMBOL(name)

VBG_LOG(vbg_info, pr_info);
VBG_LOG(vbg_warn, pr_warn);
VBG_LOG(vbg_err, pr_err);
#if defined(DEBUG) && !defined(CONFIG_DYNAMIC_DEBUG)
VBG_LOG(vbg_debug, pr_debug);
#endif

void *vbg_req_alloc(size_t len, enum vmmdev_request_type req_type)
{
	struct vmmdev_request_header *req;

	req = kmalloc(len, GFP_KERNEL | __GFP_DMA32);
	if (!req)
		return NULL;

	memset(req, 0xaa, len);

	req->size = len;
	req->version = VMMDEV_REQUEST_HEADER_VERSION;
	req->request_type = req_type;
	req->rc = VERR_GENERAL_FAILURE;
	req->reserved1 = 0;
	req->reserved2 = 0;

	return req;
}

/* Note this function returns a VBox status code, not a negative errno!! */
int vbg_req_perform(struct vbg_dev *gdev, void *req)
{
	unsigned long phys_req = virt_to_phys(req);

	outl(phys_req, gdev->io_port + VMMDEV_PORT_OFF_REQUEST);
	/*
	 * The host changes the request as a result of the outl, make sure
	 * the outl and any reads of the req happen in the correct order.
	 */
	mb();

	return ((struct vmmdev_request_header *)req)->rc;
}

static bool hgcm_req_done(struct vbg_dev *gdev,
			  struct vmmdev_hgcmreq_header *header)
{
	unsigned long flags;
	bool done;

	spin_lock_irqsave(&gdev->event_spinlock, flags);
	done = header->flags & VMMDEV_HGCM_REQ_DONE;
	spin_unlock_irqrestore(&gdev->event_spinlock, flags);

	return done;
}

int vbg_hgcm_connect(struct vbg_dev *gdev,
		     struct vmmdev_hgcm_service_location *loc,
		     u32 *client_id, int *vbox_status)
{
	struct vmmdev_hgcm_connect *hgcm_connect = NULL;
	int rc;

	hgcm_connect = vbg_req_alloc(sizeof(*hgcm_connect),
				     VMMDevReq_HGCMConnect);
	if (!hgcm_connect)
		return -ENOMEM;

	hgcm_connect->header.flags = 0;
	memcpy(&hgcm_connect->loc, loc, sizeof(*loc));
	hgcm_connect->client_id = 0;

	rc = vbg_req_perform(gdev, hgcm_connect);

	if (rc == VINF_HGCM_ASYNC_EXECUTE)
		wait_event(gdev->hgcm_wq,
			   hgcm_req_done(gdev, &hgcm_connect->header));

	if (rc >= 0) {
		*client_id = hgcm_connect->client_id;
		rc = hgcm_connect->header.result;
	}

	kfree(hgcm_connect);

	*vbox_status = rc;
	return 0;
}
EXPORT_SYMBOL(vbg_hgcm_connect);

int vbg_hgcm_disconnect(struct vbg_dev *gdev, u32 client_id, int *vbox_status)
{
	struct vmmdev_hgcm_disconnect *hgcm_disconnect = NULL;
	int rc;

	hgcm_disconnect = vbg_req_alloc(sizeof(*hgcm_disconnect),
					VMMDevReq_HGCMDisconnect);
	if (!hgcm_disconnect)
		return -ENOMEM;

	hgcm_disconnect->header.flags = 0;
	hgcm_disconnect->client_id = client_id;

	rc = vbg_req_perform(gdev, hgcm_disconnect);

	if (rc == VINF_HGCM_ASYNC_EXECUTE)
		wait_event(gdev->hgcm_wq,
			   hgcm_req_done(gdev, &hgcm_disconnect->header));

	if (rc >= 0)
		rc = hgcm_disconnect->header.result;

	kfree(hgcm_disconnect);

	*vbox_status = rc;
	return 0;
}
EXPORT_SYMBOL(vbg_hgcm_disconnect);

static u32 hgcm_call_buf_size_in_pages(void *buf, u32 len)
{
	u32 size = PAGE_ALIGN(len + ((unsigned long)buf & ~PAGE_MASK));

	return size >> PAGE_SHIFT;
}

static void hgcm_call_add_pagelist_size(void *buf, u32 len, size_t *extra)
{
	u32 page_count;

	page_count = hgcm_call_buf_size_in_pages(buf, len);
	*extra += offsetof(struct vmmdev_hgcm_pagelist, pages[page_count]);
}

static int hgcm_call_preprocess_linaddr(
	const struct vmmdev_hgcm_function_parameter *src_parm,
	void **bounce_buf_ret, size_t *extra)
{
	void *buf, *bounce_buf;
	bool copy_in;
	u32 len;
	int ret;

	buf = (void *)src_parm->u.pointer.u.linear_addr;
	len = src_parm->u.pointer.size;
	copy_in = src_parm->type != VMMDevHGCMParmType_LinAddr_Out;

	if (len > VBG_MAX_HGCM_USER_PARM)
		return -E2BIG;

	bounce_buf = kvmalloc(len, GFP_KERNEL);
	if (!bounce_buf)
		return -ENOMEM;

	if (copy_in) {
		ret = copy_from_user(bounce_buf, (void __user *)buf, len);
		if (ret)
			return -EFAULT;
	} else {
		memset(bounce_buf, 0, len);
	}

	*bounce_buf_ret = bounce_buf;
	hgcm_call_add_pagelist_size(bounce_buf, len, extra);
	return 0;
}

/**
 * Preprocesses the HGCM call, validate parameters, alloc bounce buffers and
 * figure out how much extra storage we need for page lists.
 *
 * @returns 0 or negative errno value.
 *
 * @param   src_parm         Pointer to source function call parameters
 * @param   parm_count       Number of function call parameters.
 * @param   bounce_bufs_ret  Where to return the allocated bouncebuffer array
 * @param   extra            Where to return the extra request space needed for
 *                           physical page lists.
 */
static int hgcm_call_preprocess(
	const struct vmmdev_hgcm_function_parameter *src_parm,
	u32 parm_count, void ***bounce_bufs_ret, size_t *extra)
{
	void *buf, **bounce_bufs = NULL;
	u32 i, len;
	int ret;

	for (i = 0; i < parm_count; i++, src_parm++) {
		switch (src_parm->type) {
		case VMMDevHGCMParmType_32bit:
		case VMMDevHGCMParmType_64bit:
			break;

		case VMMDevHGCMParmType_LinAddr:
		case VMMDevHGCMParmType_LinAddr_In:
		case VMMDevHGCMParmType_LinAddr_Out:
			if (!bounce_bufs) {
				bounce_bufs = kcalloc(parm_count,
						      sizeof(void *),
						      GFP_KERNEL);
				if (!bounce_bufs)
					return -ENOMEM;

				*bounce_bufs_ret = bounce_bufs;
			}

			ret = hgcm_call_preprocess_linaddr(src_parm,
							   &bounce_bufs[i],
							   extra);
			if (ret)
				return ret;

			break;

		case VMMDevHGCMParmType_LinAddr_Kernel:
		case VMMDevHGCMParmType_LinAddr_Kernel_In:
		case VMMDevHGCMParmType_LinAddr_Kernel_Out:
			buf = (void *)src_parm->u.pointer.u.linear_addr;
			len = src_parm->u.pointer.size;
			if (WARN_ON(len > VBG_MAX_HGCM_KERNEL_PARM))
				return -E2BIG;

			hgcm_call_add_pagelist_size(buf, len, extra);
			break;

		default:
			return -EINVAL;
		}
	}

	return 0;
}

/**
 * Translates linear address types to page list direction flags.
 *
 * @returns page list flags.
 * @param   type	The type.
 */
static u32 hgcm_call_linear_addr_type_to_pagelist_flags(
	enum vmmdev_hgcm_function_parameter_type type)
{
	switch (type) {
	default:
		WARN_ON(1);
	case VMMDevHGCMParmType_LinAddr:
	case VMMDevHGCMParmType_LinAddr_Kernel:
		return VMMDEV_HGCM_F_PARM_DIRECTION_BOTH;

	case VMMDevHGCMParmType_LinAddr_In:
	case VMMDevHGCMParmType_LinAddr_Kernel_In:
		return VMMDEV_HGCM_F_PARM_DIRECTION_TO_HOST;

	case VMMDevHGCMParmType_LinAddr_Out:
	case VMMDevHGCMParmType_LinAddr_Kernel_Out:
		return VMMDEV_HGCM_F_PARM_DIRECTION_FROM_HOST;
	}
}

static void hgcm_call_init_linaddr(struct vmmdev_hgcm_call *call,
	struct vmmdev_hgcm_function_parameter *dst_parm, void *buf, u32 len,
	enum vmmdev_hgcm_function_parameter_type type, u32 *off_extra)
{
	struct vmmdev_hgcm_pagelist *dst_pg_lst;
	struct page *page;
	bool is_vmalloc;
	u32 i, page_count;

	dst_parm->type = type;

	if (len == 0) {
		dst_parm->u.pointer.size = 0;
		dst_parm->u.pointer.u.linear_addr = 0;
		return;
	}

	dst_pg_lst = (void *)call + *off_extra;
	page_count = hgcm_call_buf_size_in_pages(buf, len);
	is_vmalloc = is_vmalloc_addr(buf);

	dst_parm->type = VMMDevHGCMParmType_PageList;
	dst_parm->u.page_list.size = len;
	dst_parm->u.page_list.offset = *off_extra;
	dst_pg_lst->flags = hgcm_call_linear_addr_type_to_pagelist_flags(type);
	dst_pg_lst->offset_first_page = (unsigned long)buf & ~PAGE_MASK;
	dst_pg_lst->page_count = page_count;

	for (i = 0; i < page_count; i++) {
		if (is_vmalloc)
			page = vmalloc_to_page(buf);
		else
			page = virt_to_page(buf);

		dst_pg_lst->pages[i] = page_to_phys(page);
		buf += PAGE_SIZE;
	}

	*off_extra += offsetof(struct vmmdev_hgcm_pagelist, pages[page_count]);
}

/**
 * Initializes the call request that we're sending to the host.
 *
 * @param   call            The call to initialize.
 * @param   client_id       The client ID of the caller.
 * @param   function        The function number of the function to call.
 * @param   src_parm        Pointer to source function call parameters.
 * @param   parm_count      Number of function call parameters.
 * @param   bounce_bufs     The bouncebuffer array.
 */
static void hgcm_call_init_call(
        struct vmmdev_hgcm_call *call, u32 client_id, u32 function,
	const struct vmmdev_hgcm_function_parameter *src_parm,
	u32 parm_count, void **bounce_bufs)
{
	struct vmmdev_hgcm_function_parameter *dst_parm =
		VMMDEV_HGCM_CALL_PARMS(call);
	u32 i, off_extra = (uintptr_t)(dst_parm + parm_count) - (uintptr_t)call;
	void *buf;

	call->header.flags = 0;
	call->header.result = VINF_SUCCESS;
	call->client_id = client_id;
	call->function = function;
	call->parm_count = parm_count;

	for (i = 0; i < parm_count; i++, src_parm++, dst_parm++) {
		switch (src_parm->type) {
		case VMMDevHGCMParmType_32bit:
		case VMMDevHGCMParmType_64bit:
			*dst_parm = *src_parm;
			break;

		case VMMDevHGCMParmType_LinAddr:
		case VMMDevHGCMParmType_LinAddr_In:
		case VMMDevHGCMParmType_LinAddr_Out:
			hgcm_call_init_linaddr(call, dst_parm, bounce_bufs[i],
					       src_parm->u.pointer.size,
					       src_parm->type, &off_extra);
			break;

		case VMMDevHGCMParmType_LinAddr_Kernel:
		case VMMDevHGCMParmType_LinAddr_Kernel_In:
		case VMMDevHGCMParmType_LinAddr_Kernel_Out:
			buf = (void *)src_parm->u.pointer.u.linear_addr;
			hgcm_call_init_linaddr(call, dst_parm, buf,
					       src_parm->u.pointer.size,
					       src_parm->type, &off_extra);
			break;

		default:
			WARN_ON(1);
			dst_parm->type = VMMDevHGCMParmType_Invalid;
		}
	}
}

/**
 * Tries to cancel a pending HGCM call.
 *
 * @returns VBox status code
 */
static int hgcm_cancel_call(struct vbg_dev *gdev, struct vmmdev_hgcm_call *call)
{
	int rc;

	/*
	 * We use a pre-allocated request for cancellations, which is
	 * protected by cancel_req_mutex. This means that all cancellations
	 * get serialized, this should be fine since they should be rare.
	 */
	mutex_lock(&gdev->cancel_req_mutex);
	gdev->cancel_req->phys_req_to_cancel = virt_to_phys(call);
	rc = vbg_req_perform(gdev, gdev->cancel_req);
	mutex_unlock(&gdev->cancel_req_mutex);

	/** @todo ADDVER: Remove this on next minor version change. */
	if (rc == VERR_NOT_IMPLEMENTED) {
		call->header.flags |= VMMDEV_HGCM_REQ_CANCELLED;
		call->header.header.request_type = VMMDevReq_HGCMCancel;

		rc = vbg_req_perform(gdev, call);
		if (rc == VERR_INVALID_PARAMETER)
			rc = VERR_NOT_FOUND;
	}

	if (rc >= 0)
		call->header.flags |= VMMDEV_HGCM_REQ_CANCELLED;

	return rc;
}

/**
 * Performs the call and completion wait.
 *
 * @returns 0 or negative errno value.
 *
 * @param   gdev	   The VBoxGuest device extension.
 * @param   call           The call to execute.
 * @param   timeout_ms	   Timeout in ms.
 * @param   leak_it	   Where to return the leak it / free it,
 *			   indicator. Cancellation fun.
 */
static int vbg_hgcm_do_call(struct vbg_dev *gdev, struct vmmdev_hgcm_call *call,
			    u32 timeout_ms, bool *leak_it)
{
	int rc, cancel_rc, ret;
	long timeout;

	*leak_it = false;

	rc = vbg_req_perform(gdev, call);

	/*
	 * If the call failed, then pretend success. Upper layers will
	 * interpret the result code in the packet.
	 */
	if (rc < 0) {
		call->header.result = rc;
		return 0;
	}

	if (rc != VINF_HGCM_ASYNC_EXECUTE)
		return 0;

	/* Host decided to process the request asynchronously, wait for it */
	if (timeout_ms == U32_MAX)
		timeout = MAX_SCHEDULE_TIMEOUT;
	else
		timeout = msecs_to_jiffies(timeout_ms);

	timeout = wait_event_interruptible_timeout(
					gdev->hgcm_wq,
					hgcm_req_done(gdev, &call->header),
					timeout);

	/* timeout > 0 means hgcm_req_done has returned true, so success */
	if (timeout > 0)
		return 0;

	if (timeout == 0)
		ret = -ETIMEDOUT;
	else
		ret = -EINTR;

	/* Cancel the request */
	cancel_rc = hgcm_cancel_call(gdev, call);
	if (cancel_rc >= 0)
		return ret;

	/*
	 * Failed to cancel, this should mean that the cancel has lost the
	 * race with normal completion, wait while the host completes it.
	 */
	if (cancel_rc == VERR_NOT_FOUND || cancel_rc == VERR_SEM_DESTROYED)
		timeout = msecs_to_jiffies(500);
	else
		timeout = msecs_to_jiffies(2000);

	timeout = wait_event_timeout(gdev->hgcm_wq,
				     hgcm_req_done(gdev, &call->header),
				     timeout);

	if (WARN_ON(timeout == 0)) {
		/* We really should never get here */
		vbg_err("%s: Call timedout and cancellation failed, leaking the request\n",
			__func__);
		*leak_it = true;
		return ret;
	}

	/* The call has completed normally after all */
	return 0;
}

/**
 * Copies the result of the call back to the caller info structure and user
 * buffers.
 *
 * @returns 0 or negative errno value.
 * @param   call            HGCM call request.
 * @param   dst_parm        Pointer to function call parameters destination.
 * @param   parm_count      Number of function call parameters.
 * @param   bounce_bufs     The bouncebuffer array.
 */
static int hgcm_call_copy_back_result(
	const struct vmmdev_hgcm_call *call,
	struct vmmdev_hgcm_function_parameter *dst_parm,
	u32 parm_count, void **bounce_bufs)
{
	const struct vmmdev_hgcm_function_parameter *src_parm =
		VMMDEV_HGCM_CALL_PARMS(call);
	void __user *p;
	int ret;
	u32 i;

	/* Copy back parameters. */
	for (i = 0; i < parm_count; i++, src_parm++, dst_parm++) {
		switch (dst_parm->type) {
		case VMMDevHGCMParmType_32bit:
		case VMMDevHGCMParmType_64bit:
			*dst_parm = *src_parm;
			break;

		case VMMDevHGCMParmType_PageList:
			dst_parm->u.page_list.size = src_parm->u.page_list.size;
			break;

		case VMMDevHGCMParmType_LinAddr_In:
		case VMMDevHGCMParmType_LinAddr_Kernel:
		case VMMDevHGCMParmType_LinAddr_Kernel_In:
		case VMMDevHGCMParmType_LinAddr_Kernel_Out:
			dst_parm->u.pointer.size = src_parm->u.pointer.size;
			break;

		case VMMDevHGCMParmType_LinAddr:
		case VMMDevHGCMParmType_LinAddr_Out:
			dst_parm->u.pointer.size = src_parm->u.pointer.size;

			p = (void __user *)dst_parm->u.pointer.u.linear_addr;
			ret = copy_to_user(p, bounce_bufs[i],
					   min(src_parm->u.pointer.size,
					       dst_parm->u.pointer.size));
			if (ret)
				return -EFAULT;
			break;

		default:
			WARN_ON(1);
			return -EINVAL;
		}
	}

	return 0;
}

int vbg_hgcm_call(struct vbg_dev *gdev, u32 client_id, u32 function,
		  u32 timeout_ms, struct vmmdev_hgcm_function_parameter *parms,
		  u32 parm_count, int *vbox_status)
{
	struct vmmdev_hgcm_call *call;
	void **bounce_bufs = NULL;
	bool leak_it;
	size_t size;
	int i, ret;

	size = sizeof(struct vmmdev_hgcm_call) +
		   parm_count * sizeof(struct vmmdev_hgcm_function_parameter);
	/*
	 * Validate and buffer the parameters for the call. This also increases
	 * call_size with the amount of extra space needed for page lists.
	 */
	ret = hgcm_call_preprocess(parms, parm_count, &bounce_bufs, &size);
	if (ret) {
		/* Even on error bounce bufs may still have been allocated */
		goto free_bounce_bufs;
	}

	call = vbg_req_alloc(size, VMMDevReq_HGCMCall);
	if (!call) {
		ret = -ENOMEM;
		goto free_bounce_bufs;
	}

	hgcm_call_init_call(call, client_id, function, parms, parm_count,
			    bounce_bufs);

	ret = vbg_hgcm_do_call(gdev, call, timeout_ms, &leak_it);
	if (ret == 0) {
		*vbox_status = call->header.result;
		ret = hgcm_call_copy_back_result(call, parms, parm_count,
						 bounce_bufs);
	}

	if (!leak_it)
		kfree(call);

free_bounce_bufs:
	if (bounce_bufs) {
		for (i = 0; i < parm_count; i++)
			kvfree(bounce_bufs[i]);
		kfree(bounce_bufs);
	}

	return ret;
}
EXPORT_SYMBOL(vbg_hgcm_call);

#ifdef CONFIG_COMPAT
int vbg_hgcm_call32(
	struct vbg_dev *gdev, u32 client_id, u32 function, u32 timeout_ms,
	struct vmmdev_hgcm_function_parameter32 *parm32, u32 parm_count,
	int *vbox_status)
{
	struct vmmdev_hgcm_function_parameter *parm64 = NULL;
	u32 i, size;
	int ret = 0;

	/* KISS allocate a temporary request and convert the parameters. */
	size = parm_count * sizeof(struct vmmdev_hgcm_function_parameter);
	parm64 = kzalloc(size, GFP_KERNEL);
	if (!parm64)
		return -ENOMEM;

	for (i = 0; i < parm_count; i++) {
		switch (parm32[i].type) {
		case VMMDevHGCMParmType_32bit:
			parm64[i].type = VMMDevHGCMParmType_32bit;
			parm64[i].u.value32 = parm32[i].u.value32;
			break;

		case VMMDevHGCMParmType_64bit:
			parm64[i].type = VMMDevHGCMParmType_64bit;
			parm64[i].u.value64 = parm32[i].u.value64;
			break;

		case VMMDevHGCMParmType_LinAddr_Out:
		case VMMDevHGCMParmType_LinAddr:
		case VMMDevHGCMParmType_LinAddr_In:
			parm64[i].type = parm32[i].type;
			parm64[i].u.pointer.size = parm32[i].u.pointer.size;
			parm64[i].u.pointer.u.linear_addr =
			    parm32[i].u.pointer.u.linear_addr;
			break;

		default:
			ret = -EINVAL;
		}
		if (ret < 0)
			goto out_free;
	}

	ret = vbg_hgcm_call(gdev, client_id, function, timeout_ms,
			    parm64, parm_count, vbox_status);
	if (ret < 0)
		goto out_free;

	/* Copy back. */
	for (i = 0; i < parm_count; i++, parm32++, parm64++) {
		switch (parm64[i].type) {
		case VMMDevHGCMParmType_32bit:
			parm32[i].u.value32 = parm64[i].u.value32;
			break;

		case VMMDevHGCMParmType_64bit:
			parm32[i].u.value64 = parm64[i].u.value64;
			break;

		case VMMDevHGCMParmType_LinAddr_Out:
		case VMMDevHGCMParmType_LinAddr:
		case VMMDevHGCMParmType_LinAddr_In:
			parm32[i].u.pointer.size = parm64[i].u.pointer.size;
			break;

		default:
			WARN_ON(1);
			ret = -EINVAL;
		}
	}

out_free:
	kfree(parm64);
	return ret;
}
#endif

int vbg_status_code_to_errno(int rc)
{
	if (rc >= 0)
		return 0;

	switch (rc) {
	case VERR_ACCESS_DENIED:                    return -EPERM;
	case VERR_FILE_NOT_FOUND:                   return -ENOENT;
	case VERR_PROCESS_NOT_FOUND:                return -ESRCH;
	case VERR_INTERRUPTED:                      return -EINTR;
	case VERR_DEV_IO_ERROR:                     return -EIO;
	case VERR_TOO_MUCH_DATA:                    return -E2BIG;
	case VERR_BAD_EXE_FORMAT:                   return -ENOEXEC;
	case VERR_INVALID_HANDLE:                   return -EBADF;
	case VERR_TRY_AGAIN:                        return -EAGAIN;
	case VERR_NO_MEMORY:                        return -ENOMEM;
	case VERR_INVALID_POINTER:                  return -EFAULT;
	case VERR_RESOURCE_BUSY:                    return -EBUSY;
	case VERR_ALREADY_EXISTS:                   return -EEXIST;
	case VERR_NOT_SAME_DEVICE:                  return -EXDEV;
	case VERR_NOT_A_DIRECTORY:
	case VERR_PATH_NOT_FOUND:                   return -ENOTDIR;
	case VERR_IS_A_DIRECTORY:                   return -EISDIR;
	case VERR_INVALID_PARAMETER:                return -EINVAL;
	case VERR_TOO_MANY_OPEN_FILES:              return -ENFILE;
	case VERR_INVALID_FUNCTION:                 return -ENOTTY;
	case VERR_SHARING_VIOLATION:                return -ETXTBSY;
	case VERR_FILE_TOO_BIG:                     return -EFBIG;
	case VERR_DISK_FULL:                        return -ENOSPC;
	case VERR_SEEK_ON_DEVICE:                   return -ESPIPE;
	case VERR_WRITE_PROTECT:                    return -EROFS;
	case VERR_BROKEN_PIPE:                      return -EPIPE;
	case VERR_DEADLOCK:                         return -EDEADLK;
	case VERR_FILENAME_TOO_LONG:                return -ENAMETOOLONG;
	case VERR_FILE_LOCK_FAILED:                 return -ENOLCK;
	case VERR_NOT_IMPLEMENTED:
	case VERR_NOT_SUPPORTED:                    return -ENOSYS;
	case VERR_DIR_NOT_EMPTY:                    return -ENOTEMPTY;
	case VERR_TOO_MANY_SYMLINKS:                return -ELOOP;
	case VERR_NO_DATA:                          return -ENODATA;
	case VERR_NET_NO_NETWORK:                   return -ENONET;
	case VERR_NET_NOT_UNIQUE_NAME:              return -ENOTUNIQ;
	case VERR_NO_TRANSLATION:                   return -EILSEQ;
	case VERR_NET_NOT_SOCKET:                   return -ENOTSOCK;
	case VERR_NET_DEST_ADDRESS_REQUIRED:        return -EDESTADDRREQ;
	case VERR_NET_MSG_SIZE:                     return -EMSGSIZE;
	case VERR_NET_PROTOCOL_TYPE:                return -EPROTOTYPE;
	case VERR_NET_PROTOCOL_NOT_AVAILABLE:       return -ENOPROTOOPT;
	case VERR_NET_PROTOCOL_NOT_SUPPORTED:       return -EPROTONOSUPPORT;
	case VERR_NET_SOCKET_TYPE_NOT_SUPPORTED:    return -ESOCKTNOSUPPORT;
	case VERR_NET_OPERATION_NOT_SUPPORTED:      return -EOPNOTSUPP;
	case VERR_NET_PROTOCOL_FAMILY_NOT_SUPPORTED: return -EPFNOSUPPORT;
	case VERR_NET_ADDRESS_FAMILY_NOT_SUPPORTED: return -EAFNOSUPPORT;
	case VERR_NET_ADDRESS_IN_USE:               return -EADDRINUSE;
	case VERR_NET_ADDRESS_NOT_AVAILABLE:        return -EADDRNOTAVAIL;
	case VERR_NET_DOWN:                         return -ENETDOWN;
	case VERR_NET_UNREACHABLE:                  return -ENETUNREACH;
	case VERR_NET_CONNECTION_RESET:             return -ENETRESET;
	case VERR_NET_CONNECTION_ABORTED:           return -ECONNABORTED;
	case VERR_NET_CONNECTION_RESET_BY_PEER:     return -ECONNRESET;
	case VERR_NET_NO_BUFFER_SPACE:              return -ENOBUFS;
	case VERR_NET_ALREADY_CONNECTED:            return -EISCONN;
	case VERR_NET_NOT_CONNECTED:                return -ENOTCONN;
	case VERR_NET_SHUTDOWN:                     return -ESHUTDOWN;
	case VERR_NET_TOO_MANY_REFERENCES:          return -ETOOMANYREFS;
	case VERR_TIMEOUT:                          return -ETIMEDOUT;
	case VERR_NET_CONNECTION_REFUSED:           return -ECONNREFUSED;
	case VERR_NET_HOST_DOWN:                    return -EHOSTDOWN;
	case VERR_NET_HOST_UNREACHABLE:             return -EHOSTUNREACH;
	case VERR_NET_ALREADY_IN_PROGRESS:          return -EALREADY;
	case VERR_NET_IN_PROGRESS:                  return -EINPROGRESS;
	case VERR_MEDIA_NOT_PRESENT:                return -ENOMEDIUM;
	case VERR_MEDIA_NOT_RECOGNIZED:             return -EMEDIUMTYPE;
	default:
		vbg_warn("%s: Unhandled err %d\n", __func__, rc);
		return -EPROTO;
	}
}
EXPORT_SYMBOL(vbg_status_code_to_errno);
