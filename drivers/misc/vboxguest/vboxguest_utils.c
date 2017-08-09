/*
 * vboxguest vmm-req and hgcm-call code, GenericRequest.c and HGCMInternal.c
 * in vbox upstream svn.
 *
 * Copyright (C) 2006-2016 Oracle Corporation
 *
 * This file is part of VirtualBox Open Source Edition (OSE), as
 * available from http://www.virtualbox.org. This file is free software;
 * you can redistribute it and/or modify it under the terms of the GNU
 * General Public License (GPL) as published by the Free Software
 * Foundation, in version 2 as it comes in the "COPYING" file of the
 * VirtualBox OSE distribution. VirtualBox OSE is distributed in the
 * hope that it will be useful, but WITHOUT ANY WARRANTY of any kind.
 *
 * The contents of this file may alternatively be used under the terms
 * of the Common Development and Distribution License Version 1.0
 * (CDDL) only, as it comes in the "COPYING.CDDL" file of the
 * VirtualBox OSE distribution, in which case the provisions of the
 * CDDL are applicable instead of those of the GPL.
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

/** The max parameter buffer size for a user request. */
#define VBGLR0_MAX_HGCM_USER_PARM	(24 * SZ_1M)
/** The max parameter buffer size for a kernel request. */
#define VBGLR0_MAX_HGCM_KERNEL_PARM	(16 * SZ_1M)

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
EXPORT_SYMBOL(name);

VBG_LOG(vbg_info, pr_info)
VBG_LOG(vbg_warn, pr_warn)
VBG_LOG(vbg_err, pr_err)
#if defined(DEBUG) && !defined(CONFIG_DYNAMIC_DEBUG)
VBG_LOG(vbg_debug, pr_debug)
#endif

/**
 * Helper to determine the minimum request size for the given request.
 * Returns 0 if the given operation is not handled and/or supported.
 *
 * @returns Size.
 * @param   req     The VMMDev request to get the size for.
 */
static size_t vbg_req_get_min_size(const VMMDevRequestHeader *req)
{
	switch (req->requestType) {
	case VMMDevReq_GetMouseStatus:
	case VMMDevReq_SetMouseStatus:
		return sizeof(VMMDevReqMouseStatus);
	case VMMDevReq_SetPointerShape:
		return sizeof(VMMDevReqMousePointer);
	case VMMDevReq_GetHostVersion:
		return sizeof(VMMDevReqHostVersion);
	case VMMDevReq_Idle:
		return sizeof(VMMDevReqIdle);
	case VMMDevReq_GetHostTime:
		return sizeof(VMMDevReqHostTime);
	case VMMDevReq_GetHypervisorInfo:
	case VMMDevReq_SetHypervisorInfo:
		return sizeof(VMMDevReqHypervisorInfo);
	case VMMDevReq_RegisterPatchMemory:
	case VMMDevReq_DeregisterPatchMemory:
		return sizeof(VMMDevReqPatchMemory);
	case VMMDevReq_SetPowerStatus:
		return sizeof(VMMDevPowerStateRequest);
	case VMMDevReq_AcknowledgeEvents:
		return sizeof(VMMDevEvents);
	case VMMDevReq_ReportGuestInfo:
		return sizeof(VMMDevReportGuestInfo);
	case VMMDevReq_ReportGuestInfo2:
		return sizeof(VMMDevReportGuestInfo2);
	case VMMDevReq_ReportGuestStatus:
		return sizeof(VMMDevReportGuestStatus);
	case VMMDevReq_ReportGuestUserState:
		return sizeof(VMMDevReportGuestUserState);
	case VMMDevReq_GetDisplayChangeRequest:
		return sizeof(VMMDevDisplayChangeRequest);
	case VMMDevReq_GetDisplayChangeRequest2:
		return sizeof(VMMDevDisplayChangeRequest2);
	case VMMDevReq_GetDisplayChangeRequestEx:
		return sizeof(VMMDevDisplayChangeRequestEx);
	case VMMDevReq_VideoModeSupported:
		return sizeof(VMMDevVideoModeSupportedRequest);
	case VMMDevReq_GetHeightReduction:
		return sizeof(VMMDevGetHeightReductionRequest);
	case VMMDevReq_ReportGuestCapabilities:
		return sizeof(VMMDevReqGuestCapabilities);
	case VMMDevReq_SetGuestCapabilities:
		return sizeof(VMMDevReqGuestCapabilities2);
	case VMMDevReq_HGCMConnect:
		return sizeof(VMMDevHGCMConnect);
	case VMMDevReq_HGCMDisconnect:
		return sizeof(VMMDevHGCMDisconnect);
	case VMMDevReq_HGCMCall32:
		return sizeof(VMMDevHGCMCall);
	case VMMDevReq_HGCMCall64:
		return sizeof(VMMDevHGCMCall);
	case VMMDevReq_HGCMCancel:
		return sizeof(VMMDevHGCMCancel);
	case VMMDevReq_VideoAccelEnable:
		return sizeof(VMMDevVideoAccelEnable);
	case VMMDevReq_VideoAccelFlush:
		return sizeof(VMMDevVideoAccelFlush);
	case VMMDevReq_VideoSetVisibleRegion:
		/*
		 * The original protocol didn't consider a guest with NO visible
		 * windows.
		 */
		return sizeof(VMMDevVideoSetVisibleRegion) - sizeof(RTRECT);
	case VMMDevReq_GetSeamlessChangeRequest:
		return sizeof(VMMDevSeamlessChangeRequest);
	case VMMDevReq_QueryCredentials:
		return sizeof(VMMDevCredentials);
	case VMMDevReq_ReportGuestStats:
		return sizeof(VMMDevReportGuestStats);
	case VMMDevReq_GetMemBalloonChangeRequest:
		return sizeof(VMMDevGetMemBalloonChangeRequest);
	case VMMDevReq_GetStatisticsChangeRequest:
		return sizeof(VMMDevGetStatisticsChangeRequest);
	case VMMDevReq_ChangeMemBalloon:
		return sizeof(VMMDevChangeMemBalloon);
	case VMMDevReq_GetVRDPChangeRequest:
		return sizeof(VMMDevVRDPChangeRequest);
	case VMMDevReq_LogString:
		return sizeof(VMMDevReqLogString);
	case VMMDevReq_CtlGuestFilterMask:
		return sizeof(VMMDevCtlGuestFilterMask);
	case VMMDevReq_GetCpuHotPlugRequest:
		return sizeof(VMMDevGetCpuHotPlugRequest);
	case VMMDevReq_SetCpuHotPlugStatus:
		return sizeof(VMMDevCpuHotPlugStatusRequest);
	case VMMDevReq_RegisterSharedModule:
		return sizeof(VMMDevSharedModuleRegistrationRequest);
	case VMMDevReq_UnregisterSharedModule:
		return sizeof(VMMDevSharedModuleUnregistrationRequest);
	case VMMDevReq_CheckSharedModules:
		return sizeof(VMMDevSharedModuleCheckRequest);
	case VMMDevReq_GetPageSharingStatus:
		return sizeof(VMMDevPageSharingStatusRequest);
	case VMMDevReq_DebugIsPageShared:
		return sizeof(VMMDevPageIsSharedRequest);
	case VMMDevReq_GetSessionId:
		return sizeof(VMMDevReqSessionId);
	case VMMDevReq_HeartbeatConfigure:
		return sizeof(VMMDevReqHeartbeat);
	case VMMDevReq_GuestHeartbeat:
		return sizeof(VMMDevRequestHeader);
	default:
		break;
	}

	return 0;
}

int vbg_req_verify(const VMMDevRequestHeader *req, size_t buffer_size)
{
	size_t min_size;

	if (!req || buffer_size < sizeof(VMMDevRequestHeader)) {
		vbg_debug("VbglGRVerify: Invalid parameter: req = %p, buffer_size = %zu\n",
			  req, buffer_size);
		return VERR_INVALID_PARAMETER;
	}

	if (req->size > buffer_size) {
		vbg_debug("VbglGRVerify: request size %u > buffer size %zu\n",
			  req->size, buffer_size);
		return VERR_INVALID_PARAMETER;
	}

	/* The request size must correspond to the request type. */
	min_size = vbg_req_get_min_size(req);

	if (buffer_size < min_size) {
		vbg_debug("VbglGRVerify: buffer size %zu < expected size %zu\n",
			  buffer_size, min_size);
		return VERR_INVALID_PARAMETER;
	}

	if (req->size < min_size) {
		vbg_debug("VbglGRVerify: header size %u < expected size %zu\n",
			  req->size, min_size);
		return VERR_INVALID_PARAMETER;
	}

	if (buffer_size == min_size) {
		/*
		 * This is most likely a fixed size request, and in this case the
		 * request size must be also equal to the expected size.
		 */
		if (req->size != min_size) {
			vbg_debug("VbglGRVerify: request size %u != expected size %zu\n",
				  req->size, min_size);
			return VERR_INVALID_PARAMETER;
		}

		return VINF_SUCCESS;
	}

	/*
	 * This can be a variable size request. Check the request type and limit
	 * the size to VMMDEV_MAX_VMMDEVREQ_SIZE, which is max size supported by
	 * the host.
	 *
	 * Note: Keep this list sorted for easier human lookup!
	 */
	if (req->requestType == VMMDevReq_ChangeMemBalloon ||
	    req->requestType == VMMDevReq_HGCMCall32 ||
	    req->requestType == VMMDevReq_HGCMCall64 ||
	    req->requestType == VMMDevReq_RegisterSharedModule ||
	    req->requestType == VMMDevReq_ReportGuestUserState ||
	    req->requestType == VMMDevReq_LogString ||
	    req->requestType == VMMDevReq_SetPointerShape ||
	    req->requestType == VMMDevReq_VideoSetVisibleRegion) {
		if (buffer_size > VMMDEV_MAX_VMMDEVREQ_SIZE) {
			vbg_debug("VbglGRVerify: VMMDevReq_LogString: buffer size %zu too big\n",
				  buffer_size);
			return VERR_BUFFER_OVERFLOW;
		}
	} else {
		vbg_debug("VbglGRVerify: unknown request-type %#08x\n",
			  req->requestType);
		return VERR_IO_BAD_LENGTH; /* ??? */
	}

	return VINF_SUCCESS;
}

void *vbg_req_alloc(size_t len, VMMDevRequestType req_type)
{
	VMMDevRequestHeader *req;

	req = kmalloc(len, GFP_KERNEL | __GFP_DMA32);
	if (!req)
		return NULL;

	memset(req, 0xaa, len);

	req->size = len;
	req->version = VMMDEV_REQUEST_HEADER_VERSION;
	req->requestType = req_type;
	req->rc = VERR_GENERAL_FAILURE;
	req->reserved1 = 0;
	req->reserved2 = 0;

	return req;
}

/* Note this function returns a VBox status code, not a negative errno!! */
int vbg_req_perform(VBOXGUESTDEVEXT *gdev, void *req)
{
	unsigned long phys_req = virt_to_phys(req);

	outl(phys_req, gdev->IOPortBase + VMMDEV_PORT_OFF_REQUEST);
	mb();

	return ((VMMDevRequestHeader *)req)->rc;
}

static bool hgcm_req_done(VBOXGUESTDEVEXT *gdev,
			  VMMDevHGCMRequestHeader * header)
{
	unsigned long flags;
	bool done;

	spin_lock_irqsave(&gdev->event_spinlock, flags);
	done = header->fu32Flags & VBOX_HGCM_REQ_DONE;
	spin_unlock_irqrestore(&gdev->event_spinlock, flags);

	return done;
}

int vbg_hgcm_connect(VBOXGUESTDEVEXT *gdev, HGCMServiceLocation * loc,
		     u32 * client_id)
{
	VMMDevHGCMConnect *hgcm_connect = NULL;
	int rc;

	hgcm_connect = vbg_req_alloc(sizeof(*hgcm_connect),
				     VMMDevReq_HGCMConnect);
	if (!hgcm_connect)
		return VERR_NO_MEMORY;

	hgcm_connect->header.fu32Flags = 0;
	memcpy(&hgcm_connect->loc, loc, sizeof(*loc));
	hgcm_connect->u32ClientID = 0;

	rc = vbg_req_perform(gdev, hgcm_connect);

	if (rc == VINF_HGCM_ASYNC_EXECUTE)
		wait_event(gdev->hgcm_wq,
			   hgcm_req_done(gdev, &hgcm_connect->header));

	if (rc >= 0) {
		*client_id = hgcm_connect->u32ClientID;
		rc = hgcm_connect->header.result;
	}

	kfree(hgcm_connect);

	return rc;
}
EXPORT_SYMBOL(vbg_hgcm_connect);

int vbg_hgcm_disconnect(VBOXGUESTDEVEXT *gdev, u32 client_id)
{
	VMMDevHGCMDisconnect *hgcm_disconnect = NULL;
	int rc;

	hgcm_disconnect = vbg_req_alloc(sizeof(*hgcm_disconnect),
					VMMDevReq_HGCMDisconnect);
	if (!hgcm_disconnect)
		return VERR_NO_MEMORY;

	hgcm_disconnect->header.fu32Flags = 0;
	hgcm_disconnect->u32ClientID = client_id;

	rc = vbg_req_perform(gdev, hgcm_disconnect);

	if (rc == VINF_HGCM_ASYNC_EXECUTE)
		wait_event(gdev->hgcm_wq,
			   hgcm_req_done(gdev, &hgcm_disconnect->header));

	if (rc >= 0)
		rc = hgcm_disconnect->header.result;

	kfree(hgcm_disconnect);

	return rc;
}
EXPORT_SYMBOL(vbg_hgcm_disconnect);

static u32 hgcm_call_buf_size_in_pages(void *buf, u32 len)
{
	u32 size = PAGE_ALIGN(len + ((unsigned long)buf & ~PAGE_MASK));

	return size >> PAGE_SHIFT;
}

static void hgcm_call_inc_pcb_extra(void *buf, u32 len, size_t * pcb_extra)
{
	u32 pages;

	pages = hgcm_call_buf_size_in_pages(buf, len);
	*pcb_extra += offsetof(HGCMPageListInfo, aPages[pages]);
}

/* Kernel mode use only, use WARN_ON for sanity checks. */
static int hgcm_call_check_pagelist(const HGCMFunctionParameter *src_parm,
	const VBoxGuestHGCMCallInfo *callinfo, u32 callinfo_size,
	size_t *pcb_extra)
{
	HGCMPageListInfo *pg_lst;
	u32 u, offset, size;

	offset = src_parm->u.PageList.offset;
	size = src_parm->u.PageList.size;
	if (!size)
		return VINF_SUCCESS;

	if (WARN_ON(size > VBGLR0_MAX_HGCM_KERNEL_PARM))
		return VERR_OUT_OF_RANGE;

	if (WARN_ON(offset < callinfo->cParms * sizeof(HGCMFunctionParameter) ||
		    offset > callinfo_size - sizeof(HGCMPageListInfo)))
		return VERR_INVALID_PARAMETER;

	pg_lst = (HGCMPageListInfo *)((u8 *)callinfo + offset);

	u = offset + offsetof(HGCMPageListInfo, aPages[pg_lst->cPages]);
	if (WARN_ON(u > callinfo_size))
		return VERR_INVALID_PARAMETER;

	if (WARN_ON(pg_lst->offFirstPage >= PAGE_SIZE))
		return VERR_INVALID_PARAMETER;

	u = PAGE_ALIGN(pg_lst->offFirstPage + size) >> PAGE_SHIFT;
	if (WARN_ON(u != pg_lst->cPages))
		return VERR_INVALID_PARAMETER;

	if (WARN_ON(!VBOX_HGCM_F_PARM_ARE_VALID(pg_lst->flags)))
		return VERR_INVALID_PARAMETER;

	for (u = 0; u < pg_lst->cPages; u++) {
		if (WARN_ON(pg_lst->aPages[u] &
			    (0xfff0000000000000ULL | ~PAGE_MASK)))
			return VERR_INVALID_PARAMETER;
	}

	*pcb_extra += offsetof(HGCMPageListInfo, aPages[pg_lst->cPages]);

	return VINF_SUCCESS;
}

static int hgcm_call_preprocess_linaddr(const HGCMFunctionParameter *src_parm,
					bool is_user, void **bounce_buf_ret,
					size_t *pcb_extra)
{
	void *buf, *bounce_buf;
	bool copy_in;
	u32 len;
	int ret;

	buf = (void *)src_parm->u.Pointer.u.linearAddr;
	len = src_parm->u.Pointer.size;
	copy_in = src_parm->type != VMMDevHGCMParmType_LinAddr_Out;

	if (!is_user) {
		if (WARN_ON(len > VBGLR0_MAX_HGCM_KERNEL_PARM))
			return VERR_OUT_OF_RANGE;

		hgcm_call_inc_pcb_extra(buf, len, pcb_extra);
		return VINF_SUCCESS;
	}

	if (len > VBGLR0_MAX_HGCM_USER_PARM)
		return VERR_OUT_OF_RANGE;

	if (len <= PAGE_SIZE * 2)
		bounce_buf = kmalloc(len, GFP_KERNEL);
	else
		bounce_buf = vmalloc(len);

	if (!bounce_buf)
		return VERR_NO_MEMORY;

	if (copy_in) {
		ret = copy_from_user(bounce_buf, (void __user *)buf, len);
		if (ret)
			return VERR_ACCESS_DENIED;
	} else {
		memset(bounce_buf, 0, len);
	}

	*bounce_buf_ret = bounce_buf;
	hgcm_call_inc_pcb_extra(bounce_buf, len, pcb_extra);
	return VINF_SUCCESS;
}

/**
 * Preprocesses the HGCM call, validate parameters, alloc bounce buffers and
 * figure out how much extra storage we need for page lists.
 *
 * @returns VBox status code
 *
 * @param   call             The call info.
 * @param   call_size        The size of the call info structure.
 * @param   is_user          Is it a user request or kernel request.
 * @param   bounce_bufs_ret  Where to return the allocated bouncebuffer array
 * @param   pcb_extra        Where to return the extra request space needed for
 *                           physical page lists.
 */
static int hgcm_call_preprocess(const VBoxGuestHGCMCallInfo *call,
	u32 call_size, bool is_user, void ***bounce_bufs_ret, size_t *pcb_extra)
{
	const HGCMFunctionParameter *src_parm = VBOXGUEST_HGCM_CALL_PARMS(call);
	u32 i, parms = call->cParms;
	void **bounce_bufs = NULL;
	int rc;

	*bounce_bufs_ret = NULL;
	*pcb_extra = 0;

	for (i = 0; i < parms; i++, src_parm++) {
		switch (src_parm->type) {
		case VMMDevHGCMParmType_32bit:
		case VMMDevHGCMParmType_64bit:
			break;

		case VMMDevHGCMParmType_PageList:
			if (is_user)
				return VERR_INVALID_PARAMETER;

			rc = hgcm_call_check_pagelist(src_parm, call,
						      call_size, pcb_extra);
			if (rc)
				return rc;

			break;

		case VMMDevHGCMParmType_LinAddr_In:
		case VMMDevHGCMParmType_LinAddr_Out:
		case VMMDevHGCMParmType_LinAddr:
			if (is_user && !bounce_bufs) {
				bounce_bufs =
				    (void **)kcalloc(parms, sizeof(void *),
						     GFP_KERNEL);
				if (!bounce_bufs)
					return VERR_NO_MEMORY;

				*bounce_bufs_ret = bounce_bufs;
			}

			rc = hgcm_call_preprocess_linaddr(src_parm, is_user,
							  &bounce_bufs[i],
							  pcb_extra);
			if (rc)
				return rc;

			break;

		default:
			return VERR_INVALID_PARAMETER;
		}
	}

	return VINF_SUCCESS;
}

/**
 * Translates linear address types to page list direction flags.
 *
 * @returns page list flags.
 * @param   enmType     The type.
 */
static u32
vbglR0HGCMInternalLinAddrTypeToPageListFlags(HGCMFunctionParameterType enmType)
{
	switch (enmType) {
	case VMMDevHGCMParmType_LinAddr_In:
		return VBOX_HGCM_F_PARM_DIRECTION_TO_HOST;

	case VMMDevHGCMParmType_LinAddr_Out:
		return VBOX_HGCM_F_PARM_DIRECTION_FROM_HOST;

	default:
		WARN_ON(1);
	case VMMDevHGCMParmType_LinAddr:
		return VBOX_HGCM_F_PARM_DIRECTION_BOTH;
	}
}

static void hgcm_call_init_linaddr(VMMDevHGCMCall *call,
				   HGCMFunctionParameter *dst_parm,
				   void *buf, u32 len,
				   HGCMFunctionParameterType type,
				   u32 *off_extra)
{
	HGCMPageListInfo *dst_pg_lst;
	struct page *page;
	bool is_vmalloc;
	u32 i, pages;

	dst_parm->type = type;

	if (len == 0) {
		dst_parm->u.Pointer.size = 0;
		dst_parm->u.Pointer.u.linearAddr = 0;
		return;
	}

	dst_pg_lst = (void *)call + *off_extra;
	pages = hgcm_call_buf_size_in_pages(buf, len);
	is_vmalloc = is_vmalloc_addr(buf);

	dst_parm->type = VMMDevHGCMParmType_PageList;
	dst_parm->u.PageList.size = len;
	dst_parm->u.PageList.offset = *off_extra;
	dst_pg_lst->flags = vbglR0HGCMInternalLinAddrTypeToPageListFlags(type);
	dst_pg_lst->offFirstPage = (unsigned long)buf & ~PAGE_MASK;
	dst_pg_lst->cPages = pages;

	for (i = 0; i < pages; i++) {
		if (is_vmalloc)
			page = vmalloc_to_page(buf);
		else
			page = virt_to_page(buf);

		dst_pg_lst->aPages[i] = page_to_phys(page);
		buf += PAGE_SIZE;
	}

	*off_extra += offsetof(HGCMPageListInfo, aPages[pages]);
}

/**
 * Initializes the call request that we're sending to the host.
 *
 * @param   pHGCMCall       The call to initialize.
 * @param   pCallInfo       The call info.
 * @param   cbCallInfo      The size of the call info structure.
 * @param   fIsUser         Is it a user request or kernel request.
 * @param   bounce_bufs     The bouncebuffer array.
 */
static void vbglR0HGCMInternalInitCall(VMMDevHGCMCall * pHGCMCall,
				       VBoxGuestHGCMCallInfo const *pCallInfo,
				       u32 cbCallInfo, void **bounce_bufs)
{
	HGCMFunctionParameter const *pSrcParm =
	    VBOXGUEST_HGCM_CALL_PARMS(pCallInfo);
	HGCMFunctionParameter *pDstParm = VMMDEV_HGCM_CALL_PARMS(pHGCMCall);
	u32 cParms = pCallInfo->cParms;
	u32 offExtra =
	    (u32) ((uintptr_t) (pDstParm + cParms) -
			(uintptr_t) pHGCMCall);
	u32 iParm;
	void *buf;

	/*
	 * The call request headers.
	 */
	pHGCMCall->header.fu32Flags = 0;
	pHGCMCall->header.result = VINF_SUCCESS;

	pHGCMCall->u32ClientID = pCallInfo->u32ClientID;
	pHGCMCall->u32Function = pCallInfo->u32Function;
	pHGCMCall->cParms = cParms;

	/*
	 * The parameters.
	 */
	for (iParm = 0; iParm < pCallInfo->cParms;
	     iParm++, pSrcParm++, pDstParm++) {
		switch (pSrcParm->type) {
		case VMMDevHGCMParmType_32bit:
		case VMMDevHGCMParmType_64bit:
			*pDstParm = *pSrcParm;
			break;

		case VMMDevHGCMParmType_PageList:
			pDstParm->type = VMMDevHGCMParmType_PageList;
			pDstParm->u.PageList.size = pSrcParm->u.PageList.size;
			if (pSrcParm->u.PageList.size) {
				HGCMPageListInfo const *pSrcPgLst =
				    (HGCMPageListInfo *) ((u8 *) pCallInfo
							  +
							  pSrcParm->u.PageList.
							  offset);
				HGCMPageListInfo *pDstPgLst =
				    (HGCMPageListInfo *) ((u8 *) pHGCMCall
							  + offExtra);
				u32 const cPages = pSrcPgLst->cPages;
				u32 iPage;

				pDstParm->u.PageList.offset = offExtra;
				pDstPgLst->flags = pSrcPgLst->flags;
				pDstPgLst->offFirstPage =
				    pSrcPgLst->offFirstPage;
				pDstPgLst->cPages = cPages;
				for (iPage = 0; iPage < cPages; iPage++)
					pDstPgLst->aPages[iPage] =
					    pSrcPgLst->aPages[iPage];

				offExtra +=
				    offsetof(HGCMPageListInfo,
						aPages[cPages]);
			} else
				pDstParm->u.PageList.offset = 0;
			break;

		case VMMDevHGCMParmType_LinAddr_In:
		case VMMDevHGCMParmType_LinAddr_Out:
		case VMMDevHGCMParmType_LinAddr:
			if (bounce_bufs && bounce_bufs[iParm])
				buf = bounce_bufs[iParm];
			else
				buf = (void *)pSrcParm->u.Pointer.u.linearAddr;

			hgcm_call_init_linaddr(pHGCMCall, pDstParm, buf,
					       pSrcParm->u.Pointer.size,
					       pSrcParm->type, &offExtra);
			break;

		default:
			WARN_ON(1);
			pDstParm->type = VMMDevHGCMParmType_Invalid;
		}
	}
}

/* Note this function returns a VBox status code, not a negative errno!! */
static int hgcm_cancel_call(VBOXGUESTDEVEXT *gdev, VMMDevHGCMCall * call)
{
	int rc;

	/*
	 * We use a pre-allocated request for cancellations, which is
	 * protected by cancel_req_mutex. This means that all cancellations
	 * get serialized, this should be fine since they should be rare.
	 */
	mutex_lock(&gdev->cancel_req_mutex);
	gdev->cancel_req->physReqToCancel = virt_to_phys(call);
	rc = vbg_req_perform(gdev, gdev->cancel_req);
	mutex_unlock(&gdev->cancel_req_mutex);

	/** @todo ADDVER: Remove this on next minor version change. */
	if (rc == VERR_NOT_IMPLEMENTED) {
		call->header.fu32Flags |= VBOX_HGCM_REQ_CANCELLED;
		call->header.header.requestType = VMMDevReq_HGCMCancel;

		rc = vbg_req_perform(gdev, call);
		if (rc == VERR_INVALID_PARAMETER)
			rc = VERR_NOT_FOUND;
	}

	if (rc >= 0)
		call->header.fu32Flags |= VBOX_HGCM_REQ_CANCELLED;

	return rc;
}

/**
 * Performs the call and completion wait.
 *
 * @returns VBox status code
 *
 * @param   gdev             The VBoxGuest device extension.
 * @param   call                The HGCM call info.
 * @param   timeout_ms          Timeout in ms.
 * @param   is_user             Is this an in kernel call or from userspace ?
 * @param   leak_it             Where to return the leak it / free it,
 *                              indicator. Cancellation fun.
 */
static int vbg_hgcm_do_call(VBOXGUESTDEVEXT *gdev, VMMDevHGCMCall *call,
			    u32 timeout_ms, bool is_user, bool *leak_it)
{
	long timeout;
	int rc, cancel_rc;

	*leak_it = false;

	rc = vbg_req_perform(gdev, call);

	/*
	 * If the call failed, then pretend success.
	 * Upper layers will interpret the result code in the packet.
	 */
	if (rc < 0) {
		WARN_ON(!(call->header.fu32Flags & VBOX_HGCM_REQ_DONE));
		return VINF_SUCCESS;
	}

	if (rc != VINF_HGCM_ASYNC_EXECUTE)
		return rc;

	/* Host decided to process the request asynchronously, wait for it */
	if (timeout_ms == U32_MAX)
		timeout = MAX_SCHEDULE_TIMEOUT;
	else
		timeout = msecs_to_jiffies(timeout_ms);

	if (is_user) {
		timeout = wait_event_interruptible_timeout(gdev->hgcm_wq,
							   hgcm_req_done
							   (gdev,
							    &call->header),
							   timeout);
	} else {
		timeout = wait_event_timeout(gdev->hgcm_wq,
					     hgcm_req_done(gdev,
							   &call->header),
					     timeout);
	}

	/* timeout > 0 means hgcm_req_done has returned true, so success */
	if (timeout > 0)
		return VINF_SUCCESS;

	if (timeout == 0)
		rc = VERR_TIMEOUT;
	else
		rc = VERR_INTERRUPTED;

	/* Cancel the request */
	cancel_rc = hgcm_cancel_call(gdev, call);
	if (cancel_rc >= 0)
		return rc;

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
		vbg_err("vbg_hgcm_do_call: Call timedout and cancelation failed, leaking the request\n");
		*leak_it = true;
		return rc;
	}

	/* The call has completed normally after all */
	return VINF_SUCCESS;
}

/**
 * Copies the result of the call back to the caller info structure and user
 * buffers.
 *
 * @returns VBox status code
 * @param   pCallInfo           Call info structure to update.
 * @param   pHGCMCall           HGCM call request.
 * @param   bounce_bufs         The bouncebuffer array.
 */
static int vbglR0HGCMInternalCopyBackResult(VBoxGuestHGCMCallInfo * pCallInfo,
					    VMMDevHGCMCall const *pHGCMCall,
					    void **bounce_bufs)
{
	HGCMFunctionParameter const *pSrcParm =
	    VMMDEV_HGCM_CALL_PARMS(pHGCMCall);
	HGCMFunctionParameter *pDstParm = VBOXGUEST_HGCM_CALL_PARMS(pCallInfo);
	u32 cParms = pCallInfo->cParms;
	u32 iParm;
	int ret;

	/*
	 * The call result.
	 */
	pCallInfo->result = pHGCMCall->header.result;

	/*
	 * Copy back parameters.
	 */
	for (iParm = 0; iParm < cParms; iParm++, pSrcParm++, pDstParm++) {
		switch (pDstParm->type) {
		case VMMDevHGCMParmType_32bit:
		case VMMDevHGCMParmType_64bit:
			*pDstParm = *pSrcParm;
			break;

		case VMMDevHGCMParmType_PageList:
			pDstParm->u.PageList.size = pSrcParm->u.PageList.size;
			break;

		case VMMDevHGCMParmType_LinAddr_In:
			pDstParm->u.Pointer.size = pSrcParm->u.Pointer.size;
			break;

		case VMMDevHGCMParmType_LinAddr_Out:
		case VMMDevHGCMParmType_LinAddr:
			if (bounce_bufs && bounce_bufs[iParm]) {
				ret = copy_to_user((void __user *)
						   pDstParm->u.Pointer.u.
						   linearAddr,
						   bounce_bufs[iParm],
						   min(pSrcParm->u.Pointer.size,
						       pDstParm->u.Pointer.
						       size));
				if (ret)
					return VERR_ACCESS_DENIED;
			}
			pDstParm->u.Pointer.size = pSrcParm->u.Pointer.size;
			break;

		default:
			WARN_ON(1);
			return VERR_INTERNAL_ERROR_4;
		}
	}

	return VINF_SUCCESS;
}

int vbg_hgcm_call(VBOXGUESTDEVEXT *gdev, VBoxGuestHGCMCallInfo *pCallInfo,
		  u32 cbCallInfo, u32 timeout_ms, bool is_user)
{
	VMMDevHGCMCall *pHGCMCall;
	void **bounce_bufs;
	size_t cbExtra;
	bool leak_it;
	int i, rc;

	/*
	 * Validate, lock and buffer the parameters for the call.
	 * This will calculate the amount of extra space for physical page list.
	 */
	rc = hgcm_call_preprocess(pCallInfo, cbCallInfo, is_user,
				  &bounce_bufs, &cbExtra);
	if (rc) {
		/* Even on error bounce bufs may still have been allocated */
		goto free_bounce_bufs;
	}

	pHGCMCall = vbg_req_alloc(sizeof(VMMDevHGCMCall) + pCallInfo->cParms *
				  sizeof(HGCMFunctionParameter) + cbExtra,
				  VMMDevReq_HGCMCall);
	if (!pHGCMCall) {
		rc = VERR_NO_MEMORY;
		goto free_bounce_bufs;
	}

	vbglR0HGCMInternalInitCall(pHGCMCall, pCallInfo, cbCallInfo, bounce_bufs);

	rc = vbg_hgcm_do_call(gdev, pHGCMCall, timeout_ms, is_user, &leak_it);
	if (rc >= 0)
		rc = vbglR0HGCMInternalCopyBackResult(pCallInfo, pHGCMCall,
						      bounce_bufs);

	if (!leak_it)
		kfree(pHGCMCall);

free_bounce_bufs:
	if (bounce_bufs) {
		for (i = 0; i < pCallInfo->cParms; i++) {
			if (is_vmalloc_addr(bounce_bufs[i]))
				vfree(bounce_bufs[i]);
			else
				kfree(bounce_bufs[i]);
		}
		kfree(bounce_bufs);
	}

	return rc;
}
EXPORT_SYMBOL(vbg_hgcm_call);

#ifdef CONFIG_X86_64
int vbg_hgcm_call32(VBOXGUESTDEVEXT *gdev, VBoxGuestHGCMCallInfo * pCallInfo,
		    u32 cbCallInfo, u32 timeout_ms, bool is_user)
{
	VBoxGuestHGCMCallInfo *pCallInfo64 = NULL;
	HGCMFunctionParameter *pParm64 = NULL;
	HGCMFunctionParameter32 *pParm32 = NULL;
	u32 cParms = pCallInfo->cParms;
	u32 iParm;
	int rc = VINF_SUCCESS;

	/*
	 * The simple approach, allocate a temporary request and convert the parameters.
	 */
	pCallInfo64 = kzalloc(sizeof(*pCallInfo64) +
			      cParms * sizeof(HGCMFunctionParameter),
			      GFP_KERNEL);
	if (!pCallInfo64)
		return VERR_NO_MEMORY;

	*pCallInfo64 = *pCallInfo;
	pParm32 = VBOXGUEST_HGCM_CALL_PARMS32(pCallInfo);
	pParm64 = VBOXGUEST_HGCM_CALL_PARMS(pCallInfo64);
	for (iParm = 0; iParm < cParms; iParm++, pParm32++, pParm64++) {
		switch (pParm32->type) {
		case VMMDevHGCMParmType_32bit:
			pParm64->type = VMMDevHGCMParmType_32bit;
			pParm64->u.value32 = pParm32->u.value32;
			break;

		case VMMDevHGCMParmType_64bit:
			pParm64->type = VMMDevHGCMParmType_64bit;
			pParm64->u.value64 = pParm32->u.value64;
			break;

		case VMMDevHGCMParmType_LinAddr_Out:
		case VMMDevHGCMParmType_LinAddr:
		case VMMDevHGCMParmType_LinAddr_In:
			pParm64->type = pParm32->type;
			pParm64->u.Pointer.size = pParm32->u.Pointer.size;
			pParm64->u.Pointer.u.linearAddr =
			    pParm32->u.Pointer.u.linearAddr;
			break;

		default:
			rc = VERR_INVALID_PARAMETER;
		}
		if (rc < 0)
			goto out_free;
	}

	rc = vbg_hgcm_call(gdev, pCallInfo64,
			   sizeof(*pCallInfo64) +
				cParms * sizeof(HGCMFunctionParameter),
			   timeout_ms, is_user);
	if (rc >= 0) {
		*pCallInfo = *pCallInfo64;

		/*
		 * Copy back.
		 */
		pParm32 = VBOXGUEST_HGCM_CALL_PARMS32(pCallInfo);
		pParm64 = VBOXGUEST_HGCM_CALL_PARMS(pCallInfo64);
		for (iParm = 0; iParm < cParms;
		     iParm++, pParm32++, pParm64++) {
			switch (pParm64->type) {
			case VMMDevHGCMParmType_32bit:
				pParm32->u.value32 = pParm64->u.value32;
				break;

			case VMMDevHGCMParmType_64bit:
				pParm32->u.value64 = pParm64->u.value64;
				break;

			case VMMDevHGCMParmType_LinAddr_Out:
			case VMMDevHGCMParmType_LinAddr:
			case VMMDevHGCMParmType_LinAddr_In:
				pParm32->u.Pointer.size =
				    pParm64->u.Pointer.size;
				break;
			default:
				WARN_ON(1);
				rc = VERR_INTERNAL_ERROR_3;
			}
		}
	}

out_free:
	kfree(pCallInfo64);
	return rc;
}
#endif

int vbg_status_code_to_errno(int rc)
{
	if (rc >= 0)
		return 0;

	switch (rc) {
	case VERR_ACCESS_DENIED:                    return EPERM;
	case VERR_FILE_NOT_FOUND:                   return ENOENT;
	case VERR_PROCESS_NOT_FOUND:                return ESRCH;
	case VERR_INTERRUPTED:                      return EINTR;
	case VERR_DEV_IO_ERROR:                     return EIO;
	case VERR_TOO_MUCH_DATA:                    return E2BIG;
	case VERR_BAD_EXE_FORMAT:                   return ENOEXEC;
	case VERR_INVALID_HANDLE:                   return EBADF;
	case VERR_TRY_AGAIN:                        return EAGAIN;
	case VERR_NO_MEMORY:                        return ENOMEM;
	case VERR_INVALID_POINTER:                  return EFAULT;
	case VERR_RESOURCE_BUSY:                    return EBUSY;
	case VERR_ALREADY_EXISTS:                   return EEXIST;
	case VERR_NOT_SAME_DEVICE:                  return EXDEV;
	case VERR_NOT_A_DIRECTORY:
	case VERR_PATH_NOT_FOUND:                   return ENOTDIR;
	case VERR_IS_A_DIRECTORY:                   return EISDIR;
	case VERR_INVALID_PARAMETER:                return EINVAL;
	case VERR_TOO_MANY_OPEN_FILES:              return ENFILE;
	case VERR_INVALID_FUNCTION:                 return ENOTTY;
	case VERR_SHARING_VIOLATION:                return ETXTBSY;
	case VERR_FILE_TOO_BIG:                     return EFBIG;
	case VERR_DISK_FULL:                        return ENOSPC;
	case VERR_SEEK_ON_DEVICE:                   return ESPIPE;
	case VERR_WRITE_PROTECT:                    return EROFS;
	case VERR_BROKEN_PIPE:                      return EPIPE;
	case VERR_DEADLOCK:                         return EDEADLK;
	case VERR_FILENAME_TOO_LONG:                return ENAMETOOLONG;
	case VERR_FILE_LOCK_FAILED:                 return ENOLCK;
	case VERR_NOT_IMPLEMENTED:
	case VERR_NOT_SUPPORTED:                    return ENOSYS;
	case VERR_DIR_NOT_EMPTY:                    return ENOTEMPTY;
	case VERR_TOO_MANY_SYMLINKS:                return ELOOP;
	case VERR_NO_DATA:                          return ENODATA;
	case VERR_NET_NO_NETWORK:                   return ENONET;
	case VERR_NET_NOT_UNIQUE_NAME:              return ENOTUNIQ;
	case VERR_NO_TRANSLATION:                   return EILSEQ;
	case VERR_NET_NOT_SOCKET:                   return ENOTSOCK;
	case VERR_NET_DEST_ADDRESS_REQUIRED:        return EDESTADDRREQ;
	case VERR_NET_MSG_SIZE:                     return EMSGSIZE;
	case VERR_NET_PROTOCOL_TYPE:                return EPROTOTYPE;
	case VERR_NET_PROTOCOL_NOT_AVAILABLE:       return ENOPROTOOPT;
	case VERR_NET_PROTOCOL_NOT_SUPPORTED:       return EPROTONOSUPPORT;
	case VERR_NET_SOCKET_TYPE_NOT_SUPPORTED:    return ESOCKTNOSUPPORT;
	case VERR_NET_OPERATION_NOT_SUPPORTED:      return EOPNOTSUPP;
	case VERR_NET_PROTOCOL_FAMILY_NOT_SUPPORTED: return EPFNOSUPPORT;
	case VERR_NET_ADDRESS_FAMILY_NOT_SUPPORTED: return EAFNOSUPPORT;
	case VERR_NET_ADDRESS_IN_USE:               return EADDRINUSE;
	case VERR_NET_ADDRESS_NOT_AVAILABLE:        return EADDRNOTAVAIL;
	case VERR_NET_DOWN:                         return ENETDOWN;
	case VERR_NET_UNREACHABLE:                  return ENETUNREACH;
	case VERR_NET_CONNECTION_RESET:             return ENETRESET;
	case VERR_NET_CONNECTION_ABORTED:           return ECONNABORTED;
	case VERR_NET_CONNECTION_RESET_BY_PEER:     return ECONNRESET;
	case VERR_NET_NO_BUFFER_SPACE:              return ENOBUFS;
	case VERR_NET_ALREADY_CONNECTED:            return EISCONN;
	case VERR_NET_NOT_CONNECTED:                return ENOTCONN;
	case VERR_NET_SHUTDOWN:                     return ESHUTDOWN;
	case VERR_NET_TOO_MANY_REFERENCES:          return ETOOMANYREFS;
	case VERR_TIMEOUT:                          return ETIMEDOUT;
	case VERR_NET_CONNECTION_REFUSED:           return ECONNREFUSED;
	case VERR_NET_HOST_DOWN:                    return EHOSTDOWN;
	case VERR_NET_HOST_UNREACHABLE:             return EHOSTUNREACH;
	case VERR_NET_ALREADY_IN_PROGRESS:          return EALREADY;
	case VERR_NET_IN_PROGRESS:                  return EINPROGRESS;
	case VERR_MEDIA_NOT_PRESENT:                return ENOMEDIUM;
	case VERR_MEDIA_NOT_RECOGNIZED:             return EMEDIUMTYPE;
        default:
		vbg_warn("vbg_status_code_to_errno: Unhandled err %d\n", rc);
		return EPROTO;
	}
}
EXPORT_SYMBOL(vbg_status_code_to_errno);
