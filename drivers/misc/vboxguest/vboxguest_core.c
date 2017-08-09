/*
 * vboxguest core guest-device handling code, VBoxGuest.cpp in upstream svn.
 *
 * Copyright (C) 2007-2016 Oracle Corporation
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

#include <linux/device.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/sizes.h>
#include <linux/slab.h>
#include <linux/vbox_err.h>
#include <linux/vbox_utils.h>
#include "vboxguest_core.h"
#include "vboxguest_version.h"

/*********************************************************************************************************************************
*   Defined Constants And Macros                                                                                                 *
*********************************************************************************************************************************/
#define GUEST_MAPPINGS_TRIES	5

/*********************************************************************************************************************************
*   Internal Functions                                                                                                           *
*********************************************************************************************************************************/
static void vgdrvBitUsageTrackerClear(PVBOXGUESTBITUSAGETRACER pTracker);
static int vgdrvResetEventFilterOnHost(PVBOXGUESTDEVEXT gdev,
				       u32 fFixedEvents);
static int vgdrvResetCapabilitiesOnHost(PVBOXGUESTDEVEXT gdev);
static int vgdrvSetSessionEventFilter(PVBOXGUESTDEVEXT gdev,
				      PVBOXGUESTSESSION session,
				      u32 fOrMask, u32 fNotMask,
				      bool fSessionTermination);
static int vgdrvSetSessionCapabilities(PVBOXGUESTDEVEXT gdev,
				       PVBOXGUESTSESSION session,
				       u32 fOrMask, u32 fNoMask,
				       bool fSessionTermination);

/**
 * Reserves memory in which the VMM can relocate any guest mappings
 * that are floating around.
 *
 * This operation is a little bit tricky since the VMM might not accept
 * just any address because of address clashes between the three contexts
 * it operates in, so we try several times.
 *
 * Failure to reserve the guest mappings is ignored.
 *
 * @param   gdev     The Guest extension device.
 */
static void vgdrvInitFixateGuestMappings(PVBOXGUESTDEVEXT gdev)
{
	VMMDevReqHypervisorInfo *req = NULL;
	void *guest_mappings[GUEST_MAPPINGS_TRIES];
	struct page **pages = NULL;
	u32 size, hypervisor_size;
	int i, rc;

	/* Query the required space. */
	req = vbg_req_alloc(sizeof(*req), VMMDevReq_GetHypervisorInfo);
	if (!req)
		return;

	req->hypervisorStart = 0;
	req->hypervisorSize = 0;
	rc = vbg_req_perform(gdev, req);
	if (rc < 0)
		goto out;

	/*
	 * The VMM will report back if there is nothing it wants to map, like
	 * for instance in VT-x and AMD-V mode.
	 */
	if (req->hypervisorSize == 0)
		goto out;

	hypervisor_size = req->hypervisorSize;
	/* Add 4M so that we can align the vmap to 4MiB as the host requires. */
	size = PAGE_ALIGN(req->hypervisorSize) + SZ_4M;

	pages = kmalloc(sizeof(*pages) * (size >> PAGE_SHIFT), GFP_KERNEL);
	if (!pages)
		goto out;

	gdev->guest_mappings_dummy_page = alloc_page(GFP_HIGHUSER);
	if (!gdev->guest_mappings_dummy_page)
		goto out;

	for (i = 0; i < (size >> PAGE_SHIFT); i++)
		pages[i] = gdev->guest_mappings_dummy_page;

	/* Try several times, the host can be picky about certain addresses. */
	for (i = 0; i < GUEST_MAPPINGS_TRIES; i++) {
		guest_mappings[i] = vmap(pages, (size >> PAGE_SHIFT),
					 VM_MAP, PAGE_KERNEL_RO);
		if (!guest_mappings[i])
			break;

		req->header.requestType = VMMDevReq_SetHypervisorInfo;
		req->header.rc = VERR_INTERNAL_ERROR;
		req->hypervisorSize = hypervisor_size;
		req->hypervisorStart =
			(unsigned long)PTR_ALIGN(guest_mappings[i], SZ_4M);

		rc = vbg_req_perform(gdev, req);
		if (rc >= 0) {
			gdev->guest_mappings = guest_mappings[i];
			break;
		}
	}

	/* Free vmap's from failed attempts. */
	while (--i >= 0)
		vunmap(guest_mappings[i]);

	/* On failure free the dummy-page backing the vmap */
	if (!gdev->guest_mappings) {
		__free_page(gdev->guest_mappings_dummy_page);
		gdev->guest_mappings_dummy_page = NULL;
	}

out:
	kfree(req);
	kfree(pages);
}

/**
 * Undo what vgdrvInitFixateGuestMappings did.
 *
 * @param   gdev     The Guest extension device.
 */
static void vgdrvTermUnfixGuestMappings(PVBOXGUESTDEVEXT gdev)
{
	VMMDevReqHypervisorInfo *req;
	int rc;

	if (!gdev->guest_mappings)
		return;

	/*
	 * Tell the host that we're going to free the memory we reserved for
	 * it, the free it up. (Leak the memory if anything goes wrong here.)
	 */
	req = vbg_req_alloc(sizeof(*req), VMMDevReq_SetHypervisorInfo);
	if (!req)
		return;

	req->hypervisorStart = 0;
	req->hypervisorSize = 0;

	rc = vbg_req_perform(gdev, req);

	kfree(req);

	if (rc < 0) {
		vbg_err("vgdrvTermUnfixGuestMappings: vbg_req_perform error: %d\n",
			rc);
		return;
	}

	vunmap(gdev->guest_mappings);
	gdev->guest_mappings = NULL;

	__free_page(gdev->guest_mappings_dummy_page);
	gdev->guest_mappings_dummy_page = NULL;
}

/**
 * Report the guest information to the host.
 *
 * @returns 0 or negative errno value.
 * @param   gdev            The Guest extension device.
 */
static int vgdrvReportGuestInfo(PVBOXGUESTDEVEXT gdev)
{
	/*
	 * Allocate and fill in the two guest info reports.
	 */
	VMMDevReportGuestInfo *req1 = NULL;
	VMMDevReportGuestInfo2 *req2 = NULL;
	int rc, ret = -ENOMEM;

	req1 = vbg_req_alloc(sizeof(*req1), VMMDevReq_ReportGuestInfo);
	req2 = vbg_req_alloc(sizeof(*req2), VMMDevReq_ReportGuestInfo2);
	if (!req1 || !req2)
		goto out_free;

	req1->guestInfo.interfaceVersion = VMMDEV_VERSION;
#ifdef CONFIG_X86_64
	req1->guestInfo.osType = VBOXOSTYPE_Linux26_x64;
#else
	req1->guestInfo.osType = VBOXOSTYPE_Linux26;
#endif

	req2->guestInfo.additionsMajor = VBOX_VERSION_MAJOR;
	req2->guestInfo.additionsMinor = VBOX_VERSION_MINOR;
	req2->guestInfo.additionsBuild = VBOX_VERSION_BUILD;
	req2->guestInfo.additionsRevision = VBOX_SVN_REV;
	/* (no features defined yet) */
	req2->guestInfo.additionsFeatures = 0;
	strlcpy(req2->guestInfo.szName, VBOX_VERSION_STRING,
		sizeof(req2->guestInfo.szName));

	/*
	 * There are two protocols here:
	 *      1. Info2 + Info1. Supported by >=3.2.51.
	 *      2. Info1 and optionally Info2. The old protocol.
	 *
	 * We try protocol 2 first.  It will fail with VERR_NOT_SUPPORTED
	 * if not supported by the VMMDev (message ordering requirement).
	 */
	rc = vbg_req_perform(gdev, req2);
	if (rc >= 0) {
		rc = vbg_req_perform(gdev, req1);
	} else if (rc == VERR_NOT_SUPPORTED || rc == VERR_NOT_IMPLEMENTED) {
		rc = vbg_req_perform(gdev, req1);
		if (rc >= 0) {
			rc = vbg_req_perform(gdev, req2);
			if (rc == VERR_NOT_IMPLEMENTED)
				rc = VINF_SUCCESS;
		}
	}
	ret = -vbg_status_code_to_errno(rc);

out_free:
	kfree(req2);
	kfree(req1);
	return ret;
}

/**
 * Report the guest driver status to the host.
 *
 * @returns 0 or negative errno value.
 * @param   gdev         The Guest extension device.
 * @param   active       Flag whether the driver is now active or not.
 */
static int vgdrvReportDriverStatus(PVBOXGUESTDEVEXT gdev, bool active)
{
	VMMDevReportGuestStatus *req;
	int rc;

	req = vbg_req_alloc(sizeof(*req), VMMDevReq_ReportGuestStatus);
	if (!req)
		return -ENOMEM;

	req->guestStatus.facility = VBoxGuestFacilityType_VBoxGuestDriver;
	req->guestStatus.status = active ? VBoxGuestFacilityStatus_Active :
					   VBoxGuestFacilityStatus_Inactive;
	req->guestStatus.flags = 0;

	rc = vbg_req_perform(gdev, req);
	if (rc == VERR_NOT_IMPLEMENTED)	/* Compatibility with older hosts. */
		rc = VINF_SUCCESS;

	kfree(req);

	return -vbg_status_code_to_errno(rc);
}

/** @name Memory Ballooning
 * @{
 */

/**
 * Inflate the balloon by one chunk.
 *
 * The caller owns the balloon mutex.
 *
 * @returns VBox status code
 * @param   gdev        The Guest extension device.
 * @param   chunk_idx	Index of the chunk.
 */
static int vbg_balloon_inflate(PVBOXGUESTDEVEXT gdev, u32 chunk_idx)
{
	VMMDevChangeMemBalloon *req = gdev->mem_balloon.change_req;
	struct page **pages;
	int i, rc;

	pages = kmalloc(sizeof(*pages) * VMMDEV_MEMORY_BALLOON_CHUNK_PAGES,
			GFP_KERNEL | __GFP_NOWARN);
	if (!pages)
		return VERR_NO_MEMORY;

	req->header.size = sizeof(*req);
	req->inflate = true;
	req->pages = VMMDEV_MEMORY_BALLOON_CHUNK_PAGES;

	for (i = 0; i < VMMDEV_MEMORY_BALLOON_CHUNK_PAGES; i++) {
		pages[i] = alloc_page(GFP_KERNEL | __GFP_NOWARN);
		if (!pages[i]) {
			rc = VERR_NO_MEMORY;
			goto out_error;
		}

		req->phys_page[i] = page_to_phys(pages[i]);
	}

	rc = vbg_req_perform(gdev, req);
	if (rc < 0) {
		vbg_err("vbg_balloon_inflate: vbg_req_perform error: %d\n", rc);
		goto out_error;
	}

	gdev->mem_balloon.pages[chunk_idx] = pages;

	return VINF_SUCCESS;

out_error:
	while (--i >= 0)
		__free_page(pages[i]);
	kfree(pages);

	return rc;
}

/**
 * Deflate the balloon by one chunk.
 *
 * The caller owns the balloon mutex.
 *
 * @returns VBox status code
 * @param   gdev        The Guest extension device.
 * @param   chunk_idx	Index of the chunk.
 */
static int vbg_balloon_deflate(PVBOXGUESTDEVEXT gdev, u32 chunk_idx)
{
	VMMDevChangeMemBalloon *req = gdev->mem_balloon.change_req;
	struct page **pages = gdev->mem_balloon.pages[chunk_idx];
	int i, rc;

	req->header.size = sizeof(*req);
	req->inflate = false;
	req->pages = VMMDEV_MEMORY_BALLOON_CHUNK_PAGES;

	for (i = 0; i < VMMDEV_MEMORY_BALLOON_CHUNK_PAGES; i++)
		req->phys_page[i] = page_to_phys(pages[i]);

	rc = vbg_req_perform(gdev, req);
	if (rc < 0) {
		vbg_err("vbg_balloon_deflate: vbg_req_perform error: %d\n", rc);
		return rc;
	}

	for (i = 0; i < VMMDEV_MEMORY_BALLOON_CHUNK_PAGES; i++)
		__free_page(pages[i]);
	kfree(pages);
	gdev->mem_balloon.pages[chunk_idx] = NULL;

	return VINF_SUCCESS;
}

/**
 * Cleanup the memory balloon of a session.
 *
 * Will request the balloon mutex, so it must be valid and the caller must not
 * own it already.
 *
 * @param   gdev        The Guest extension device.
 * @param   session     The session.
 */
static void vbg_balloon_close(PVBOXGUESTDEVEXT gdev, PVBOXGUESTSESSION session)
{
	int i, rc;

	mutex_lock(&gdev->mem_balloon.mutex);

	if (gdev->mem_balloon.owner == session) {
		for (i = gdev->mem_balloon.chunks - 1; i >= 0; i--) {
			rc = vbg_balloon_deflate(gdev, i);
			if (rc < 0)
				break;

			gdev->mem_balloon.chunks--;
		}
		gdev->mem_balloon.owner = NULL;
	}

	mutex_unlock(&gdev->mem_balloon.mutex);
}

/** @} */

/** @name Heartbeat
 * @{
 */

/**
 * Callback for heartbeat timer.
 */
static void vbg_heartbeat_timer(unsigned long data)
{
	PVBOXGUESTDEVEXT gdev = (PVBOXGUESTDEVEXT)data;

	vbg_req_perform(gdev, gdev->guest_heartbeat_req);
	mod_timer(&gdev->heartbeat_timer,
		  msecs_to_jiffies(gdev->heartbeat_interval_ms));
}

/**
 * Configure the host to check guest's heartbeat
 * and get heartbeat interval from the host.
 *
 * @returns 0 or negative errno value.
 * @param   gdev         The Guest extension device.
 * @param   fEnabled        Set true to enable guest heartbeat checks on host.
 */
static int vgdrvHeartbeatHostConfigure(PVBOXGUESTDEVEXT gdev, bool fEnabled)
{
	VMMDevReqHeartbeat *req;
	int rc;

	req = vbg_req_alloc(sizeof(*req), VMMDevReq_HeartbeatConfigure);
	if (!req)
		return -ENOMEM;

	req->fEnabled = fEnabled;
	req->cNsInterval = 0;
	rc = vbg_req_perform(gdev, req);
	gdev->heartbeat_interval_ms = req->cNsInterval / 1000000;
	kfree(req);

	return -vbg_status_code_to_errno(rc);
}

/**
 * Initializes the heartbeat timer.
 *
 * This feature may be disabled by the host.
 *
 * @returns 0 or negative errno value (ignored).
 * @param   gdev         The Guest extension device.
 */
static int vgdrvHeartbeatInit(PVBOXGUESTDEVEXT gdev)
{
	int ret;

	/* Make sure that heartbeat checking is disabled if we fail. */
	ret = vgdrvHeartbeatHostConfigure(gdev, false);
	if (ret < 0)
		return ret;

	ret = vgdrvHeartbeatHostConfigure(gdev, true);
	if (ret < 0)
		return ret;

	/*
	 * Preallocate the request to use it from the timer callback because:
	 *    1) on Windows vbg_req_alloc must be called at IRQL <= APC_LEVEL
	 *       and the timer callback runs at DISPATCH_LEVEL;
	 *    2) avoid repeated allocations.
	 */
	gdev->guest_heartbeat_req = vbg_req_alloc(
					sizeof(*gdev->guest_heartbeat_req),
					VMMDevReq_GuestHeartbeat);
	if (!gdev->guest_heartbeat_req)
		return -ENOMEM;

	vbg_info("vgdrvHeartbeatInit: Setting up heartbeat to trigger every %d milliseconds\n",
		 gdev->heartbeat_interval_ms);
	mod_timer(&gdev->heartbeat_timer, 0);

	return 0;
}

/** @} */

/**
 * vbg_query_host_version try get the host feature mask and version information
 * (vbg_host_version).
 *
 * This was first implemented by the host in 3.1 and we quietly ignore failures
 * for that reason.
 */
static void vbg_query_host_version(PVBOXGUESTDEVEXT gdev)
{
	VMMDevReqHostVersion *req;
	int rc;

	req = vbg_req_alloc(sizeof(*req), VMMDevReq_GetHostVersion);
	if (!req)
		return;

	rc = vbg_req_perform(gdev, req);
	if (rc >= 0) {
		pr_info("vboxguest: host-version: %u.%u.%ur%u %#x\n",
			req->major, req->minor, req->build,
			req->revision, req->features);
	}

	kfree(req);
}

/**
 * Initializes the VBoxGuest device extension when the
 * device driver is loaded.
 *
 * The native code locates the VMMDev on the PCI bus and retrieve
 * the MMIO and I/O port ranges, this function will take care of
 * mapping the MMIO memory (if present). Upon successful return
 * the native code should set up the interrupt handler.
 *
 * @returns 0 or negative errno value.
 *
 * @param   gdev           The Guest extension device.
 * @param   fixed_events   Events that will be enabled upon init and no client
 *                         will ever be allowed to mask.
 */
int vbg_core_init(PVBOXGUESTDEVEXT gdev, u32 fixed_events)
{
	int ret = -ENOMEM;

	gdev->fFixedEvents = fixed_events | VMMDEV_EVENT_HGCM;
	gdev->fEventFilterHost = U32_MAX;	/* forces a report */
	gdev->fGuestCapsHost = U32_MAX;	/* forces a report */

	init_waitqueue_head(&gdev->event_wq);
	init_waitqueue_head(&gdev->hgcm_wq);
	INIT_LIST_HEAD(&gdev->session_list);
	spin_lock_init(&gdev->event_spinlock);
	spin_lock_init(&gdev->session_spinlock);
	mutex_init(&gdev->cancel_req_mutex);
	mutex_init(&gdev->mem_balloon.mutex);
	setup_timer(&gdev->heartbeat_timer, vbg_heartbeat_timer,
		    (unsigned long)gdev);

	vgdrvBitUsageTrackerClear(&gdev->EventFilterTracker);
	vgdrvBitUsageTrackerClear(&gdev->SetGuestCapsTracker);

	gdev->mem_balloon.change_req =
		vbg_req_alloc(sizeof(*gdev->mem_balloon.change_req),
			      VMMDevReq_ChangeMemBalloon);
	gdev->cancel_req =
		vbg_req_alloc(sizeof(*(gdev->cancel_req)),
			      VMMDevReq_HGCMCancel2);
	gdev->pIrqAckEvents =
		vbg_req_alloc(sizeof(*gdev->pIrqAckEvents),
			      VMMDevReq_AcknowledgeEvents);
	gdev->mouse_status_req =
		vbg_req_alloc(sizeof(*gdev->mouse_status_req),
			      VMMDevReq_GetMouseStatus);

	if (!gdev->mem_balloon.change_req || !gdev->cancel_req ||
	    !gdev->pIrqAckEvents || !gdev->mouse_status_req)
	        goto err_free_reqs;

	vbg_query_host_version(gdev);

	ret = vgdrvReportGuestInfo(gdev);
	if (ret) {
		vbg_err("vboxguest: VBoxReportGuestInfo error: %d\n", ret);
	        goto err_free_reqs;
	}
	
	ret = vgdrvResetEventFilterOnHost(gdev, gdev->fFixedEvents);
	if (ret) {
		vbg_err("vboxguest: Error setting fixed event filter: %d\n", ret);
	        goto err_free_reqs;
	}

	ret = vgdrvResetCapabilitiesOnHost(gdev);
	if (ret) {
		vbg_err("vboxguest: Error clearing guest capabilities: %d\n", ret);
	        goto err_free_reqs;
	}

	ret = vbg_core_set_mouse_status(gdev, 0);
	if (ret) {
		vbg_err("vboxguest: Error clearing mouse status: %d\n", ret);
	        goto err_free_reqs;
	}

	/* These may fail without requiring the driver init to fail. */
	vgdrvInitFixateGuestMappings(gdev);
	vgdrvHeartbeatInit(gdev);

	/* All Done! */
	ret = vgdrvReportDriverStatus(gdev, true);
	if (ret < 0)
		vbg_err("vboxguest: VBoxReportGuestDriverStatus error: %d\n",
			ret);

	return 0;

err_free_reqs:
	kfree(gdev->mouse_status_req);
	kfree(gdev->pIrqAckEvents);
	kfree(gdev->cancel_req);
	kfree(gdev->mem_balloon.change_req);
	return ret;
}

/**
 * Call this on exit to clean-up vboxguest-core managed resources.
 *
 * The native code should call this before the driver is loaded,
 * but don't call this on shutdown.
 *
 * @param   gdev         The Guest extension device.
 */
void vbg_core_exit(PVBOXGUESTDEVEXT gdev)
{
	/* Stop HB timer and disable host heartbeat checking. */
	del_timer_sync(&gdev->heartbeat_timer);
	vgdrvHeartbeatHostConfigure(gdev, false);
	kfree(gdev->guest_heartbeat_req);

	/* Clean up the bits that involves the host first. */
	vgdrvTermUnfixGuestMappings(gdev);

	/* Clear the host flags (mouse status etc). */
	vgdrvResetEventFilterOnHost(gdev, 0);
	vgdrvResetCapabilitiesOnHost(gdev);
	vbg_core_set_mouse_status(gdev, 0);

	kfree(gdev->pIrqAckEvents);
	kfree(gdev->cancel_req);
	kfree(gdev->mem_balloon.change_req);
}

/**
 * Creates a VBoxGuest user session.
 *
 * vboxguest_linux.c calls this when userspace opens the char-device.
 *
 * @returns 0 or negative errno value.
 * @param   gdev          The Guest extension device.
 * @param   session_ret   Where to store the session on success.
 * @param   user_session  Set if this is a session for the vboxuser device.
 */
int vbg_core_open_session(PVBOXGUESTDEVEXT gdev,
			  VBOXGUESTSESSION **session_ret, bool user_session)
{
	VBOXGUESTSESSION *session;
	unsigned long flags;

	session = kzalloc(sizeof(*session), GFP_KERNEL);
	if (!session)
		return -ENOMEM;

	session->gdev = gdev;
	session->user_session = user_session;

	spin_lock_irqsave(&gdev->session_spinlock, flags);
	list_add(&session->list_node, &gdev->session_list);
	spin_unlock_irqrestore(&gdev->session_spinlock, flags);

	*session_ret = session;

	return 0;
}

/**
 * Closes a VBoxGuest session.
 *
 * @param   session       The session to close (and free).
 */
void vbg_core_close_session(VBOXGUESTSESSION *session)
{
	PVBOXGUESTDEVEXT gdev = session->gdev;
	unsigned long flags;
	unsigned i;

	spin_lock_irqsave(&gdev->session_spinlock, flags);
	list_del(&session->list_node);
	spin_unlock_irqrestore(&gdev->session_spinlock, flags);

	vgdrvSetSessionCapabilities(gdev, session, 0 /*fOrMask */ ,
				    U32_MAX /*fNotMask */ ,
				    true /*fSessionTermination */ );
	vgdrvSetSessionEventFilter(gdev, session, 0 /*fOrMask */ ,
				   U32_MAX /*fNotMask */ ,
				   true /*fSessionTermination */ );

	for (i = 0; i < ARRAY_SIZE(session->aHGCMClientIds); i++) {
		if (session->aHGCMClientIds[i])
			vbg_hgcm_disconnect(gdev, session->aHGCMClientIds[i]);
	}

	vbg_balloon_close(gdev, session);
	kfree(session);
}

/**
 * Used by VGDrvCommonISR as well as the acquire guest capability code.
 * The caller must held the event_spinlock.
 *
 * @param   gdev            The VBoxGuest device extension.
 * @param   events             The events to dispatch.
 */
static void vbg_dispatch_events_locked(PVBOXGUESTDEVEXT gdev, u32 events)
{
	gdev->f32PendingEvents |= events;

	wake_up(&gdev->event_wq);
}

static bool vbg_wait_event_cond(PVBOXGUESTDEVEXT gdev,
				PVBOXGUESTSESSION session,
				VBoxGuestWaitEventInfo * info)
{
	unsigned long flags;
	bool wakeup;
	u32 events;

	spin_lock_irqsave(&gdev->event_spinlock, flags);

	events = gdev->f32PendingEvents & info->u32EventMaskIn;
	wakeup = events || session->cancel_waiters;

	spin_unlock_irqrestore(&gdev->event_spinlock, flags);

	return wakeup;
}

/* Must be called with the event_lock held */
static u32 vbg_consume_events_locked(PVBOXGUESTDEVEXT gdev,
				     PVBOXGUESTSESSION session,
				     VBoxGuestWaitEventInfo * info)
{
	u32 events = gdev->f32PendingEvents & info->u32EventMaskIn;

	gdev->f32PendingEvents &= ~events;
	return events;
}

static int vbg_ioctl_wait_event(PVBOXGUESTDEVEXT gdev,
				PVBOXGUESTSESSION session,
				VBoxGuestWaitEventInfo *info,
				size_t *info_len_ret)
{
	unsigned long flags;
	long timeout;
	int rc = VINF_SUCCESS;

	if (info->u32TimeoutIn == U32_MAX)
		timeout = MAX_SCHEDULE_TIMEOUT;
	else
		timeout = msecs_to_jiffies(info->u32TimeoutIn);

	info->u32Result = VBOXGUEST_WAITEVENT_OK;
	info->u32EventFlagsOut = 0;

	if (info_len_ret)
		*info_len_ret = sizeof(*info);

	do {
		timeout = wait_event_interruptible_timeout(
				gdev->event_wq,
				vbg_wait_event_cond(gdev, session, info),
				timeout);

		spin_lock_irqsave(&gdev->event_spinlock, flags);

		if (timeout < 0 || session->cancel_waiters) {
			info->u32Result = VBOXGUEST_WAITEVENT_INTERRUPTED;
			rc = VERR_INTERRUPTED;
		} else if (timeout == 0) {
			info->u32Result = VBOXGUEST_WAITEVENT_TIMEOUT;
			rc = VERR_TIMEOUT;
		} else {
			info->u32EventFlagsOut =
			    vbg_consume_events_locked(gdev, session, info);
		}

		spin_unlock_irqrestore(&gdev->event_spinlock, flags);

		/*
		 * Someone else may have consumed the event(s) first, in
		 * which case we go back to waiting.
		 */
	} while (rc == VINF_SUCCESS && info->u32EventFlagsOut == 0);

	return rc;
}

static int vbg_ioctl_cancel_all_wait_events(PVBOXGUESTDEVEXT gdev,
					    PVBOXGUESTSESSION session)
{
	unsigned long flags;

	spin_lock_irqsave(&gdev->event_spinlock, flags);
	session->cancel_waiters = true;
	spin_unlock_irqrestore(&gdev->event_spinlock, flags);

	return VINF_SUCCESS;
}

/**
 * Checks if the VMM request is allowed in the context of the given session.
 *
 * @returns VBox status code
 * @param   gdev             The Guest extension device.
 * @param   session          The calling session.
 * @param   req              The request.
 */
static int vbg_req_allowed(PVBOXGUESTDEVEXT gdev, PVBOXGUESTSESSION session,
			   VMMDevRequestHeader const *req)
{
	const VMMDevReportGuestStatus *guest_status;
	bool trusted_apps_only;

	switch (req->requestType) {
	/* Trusted users apps only. */
	case VMMDevReq_QueryCredentials:
	case VMMDevReq_ReportCredentialsJudgement:
	case VMMDevReq_RegisterSharedModule:
	case VMMDevReq_UnregisterSharedModule:
	case VMMDevReq_WriteCoreDump:
	case VMMDevReq_GetCpuHotPlugRequest:
	case VMMDevReq_SetCpuHotPlugStatus:
	case VMMDevReq_CheckSharedModules:
	case VMMDevReq_GetPageSharingStatus:
	case VMMDevReq_DebugIsPageShared:
	case VMMDevReq_ReportGuestStats:
	case VMMDevReq_ReportGuestUserState:
	case VMMDevReq_GetStatisticsChangeRequest:
	case VMMDevReq_ChangeMemBalloon:
		trusted_apps_only = true;
		break;

	/* Anyone. */
	case VMMDevReq_GetMouseStatus:
	case VMMDevReq_SetMouseStatus:
	case VMMDevReq_SetPointerShape:
	case VMMDevReq_GetHostVersion:
	case VMMDevReq_Idle:
	case VMMDevReq_GetHostTime:
	case VMMDevReq_SetPowerStatus:
	case VMMDevReq_AcknowledgeEvents:
	case VMMDevReq_CtlGuestFilterMask:
	case VMMDevReq_ReportGuestStatus:
	case VMMDevReq_GetDisplayChangeRequest:
	case VMMDevReq_VideoModeSupported:
	case VMMDevReq_GetHeightReduction:
	case VMMDevReq_GetDisplayChangeRequest2:
	case VMMDevReq_VideoModeSupported2:
	case VMMDevReq_VideoAccelEnable:
	case VMMDevReq_VideoAccelFlush:
	case VMMDevReq_VideoSetVisibleRegion:
	case VMMDevReq_GetDisplayChangeRequestEx:
	case VMMDevReq_GetSeamlessChangeRequest:
	case VMMDevReq_GetVRDPChangeRequest:
	case VMMDevReq_LogString:
	case VMMDevReq_GetSessionId:
		trusted_apps_only = false;
		break;

	/**
	 * @todo this have to be changed into an I/O control and the facilities
	 *    tracked in the session so they can automatically be failed when
	 *    the session terminates without reporting the new status.
	 *
	 * The information presented by IGuest is not reliable without this!
	 */
	/* Depends on the request parameters... */
	case VMMDevReq_ReportGuestCapabilities:
		guest_status = (const VMMDevReportGuestStatus *)req;
		switch (guest_status->guestStatus.facility) {
		case VBoxGuestFacilityType_All:
		case VBoxGuestFacilityType_VBoxGuestDriver:
			vbg_err("Denying userspace vmm report guest cap. call facility %#08x\n",
				guest_status->guestStatus.facility);
			return VERR_PERMISSION_DENIED;
		case VBoxGuestFacilityType_VBoxService:
			trusted_apps_only = true;
			break;
		case VBoxGuestFacilityType_VBoxTrayClient:
		case VBoxGuestFacilityType_Seamless:
		case VBoxGuestFacilityType_Graphics:
		default:
			trusted_apps_only = false;
			break;
		}
		break;

	/* Anything else is not allowed. */
	default:
		vbg_err("Denying userspace vmm call type %#08x\n",
			req->requestType);
		return VERR_PERMISSION_DENIED;
	}

	if (trusted_apps_only && session->user_session) {
		vbg_err("Denying userspace vmm call type %#08x through vboxuser device node\n",
			req->requestType);
		return VERR_PERMISSION_DENIED;
	}

	return VINF_SUCCESS;
}

static int vgdrvIoCtl_VMMRequest(PVBOXGUESTDEVEXT gdev,
				 PVBOXGUESTSESSION session,
				 VMMDevRequestHeader *req, size_t req_size,
				 size_t *req_size_ret)
{
	int rc;

	rc = vbg_req_verify(req, req_size);
	if (rc < 0)
		return rc;

	rc = vbg_req_allowed(gdev, session, req);
	if (rc < 0)
		return rc;

	rc = vbg_req_perform(gdev, req);
	if (rc >= 0) {
		WARN_ON(rc == VINF_HGCM_ASYNC_EXECUTE);
		*req_size_ret = req->size;
	}

	return rc;
}

static int vgdrvIoCtl_HGCMConnect(PVBOXGUESTDEVEXT gdev,
				  PVBOXGUESTSESSION session,
				  VBoxGuestHGCMConnectInfo * pInfo,
				  size_t *info_size_ret)
{
	unsigned long flags;
	u32 client_id;
	int i, rc;

	/* Find a free place in the sessions clients array and claim it */
	spin_lock_irqsave(&gdev->session_spinlock, flags);
	for (i = 0; i < ARRAY_SIZE(session->aHGCMClientIds); i++) {
		if (!session->aHGCMClientIds[i]) {
			session->aHGCMClientIds[i] = U32_MAX;
			break;
		}
	}
	spin_unlock_irqrestore(&gdev->session_spinlock, flags);

	if (i >= ARRAY_SIZE(session->aHGCMClientIds))
		return VERR_TOO_MANY_OPEN_FILES;

	rc = vbg_hgcm_connect(gdev, &pInfo->Loc, &client_id);

	spin_lock_irqsave(&gdev->session_spinlock, flags);
	if (rc >= 0) {
		pInfo->result = VINF_SUCCESS;
		pInfo->u32ClientID = client_id;
		*info_size_ret = sizeof(*pInfo);

		session->aHGCMClientIds[i] = client_id;
	} else {
		session->aHGCMClientIds[i] = 0;
	}
	spin_unlock_irqrestore(&gdev->session_spinlock, flags);

	return rc;
}

static int vgdrvIoCtl_HGCMDisconnect(PVBOXGUESTDEVEXT gdev,
				     PVBOXGUESTSESSION session,
				     VBoxGuestHGCMDisconnectInfo * pInfo,
				     size_t *info_size_ret)
{
	u32 client_id = pInfo->u32ClientID;
	unsigned long flags;
	int i, rc;

	if (client_id == 0 || client_id == U32_MAX)
		return VERR_INVALID_HANDLE;

	spin_lock_irqsave(&gdev->session_spinlock, flags);
	for (i = 0; i < ARRAY_SIZE(session->aHGCMClientIds); i++) {
		if (session->aHGCMClientIds[i] == client_id) {
			session->aHGCMClientIds[i] = U32_MAX;
			break;
		}
	}
	spin_unlock_irqrestore(&gdev->session_spinlock, flags);

	if (i >= ARRAY_SIZE(session->aHGCMClientIds))
		return VERR_INVALID_HANDLE;

	rc = vbg_hgcm_disconnect(gdev, client_id);

	spin_lock_irqsave(&gdev->session_spinlock, flags);
	if (rc >= 0) {
		pInfo->result = VINF_SUCCESS;
		*info_size_ret = sizeof(*pInfo);

		session->aHGCMClientIds[i] = 0;
	} else {
		session->aHGCMClientIds[i] = client_id;
	}
	spin_unlock_irqrestore(&gdev->session_spinlock, flags);

	return rc;
}

static int vgdrvIoCtl_HGCMCall(PVBOXGUESTDEVEXT gdev,
			       PVBOXGUESTSESSION session,
			       VBoxGuestHGCMCallInfo *pInfo, u32 cMillies,
			       bool f32bit, size_t cbExtra, size_t cbData,
			       size_t *info_size_ret)
{
	u32 cbInfo, client_id = pInfo->u32ClientID;
	unsigned long flags;
	size_t cbActual;
	unsigned i;
	int rc;

	if (pInfo->cParms > VBOX_HGCM_MAX_PARMS)
		return VERR_INVALID_PARAMETER;
	
	if (client_id == 0 || client_id == U32_MAX)
		return VERR_INVALID_HANDLE;

	cbActual = cbExtra + sizeof(*pInfo);
	if (f32bit)
		cbActual += pInfo->cParms * sizeof(HGCMFunctionParameter32);
	else
		cbActual += pInfo->cParms * sizeof(HGCMFunctionParameter);
	if (cbData < cbActual) {
		vbg_debug("VBOXGUEST_IOCTL_HGCM_CALL: cbData=%#zx (%zu) required size is %#zx (%zu)\n",
			cbData, cbData, cbActual, cbActual);
		return VERR_INVALID_PARAMETER;
	}

	/*
	 * Validate the client id.
	 */
	spin_lock_irqsave(&gdev->session_spinlock, flags);
	for (i = 0; i < ARRAY_SIZE(session->aHGCMClientIds); i++)
		if (session->aHGCMClientIds[i] == client_id)
			break;
	spin_unlock_irqrestore(&gdev->session_spinlock, flags);
	if (i >= ARRAY_SIZE(session->aHGCMClientIds)) {
		vbg_debug("VBOXGUEST_IOCTL_HGCM_CALL: Invalid handle. u32Client=%#08x\n",
			  client_id);
		return VERR_INVALID_HANDLE;
	}

	cbInfo = (u32) (cbData - cbExtra);

	if (f32bit)
		rc = vbg_hgcm_call32(gdev, pInfo, cbInfo, cMillies, true);
	else
		rc = vbg_hgcm_call(gdev, pInfo, cbInfo, cMillies, true);

	if (rc >= 0) {
		*info_size_ret = cbActual;
	} else if (rc == VERR_INTERRUPTED || rc == VERR_TIMEOUT ||
		   rc == VERR_OUT_OF_RANGE) {
		vbg_debug("VBOXGUEST_IOCTL_HGCM_CALL%s error: %d\n",
			  f32bit ? "32" : "64", rc);
	} else {
		vbg_err("VBOXGUEST_IOCTL_HGCM_CALL%s error: %d\n",
			f32bit ? "32" : "64", rc);
	}
	return rc;
}

/**
 * Handle VBOXGUEST_IOCTL_CHECK_BALLOON from R3.
 *
 * Ask the host for the size of the balloon and try to set it accordingly.
 *
 * @returns VBox status code
 *
 * @param   gdev                The Guest extension device.
 * @param   session             The session.
 * @param   info                The output buffer.
 * @param   info_size_ret     Where to store the amount of returned data.
 */
static int vgdrvIoCtl_CheckMemoryBalloon(PVBOXGUESTDEVEXT gdev,
					 PVBOXGUESTSESSION session,
					 VBoxGuestCheckBalloonInfo *info,
					 size_t *info_size_ret)
{
	VMMDevGetMemBalloonChangeRequest *req = NULL;
	u32 i, chunks;
	int rc;

	mutex_lock(&gdev->mem_balloon.mutex);

	/*
	 * The first user trying to query/change the balloon becomes the
	 * owner and owns it until the session is closed (vgdrvCloseMemBalloon).
	 */
	if (gdev->mem_balloon.owner && gdev->mem_balloon.owner != session) {
		rc = VERR_PERMISSION_DENIED;
		goto out;
	}

	req = vbg_req_alloc(sizeof(*req), VMMDevReq_GetMemBalloonChangeRequest);
	if (!req) {
		rc = VERR_NO_MEMORY;
		goto out;
	}

	/*
	 * Setting this bit means that we request the value from the host and
	 * change the guest memory balloon according to the returned value.
	 */
	req->eventAck = VMMDEV_EVENT_BALLOON_CHANGE_REQUEST;
	rc = vbg_req_perform(gdev, req);
	if (rc < 0)
		goto out;

	/*
	 * The host always returns the same maximum amount of chunks, so
	 * we do this once.
	 */
	if (!gdev->mem_balloon.max_chunks) {
		gdev->mem_balloon.pages =
			devm_kcalloc(gdev->dev, req->cPhysMemChunks,
				     sizeof(struct page **), GFP_KERNEL);
		if (!gdev->mem_balloon.pages) {
			rc = VERR_NO_MEMORY;
			goto out;
		}
		gdev->mem_balloon.max_chunks = req->cPhysMemChunks;
	}

	chunks = req->cBalloonChunks;
	if (chunks > gdev->mem_balloon.max_chunks) {
		vbg_err("VBOXGUEST_IOCTL_CHECK_BALLOON: illegal balloon size %u (max=%u)\n",
			chunks, gdev->mem_balloon.max_chunks);
		rc = VERR_INVALID_PARAMETER;
		goto out;
	}

	if (req->cBalloonChunks > gdev->mem_balloon.chunks) {
		/* inflate */
		for (i = gdev->mem_balloon.chunks; i < chunks; i++) {
			rc = vbg_balloon_inflate(gdev, i);
			if (rc < 0) {
				/* Failure to alloc memory is not an error */
				if (rc == VERR_NO_MEMORY)
					rc = VINF_SUCCESS;
				break;
			}
			gdev->mem_balloon.chunks++;
		}
	} else {
		/* deflate */
		for (i = gdev->mem_balloon.chunks; i-- > chunks;) {
			rc = vbg_balloon_deflate(gdev, i);
			if (rc < 0)
				break;

			gdev->mem_balloon.chunks--;
		}
	}

	info->cBalloonChunks = gdev->mem_balloon.chunks;
	/* Under Linux we always handle the balloon in R0 / in the kernel */
	info->fHandleInR3 = false;
	*info_size_ret = sizeof(VBoxGuestCheckBalloonInfo);

	gdev->mem_balloon.owner = session;
out:
	kfree(req);
	mutex_unlock(&gdev->mem_balloon.mutex);
	return rc;
}

/**
 * Handle a request for writing a core dump of the guest on the host.
 *
 * @returns VBox status code
 *
 * @param gdev               The Guest extension device.
 * @param pInfo                 The output buffer.
 */
static int vgdrvIoCtl_WriteCoreDump(PVBOXGUESTDEVEXT gdev,
				    VBoxGuestWriteCoreDump * pInfo)
{
	VMMDevReqWriteCoreDump *req = NULL;
	int rc;

	req = vbg_req_alloc(sizeof(*req), VMMDevReq_WriteCoreDump);
	if (!req)
		return VERR_NO_MEMORY;

	req->fFlags = pInfo->fFlags;
	rc = vbg_req_perform(gdev, req);

	kfree(req);
	return rc;
}

/** @name Guest Capabilities, Mouse Status and Event Filter
 * @{
 */

/**
 * Clears a bit usage tracker (init time).
 *
 * @param   pTracker            The tracker to clear.
 */
static void vgdrvBitUsageTrackerClear(PVBOXGUESTBITUSAGETRACER pTracker)
{
	u32 iBit;

	for (iBit = 0; iBit < 32; iBit++)
		pTracker->acPerBitUsage[iBit] = 0;
	pTracker->fMask = 0;
}

/**
 * Applies a change to the bit usage tracker.
 *
 * @returns true if the mask changed, false if not.
 * @param   pTracker            The bit usage tracker.
 * @param   changed            The bits to change.
 * @param   previous           The previous value of the bits.
 */
static bool vgdrvBitUsageTrackerChange(PVBOXGUESTBITUSAGETRACER pTracker,
				       u32 changed, u32 previous)
{
	bool global_change = false;

	while (changed) {
		u32 const iBit = ffs(changed) - 1;
		u32 const fBitMask = BIT(iBit);

		if (fBitMask & previous) {
			pTracker->acPerBitUsage[iBit] -= 1;
			if (pTracker->acPerBitUsage[iBit] == 0) {
				global_change = true;
				pTracker->fMask &= ~fBitMask;
			}
		} else {
			pTracker->acPerBitUsage[iBit] += 1;
			if (pTracker->acPerBitUsage[iBit] == 1) {
				global_change = true;
				pTracker->fMask |= fBitMask;
			}
		}

		changed &= ~fBitMask;
	}

	return global_change;
}

/**
 * Init and termination worker for resetting the (host) event filter on the host
 *
 * @returns 0 or negative errno value.
 * @param   gdev         The Guest extension device.
 * @param   fFixedEvents    Fixed events (init time).
 */
static int vgdrvResetEventFilterOnHost(PVBOXGUESTDEVEXT gdev,
				       u32 fFixedEvents)
{
	VMMDevCtlGuestFilterMask *req;
	int rc;

	req = vbg_req_alloc(sizeof(*req), VMMDevReq_CtlGuestFilterMask);
	if (!req)
		return -ENOMEM;

	req->u32NotMask = U32_MAX & ~fFixedEvents;
	req->u32OrMask = fFixedEvents;
	rc = vbg_req_perform(gdev, req);
	if (rc < 0)
		vbg_err("vgdrvResetEventFilterOnHost error: %d\n", rc);

	kfree(req);
	return -vbg_status_code_to_errno(rc);
}

/**
 * Changes the event filter mask for the given session.
 *
 * This is called in response to VBOXGUEST_IOCTL_CTL_FILTER_MASK as well as to
 * do session cleanup.
 *
 * @returns VBox status code
 * @param   gdev             The Guest extension device.
 * @param   session            The session.
 * @param   fOrMask             The events to add.
 * @param   fNotMask            The events to remove.
 * @param   fSessionTermination Set if we're called by the session cleanup code.
 *                              This tweaks the error handling so we perform
 *                              proper session cleanup even if the host
 *                              misbehaves.
 *
 * @remarks Takes the session spinlock.
 */
static int vgdrvSetSessionEventFilter(PVBOXGUESTDEVEXT gdev,
				      PVBOXGUESTSESSION session,
				      u32 fOrMask, u32 fNotMask,
				      bool fSessionTermination)
{
	VMMDevCtlGuestFilterMask *req;
	u32 changed, previous;
	unsigned long flags;
	bool global_change;
	int rc = VINF_SUCCESS;

	/* Allocate a request buffer before taking the spinlock */
	req = vbg_req_alloc(sizeof(*req), VMMDevReq_CtlGuestFilterMask);
	if (!req) {
		if (!fSessionTermination)
			return VERR_NO_MEMORY;
		/* Ignore failure, we must do session cleanup. */
	}

	spin_lock_irqsave(&gdev->session_spinlock, flags);

	/* Apply the changes to the session mask. */
	previous = session->fEventFilter;
	session->fEventFilter |= fOrMask;
	session->fEventFilter &= ~fNotMask;

	/* If anything actually changed, update the global usage counters. */
	changed = previous ^ session->fEventFilter;
	if (!changed)
		goto out;

	global_change = vgdrvBitUsageTrackerChange(&gdev->EventFilterTracker,
						   changed, previous);

	if (!(global_change || gdev->fEventFilterHost == U32_MAX) || !req)
		goto out;

	req->u32OrMask = gdev->fFixedEvents | gdev->EventFilterTracker.fMask;
	if (req->u32OrMask == gdev->fEventFilterHost)
		goto out;

	gdev->fEventFilterHost = req->u32OrMask;
	req->u32NotMask = ~req->u32OrMask;
	rc = vbg_req_perform(gdev, req);
	if (rc < 0) {
		/* Failed, roll back (unless it's session termination time). */
		gdev->fEventFilterHost = U32_MAX;
		if (fSessionTermination)
			goto out;

		vgdrvBitUsageTrackerChange(&gdev->EventFilterTracker, changed,
					   session->fEventFilter);
		session->fEventFilter = previous;
	}

out:
	spin_unlock_irqrestore(&gdev->session_spinlock, flags);
	kfree(req);

	return rc;
}

/**
 * Handle VBOXGUEST_IOCTL_CTL_FILTER_MASK.
 *
 * @returns VBox status code
 * @param   gdev             The Guest extension device.
 * @param   session            The session.
 * @param   pInfo               The request.
 */
static int vgdrvIoCtl_CtlFilterMask(PVBOXGUESTDEVEXT gdev,
				    PVBOXGUESTSESSION session,
				    VBoxGuestFilterMaskInfo * pInfo)
{
	if ((pInfo->u32OrMask | pInfo->u32NotMask) &
						~VMMDEV_EVENT_VALID_EVENT_MASK)
		return VERR_INVALID_PARAMETER;

	return vgdrvSetSessionEventFilter(gdev, session, pInfo->u32OrMask,
					  pInfo->u32NotMask,
					  false /*fSessionTermination */ );
}

/**
 * Report guest supported mouse-features to the host.
 *
 * @returns 0 or negative errno value.
 * @returns VBox status code
 * @param   gdev               The Guest extension device.
 * @param   features           The set of features to report to the host.
 */
int vbg_core_set_mouse_status(PVBOXGUESTDEVEXT gdev, u32 features)
{
	VMMDevReqMouseStatus *req;
	int rc;

	req = vbg_req_alloc(sizeof(*req), VMMDevReq_SetMouseStatus);
	if (!req)
		return -ENOMEM;

	req->mouseFeatures = features;
	req->pointerXPos = 0;
	req->pointerYPos = 0;

	rc = vbg_req_perform(gdev, req);
	if (rc < 0)
		vbg_err("vbg_core_set_mouse_status error: %d\n", rc);

	kfree(req);
	return -vbg_status_code_to_errno(rc);
}

/**
 * Init and termination worker for set guest capabilities to zero on the host.
 *
 * @returns 0 or negative errno value.
 * @param   gdev         The Guest extension device.
 */
static int vgdrvResetCapabilitiesOnHost(PVBOXGUESTDEVEXT gdev)
{
	VMMDevReqGuestCapabilities2 *req;
	int rc;

	req = vbg_req_alloc(sizeof(*req), VMMDevReq_SetGuestCapabilities);
	if (!req)
		return -ENOMEM;

	req->u32NotMask = U32_MAX;
	req->u32OrMask = 0;
	rc = vbg_req_perform(gdev, req);
	if (rc < 0)
		vbg_err("vgdrvResetCapabilitiesOnHost error: %d\n", rc);

	kfree(req);
	return -vbg_status_code_to_errno(rc);
}

/**
 * Sets the guest capabilities to the host while holding the lock.
 *
 * This will ASSUME that we're the ones in charge of the mask, so
 * we'll simply clear all bits we don't set.
 *
 * @returns VBox status code
 * @param   gdev          The Guest extension device.
 * @param   req           The request.
 */
static int vgdrvUpdateCapabilitiesOnHostWithReqAndLock(PVBOXGUESTDEVEXT gdev,
	VMMDevReqGuestCapabilities2 *req)
{
	int rc;

	req->u32OrMask = gdev->SetGuestCapsTracker.fMask;

	if (req->u32OrMask == gdev->fGuestCapsHost)
		return VINF_SUCCESS;

	gdev->fGuestCapsHost = req->u32OrMask;
	req->u32NotMask = ~req->u32OrMask;
	rc = vbg_req_perform(gdev, req);
	if (rc < 0)
		gdev->fGuestCapsHost = U32_MAX;

	return rc;
}

/**
 * Sets the guest capabilities for a session.
 *
 * @returns VBox status code
 * @param   gdev             The Guest extension device.
 * @param   session            The session.
 * @param   fOrMask             The capabilities to add.
 * @param   fNotMask            The capabilities to remove.
 * @param   fSessionTermination Set if we're called by the session cleanup code.
 *                              This tweaks the error handling so we perform
 *                              proper session cleanup even if the host
 *                              misbehaves.
 *
 * @remarks Takes the session spinlock.
 */
static int vgdrvSetSessionCapabilities(PVBOXGUESTDEVEXT gdev,
				       PVBOXGUESTSESSION session,
				       u32 fOrMask, u32 fNotMask,
				       bool fSessionTermination)
{
	VMMDevReqGuestCapabilities2 *req;
	unsigned long flags;
	int rc = VINF_SUCCESS;
	u32 changed, previous;

	/* Allocate a request buffer before taking the spinlock */
	req = vbg_req_alloc(sizeof(*req), VMMDevReq_SetGuestCapabilities);
	if (!req) {
		if (!fSessionTermination)
			return VERR_NO_MEMORY;
		/* Ignore failure, we must do session cleanup. */
	}

	spin_lock_irqsave(&gdev->session_spinlock, flags);

	/*
	 * Apply the changes to the session mask.
	 */
	previous = session->fCapabilities;
	session->fCapabilities |= fOrMask;
	session->fCapabilities &= ~fNotMask;

	/*
	 * If anything actually changed, update the global usage counters.
	 */
	changed = previous ^ session->fCapabilities;
	if (changed) {
		bool global_change =
		    vgdrvBitUsageTrackerChange(&gdev->
					       SetGuestCapsTracker,
					       changed, previous);

		/*
		 * If there are global changes, update the capabilities on the host.
		 */
		if (global_change
		    || gdev->fGuestCapsHost == U32_MAX) {
			if (req) {
				rc = vgdrvUpdateCapabilitiesOnHostWithReqAndLock(gdev, req);

				/* On failure, roll back (unless it's session termination time). */
				if (rc < 0 && !fSessionTermination) {
					vgdrvBitUsageTrackerChange
					    (&gdev->
					     SetGuestCapsTracker,
					     changed,
					     session->fCapabilities);
					session->fCapabilities =
					    previous;
				}
			}
		}
	}

	spin_unlock_irqrestore(&gdev->session_spinlock, flags);
	kfree(req);

	return rc;
}

/**
 * Handle VBOXGUEST_IOCTL_SET_GUEST_CAPABILITIES.
 *
 * @returns VBox status code
 * @param   gdev             The Guest extension device.
 * @param   session            The session.
 * @param   pInfo               The request.
 */
static int vgdrvIoCtl_SetCapabilities(PVBOXGUESTDEVEXT gdev,
				      PVBOXGUESTSESSION session,
				      VBoxGuestSetCapabilitiesInfo * pInfo)
{
	if ((pInfo->u32OrMask | pInfo->u32NotMask) &
					~VMMDEV_GUEST_CAPABILITIES_MASK)
		return VERR_INVALID_PARAMETER;

	return vgdrvSetSessionCapabilities(gdev, session,
					   pInfo->u32OrMask, pInfo->u32NotMask,
					   false);
}

/** @} */

/**
 * Common IOCtl for user to kernel communication.
 *
 * This function only does the basic validation and then invokes
 * worker functions that takes care of each specific function.
 *
 * @returns VBox status code
 * @param   iFunction           The requested function.
 * @param   gdev             The Guest extension device.
 * @param   session            The client session.
 * @param   pvData              The input/output data buffer. Can be NULL depending on the function.
 * @param   cbData              The max size of the data buffer.
 * @param   data_size_ret     Where to store the amount of returned data.
 */
int VGDrvCommonIoCtl(unsigned iFunction, PVBOXGUESTDEVEXT gdev,
		     PVBOXGUESTSESSION session, void *pvData, size_t cbData,
		     size_t *data_size_ret)
{
	int rc;

	*data_size_ret = 0;

	/*
	 * Deal with variably sized requests first.
	 */
	if (VBOXGUEST_IOCTL_STRIP_SIZE(iFunction) ==
	    VBOXGUEST_IOCTL_STRIP_SIZE(VBOXGUEST_IOCTL_VMMREQUEST(0))) {
		rc = vgdrvIoCtl_VMMRequest(gdev, session,
					   (VMMDevRequestHeader *) pvData,
					   cbData, data_size_ret);
	}
	/*
	 * These ones are a bit tricky.
	 */
	else if (VBOXGUEST_IOCTL_STRIP_SIZE(iFunction) ==
		 VBOXGUEST_IOCTL_STRIP_SIZE(VBOXGUEST_IOCTL_HGCM_CALL(0))) {
		if (cbData < sizeof(VBoxGuestHGCMCallInfo))
			return VERR_BUFFER_OVERFLOW;
		rc = vgdrvIoCtl_HGCMCall(gdev, session,
					 (VBoxGuestHGCMCallInfo *)pvData,
					 U32_MAX, false, 0,
					 cbData, data_size_ret);
	} else if (VBOXGUEST_IOCTL_STRIP_SIZE(iFunction) ==
		   VBOXGUEST_IOCTL_STRIP_SIZE(VBOXGUEST_IOCTL_HGCM_CALL_TIMED
					      (0))) {
		VBoxGuestHGCMCallInfoTimed *pInfo =
		    (VBoxGuestHGCMCallInfoTimed *) pvData;
		if (cbData < sizeof(VBoxGuestHGCMCallInfoTimed))
			return VERR_BUFFER_OVERFLOW;
		rc = vgdrvIoCtl_HGCMCall(gdev, session, &pInfo->info,
					 pInfo->u32Timeout, false,
					 offsetof(VBoxGuestHGCMCallInfoTimed,
						     info),
					 cbData, data_size_ret);
	}
#ifdef CONFIG_X86_64
	else if (VBOXGUEST_IOCTL_STRIP_SIZE(iFunction) ==
		 VBOXGUEST_IOCTL_STRIP_SIZE(VBOXGUEST_IOCTL_HGCM_CALL_32(0))) {
		if (cbData < sizeof(VBoxGuestHGCMCallInfo))
			return VERR_BUFFER_OVERFLOW;
		rc = vgdrvIoCtl_HGCMCall(gdev, session,
					 (VBoxGuestHGCMCallInfo *)pvData,
					 U32_MAX, true, 0,
					 cbData, data_size_ret);
	} else if (VBOXGUEST_IOCTL_STRIP_SIZE(iFunction) ==
		   VBOXGUEST_IOCTL_STRIP_SIZE(VBOXGUEST_IOCTL_HGCM_CALL_TIMED_32
					      (0))) {
		VBoxGuestHGCMCallInfoTimed *pInfo = pvData;

		if (cbData < sizeof(VBoxGuestHGCMCallInfoTimed))
			return VERR_BUFFER_OVERFLOW;
		rc = vgdrvIoCtl_HGCMCall(gdev, session, &pInfo->info,
					 pInfo->u32Timeout, true,
					 offsetof(VBoxGuestHGCMCallInfoTimed,
						     info),
					 cbData, data_size_ret);
	}
#endif
	else if (VBOXGUEST_IOCTL_STRIP_SIZE(iFunction) ==
		 VBOXGUEST_IOCTL_STRIP_SIZE(VBOXGUEST_IOCTL_LOG(0))) {
		vbg_info("%.*s", (int)cbData, (char *)pvData);
	} else {
		switch (iFunction) {
		case VBOXGUEST_IOCTL_WAITEVENT:
			if (cbData < sizeof(VBoxGuestWaitEventInfo))
				return VERR_BUFFER_OVERFLOW;
			rc = vbg_ioctl_wait_event(gdev, session,
						  (VBoxGuestWaitEventInfo *)
						  pvData, data_size_ret);
			break;

		case VBOXGUEST_IOCTL_CANCEL_ALL_WAITEVENTS:
			if (cbData != 0)
				return VERR_BUFFER_OVERFLOW;
			rc = vbg_ioctl_cancel_all_wait_events(gdev,
							      session);
			break;

		case VBOXGUEST_IOCTL_CTL_FILTER_MASK:
			if (cbData < sizeof(VBoxGuestFilterMaskInfo))
				return VERR_BUFFER_OVERFLOW;
			rc = vgdrvIoCtl_CtlFilterMask(gdev, session,
						      (VBoxGuestFilterMaskInfo
						       *) pvData);
			break;

		case VBOXGUEST_IOCTL_HGCM_CONNECT:
#ifdef CONFIG_X86_64 /* Needed because these are identical on 32 bit builds */
		case VBOXGUEST_IOCTL_HGCM_CONNECT_32:
#endif
			if (cbData < sizeof(VBoxGuestHGCMConnectInfo))
				return VERR_BUFFER_OVERFLOW;
			rc = vgdrvIoCtl_HGCMConnect(gdev, session,
						    (VBoxGuestHGCMConnectInfo *)
						    pvData, data_size_ret);
			break;

		case VBOXGUEST_IOCTL_HGCM_DISCONNECT:
#ifdef CONFIG_X86_64
		case VBOXGUEST_IOCTL_HGCM_DISCONNECT_32:
#endif
			if (cbData < sizeof(VBoxGuestHGCMDisconnectInfo))
				return VERR_BUFFER_OVERFLOW;
			rc = vgdrvIoCtl_HGCMDisconnect(gdev, session,
						       (VBoxGuestHGCMDisconnectInfo
							*) pvData,
						       data_size_ret);
			break;

		case VBOXGUEST_IOCTL_CHECK_BALLOON:
			if (cbData < sizeof(VBoxGuestCheckBalloonInfo))
				return VERR_BUFFER_OVERFLOW;
			rc = vgdrvIoCtl_CheckMemoryBalloon(gdev, session,
							   (VBoxGuestCheckBalloonInfo
							    *) pvData,
							   data_size_ret);
			break;

		case VBOXGUEST_IOCTL_CHANGE_BALLOON:
			/* Under Linux we always handle the balloon in R0. */
			rc = VERR_PERMISSION_DENIED;
			break;

		case VBOXGUEST_IOCTL_WRITE_CORE_DUMP:
			if (cbData < sizeof(VBoxGuestWriteCoreDump))
				return VERR_BUFFER_OVERFLOW;
			rc = vgdrvIoCtl_WriteCoreDump(gdev,
						      (VBoxGuestWriteCoreDump *)
						      pvData);
			break;

		case VBOXGUEST_IOCTL_SET_MOUSE_STATUS:
			vbg_err("VGDrvCommonIoCtl: VBOXGUEST_IOCTL_SET_MOUSE_STATUS should not be used under Linux\n");
			rc = VERR_NOT_SUPPORTED;
			break;

		case VBOXGUEST_IOCTL_GUEST_CAPS_ACQUIRE:
			vbg_err("VGDrvCommonIoCtl: VBOXGUEST_IOCTL_GUEST_CAPS_ACQUIRE should not be used under Linux\n");
			rc = VERR_NOT_SUPPORTED;
			break;

		case VBOXGUEST_IOCTL_SET_GUEST_CAPABILITIES:
			if (cbData < sizeof(VBoxGuestSetCapabilitiesInfo))
				return VERR_BUFFER_OVERFLOW;
			rc = vgdrvIoCtl_SetCapabilities(gdev, session,
							(VBoxGuestSetCapabilitiesInfo
							 *) pvData);
			break;

		default:
			vbg_debug("VGDrvCommonIoCtl: Unknown request %#08x\n",
				  VBOXGUEST_IOCTL_STRIP_SIZE(iFunction));
			rc = VERR_NOT_SUPPORTED;
		}
	}

	return rc;
}

/** Core interrupt service routine. */
irqreturn_t vbg_core_isr(int irq, void *dev_id)
{
	PVBOXGUESTDEVEXT gdev = dev_id;
	VMMDevEvents *req = gdev->pIrqAckEvents;
	bool fMousePositionChanged = false;
	bool fOurIrq;
	unsigned long flags;
	int rc;

	/*
	 * Enter the spinlock and check if it's our IRQ or not.
	 */
	spin_lock_irqsave(&gdev->event_spinlock, flags);
	fOurIrq = gdev->pVMMDevMemory->V.V1_04.fHaveEvents;
	if (fOurIrq) {
		/* Acknowlegde events. */
		req->header.rc = VERR_INTERNAL_ERROR;
		req->events = 0;
		rc = vbg_req_perform(gdev, req);
		if (rc >= 0) {
			u32 fEvents = req->events;

			/*
			 * VMMDEV_EVENT_MOUSE_POSITION_CHANGED can only be polled for.
			 */
			if (fEvents & VMMDEV_EVENT_MOUSE_POSITION_CHANGED) {
				fMousePositionChanged = true;
				fEvents &= ~VMMDEV_EVENT_MOUSE_POSITION_CHANGED;
			}

			/*
			 * The HGCM event/list is kind of different in that we evaluate all entries.
			 */
			if (fEvents & VMMDEV_EVENT_HGCM) {
				wake_up(&gdev->hgcm_wq);
				fEvents &= ~VMMDEV_EVENT_HGCM;
			}

			/*
			 * Normal FIFO waiter evaluation.
			 */
			vbg_dispatch_events_locked(gdev, fEvents);
		}
	}

	spin_unlock_irqrestore(&gdev->event_spinlock, flags);

	if (fMousePositionChanged)
		VGDrvNativeISRMousePollEvent(gdev);

	return fOurIrq ? IRQ_HANDLED : IRQ_NONE;
}
