/*
 * Copyright (C) 2010-2016 Oracle Corporation
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

#ifndef __VBOXGUEST_CORE_H__
#define __VBOXGUEST_CORE_H__

#include <linux/input.h>
#include <linux/interrupt.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/miscdevice.h>
#include <linux/spinlock.h>
#include <linux/wait.h>
#include <linux/vbox_vmmdev.h>
#include <linux/vboxguest.h>

/** Pointer to the VBoxGuest per session data. */
typedef struct VBOXGUESTSESSION *PVBOXGUESTSESSION;

/** VBox guest memory balloon. */
typedef struct VBOXGUESTMEMBALLOON {
	/** Mutex protecting the members below from concurrent access. */
	struct mutex mutex;
	/** Pre-allocated VMMDevChangeMemBalloon req for inflate / deflate */
	VMMDevChangeMemBalloon *change_req;
	/** The current number of chunks in the balloon. */
	u32 chunks;
	/** The maximum number of chunks in the balloon. */
	u32 max_chunks;
	/** The current owner of the balloon. */
	PVBOXGUESTSESSION owner;
	/**
	 * Array of pointers to page arrays. A page * array is allocated for
	 * each chunk when inflating, and freed when the deflating.
	 */
	struct page ***pages;
} VBOXGUESTMEMBALLOON;

/**
 * Per bit usage tracker for a u32 mask.
 *
 * Used for optimal handling of guest properties and event filter.
 */
typedef struct VBOXGUESTBITUSAGETRACER {
	/** Per bit usage counters. */
	u32 acPerBitUsage[32];
	/** The current mask according to acPerBitUsage. */
	u32 fMask;
} VBOXGUESTBITUSAGETRACER;
/** Pointer to a per bit usage tracker.  */
typedef VBOXGUESTBITUSAGETRACER *PVBOXGUESTBITUSAGETRACER;
/** Pointer to a const per bit usage tracker.  */
typedef VBOXGUESTBITUSAGETRACER const *PCVBOXGUESTBITUSAGETRACER;

/**
 * VBox guest device (data) extension.
 */
typedef struct VBOXGUESTDEVEXT {
	struct device *dev;
	/** The base of the adapter I/O ports. */
	u16 IOPortBase;
	/** Pointer to the mapping of the VMMDev adapter memory. */
	VMMDevMemory volatile *pVMMDevMemory;
	/**
	 * Dummy page and vmap address for reserved kernel virtual-address
	 * space for the guest mappings, only used on hosts lacking vtx.
	 */
	struct page *guest_mappings_dummy_page;
	void *guest_mappings;
	/** Spinlock protecting the signaling and resetting of the wait-for-event
	 * semaphores as well as the event acking in the ISR. */
	spinlock_t event_spinlock;
	/** Preallocated VMMDevEvents for the IRQ handler. */
	VMMDevEvents *pIrqAckEvents;
	/** Wait-for-event list for threads waiting for multiple events. */
	wait_queue_head_t event_wq;
	/** Mask of pending events. */
	u32 f32PendingEvents;
	/** Wait-for-event list for threads waiting on HGCM async completion. */
	wait_queue_head_t hgcm_wq;
	/** Pre-allocated hgcm cancel2 req. for cancellation on timeout */
	VMMDevHGCMCancel2 *cancel_req;
	/** Mutex protecting cancel_req accesses */
	struct mutex cancel_req_mutex;
	/** Pre-allocated mouse-status request for the input-device handling. */
	VMMDevReqMouseStatus *mouse_status_req;
	/** Input device for reporting abs mouse coordinates to the guest. */
	struct input_dev *input;

	/** Spinlock various items in the VBOXGUESTSESSION. */
	spinlock_t session_spinlock;
	/** List of guest sessions (VBOXGUESTSESSION).  We currently traverse this
	 * but do not search it, so a list data type should be fine.  Use under the
	 * #SessionSpinlock lock. */
	struct list_head session_list;
	/** Memory balloon information. */
	VBOXGUESTMEMBALLOON mem_balloon;

	/** @name Host Event Filtering
	 * @{ */
	/** Events we won't permit anyone to filter out. */
	u32 fFixedEvents;
	/** Usage counters for the host events. (Fixed events are not included.) */
	VBOXGUESTBITUSAGETRACER EventFilterTracker;
	/** The event filter last reported to the host (UINT32_MAX on failure). */
	u32 fEventFilterHost;
	/** @} */

	/** @name Guest Capabilities
	 * @{ */
	/** Usage counters for guest capabilities in "set" mode. Indexed by
	 *  capability bit number, one count per session using a capability. */
	VBOXGUESTBITUSAGETRACER SetGuestCapsTracker;
	/** The guest capabilities last reported to the host (UINT32_MAX on failure). */
	u32 fGuestCapsHost;
	/** @} */

	/** Heartbeat timer which fires with interval
	 * cNsHearbeatInterval and its handler sends
	 * VMMDevReq_GuestHeartbeat to VMMDev. */
	struct timer_list heartbeat_timer;
	/** Heartbeat timer interval in ms. */
	int heartbeat_interval_ms;
	/** Preallocated VMMDevReq_GuestHeartbeat request. */
	VMMDevRequestHeader *guest_heartbeat_req;

	/** "vboxguest" char-device */
	struct miscdevice misc_device;
	/** "vboxuser" char-device */
	struct miscdevice misc_device_user;
} VBOXGUESTDEVEXT;
/** Pointer to the VBoxGuest driver data. */
typedef VBOXGUESTDEVEXT *PVBOXGUESTDEVEXT;

/**
 * The VBoxGuest per session data.
 */
typedef struct VBOXGUESTSESSION {
	/** The list node. */
	struct list_head list_node;
	/** Pointer to the device extension. */
	PVBOXGUESTDEVEXT gdev;

	/** Array containing HGCM client IDs associated with this session.
	 * This will be automatically disconnected when the session is closed. */
	u32 volatile aHGCMClientIds[64];
	/** Host events requested by the session.
	 * An event type requested in any guest session will be added to the host
	 * filter.  Protected by VBOXGUESTDEVEXT::SessionSpinlock. */
	u32 fEventFilter;
	/** Guest capabilities in "set" mode for this session.
	 * These accumulated for sessions via VBOXGUESTDEVEXT::acGuestCapsSet and
	 * reported to the host.  Protected by VBOXGUESTDEVEXT::SessionSpinlock.  */
	u32 fCapabilities;
	/** Does this session belong to a root process or a user one? */
	bool user_session;

	/** Set on CANCEL_ALL_WAITEVENTS, protected by the event_spinlock. */
	bool cancel_waiters;
} VBOXGUESTSESSION;

int vbg_core_init(PVBOXGUESTDEVEXT gdev, u32 fixed_events);
void vbg_core_exit(PVBOXGUESTDEVEXT gdev);
int vbg_core_open_session(PVBOXGUESTDEVEXT gdev,
			  VBOXGUESTSESSION **session_ret, bool user_session);
void vbg_core_close_session(VBOXGUESTSESSION *session);
irqreturn_t vbg_core_isr(int irq, void *dev_id);

int VGDrvCommonIoCtl(unsigned iFunction, PVBOXGUESTDEVEXT gdev,
		     PVBOXGUESTSESSION session, void *data, size_t data_size,
		     size_t *data_size_ret);

int vbg_core_set_mouse_status(PVBOXGUESTDEVEXT gdev, u32 features);
void VGDrvNativeISRMousePollEvent(PVBOXGUESTDEVEXT gdev);

#endif
