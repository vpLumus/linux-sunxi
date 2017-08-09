/*
 * Virtual Device for Guest <-> VMM/Host communication, type definitions
 * which are also used for the vboxguest ioctl interface / by vboxsf
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

#ifndef __UAPI_VBOX_VMMDEV_TYPES_H__
#define __UAPI_VBOX_VMMDEV_TYPES_H__

#include <asm/bitsperlong.h>
#include <linux/types.h>

/*
 * We cannot use linux' compiletime_assert here because it expects to be used
 * inside a function only. Use a typedef to a char array with a negative size.
 */
#define VMMDEV_ASSERT_SIZE(type, size) \
	typedef char type ## _asrt_size[1 - 2*!!(sizeof(struct type) != (size))]

/** enum vmmdev_request_type - VMMDev request types. */
enum vmmdev_request_type {
	VMMDevReq_InvalidRequest             =  0,
	VMMDevReq_GetMouseStatus             =  1,
	VMMDevReq_SetMouseStatus             =  2,
	VMMDevReq_SetPointerShape            =  3,
	VMMDevReq_GetHostVersion             =  4,
	VMMDevReq_Idle                       =  5,
	VMMDevReq_GetHostTime                = 10,
	VMMDevReq_GetHypervisorInfo          = 20,
	VMMDevReq_SetHypervisorInfo          = 21,
	VMMDevReq_RegisterPatchMemory        = 22, /* since version 3.0.6 */
	VMMDevReq_DeregisterPatchMemory      = 23, /* since version 3.0.6 */
	VMMDevReq_SetPowerStatus             = 30,
	VMMDevReq_AcknowledgeEvents          = 41,
	VMMDevReq_CtlGuestFilterMask         = 42,
	VMMDevReq_ReportGuestInfo            = 50,
	VMMDevReq_ReportGuestInfo2           = 58, /* since version 3.2.0 */
	VMMDevReq_ReportGuestStatus          = 59, /* since version 3.2.8 */
	VMMDevReq_ReportGuestUserState       = 74, /* since version 4.3 */
	/* Retrieve a display resize request sent by the host, deprecated. */
	VMMDevReq_GetDisplayChangeRequest    = 51,
	VMMDevReq_VideoModeSupported         = 52,
	VMMDevReq_GetHeightReduction         = 53,
	/**
	 * @VMMDevReq_GetDisplayChangeRequest2:
	 * Retrieve a display resize request sent by the host.
	 *
	 * Queries a display resize request sent from the host.  If the
	 * event_ack member is sent to true and there is an unqueried request
	 * available for one of the virtual display then that request will
	 * be returned.  If several displays have unqueried requests the lowest
	 * numbered display will be chosen first.  Only the most recent unseen
	 * request for each display is remembered.
	 * If event_ack is set to false, the last host request queried with
	 * event_ack set is resent, or failing that the most recent received
	 * from the host.  If no host request was ever received then all zeros
	 * are returned.
	 */
	VMMDevReq_GetDisplayChangeRequest2   = 54,
	VMMDevReq_ReportGuestCapabilities    = 55,
	VMMDevReq_SetGuestCapabilities       = 56,
	VMMDevReq_VideoModeSupported2        = 57, /* since version 3.2.0 */
	VMMDevReq_GetDisplayChangeRequestEx  = 80, /* since version 4.2.4 */
	VMMDevReq_HGCMConnect                = 60,
	VMMDevReq_HGCMDisconnect             = 61,
	VMMDevReq_HGCMCall32                 = 62,
	VMMDevReq_HGCMCall64                 = 63,
	VMMDevReq_HGCMCancel                 = 64,
	VMMDevReq_HGCMCancel2                = 65,
	VMMDevReq_VideoAccelEnable           = 70,
	VMMDevReq_VideoAccelFlush            = 71,
	VMMDevReq_VideoSetVisibleRegion      = 72,
	VMMDevReq_GetSeamlessChangeRequest   = 73,
	VMMDevReq_QueryCredentials           = 100,
	VMMDevReq_ReportCredentialsJudgement = 101,
	VMMDevReq_ReportGuestStats           = 110,
	VMMDevReq_GetMemBalloonChangeRequest = 111,
	VMMDevReq_GetStatisticsChangeRequest = 112,
	VMMDevReq_ChangeMemBalloon           = 113,
	VMMDevReq_GetVRDPChangeRequest       = 150,
	VMMDevReq_LogString                  = 200,
	VMMDevReq_GetCpuHotPlugRequest       = 210,
	VMMDevReq_SetCpuHotPlugStatus        = 211,
	VMMDevReq_RegisterSharedModule       = 212,
	VMMDevReq_UnregisterSharedModule     = 213,
	VMMDevReq_CheckSharedModules         = 214,
	VMMDevReq_GetPageSharingStatus       = 215,
	VMMDevReq_DebugIsPageShared          = 216,
	VMMDevReq_GetSessionId               = 217, /* since version 3.2.8 */
	VMMDevReq_WriteCoreDump              = 218,
	VMMDevReq_GuestHeartbeat             = 219,
	VMMDevReq_HeartbeatConfigure         = 220,
	/* Ensure the enum is a 32 bit data-type */
	VMMDevReq_SizeHack                   = 0x7fffffff
};

#if __BITS_PER_LONG == 64
#define VMMDevReq_HGCMCall VMMDevReq_HGCMCall64
#else
#define VMMDevReq_HGCMCall VMMDevReq_HGCMCall32
#endif

/** HGCM service location types. */
enum vmmdev_hgcm_service_location_type {
	VMMDevHGCMLoc_Invalid    = 0,
	VMMDevHGCMLoc_LocalHost  = 1,
	VMMDevHGCMLoc_LocalHost_Existing = 2,
	/* Ensure the enum is a 32 bit data-type */
	VMMDevHGCMLoc_SizeHack   = 0x7fffffff
};

/** HGCM host service location. */
struct vmmdev_hgcm_service_location_localhost {
	/** Service name */
	char service_name[128];
};
VMMDEV_ASSERT_SIZE(vmmdev_hgcm_service_location_localhost, 128);

/** HGCM service location. */
struct vmmdev_hgcm_service_location {
	/** Type of the location. */
	enum vmmdev_hgcm_service_location_type type;

	union {
		struct vmmdev_hgcm_service_location_localhost localhost;
	} u;
};
VMMDEV_ASSERT_SIZE(vmmdev_hgcm_service_location, 128 + 4);

/** HGCM function parameter type. */
enum vmmdev_hgcm_function_parameter_type {
	VMMDevHGCMParmType_Invalid            = 0,
	VMMDevHGCMParmType_32bit              = 1,
	VMMDevHGCMParmType_64bit              = 2,
	/** Deprecated Doesn't work, use PAGELIST. */
	VMMDevHGCMParmType_PhysAddr           = 3,
	/** In and Out, user-memory */
	VMMDevHGCMParmType_LinAddr            = 4,
	/** In, user-memory  (read;  host<-guest) */
	VMMDevHGCMParmType_LinAddr_In         = 5,
	/** Out, user-memory (write; host->guest) */
	VMMDevHGCMParmType_LinAddr_Out        = 6,
	/** In and Out, kernel-memory */
	VMMDevHGCMParmType_LinAddr_Kernel     = 7,
	/** In, kernel-memory  (read;  host<-guest) */
	VMMDevHGCMParmType_LinAddr_Kernel_In  = 8,
	/** Out, kernel-memory (write; host->guest) */
	VMMDevHGCMParmType_LinAddr_Kernel_Out = 9,
	/** Physical addresses of locked pages for a buffer. */
	VMMDevHGCMParmType_PageList           = 10,
	/* Ensure the enum is a 32 bit data-type */
	VMMDevHGCMParmType_SizeHack           = 0x7fffffff
};

/** HGCM function parameter, 32-bit client. */
struct vmmdev_hgcm_function_parameter32 {
	enum vmmdev_hgcm_function_parameter_type type;
	union {
		__u32 value32;
		__u64 value64;
		struct {
			__u32 size;
			union {
				__u32 phys_addr;
				__u32 linear_addr;
			} u;
		} pointer;
		struct {
			/** Size of the buffer described by the page list. */
			__u32 size;
			/** Relative to the request header. */
			__u32 offset;
		} page_list;
	} u;
} __packed;
VMMDEV_ASSERT_SIZE(vmmdev_hgcm_function_parameter32, 4 + 8);

/** HGCM function parameter, 64-bit client. */
struct vmmdev_hgcm_function_parameter64 {
	enum vmmdev_hgcm_function_parameter_type type;
	union {
		__u32 value32;
		__u64 value64;
		struct {
			__u32 size;
			union {
				__u64 phys_addr;
				__u64 linear_addr;
			} u;
		} __packed pointer;
		struct {
			/** Size of the buffer described by the page list. */
			__u32 size;
			/** Relative to the request header. */
			__u32 offset;
		} page_list;
	} __packed u;
} __packed;
VMMDEV_ASSERT_SIZE(vmmdev_hgcm_function_parameter64, 4 + 12);

#if __BITS_PER_LONG == 64
#define vmmdev_hgcm_function_parameter vmmdev_hgcm_function_parameter64
#else
#define vmmdev_hgcm_function_parameter vmmdev_hgcm_function_parameter32
#endif

#define VMMDEV_HGCM_F_PARM_DIRECTION_NONE      0x00000000U
#define VMMDEV_HGCM_F_PARM_DIRECTION_TO_HOST   0x00000001U
#define VMMDEV_HGCM_F_PARM_DIRECTION_FROM_HOST 0x00000002U
#define VMMDEV_HGCM_F_PARM_DIRECTION_BOTH      0x00000003U

/**
 * struct vmmdev_hgcm_pagelist - parameters of type VMMDevHGCMParmType_PageList
 * point to this structure to actually describe the buffer.
 */
struct vmmdev_hgcm_pagelist {
	__u32 flags;             /** VMMDEV_HGCM_F_PARM_*. */
	__u16 offset_first_page; /** Data offset in the first page. */
	__u16 page_count;        /** Number of pages. */
	__u64 pages[1];          /** Page addresses. */
};
VMMDEV_ASSERT_SIZE(vmmdev_hgcm_pagelist, 4 + 2 + 2 + 8);

#endif
