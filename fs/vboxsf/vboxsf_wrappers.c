/*
 * Copyright (C) 2006-2016 Oracle Corporation
 *
 * Wrapper functions for the shfl host calls.
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

#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/vbox_err.h>
#include <linux/vbox_utils.h>
#include "vboxsf_wrappers.h"

#define VBOX_INIT_CALL(a, b, c) \
do { \
	(a)->result      = VINF_SUCCESS;     \
	(a)->u32ClientID = vboxsf_client_id; \
	(a)->u32Function = SHFL_FN_##b;      \
	(a)->cParms      = SHFL_CPARMS_##b;  \
} while (0)

/* globals */
static u32 vboxsf_client_id;

int vboxsf_connect(void)
{
	struct VBOXGUESTDEVEXT *gdev;
	HGCMServiceLocation loc;
	int rc;

	loc.type = VMMDevHGCMLoc_LocalHost_Existing;
	strcpy(loc.u.host.achName, "VBoxSharedFolders");

	gdev = vbg_get_gdev();
	if (IS_ERR(gdev))
		return VERR_NOT_SUPPORTED;	/* No guest-device */

	rc = vbg_hgcm_connect(gdev, &loc, &vboxsf_client_id);
	vbg_put_gdev(gdev);

	return rc;
}

void vboxsf_disconnect(void)
{
	struct VBOXGUESTDEVEXT *gdev;

	gdev = vbg_get_gdev();
	if (IS_ERR(gdev))
		return;   /* guest-device is gone, already disconnected */

	vbg_hgcm_disconnect(gdev, vboxsf_client_id);
	vbg_put_gdev(gdev);
}

static int vboxsf_hgcm_call(void *data, u32 len)
{
	VBoxGuestHGCMCallInfo *info = data;
	struct VBOXGUESTDEVEXT *gdev;
	int rc;

	gdev = vbg_get_gdev();
	if (IS_ERR(gdev))
		return VERR_DEV_IO_ERROR; /* guest-dev removed underneath us */

	rc = vbg_hgcm_call(gdev, info, len, U32_MAX, false);
	vbg_put_gdev(gdev);

	if (rc >= 0)
		rc = info->result;

	return rc;
}

int vboxsf_query_mappings(SHFLMAPPING paMappings[], u32 *pcMappings)
{
	int rc;
	VBoxSFQueryMappings data;

	VBOX_INIT_CALL(&data.callInfo, QUERY_MAPPINGS, pClient);

	data.flags.type = VMMDevHGCMParmType_32bit;
	data.flags.u.value32 = SHFL_MF_UCS2;

	data.numberOfMappings.type = VMMDevHGCMParmType_32bit;
	data.numberOfMappings.u.value32 = *pcMappings;

	data.mappings.type = VMMDevHGCMParmType_LinAddr;
	data.mappings.u.Pointer.size = sizeof(SHFLMAPPING) * *pcMappings;
	data.mappings.u.Pointer.u.linearAddr = (uintptr_t)&paMappings[0];

	rc = vboxsf_hgcm_call(&data, sizeof(data));
	if (rc >= 0)
		*pcMappings = data.numberOfMappings.u.value32;

	return rc;
}

int vboxsf_query_mapname(SHFLROOT root, SHFLSTRING *pString, u32 size)
{
	VBoxSFQueryMapName data;

	VBOX_INIT_CALL(&data.callInfo, QUERY_MAP_NAME, pClient);

	data.root.type = VMMDevHGCMParmType_32bit;
	data.root.u.value32 = root;

	data.name.type = VMMDevHGCMParmType_LinAddr;
	data.name.u.Pointer.size = size;
	data.name.u.Pointer.u.linearAddr = (uintptr_t)pString;

	return vboxsf_hgcm_call(&data, sizeof(data));
}

int vboxsf_map_folder(PSHFLSTRING szFolderName, SHFLROOT *root)
{
	int rc;
	VBoxSFMapFolder data;

	VBOX_INIT_CALL(&data.callInfo, MAP_FOLDER, pClient);

	data.path.type = VMMDevHGCMParmType_LinAddr;
	data.path.u.Pointer.size = ShflStringSizeOfBuffer(szFolderName);
	data.path.u.Pointer.u.linearAddr = (uintptr_t)szFolderName;

	data.root.type = VMMDevHGCMParmType_32bit;
	data.root.u.value32 = 0;

	data.delimiter.type = VMMDevHGCMParmType_32bit;
	data.delimiter.u.value32 = '/';

	data.fCaseSensitive.type = VMMDevHGCMParmType_32bit;
	data.fCaseSensitive.u.value32 = 1;

	rc = vboxsf_hgcm_call(&data, sizeof(data));
	if (rc >= 0) {
		*root = data.root.u.value32;
	} else if (rc == VERR_NOT_IMPLEMENTED) {
		/* try the legacy interface too; temporary to assure backwards compatibility */
		VBoxSFMapFolder_Old OldData;

		VBOX_INIT_CALL(&OldData.callInfo, MAP_FOLDER_OLD, pClient);

		OldData.path.type = VMMDevHGCMParmType_LinAddr;
		OldData.path.u.Pointer.size =
		    ShflStringSizeOfBuffer(szFolderName);
		OldData.path.u.Pointer.u.linearAddr = (uintptr_t)szFolderName;

		OldData.root.type = VMMDevHGCMParmType_32bit;
		OldData.root.u.value32 = 0;

		OldData.delimiter.type = VMMDevHGCMParmType_32bit;
		OldData.delimiter.u.value32 = '/';

		rc = vboxsf_hgcm_call(&OldData, sizeof(OldData));
		if (rc >= 0)
			*root = OldData.root.u.value32;
	}
	return rc;
}

int vboxsf_unmap_folder(SHFLROOT root)
{
	VBoxSFUnmapFolder data;

	VBOX_INIT_CALL(&data.callInfo, UNMAP_FOLDER, pClient);

	data.root.type = VMMDevHGCMParmType_32bit;
	data.root.u.value32 = root;

	return vboxsf_hgcm_call(&data, sizeof(data));
}

int vboxsf_create(SHFLROOT root, PSHFLSTRING pParsedPath,
		  struct shfl_createparms *pCreateParms)
{
	/** @todo copy buffers to physical or mapped memory. */
	VBoxSFCreate data;

	VBOX_INIT_CALL(&data.callInfo, CREATE, pClient);

	data.root.type = VMMDevHGCMParmType_32bit;
	data.root.u.value32 = root;

	data.path.type = VMMDevHGCMParmType_LinAddr;
	data.path.u.Pointer.size = ShflStringSizeOfBuffer(pParsedPath);
	data.path.u.Pointer.u.linearAddr = (uintptr_t)pParsedPath;

	data.parms.type = VMMDevHGCMParmType_LinAddr;
	data.parms.u.Pointer.size = sizeof(struct shfl_createparms);
	data.parms.u.Pointer.u.linearAddr = (uintptr_t)pCreateParms;

	return vboxsf_hgcm_call(&data, sizeof(data));
}

int vboxsf_close(SHFLROOT root, SHFLHANDLE Handle)
{
	VBoxSFClose data;

	VBOX_INIT_CALL(&data.callInfo, CLOSE, pClient);

	data.root.type = VMMDevHGCMParmType_32bit;
	data.root.u.value32 = root;

	data.handle.type = VMMDevHGCMParmType_64bit;
	data.handle.u.value64 = Handle;

	return vboxsf_hgcm_call(&data, sizeof(data));
}

int vboxsf_remove(SHFLROOT root, PSHFLSTRING pParsedPath, u32 flags)
{
	VBoxSFRemove data;

	VBOX_INIT_CALL(&data.callInfo, REMOVE, pClient);

	data.root.type = VMMDevHGCMParmType_32bit;
	data.root.u.value32 = root;

	data.path.type = VMMDevHGCMParmType_LinAddr_In;
	data.path.u.Pointer.size = ShflStringSizeOfBuffer(pParsedPath);
	data.path.u.Pointer.u.linearAddr = (uintptr_t)pParsedPath;

	data.flags.type = VMMDevHGCMParmType_32bit;
	data.flags.u.value32 = flags;

	return vboxsf_hgcm_call(&data, sizeof(data));
}

int vboxsf_rename(SHFLROOT root, PSHFLSTRING pSrcPath, PSHFLSTRING pDestPath,
		  u32 flags)
{
	VBoxSFRename data;

	VBOX_INIT_CALL(&data.callInfo, RENAME, pClient);

	data.root.type = VMMDevHGCMParmType_32bit;
	data.root.u.value32 = root;

	data.src.type = VMMDevHGCMParmType_LinAddr_In;
	data.src.u.Pointer.size = ShflStringSizeOfBuffer(pSrcPath);
	data.src.u.Pointer.u.linearAddr = (uintptr_t)pSrcPath;

	data.dest.type = VMMDevHGCMParmType_LinAddr_In;
	data.dest.u.Pointer.size = ShflStringSizeOfBuffer(pDestPath);
	data.dest.u.Pointer.u.linearAddr = (uintptr_t)pDestPath;

	data.flags.type = VMMDevHGCMParmType_32bit;
	data.flags.u.value32 = flags;

	return vboxsf_hgcm_call(&data, sizeof(data));
}

int vboxsf_read(SHFLROOT root, SHFLHANDLE hFile, u64 offset,
		u32 *pcbBuffer, u8 *pBuffer)
{
	int rc;
	VBoxSFRead data;

	VBOX_INIT_CALL(&data.callInfo, READ, pClient);

	data.root.type = VMMDevHGCMParmType_32bit;
	data.root.u.value32 = root;

	data.handle.type = VMMDevHGCMParmType_64bit;
	data.handle.u.value64 = hFile;
	data.offset.type = VMMDevHGCMParmType_64bit;
	data.offset.u.value64 = offset;
	data.cb.type = VMMDevHGCMParmType_32bit;
	data.cb.u.value32 = *pcbBuffer;
	data.buffer.type = VMMDevHGCMParmType_LinAddr_Out;
	data.buffer.u.Pointer.size = *pcbBuffer;
	data.buffer.u.Pointer.u.linearAddr = (uintptr_t)pBuffer;

	rc = vboxsf_hgcm_call(&data, sizeof(data));
	if (rc >= 0)
		*pcbBuffer = data.cb.u.value32;

	return rc;
}

int vboxsf_write(SHFLROOT root, SHFLHANDLE hFile, u64 offset,
		 u32 *pcbBuffer, u8 *pBuffer)
{
	int rc;
	VBoxSFWrite data;

	VBOX_INIT_CALL(&data.callInfo, WRITE, pClient);

	data.root.type = VMMDevHGCMParmType_32bit;
	data.root.u.value32 = root;

	data.handle.type = VMMDevHGCMParmType_64bit;
	data.handle.u.value64 = hFile;
	data.offset.type = VMMDevHGCMParmType_64bit;
	data.offset.u.value64 = offset;
	data.cb.type = VMMDevHGCMParmType_32bit;
	data.cb.u.value32 = *pcbBuffer;
	data.buffer.type = VMMDevHGCMParmType_LinAddr_In;
	data.buffer.u.Pointer.size = *pcbBuffer;
	data.buffer.u.Pointer.u.linearAddr = (uintptr_t)pBuffer;

	rc = vboxsf_hgcm_call(&data, sizeof(data));
	if (rc >= 0)
		*pcbBuffer = data.cb.u.value32;

	return rc;
}

int vboxsf_write_physcont(SHFLROOT root, SHFLHANDLE hFile, u64 offset,
			  u32 *pcbBuffer, u64 PhysBuffer)
{
	u32 cPages, cbData, cbToWrite = *pcbBuffer;
	HGCMPageListInfo *pPgLst;
	VBoxSFWrite *pData;
	u32 iPage;
	int rc;

	cPages =
	    PAGE_ALIGN((PhysBuffer & ~PAGE_MASK) + cbToWrite) >> PAGE_SHIFT;
	cbData =
	    sizeof(VBoxSFWrite) + offsetof(HGCMPageListInfo, aPages[cPages]);
	pData = kmalloc(cbData, GFP_KERNEL);
	if (!pData)
		return VERR_NO_TMP_MEMORY;

	VBOX_INIT_CALL(&pData->callInfo, WRITE, pClient);

	pData->root.type = VMMDevHGCMParmType_32bit;
	pData->root.u.value32 = root;

	pData->handle.type = VMMDevHGCMParmType_64bit;
	pData->handle.u.value64 = hFile;
	pData->offset.type = VMMDevHGCMParmType_64bit;
	pData->offset.u.value64 = offset;
	pData->cb.type = VMMDevHGCMParmType_32bit;
	pData->cb.u.value32 = cbToWrite;
	pData->buffer.type = VMMDevHGCMParmType_PageList;
	pData->buffer.u.PageList.size = cbToWrite;
	pData->buffer.u.PageList.offset = sizeof(VBoxSFWrite);

	pPgLst = (HGCMPageListInfo *) (pData + 1);
	pPgLst->flags = VBOX_HGCM_F_PARM_DIRECTION_TO_HOST;
	pPgLst->offFirstPage = (u16)(PhysBuffer & ~PAGE_MASK);
	pPgLst->cPages = cPages;
	PhysBuffer &= ~(u64) ~ PAGE_MASK;
	for (iPage = 0; iPage < cPages; iPage++, PhysBuffer += PAGE_SIZE)
		pPgLst->aPages[iPage] = PhysBuffer;

	rc = vboxsf_hgcm_call(pData, cbData);
	if (rc >= 0)
		*pcbBuffer = pData->cb.u.value32;

	kfree(pData);
	return rc;
}

int vboxsf_flush(SHFLROOT root, SHFLHANDLE hFile)
{
	VBoxSFFlush data;

	VBOX_INIT_CALL(&data.callInfo, FLUSH, pClient);

	data.root.type = VMMDevHGCMParmType_32bit;
	data.root.u.value32 = root;

	data.handle.type = VMMDevHGCMParmType_64bit;
	data.handle.u.value64 = hFile;

	return vboxsf_hgcm_call(&data, sizeof(data));
}

int vboxsf_dirinfo(SHFLROOT root, SHFLHANDLE hFile, PSHFLSTRING ParsedPath,
		   u32 flags, u32 index, u32 *pcbBuffer,
		   PSHFLDIRINFO pBuffer, u32 *pcFiles)
{
	int rc;
	VBoxSFList data;

	VBOX_INIT_CALL(&data.callInfo, LIST, pClient);

	data.root.type = VMMDevHGCMParmType_32bit;
	data.root.u.value32 = root;

	data.handle.type = VMMDevHGCMParmType_64bit;
	data.handle.u.value64 = hFile;
	data.flags.type = VMMDevHGCMParmType_32bit;
	data.flags.u.value32 = flags;
	data.cb.type = VMMDevHGCMParmType_32bit;
	data.cb.u.value32 = *pcbBuffer;
	data.path.type = VMMDevHGCMParmType_LinAddr_In;
	data.path.u.Pointer.size =
	    ParsedPath ? ShflStringSizeOfBuffer(ParsedPath) : 0;
	data.path.u.Pointer.u.linearAddr = (uintptr_t)ParsedPath;

	data.buffer.type = VMMDevHGCMParmType_LinAddr_Out;
	data.buffer.u.Pointer.size = *pcbBuffer;
	data.buffer.u.Pointer.u.linearAddr = (uintptr_t)pBuffer;

	data.resumePoint.type = VMMDevHGCMParmType_32bit;
	data.resumePoint.u.value32 = index;
	data.cFiles.type = VMMDevHGCMParmType_32bit;
	data.cFiles.u.value32 = 0;	/* out parameters only */

	rc = vboxsf_hgcm_call(&data, sizeof(data));

	*pcbBuffer = data.cb.u.value32;
	*pcFiles = data.cFiles.u.value32;

	return rc;
}

int vboxsf_fsinfo(SHFLROOT root, SHFLHANDLE hFile, u32 flags,
		  u32 *pcbBuffer, PSHFLDIRINFO pBuffer)
{
	int rc;
	VBoxSFInformation data;

	VBOX_INIT_CALL(&data.callInfo, INFORMATION, pClient);

	data.root.type = VMMDevHGCMParmType_32bit;
	data.root.u.value32 = root;

	data.handle.type = VMMDevHGCMParmType_64bit;
	data.handle.u.value64 = hFile;
	data.flags.type = VMMDevHGCMParmType_32bit;
	data.flags.u.value32 = flags;
	data.cb.type = VMMDevHGCMParmType_32bit;
	data.cb.u.value32 = *pcbBuffer;
	data.info.type = VMMDevHGCMParmType_LinAddr;
	data.info.u.Pointer.size = *pcbBuffer;
	data.info.u.Pointer.u.linearAddr = (uintptr_t)pBuffer;

	rc = vboxsf_hgcm_call(&data, sizeof(data));
	if (rc >= 0)
		*pcbBuffer = data.cb.u.value32;

	return rc;
}

int vboxsf_lock(SHFLROOT root, SHFLHANDLE hFile, u64 offset,
		u64 cbSize, u32 fLock)
{
	VBoxSFLock data;

	VBOX_INIT_CALL(&data.callInfo, LOCK, pClient);

	data.root.type = VMMDevHGCMParmType_32bit;
	data.root.u.value32 = root;

	data.handle.type = VMMDevHGCMParmType_64bit;
	data.handle.u.value64 = hFile;
	data.offset.type = VMMDevHGCMParmType_64bit;
	data.offset.u.value64 = offset;
	data.length.type = VMMDevHGCMParmType_64bit;
	data.length.u.value64 = cbSize;

	data.flags.type = VMMDevHGCMParmType_32bit;
	data.flags.u.value32 = fLock;

	return vboxsf_hgcm_call(&data, sizeof(data));
}

int vboxsf_set_utf8(void)
{
	VBoxGuestHGCMCallInfo callInfo;

	VBOX_INIT_CALL(&callInfo, SET_UTF8, pClient);

	return vboxsf_hgcm_call(&callInfo, sizeof(callInfo));
}

int vboxsf_readlink(SHFLROOT root, PSHFLSTRING pParsedPath, u32 cbBuffer,
		    u8 *pBuffer)
{
	VBoxSFReadLink data;

	VBOX_INIT_CALL(&data.callInfo, READLINK, pClient);

	data.root.type = VMMDevHGCMParmType_32bit;
	data.root.u.value32 = root;

	data.path.type = VMMDevHGCMParmType_LinAddr_In;
	data.path.u.Pointer.size = ShflStringSizeOfBuffer(pParsedPath);
	data.path.u.Pointer.u.linearAddr = (uintptr_t)pParsedPath;

	data.buffer.type = VMMDevHGCMParmType_LinAddr_Out;
	data.buffer.u.Pointer.size = cbBuffer;
	data.buffer.u.Pointer.u.linearAddr = (uintptr_t)pBuffer;

	return vboxsf_hgcm_call(&data, sizeof(data));
}

int vboxsf_symlink(SHFLROOT root, PSHFLSTRING pNewPath, PSHFLSTRING pOldPath,
		   struct shfl_fsobjinfo *pBuffer)
{
	VBoxSFSymlink data;

	VBOX_INIT_CALL(&data.callInfo, SYMLINK, pClient);

	data.root.type = VMMDevHGCMParmType_32bit;
	data.root.u.value32 = root;

	data.newPath.type = VMMDevHGCMParmType_LinAddr_In;
	data.newPath.u.Pointer.size = ShflStringSizeOfBuffer(pNewPath);
	data.newPath.u.Pointer.u.linearAddr = (uintptr_t)pNewPath;

	data.oldPath.type = VMMDevHGCMParmType_LinAddr_In;
	data.oldPath.u.Pointer.size = ShflStringSizeOfBuffer(pOldPath);
	data.oldPath.u.Pointer.u.linearAddr = (uintptr_t)pOldPath;

	data.info.type = VMMDevHGCMParmType_LinAddr_Out;
	data.info.u.Pointer.size = sizeof(struct shfl_fsobjinfo);
	data.info.u.Pointer.u.linearAddr = (uintptr_t)pBuffer;

	return vboxsf_hgcm_call(&data, sizeof(data));
}

int vboxsf_set_symlinks(void)
{
	VBoxGuestHGCMCallInfo callInfo;

	VBOX_INIT_CALL(&callInfo, SET_SYMLINKS, pClient);

	return vboxsf_hgcm_call(&callInfo, sizeof(callInfo));
}
