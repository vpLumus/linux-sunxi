/*
 * Copyright (C) 2006-2016 Oracle Corporation
 *
 * Protype declarations for the wrapper functions for the shfl host calls.
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

#ifndef VBOXSF_WRAPPERS_H
#define VBOXSF_WRAPPERS_H

#include <linux/vboxguest.h>	/* For VBoxGuestHGCMCallInfo */
#include "shfl_hostintf.h"

/**
 * @addtogroup grp_vboxguest_lib_r0
 *
 * Note all these functions (all functions prefixed with vboxsf_)
 * return a vbox status code rather then a negative errno on error.
 * @{
 */

int vboxsf_connect(void);
void vboxsf_disconnect(void);

int vboxsf_query_mappings(SHFLMAPPING paMappings[], u32 *pcMappings);
int vboxsf_query_mapname(SHFLROOT root, SHFLSTRING *pString, u32 size);

/**
 * Create a new file or folder or open an existing one in a shared folder.  Proxies
 * to vbsfCreate in the host shared folder service.
 *
 * @returns IPRT status code, but see note below
 * @param   pClient      Host-guest communication connection
 * @param   root         Root of the shared folder in which to create the file
 * @param   pParsedPath  The path of the file or folder relative to the shared
 *                       folder
 * @param   pCreateParms Parameters for file/folder creation.  See the
 *                       structure description in shflsvc.h
 * @retval  pCreateParms See the structure description in shflsvc.h
 *
 * @note This function reports errors as follows.  The return value is always
 *       VINF_SUCCESS unless an exceptional condition occurs - out of
 *       memory, invalid arguments, etc.  If the file or folder could not be
 *       opened or created, pCreateParms->Handle will be set to
 *       SHFL_HANDLE_NIL on return.  In this case the value in
 *       pCreateParms->Result provides information as to why (e.g.
 *       SHFL_FILE_EXISTS).  pCreateParms->Result is also set on success
 *       as additional information.
 */
int vboxsf_create(SHFLROOT root, PSHFLSTRING pParsedPath,
		  struct shfl_createparms *pCreateParms);

int vboxsf_close(SHFLROOT root, SHFLHANDLE Handle);
int vboxsf_remove(SHFLROOT root, PSHFLSTRING pParsedPath, u32 flags);
int vboxsf_rename(SHFLROOT root, PSHFLSTRING pSrcPath, PSHFLSTRING pDestPath,
		  u32 flags);
int vboxsf_flush(SHFLROOT root, SHFLHANDLE hFile);

int vboxsf_read(SHFLROOT root, SHFLHANDLE hFile, u64 offset,
		u32 *pcbBuffer, u8 *pBuffer);
int vboxsf_write(SHFLROOT root, SHFLHANDLE hFile, u64 offset,
		 u32 *pcbBuffer, u8 *pBuffer);
int vboxsf_write_physcont(SHFLROOT root, SHFLHANDLE hFile, u64 offset,
			  u32 *pcbBuffer, u64 PhysBuffer);

int vboxsf_lock(SHFLROOT root, SHFLHANDLE hFile, u64 offset,
		u64 cbSize, u32 fLock);

int vboxsf_dirinfo(SHFLROOT root, SHFLHANDLE hFile, PSHFLSTRING ParsedPath,
		   u32 flags, u32 index, u32 *pcbBuffer,
		   PSHFLDIRINFO pBuffer, u32 *pcFiles);
int vboxsf_fsinfo(SHFLROOT root, SHFLHANDLE hFile, u32 flags,
		  u32 *pcbBuffer, PSHFLDIRINFO pBuffer);

int vboxsf_map_folder(PSHFLSTRING szFolderName, SHFLROOT *root);
int vboxsf_unmap_folder(SHFLROOT root);

int vboxsf_readlink(SHFLROOT root, PSHFLSTRING pParsedPath, u32 cbBuffer,
		    u8 *pBuffer);
int vboxsf_symlink(SHFLROOT root, PSHFLSTRING pNewPath, PSHFLSTRING pOldPath,
		   struct shfl_fsobjinfo *pBuffer);

int vboxsf_set_utf8(void);
int vboxsf_set_symlinks(void);

/** @} */

#endif
