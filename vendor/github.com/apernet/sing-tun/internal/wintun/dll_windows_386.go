/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2021 WireGuard LLC. All Rights Reserved.
 */

package wintun

import (
	_ "embed"
)

//go:embed x86/wintun.dll
var dllContent []byte
