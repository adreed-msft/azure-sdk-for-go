// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package azblob

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
)

// ComputeHMAC
func (u UserDelegationKey) ComputeHMACSHA256(message string) (base64String string) {
	bytes, _ := base64.StdEncoding.DecodeString(*u.Value)
	h := hmac.New(sha256.New, bytes)
	h.Write([]byte(message))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}
