package translatortext

// Copyright (c) Microsoft and contributors.  All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

// Code enumerates the values for code.
type Code string

const (
	// InternalServerError ...
	InternalServerError Code = "InternalServerError"
	// InvalidArgument ...
	InvalidArgument Code = "InvalidArgument"
	// InvalidRequest ...
	InvalidRequest Code = "InvalidRequest"
	// RequestRateTooHigh ...
	RequestRateTooHigh Code = "RequestRateTooHigh"
	// ResourceNotFound ...
	ResourceNotFound Code = "ResourceNotFound"
	// ServiceUnavailable ...
	ServiceUnavailable Code = "ServiceUnavailable"
	// Unauthorized ...
	Unauthorized Code = "Unauthorized"
)

// PossibleCodeValues returns an array of possible values for the Code const type.
func PossibleCodeValues() []Code {
	return []Code{InternalServerError, InvalidArgument, InvalidRequest, RequestRateTooHigh, ResourceNotFound, ServiceUnavailable, Unauthorized}
}

// Status enumerates the values for status.
type Status string

const (
	// Cancelled ...
	Cancelled Status = "Cancelled"
	// Cancelling ...
	Cancelling Status = "Cancelling"
	// Failed ...
	Failed Status = "Failed"
	// NotStarted ...
	NotStarted Status = "NotStarted"
	// Running ...
	Running Status = "Running"
	// Succeeded ...
	Succeeded Status = "Succeeded"
)

// PossibleStatusValues returns an array of possible values for the Status const type.
func PossibleStatusValues() []Status {
	return []Status{Cancelled, Cancelling, Failed, NotStarted, Running, Succeeded}
}

// Status1 enumerates the values for status 1.
type Status1 string

const (
	// Status1Cancelled ...
	Status1Cancelled Status1 = "Cancelled"
	// Status1Cancelling ...
	Status1Cancelling Status1 = "Cancelling"
	// Status1Failed ...
	Status1Failed Status1 = "Failed"
	// Status1NotStarted ...
	Status1NotStarted Status1 = "NotStarted"
	// Status1Running ...
	Status1Running Status1 = "Running"
	// Status1Succeeded ...
	Status1Succeeded Status1 = "Succeeded"
)

// PossibleStatus1Values returns an array of possible values for the Status1 const type.
func PossibleStatus1Values() []Status1 {
	return []Status1{Status1Cancelled, Status1Cancelling, Status1Failed, Status1NotStarted, Status1Running, Status1Succeeded}
}

// StorageSource enumerates the values for storage source.
type StorageSource string

const (
	// AzureBlob ...
	AzureBlob StorageSource = "AzureBlob"
)

// PossibleStorageSourceValues returns an array of possible values for the StorageSource const type.
func PossibleStorageSourceValues() []StorageSource {
	return []StorageSource{AzureBlob}
}

// StorageSource1 enumerates the values for storage source 1.
type StorageSource1 string

const (
	// StorageSource1AzureBlob ...
	StorageSource1AzureBlob StorageSource1 = "AzureBlob"
)

// PossibleStorageSource1Values returns an array of possible values for the StorageSource1 const type.
func PossibleStorageSource1Values() []StorageSource1 {
	return []StorageSource1{StorageSource1AzureBlob}
}
