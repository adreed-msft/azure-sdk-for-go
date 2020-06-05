// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

package azmonitor

import (
	"context"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"net/http"
	"net/url"
	"strings"
)

// DiagnosticSettingsOperations contains the methods for the DiagnosticSettings group.
type DiagnosticSettingsOperations interface {
	// CreateOrUpdate - Creates or updates diagnostic settings for the specified resource.
	CreateOrUpdate(ctx context.Context, resourceUri string, name string, parameters DiagnosticSettingsResource) (*DiagnosticSettingsResourceResponse, error)
	// Delete - Deletes existing diagnostic settings for the specified resource.
	Delete(ctx context.Context, resourceUri string, name string) (*http.Response, error)
	// Get - Gets the active diagnostic settings for the specified resource.
	Get(ctx context.Context, resourceUri string, name string) (*DiagnosticSettingsResourceResponse, error)
	// List - Gets the active diagnostic settings list for the specified resource.
	List(ctx context.Context, resourceUri string) (*DiagnosticSettingsResourceCollectionResponse, error)
}

// diagnosticSettingsOperations implements the DiagnosticSettingsOperations interface.
type diagnosticSettingsOperations struct {
	*Client
}

// CreateOrUpdate - Creates or updates diagnostic settings for the specified resource.
func (client *diagnosticSettingsOperations) CreateOrUpdate(ctx context.Context, resourceUri string, name string, parameters DiagnosticSettingsResource) (*DiagnosticSettingsResourceResponse, error) {
	req, err := client.createOrUpdateCreateRequest(resourceUri, name, parameters)
	if err != nil {
		return nil, err
	}
	resp, err := client.p.Do(ctx, req)
	if err != nil {
		return nil, err
	}
	result, err := client.createOrUpdateHandleResponse(resp)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// createOrUpdateCreateRequest creates the CreateOrUpdate request.
func (client *diagnosticSettingsOperations) createOrUpdateCreateRequest(resourceUri string, name string, parameters DiagnosticSettingsResource) (*azcore.Request, error) {
	urlPath := "/{resourceUri}/providers/microsoft.insights/diagnosticSettings/{name}"
	urlPath = strings.ReplaceAll(urlPath, "{resourceUri}", resourceUri)
	urlPath = strings.ReplaceAll(urlPath, "{name}", url.PathEscape(name))
	u, err := client.u.Parse(urlPath)
	if err != nil {
		return nil, err
	}
	query := u.Query()
	query.Set("api-version", "2017-05-01-preview")
	u.RawQuery = query.Encode()
	req := azcore.NewRequest(http.MethodPut, *u)
	return req, req.MarshalAsJSON(parameters)
}

// createOrUpdateHandleResponse handles the CreateOrUpdate response.
func (client *diagnosticSettingsOperations) createOrUpdateHandleResponse(resp *azcore.Response) (*DiagnosticSettingsResourceResponse, error) {
	if !resp.HasStatusCode(http.StatusOK) {
		return nil, client.createOrUpdateHandleError(resp)
	}
	result := DiagnosticSettingsResourceResponse{RawResponse: resp.Response}
	return &result, resp.UnmarshalAsJSON(&result.DiagnosticSettingsResource)
}

// createOrUpdateHandleError handles the CreateOrUpdate error response.
func (client *diagnosticSettingsOperations) createOrUpdateHandleError(resp *azcore.Response) error {
	var err ErrorResponse
	if err := resp.UnmarshalAsJSON(&err); err != nil {
		return err
	}
	return err
}

// Delete - Deletes existing diagnostic settings for the specified resource.
func (client *diagnosticSettingsOperations) Delete(ctx context.Context, resourceUri string, name string) (*http.Response, error) {
	req, err := client.deleteCreateRequest(resourceUri, name)
	if err != nil {
		return nil, err
	}
	resp, err := client.p.Do(ctx, req)
	if err != nil {
		return nil, err
	}
	result, err := client.deleteHandleResponse(resp)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// deleteCreateRequest creates the Delete request.
func (client *diagnosticSettingsOperations) deleteCreateRequest(resourceUri string, name string) (*azcore.Request, error) {
	urlPath := "/{resourceUri}/providers/microsoft.insights/diagnosticSettings/{name}"
	urlPath = strings.ReplaceAll(urlPath, "{resourceUri}", resourceUri)
	urlPath = strings.ReplaceAll(urlPath, "{name}", url.PathEscape(name))
	u, err := client.u.Parse(urlPath)
	if err != nil {
		return nil, err
	}
	query := u.Query()
	query.Set("api-version", "2017-05-01-preview")
	u.RawQuery = query.Encode()
	req := azcore.NewRequest(http.MethodDelete, *u)
	return req, nil
}

// deleteHandleResponse handles the Delete response.
func (client *diagnosticSettingsOperations) deleteHandleResponse(resp *azcore.Response) (*http.Response, error) {
	if !resp.HasStatusCode(http.StatusOK, http.StatusNoContent) {
		return nil, client.deleteHandleError(resp)
	}
	return resp.Response, nil
}

// deleteHandleError handles the Delete error response.
func (client *diagnosticSettingsOperations) deleteHandleError(resp *azcore.Response) error {
	var err ErrorResponse
	if err := resp.UnmarshalAsJSON(&err); err != nil {
		return err
	}
	return err
}

// Get - Gets the active diagnostic settings for the specified resource.
func (client *diagnosticSettingsOperations) Get(ctx context.Context, resourceUri string, name string) (*DiagnosticSettingsResourceResponse, error) {
	req, err := client.getCreateRequest(resourceUri, name)
	if err != nil {
		return nil, err
	}
	resp, err := client.p.Do(ctx, req)
	if err != nil {
		return nil, err
	}
	result, err := client.getHandleResponse(resp)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// getCreateRequest creates the Get request.
func (client *diagnosticSettingsOperations) getCreateRequest(resourceUri string, name string) (*azcore.Request, error) {
	urlPath := "/{resourceUri}/providers/microsoft.insights/diagnosticSettings/{name}"
	urlPath = strings.ReplaceAll(urlPath, "{resourceUri}", resourceUri)
	urlPath = strings.ReplaceAll(urlPath, "{name}", url.PathEscape(name))
	u, err := client.u.Parse(urlPath)
	if err != nil {
		return nil, err
	}
	query := u.Query()
	query.Set("api-version", "2017-05-01-preview")
	u.RawQuery = query.Encode()
	req := azcore.NewRequest(http.MethodGet, *u)
	return req, nil
}

// getHandleResponse handles the Get response.
func (client *diagnosticSettingsOperations) getHandleResponse(resp *azcore.Response) (*DiagnosticSettingsResourceResponse, error) {
	if !resp.HasStatusCode(http.StatusOK) {
		return nil, client.getHandleError(resp)
	}
	result := DiagnosticSettingsResourceResponse{RawResponse: resp.Response}
	return &result, resp.UnmarshalAsJSON(&result.DiagnosticSettingsResource)
}

// getHandleError handles the Get error response.
func (client *diagnosticSettingsOperations) getHandleError(resp *azcore.Response) error {
	var err ErrorResponse
	if err := resp.UnmarshalAsJSON(&err); err != nil {
		return err
	}
	return err
}

// List - Gets the active diagnostic settings list for the specified resource.
func (client *diagnosticSettingsOperations) List(ctx context.Context, resourceUri string) (*DiagnosticSettingsResourceCollectionResponse, error) {
	req, err := client.listCreateRequest(resourceUri)
	if err != nil {
		return nil, err
	}
	resp, err := client.p.Do(ctx, req)
	if err != nil {
		return nil, err
	}
	result, err := client.listHandleResponse(resp)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// listCreateRequest creates the List request.
func (client *diagnosticSettingsOperations) listCreateRequest(resourceUri string) (*azcore.Request, error) {
	urlPath := "/{resourceUri}/providers/microsoft.insights/diagnosticSettings"
	urlPath = strings.ReplaceAll(urlPath, "{resourceUri}", resourceUri)
	u, err := client.u.Parse(urlPath)
	if err != nil {
		return nil, err
	}
	query := u.Query()
	query.Set("api-version", "2017-05-01-preview")
	u.RawQuery = query.Encode()
	req := azcore.NewRequest(http.MethodGet, *u)
	return req, nil
}

// listHandleResponse handles the List response.
func (client *diagnosticSettingsOperations) listHandleResponse(resp *azcore.Response) (*DiagnosticSettingsResourceCollectionResponse, error) {
	if !resp.HasStatusCode(http.StatusOK) {
		return nil, client.listHandleError(resp)
	}
	result := DiagnosticSettingsResourceCollectionResponse{RawResponse: resp.Response}
	return &result, resp.UnmarshalAsJSON(&result.DiagnosticSettingsResourceCollection)
}

// listHandleError handles the List error response.
func (client *diagnosticSettingsOperations) listHandleError(resp *azcore.Response) error {
	var err ErrorResponse
	if err := resp.UnmarshalAsJSON(&err); err != nil {
		return err
	}
	return err
}