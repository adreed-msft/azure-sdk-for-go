// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

package armstorage

import (
	"context"
	"errors"
	"fmt"
	"github.com/Azure/azure-sdk-for-go/sdk/armcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
)

// SKUsOperations contains the methods for the SKUs group.
type SKUsOperations interface {
	// List - Lists the available SKUs supported by Microsoft.Storage for given subscription.
	List(ctx context.Context, options *SKUsListOptions) (*StorageSKUListResultResponse, error)
}

// SKUsClient implements the SKUsOperations interface.
// Don't use this type directly, use NewSKUsClient() instead.
type SKUsClient struct {
	con            *armcore.Connection
	subscriptionID string
}

// NewSKUsClient creates a new instance of SKUsClient with the specified values.
func NewSKUsClient(con *armcore.Connection, subscriptionID string) SKUsOperations {
	return &SKUsClient{con: con, subscriptionID: subscriptionID}
}

// Pipeline returns the pipeline associated with this client.
func (client *SKUsClient) Pipeline() azcore.Pipeline {
	return client.con.Pipeline()
}

// List - Lists the available SKUs supported by Microsoft.Storage for given subscription.
func (client *SKUsClient) List(ctx context.Context, options *SKUsListOptions) (*StorageSKUListResultResponse, error) {
	req, err := client.ListCreateRequest(ctx, options)
	if err != nil {
		return nil, err
	}
	resp, err := client.Pipeline().Do(req)
	if err != nil {
		return nil, err
	}
	if !resp.HasStatusCode(http.StatusOK) {
		return nil, client.ListHandleError(resp)
	}
	result, err := client.ListHandleResponse(resp)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// ListCreateRequest creates the List request.
func (client *SKUsClient) ListCreateRequest(ctx context.Context, options *SKUsListOptions) (*azcore.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/providers/Microsoft.Storage/skus"
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	req, err := azcore.NewRequest(ctx, http.MethodGet, azcore.JoinPaths(client.con.Endpoint(), urlPath))
	if err != nil {
		return nil, err
	}
	query := req.URL.Query()
	query.Set("api-version", "2019-06-01")
	req.URL.RawQuery = query.Encode()
	req.Header.Set("Accept", "application/json")
	return req, nil
}

// ListHandleResponse handles the List response.
func (client *SKUsClient) ListHandleResponse(resp *azcore.Response) (*StorageSKUListResultResponse, error) {
	result := StorageSKUListResultResponse{RawResponse: resp.Response}
	return &result, resp.UnmarshalAsJSON(&result.StorageSKUListResult)
}

// ListHandleError handles the List error response.
func (client *SKUsClient) ListHandleError(resp *azcore.Response) error {
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("%s; failed to read response body: %w", resp.Status, err)
	}
	if len(body) == 0 {
		return azcore.NewResponseError(errors.New(resp.Status), resp.Response)
	}
	return azcore.NewResponseError(errors.New(string(body)), resp.Response)
}
