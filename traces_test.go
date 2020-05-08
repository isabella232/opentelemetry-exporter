// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package elastic_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	commonpb "github.com/census-instrumentation/opencensus-proto/gen-go/agent/common/v1"
	resourcepb "github.com/census-instrumentation/opencensus-proto/gen-go/resource/v1"
	tracepb "github.com/census-instrumentation/opencensus-proto/gen-go/trace/v1"
	elastic "github.com/elastic/opentelemetry-exporter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.elastic.co/apm/model"
)

func TestPushTraceData(t *testing.T) {
	exporter, recorder := newExporter(t)

	traceID := model.TraceID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	rootTransactionID := model.SpanID{1, 1, 1, 1, 1, 1, 1, 1}
	clientSpanID := model.SpanID{2, 2, 2, 2, 2, 2, 2, 2}
	serverTransactionID := model.SpanID{3, 3, 3, 3, 3, 3, 3, 3}

	startTime := time.Unix(123, 0).UTC()
	endTime := startTime.Add(time.Millisecond * 5)
	failed, err := exporter.PushTraceData(context.Background(), elastic.TraceData{
		Node:     &commonpb.Node{},
		Resource: &resourcepb.Resource{},
		Spans: []*tracepb.Span{{
			TraceId:   traceID[:],
			SpanId:    rootTransactionID[:],
			Name:      &tracepb.TruncatableString{Value: "root_span"},
			Kind:      tracepb.Span_SPAN_KIND_UNSPECIFIED,
			StartTime: toTimestamp(startTime),
			EndTime:   toTimestamp(endTime),
			Status:    &tracepb.Status{Code: 0},
			Attributes: &tracepb.Span_Attributes{
				AttributeMap: map[string]*tracepb.AttributeValue{
					"string.attr": stringAttributeValue("string_value"),
					"int.attr":    intAttributeValue(123),
					"double.attr": doubleAttributeValue(123.456),
					"bool.attr":   boolAttributeValue(true),
				},
			},
		}, {
			TraceId:      traceID[:],
			SpanId:       clientSpanID[:],
			ParentSpanId: rootTransactionID[:],
			Name:         &tracepb.TruncatableString{Value: "client_span"},
			Kind:         tracepb.Span_CLIENT,
			StartTime:    toTimestamp(startTime),
			EndTime:      toTimestamp(endTime),
			Status:       &tracepb.Status{Code: 0},
			Attributes: &tracepb.Span_Attributes{
				AttributeMap: map[string]*tracepb.AttributeValue{
					"string.attr": stringAttributeValue("string_value"),
					"int.attr":    intAttributeValue(123),
					"double.attr": doubleAttributeValue(123.456),
					"bool.attr":   boolAttributeValue(true),
				},
			},
		}, {
			TraceId:      traceID[:],
			SpanId:       serverTransactionID[:],
			ParentSpanId: clientSpanID[:],
			Name:         &tracepb.TruncatableString{Value: "server_span"},
			Kind:         tracepb.Span_SERVER,
			StartTime:    toTimestamp(startTime),
			EndTime:      toTimestamp(endTime),
			Status:       &tracepb.Status{Code: -1},
		}},
	})
	assert.Equal(t, 0, failed)
	assert.NoError(t, err)

	payloads := recorder.Payloads()

	assert.Equal(t, []model.Transaction{{
		TraceID:   traceID,
		ID:        rootTransactionID,
		Timestamp: model.Time(startTime),
		Duration:  5.0,
		Name:      "root_span",
		Type:      "unknown",
		Result:    "Ok",
		Context: &model.Context{
			Tags: model.IfaceMap{{
				Key:   "bool_attr",
				Value: true,
			}, {
				Key:   "double_attr",
				Value: 123.456,
			}, {
				Key:   "int_attr",
				Value: float64(123),
			}, {
				Key:   "string_attr",
				Value: "string_value",
			}},
		},
	}, {
		TraceID:   traceID,
		ID:        serverTransactionID,
		ParentID:  clientSpanID,
		Timestamp: model.Time(startTime),
		Duration:  5.0,
		Name:      "server_span",
		Type:      "unknown",
		Result:    "unknown",
	}}, payloads.Transactions)

	assert.Equal(t, []model.Span{{
		TraceID:   traceID,
		ID:        clientSpanID,
		ParentID:  rootTransactionID,
		Timestamp: model.Time(startTime),
		Duration:  5.0,
		Name:      "client_span",
		Type:      "app",
		Context: &model.SpanContext{
			Tags: model.IfaceMap{{
				Key:   "bool_attr",
				Value: true,
			}, {
				Key:   "double_attr",
				Value: 123.456,
			}, {
				Key:   "int_attr",
				Value: float64(123),
			}, {
				Key:   "string_attr",
				Value: "string_value",
			}},
		},
	}}, payloads.Spans)

	assert.Empty(t, payloads.Errors)
}

func TestTransactionHTTPRequestURL(t *testing.T) {
	test := func(t *testing.T, expectedFull string, attrs ...interface{}) {
		transaction := transactionWithAttributes(t, attrs...)
		assert.Equal(t, expectedFull, transaction.Context.Request.URL.Full)
	}
	t.Run("scheme_host_target", func(t *testing.T) {
		test(t, "https://testing.invalid:80/foo?bar",
			"http.scheme", "https",
			"http.host", "testing.invalid:80",
			"http.target", "/foo?bar",
		)
	})
	t.Run("scheme_servername_nethostport_target", func(t *testing.T) {
		test(t, "https://testing.invalid:80/foo?bar",
			"http.scheme", "https",
			"http.server_name", "testing.invalid",
			"net.host.port", 80,
			"http.target", "/foo?bar",
		)
	})
	t.Run("scheme_nethostname_nethostport_target", func(t *testing.T) {
		test(t, "https://testing.invalid:80/foo?bar",
			"http.scheme", "https",
			"net.host.name", "testing.invalid",
			"net.host.port", 80,
			"http.target", "/foo?bar",
		)
	})
	t.Run("http.url", func(t *testing.T) {
		const httpURL = "https://testing.invalid:80/foo?bar"
		test(t, httpURL, "http.url", httpURL)
	})

	// Scheme is set to "http" if it can't be deduced from attributes.
	t.Run("default_scheme", func(t *testing.T) {
		test(t, "http://testing.invalid:80/foo?bar",
			"http.host", "testing.invalid:80",
			"http.target", "/foo?bar",
		)
	})
}

func TestTransactionHTTPRequestSocketRemoteAddr(t *testing.T) {
	test := func(t *testing.T, expected string, attrs ...interface{}) {
		transaction := transactionWithAttributes(t, attrs...)
		assert.Equal(t, expected, transaction.Context.Request.Socket.RemoteAddress)
	}
	t.Run("net.peer.ip_port", func(t *testing.T) {
		test(t, "192.168.0.1:1234",
			"http.url", "http://testing.invalid",
			"net.peer.ip", "192.168.0.1",
			"net.peer.port", 1234,
		)
	})
	t.Run("net.peer.ip", func(t *testing.T) {
		test(t, "192.168.0.1",
			"http.url", "http://testing.invalid",
			"net.peer.ip", "192.168.0.1",
		)
	})
	t.Run("http.remote_addr", func(t *testing.T) {
		test(t, "192.168.0.1:1234",
			"http.url", "http://testing.invalid",
			"http.remote_addr", "192.168.0.1:1234",
		)
	})
	t.Run("http.remote_addr_no_port", func(t *testing.T) {
		test(t, "192.168.0.1",
			"http.url", "http://testing.invalid",
			"http.remote_addr", "192.168.0.1",
		)
	})
}

func TestTransactionHTTPRequestHTTPVersion(t *testing.T) {
	transaction := transactionWithAttributes(t, "http.flavor", "1.1")
	assert.Equal(t, "1.1", transaction.Context.Request.HTTPVersion)
}

func TestTransactionHTTPRequestHTTPMethod(t *testing.T) {
	transaction := transactionWithAttributes(t, "http.method", "PATCH")
	assert.Equal(t, "PATCH", transaction.Context.Request.Method)
}

func TestTransactionHTTPRequestUserAgent(t *testing.T) {
	transaction := transactionWithAttributes(t, "http.user_agent", "Foo/bar (baz)")
	assert.Equal(t, model.Headers{{
		Key:    "User-Agent",
		Values: []string{"Foo/bar (baz)"},
	}}, transaction.Context.Request.Headers)
}

func TestTransactionHTTPRequestClientIP(t *testing.T) {
	transaction := transactionWithAttributes(t, "http.client_ip", "256.257.258.259")
	assert.Equal(t, model.Headers{{
		Key:    "X-Forwarded-For",
		Values: []string{"256.257.258.259"},
	}}, transaction.Context.Request.Headers)
}

func TestTransactionHTTPResponseStatusCode(t *testing.T) {
	transaction := transactionWithAttributes(t, "http.status_code", 200)
	assert.Equal(t, 200, transaction.Context.Response.StatusCode)
}

func TestSpanHTTPURL(t *testing.T) {
	test := func(t *testing.T, expectedURL string, attrs ...interface{}) {
		span := spanWithAttributes(t, attrs...)
		assert.Equal(t, expectedURL, span.Context.HTTP.URL.String())
	}
	t.Run("http.url", func(t *testing.T) {
		const httpURL = "https://testing.invalid:80/foo?bar"
		test(t, httpURL, "http.url", httpURL)
	})
	t.Run("scheme_host_target", func(t *testing.T) {
		test(t, "https://testing.invalid:80/foo?bar",
			"http.scheme", "https",
			"http.host", "testing.invalid:80",
			"http.target", "/foo?bar",
		)
	})
	t.Run("scheme_netpeername_nethostport_target", func(t *testing.T) {
		test(t, "https://testing.invalid:80/foo?bar",
			"http.scheme", "https",
			"net.peer.name", "testing.invalid",
			"net.peer.port", 80,
			"http.target", "/foo?bar",
		)
	})
	t.Run("scheme_nethostname_nethostport_target", func(t *testing.T) {
		test(t, "https://[::1]:80/foo?bar",
			"http.scheme", "https",
			"net.peer.name", "::1",
			"net.peer.port", 80,
			"http.target", "/foo?bar",
		)
	})

	// Scheme is set to "http" if it can't be deduced from attributes.
	t.Run("default_scheme", func(t *testing.T) {
		test(t, "http://testing.invalid:80/foo?bar",
			"http.host", "testing.invalid:80",
			"http.target", "/foo?bar",
		)
	})
}

func TestSpanHTTPStatusCode(t *testing.T) {
	span := spanWithAttributes(t,
		"http.url", "http://testing.invalid",
		"http.status_code", 200,
	)
	assert.Equal(t, 200, span.Context.HTTP.StatusCode)
}

func TestSpanDatabaseContext(t *testing.T) {
	span := spanWithAttributes(t,
		"db.type", "sql",
		"db.instance", "customers",
		"db.statement", "SELECT * FROM wuser_table",
		"db.user", "readonly_user",
		"db.url", "mysql://db.example.com:3306",
	)

	assert.Equal(t, "db", span.Type)
	assert.Equal(t, "sql", span.Subtype)
	assert.Equal(t, "", span.Action)

	assert.Equal(t, &model.DatabaseSpanContext{
		Type:      "sql",
		Instance:  "customers",
		Statement: "SELECT * FROM wuser_table",
		User:      "readonly_user",
	}, span.Context.Database)

	assert.Equal(t, model.IfaceMap{
		{Key: "db_url", Value: "mysql://db.example.com:3306"},
	}, span.Context.Tags)
}

func transactionWithAttributes(t *testing.T, attrs ...interface{}) model.Transaction {
	exporter, recorder := newExporter(t)
	failed, err := exporter.PushTraceData(context.Background(), elastic.TraceData{
		Spans: []*tracepb.Span{{
			Attributes: &tracepb.Span_Attributes{AttributeMap: attributeMap(attrs...)},
		}},
	})
	assert.Equal(t, 0, failed)
	assert.NoError(t, err)

	payloads := recorder.Payloads()
	require.Len(t, payloads.Transactions, 1)
	return payloads.Transactions[0]
}

func spanWithAttributes(t *testing.T, attrs ...interface{}) model.Span {
	exporter, recorder := newExporter(t)
	failed, err := exporter.PushTraceData(context.Background(), elastic.TraceData{
		Spans: []*tracepb.Span{{
			ParentSpanId: []byte{1},
			Attributes:   &tracepb.Span_Attributes{AttributeMap: attributeMap(attrs...)},
		}},
	})
	assert.Equal(t, 0, failed)
	assert.NoError(t, err)

	payloads := recorder.Payloads()
	require.Len(t, payloads.Spans, 1)
	return payloads.Spans[0]
}

func attributeMap(kv ...interface{}) map[string]*tracepb.AttributeValue {
	out := make(map[string]*tracepb.AttributeValue)
	for i := 0; i < len(kv); i += 2 {
		k := kv[i].(string)
		switch v := kv[i+1].(type) {
		case string:
			out[k] = stringAttributeValue(v)
		case int:
			out[k] = intAttributeValue(int64(v))
		default:
			panic(fmt.Errorf("unhandled type %T", v))
		}
	}
	return out
}

func stringAttributeValue(v string) *tracepb.AttributeValue {
	return &tracepb.AttributeValue{
		Value: &tracepb.AttributeValue_StringValue{
			StringValue: &tracepb.TruncatableString{Value: v},
		},
	}
}

func intAttributeValue(v int64) *tracepb.AttributeValue {
	return &tracepb.AttributeValue{
		Value: &tracepb.AttributeValue_IntValue{
			IntValue: v,
		},
	}
}

func doubleAttributeValue(v float64) *tracepb.AttributeValue {
	return &tracepb.AttributeValue{
		Value: &tracepb.AttributeValue_DoubleValue{
			DoubleValue: v,
		},
	}
}

func boolAttributeValue(v bool) *tracepb.AttributeValue {
	return &tracepb.AttributeValue{
		Value: &tracepb.AttributeValue_BoolValue{
			BoolValue: v,
		},
	}
}
