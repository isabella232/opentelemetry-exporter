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

// Package elastic contains the core functionality for
// an OpenTelemetry Collector exporter for Elastic APM.
package elastic

import (
	"bytes"
	"compress/zlib"
	"context"
	"fmt"
	"net/url"

	commonpb "github.com/census-instrumentation/opencensus-proto/gen-go/agent/common/v1"
	metricspb "github.com/census-instrumentation/opencensus-proto/gen-go/metrics/v1"
	resourcepb "github.com/census-instrumentation/opencensus-proto/gen-go/resource/v1"
	tracepb "github.com/census-instrumentation/opencensus-proto/gen-go/trace/v1"
	"github.com/open-telemetry/opentelemetry-collector/component/componenterror"
	"go.elastic.co/apm/transport"
	"go.elastic.co/fastjson"
	"go.uber.org/zap"
)

const exporterVersion = "0.4.0"

// Exporter is an Elastic APM exporter for OpenTelemetry Collector.
type Exporter struct {
	transport transport.Transport
	logger    *zap.Logger
}

// NewExporter creates a new Exporter with config.
func NewExporter(config Config) (*Exporter, error) {
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %s", err)
	}
	transport, err := newTransport(config)
	if err != nil {
		return nil, err
	}
	logger := config.Logger
	if logger == nil {
		logger = zap.NewNop()
	}
	return &Exporter{transport: transport, logger: logger}, nil
}

func newTransport(config Config) (transport.Transport, error) {
	transport, err := transport.NewHTTPTransport()
	if err != nil {
		return nil, fmt.Errorf("error creating HTTP transport: %v", err)
	}
	if config.HTTPClient != nil {
		transport.Client = config.HTTPClient
	}

	urls := make([]*url.URL, len(config.APMServerURLs))
	for i, v := range config.APMServerURLs {
		u, err := url.Parse(v)
		if err != nil {
			return nil, err
		}
		urls[i] = u
	}
	transport.SetServerURL(urls...)

	if config.APIKey != "" {
		transport.SetAPIKey(config.APIKey)
	} else if config.SecretToken != "" {
		transport.SetSecretToken(config.SecretToken)
	}

	transport.SetUserAgent("opentelemetry-collector elastic/" + exporterVersion)
	return transport, nil
}

// MetricsData is a struct that groups proto metrics with a unique node and a resource.
type MetricsData struct {
	Node     *commonpb.Node
	Resource *resourcepb.Resource
	Metrics  []*metricspb.Metric
}

// TraceData is a struct that groups proto spans with a unique node and a resource.
type TraceData struct {
	Node         *commonpb.Node
	Resource     *resourcepb.Resource
	Spans        []*tracepb.Span
	SourceFormat string
}

// PushTraceData pushes trace data to Elastic APM Server, returning the
// number of spans that were dropped along with any errors.
func (e *Exporter) PushTraceData(ctx context.Context, td TraceData) (int, error) {
	var w fastjson.Writer
	encodeMetadata(td.Node, td.Resource, &w)
	var errs []error
	for _, otelSpan := range td.Spans {
		before := w.Size()
		if err := encodeSpan(otelSpan, &w); err != nil {
			w.Rewind(before)
			errs = append(errs, err)
		}
	}
	if err := e.sendEvents(ctx, &w); err != nil {
		return len(td.Spans), err
	}
	return len(errs), componenterror.CombineErrors(errs)
}

// PushMetricsData pushes metrics data to Elastic APM Server, returning the
// number of timeseries that were dropped along with any errors.
func (e *Exporter) PushMetricsData(ctx context.Context, md MetricsData) (int, error) {
	var w fastjson.Writer
	encodeMetadata(md.Node, md.Resource, &w)
	var errs []error
	for _, otelMetric := range md.Metrics {
		before := w.Size()
		if err := encodeMetric(otelMetric, &w); err != nil {
			w.Rewind(before)
			errs = append(errs, err)
		}
	}
	if err := e.sendEvents(ctx, &w); err != nil {
		return len(md.Metrics), err
	}
	return len(errs), componenterror.CombineErrors(errs)
}

func (e *Exporter) sendEvents(ctx context.Context, w *fastjson.Writer) error {
	e.logger.Debug("sending events", zap.ByteString("events", w.Bytes()))

	var buf bytes.Buffer
	zw, err := zlib.NewWriterLevel(&buf, zlib.DefaultCompression)
	if err != nil {
		return err
	}
	if _, err := zw.Write(w.Bytes()); err != nil {
		return err
	}
	if err := zw.Close(); err != nil {
		return err
	}
	if err := e.transport.SendStream(ctx, &buf); err != nil {
		// TODO(axw) check response for number of accepted items,
		// and take that into account in the result.
		return err
	}
	return nil
}
