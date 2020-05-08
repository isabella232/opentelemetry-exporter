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
	"testing"
	"time"

	metricspb "github.com/census-instrumentation/opencensus-proto/gen-go/metrics/v1"
	elastic "github.com/elastic/opentelemetry-exporter"
	"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.elastic.co/apm/model"
)

func TestPushMetricsData(t *testing.T) {
	exporter, recorder := newExporter(t)

	time1 := time.Unix(123, 0).UTC()
	before := time.Now()
	failed, err := exporter.PushMetricsData(context.Background(), elastic.MetricsData{
		Metrics: []*metricspb.Metric{{
			MetricDescriptor: &metricspb.MetricDescriptor{
				Name: "metric.name",
				LabelKeys: []*metricspb.LabelKey{
					{Key: "k1"},
					{Key: "k2"},
					{Key: "k3"},
				},
			},
			Timeseries: []*metricspb.TimeSeries{{
				LabelValues: []*metricspb.LabelValue{
					{Value: "v1", HasValue: true},
					{Value: "", HasValue: true},
					{HasValue: false},
				},
				Points: []*metricspb.Point{{
					Timestamp: toTimestamp(time1),
					Value:     &metricspb.Point_Int64Value{Int64Value: 123},
				}, {
					Value: &metricspb.Point_Int64Value{Int64Value: 456},
				}},
			}},
		}},
	})
	assert.Equal(t, 0, failed)
	assert.NoError(t, err)
	after := time.Now()

	payloads := recorder.Payloads()
	require.Len(t, payloads.Metrics, 2)

	// The second metric's timestamp is set by the exporter, as it wasn't specified.
	assert.Condition(t, func() bool {
		timestamp := time.Time(payloads.Metrics[1].Timestamp)
		return !timestamp.Before(before) && !timestamp.After(after)
	})
	payloads.Metrics[1].Timestamp = model.Time{}

	assert.Equal(t, []model.Metrics{{
		Timestamp: model.Time(time1),
		Labels: model.StringMap{
			{Key: "k1", Value: "v1"},
			{Key: "k2", Value: ""},
		},
		Samples: map[string]model.Metric{
			"metric.name": {Value: 123.0},
		},
	}, {
		Labels: model.StringMap{
			{Key: "k1", Value: "v1"},
			{Key: "k2", Value: ""},
		},
		Samples: map[string]model.Metric{
			"metric.name": {Value: 456.0},
		},
	}}, payloads.Metrics)
}

func TestMetricsTypes(t *testing.T) {
	exporter, recorder := newExporter(t)

	time1 := time.Unix(123, 0).UTC()
	failed, err := exporter.PushMetricsData(context.Background(), elastic.MetricsData{
		Metrics: []*metricspb.Metric{{
			MetricDescriptor: &metricspb.MetricDescriptor{Name: "double"},
			Timeseries: []*metricspb.TimeSeries{{
				Points: []*metricspb.Point{{
					Timestamp: toTimestamp(time1),
					Value:     &metricspb.Point_DoubleValue{DoubleValue: 123},
				}},
			}},
		}, {
			MetricDescriptor: &metricspb.MetricDescriptor{Name: "summary"},
			Timeseries: []*metricspb.TimeSeries{{
				Points: []*metricspb.Point{{
					Timestamp: toTimestamp(time1),
					Value: &metricspb.Point_SummaryValue{
						SummaryValue: &metricspb.SummaryValue{
							Count: &wrappers.Int64Value{Value: 1},
							Sum:   &wrappers.DoubleValue{Value: 2},
						},
					},
				}},
			}},
		}, {
			MetricDescriptor: &metricspb.MetricDescriptor{Name: "distribution"},
			Timeseries: []*metricspb.TimeSeries{{
				Points: []*metricspb.Point{{
					Timestamp: toTimestamp(time1),
					Value:     &metricspb.Point_DistributionValue{},
				}},
			}},
		}},
	})
	assert.Equal(t, 1, failed)
	assert.EqualError(t, err, "metric type *v1.Point_DistributionValue unsupported")

	payloads := recorder.Payloads()
	assert.Equal(t, []model.Metrics{{
		Timestamp: model.Time(time1),
		Samples: map[string]model.Metric{
			"double": {Value: 123.0},
		},
	}, {
		Timestamp: model.Time(time1),
		Samples: map[string]model.Metric{
			"summary.count": {Value: 1.0},
			"summary.sum":   {Value: 2.0},
		},
	}}, payloads.Metrics)
}
