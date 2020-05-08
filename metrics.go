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

// Package elastic contains an opentelemetry-collector exporter
// for Elastic APM.
package elastic

import (
	"fmt"
	"time"

	metricspb "github.com/census-instrumentation/opencensus-proto/gen-go/metrics/v1"
	"go.elastic.co/apm/model"
	"go.elastic.co/fastjson"
)

func encodeMetric(otelMetric *metricspb.Metric, w *fastjson.Writer) error {
	descriptor := otelMetric.GetMetricDescriptor()
	labelKeys := descriptor.GetLabelKeys()
	metricName := descriptor.GetName()

	// TODO(axw) propagate metric type, unit, and description once we
	// have support for self-describing metrics.
	//
	//metricType := descriptor.GetType()
	//metricUnit := descriptor.GetUnit
	//metricDescription := descriptor.GetDescription()

	for _, ts := range otelMetric.GetTimeseries() {
		labels := make(model.StringMap, 0, len(labelKeys))
		for i, labelValue := range ts.GetLabelValues() {
			if !labelValue.GetHasValue() {
				continue
			}
			labels = append(labels, model.StringMapItem{
				Key:   cleanLabelKey(labelKeys[i].GetKey()),
				Value: labelValue.GetValue(),
			})
		}
		samples := make(map[string]model.Metric)
		metricset := model.Metrics{Labels: labels, Samples: samples}
		for _, point := range ts.GetPoints() {
			timestamp := parseTimestamp(point.GetTimestamp())
			if timestamp.Unix() <= 0 {
				timestamp = time.Now().UTC()
			}
			metricset.Timestamp = model.Time(timestamp)

			switch value := point.GetValue().(type) {
			case *metricspb.Point_Int64Value:
				samples[metricName] = model.Metric{Value: float64(value.Int64Value)}
			case *metricspb.Point_DoubleValue:
				samples[metricName] = model.Metric{Value: value.DoubleValue}
			case *metricspb.Point_SummaryValue:
				// TODO(axw) native support for summary metrics,
				// once apm-server understands how to store them.
				samples[metricName+".count"] = model.Metric{
					Value: float64(value.SummaryValue.GetCount().GetValue()),
				}
				samples[metricName+".sum"] = model.Metric{
					Value: value.SummaryValue.GetSum().GetValue(),
				}
			default:
				// TODO(axw) handle distributions when we have
				// support for storing histogram metrics in
				// apm-server, and have updated the intake.
				return fmt.Errorf("metric type %T unsupported", value)
			}
			w.RawString(`{"metricset":`)
			if err := metricset.MarshalFastJSON(w); err != nil {
				return err
			}
			w.RawString("}\n")
		}
	}
	return nil
}
