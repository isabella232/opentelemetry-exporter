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
	commonpb "github.com/census-instrumentation/opencensus-proto/gen-go/agent/common/v1"
	resourcepb "github.com/census-instrumentation/opencensus-proto/gen-go/resource/v1"
	"github.com/open-telemetry/opentelemetry-collector/translator/conventions"
	"go.elastic.co/apm/model"
	"go.elastic.co/fastjson"
)

func encodeMetadata(node *commonpb.Node, resource *resourcepb.Resource, w *fastjson.Writer) {
	var agent model.Agent
	var service model.Service
	var system model.System
	var process model.Process
	var labels model.StringMap

	service.Agent = &agent
	service.Name = cleanServiceName(node.GetServiceInfo().GetName())
	if service.Name == "" {
		// service.name is a required field.
		service.Name = "unknown"
	}
	if ident := node.GetIdentifier(); ident != nil {
		process.Pid = int(ident.Pid)
		if hostname := truncate(ident.HostName); hostname != "" {
			system.Hostname = hostname
		}
	}
	if libraryInfo := node.GetLibraryInfo(); libraryInfo != nil {
		if languageName, ok := languageName[libraryInfo.GetLanguage()]; ok {
			service.Language = &model.Language{Name: languageName}
		}
		// TODO(axw) revise, this is almost certainly not correct
		agent.Name = truncate(libraryInfo.GetExporterVersion())
	}
	for k, v := range node.GetAttributes() {
		labels = append(labels, model.StringMapItem{
			Key:   cleanLabelKey(k),
			Value: v,
		})
	}
	for k, v := range resource.GetLabels() {
		switch k {
		case conventions.AttributeServiceVersion:
			service.Version = v
		default:
			labels = append(labels, model.StringMapItem{
				Key:   cleanLabelKey(k),
				Value: v,
			})
		}
	}
	if agent.Name == "" {
		// service.agent.name is a required field.
		agent.Name = "OpenTelemetry"
	}
	if agent.Version == "" {
		// service.agent.version is a required field.
		agent.Version = "unknown"
	}

	w.RawString(`{"metadata":{`)
	w.RawString(`"service":`)
	service.MarshalFastJSON(w)
	if system != (model.System{}) {
		w.RawString(`,"system":`)
		system.MarshalFastJSON(w)
	}
	if process.Pid != 0 {
		w.RawString(`,"process":`)
		process.MarshalFastJSON(w)
	}
	if len(labels) > 0 {
		w.RawString(`,"labels":`)
		labels.MarshalFastJSON(w)
	}
	w.RawString("}}\n")
}
