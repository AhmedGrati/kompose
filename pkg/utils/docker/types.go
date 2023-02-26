/*
Copyright 2016 The Kubernetes Authors All rights reserved

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package docker

import (
	"github.com/docker/docker/api/types/strslice"
)

type Networks map[string]struct{}
type Volumes []string

type InspectedContainers struct {
	Volumes
	Networks
	Containers []Container
}

type Container struct {
	CapDrop         strslice.StrSlice
	CgroupParent    string
	Name            string
	Devices         []string
	Networks        []string
	DNS             []string
	DNSSearch       []string
	Environment     []string
	ExtraHosts      []string
	Image           string
	Labels          map[string]string
	Links           []string
	Logging         ContainerLogging
	SecurityOptions []string
	ULimits         []ULimit
	VolumeDriver    string
	VolumesFrom     []string
	Entrypoint      strslice.StrSlice
	User            string
	WorkingDir      string
	Domainname      string
	Hostname        string
	IpcMode         IpcMode
	MacAddress      string
	Privileged      bool
	RestartPolicy
	ReadonlyRootfs bool
	OpenStdin      bool
	Tty            bool
	NetworkMode    string
}

type ContainerLogging struct {
	Driver  string
	Options map[string]string
}

type IpcMode string

type RestartPolicy struct {
	Name              string
	MaximumRetryCount int
}

type ULimit struct {
	Name string
	Soft int64
	Hard int64
}
