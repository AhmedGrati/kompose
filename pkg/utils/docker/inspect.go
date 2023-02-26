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
	"fmt"

	dockerlib "github.com/fsouza/go-dockerclient"
	log "github.com/sirupsen/logrus"
)

// Inspect will provide methods for interaction with API regarding inspecting containers
type Inspect struct {
	Client dockerlib.Client
}

var DEFAULT_NETWORKS = map[string]struct{}{
	"bridge": struct{}{},
	"host":   struct{}{},
	"none":   struct{}{},
}

/*
InspectContainers inspect Docker containers via the Docker API or Docker CLI.
Takes the name of containers to be inspected and return output as string.
*/
func (i *Inspect) InspectContainers(containers []string) (*InspectedContainers, error) {
	log.Infof("Inspecting containers '%v'", containers)

	var inspectedContainers InspectedContainers
	var networks map[string]struct{}

	for _, containerName := range containers {
		_, _, _, err := i.generateContainerInspection(containerName, networks)
		if err != nil {
			return nil, err
		}
	}
	return &inspectedContainers, nil
}

func (i *Inspect) generateContainerInspection(containerName string, networks Networks) (Container, Networks, Volumes, error) {
	var containerNetworks Networks
	containerId, err := i.getContainerId(containerName)
	if err != nil {
		return Container{}, nil, nil, err
	}
	c, err := i.Client.InspectContainerWithOptions(dockerlib.InspectContainerOptions{
		ID: *containerId,
	})
	if err != nil {
		return Container{}, nil, nil, fmt.Errorf("container while inspecting container with name %v", containerName)
	}

	container := Container{
		CapDrop:      c.HostConfig.CapDrop,
		CgroupParent: c.HostConfig.CgroupParent,
		Name:         containerName,
		Devices:      getContainerDevices(*c),
		DNS:          c.HostConfig.DNS,
		DNSSearch:    c.HostConfig.DNSSearch,
		Environment:  c.Config.Env,
		ExtraHosts:   c.HostConfig.ExtraHosts,
		Image:        c.Config.Image,
		Labels:       c.Config.Labels,
		Links:        c.HostConfig.Links,
		Logging: ContainerLogging{
			Driver:  c.HostConfig.LogConfig.Type,
			Options: c.HostConfig.LogConfig.Config,
		},
		SecurityOptions: c.HostConfig.SecurityOpt,
		ULimits:         getContainerULimits(*c),
		VolumeDriver:    c.HostConfig.VolumeDriver,
		VolumesFrom:     c.HostConfig.VolumesFrom,
		Entrypoint:      c.Config.Entrypoint,
		User:            c.Config.User,
		WorkingDir:      c.Config.WorkingDir,
		Domainname:      c.Config.Domainname,
		Hostname:        c.Config.Hostname,
		IpcMode:         IpcMode(c.HostConfig.IpcMode),
		MacAddress:      c.NetworkSettings.MacAddress,
		Privileged:      c.HostConfig.Privileged,
		ReadonlyRootfs:  c.HostConfig.ReadonlyRootfs,
		OpenStdin:       c.Config.OpenStdin,
		Tty:             c.Config.Tty,
		Networks:        getContainerNetworks(*c),
	}

	// TODO: Please return to this
	if len(container.Networks) == 0 {
		if len(c.NetworkSettings.Networks) > 0 {
			assumedDefaultNetwork := getAssumedDefaultNetwork(*c)
			container.NetworkMode = assumedDefaultNetwork
		}
	} else {
		allNetworks, err := i.getAllNetworks()
		if err != nil {
			return Container{}, nil, nil, err
		}
		for _, network := range container.Networks {
			if _, ok := allNetworks[network]; ok {
				containerNetworks[network] = struct{}{}
			}
		}
	}
	return container, nil, nil, nil
}

func (i *Inspect) getContainerId(containerName string) (*string, error) {
	containers, err := i.Client.ListContainers(dockerlib.ListContainersOptions{})
	if err != nil {
		log.Errorf("error while trying to list containers.")
		return nil, err
	}
	for _, container := range containers {
		for _, name := range container.Names {
			if name == fmt.Sprintf("/%v", containerName) {
				return &container.ID, nil
			}
		}
	}
	return nil, fmt.Errorf("container with name %v does not exist", containerName)
}

func (i *Inspect) getAllNetworks() (Networks, error) {
	var networks map[string]struct{}
	allNetworks, err := i.Client.ListNetworks()
	if err != nil {
		log.Errorf("error while trying to list networks.")
		return nil, err
	}
	for _, network := range allNetworks {
		networks[network.Name] = struct{}{}
	}
	return networks, err
}

func getContainerDevices(container dockerlib.Container) []string {
	var devices []string
	for _, device := range container.HostConfig.Devices {
		devices = append(devices, fmt.Sprintf("%v:%v", device.PathOnHost, device.PathInContainer))
	}
	return devices
}

func getContainerULimits(container dockerlib.Container) []ULimit {
	var ulimits []ULimit
	for _, ulimit := range container.HostConfig.Ulimits {
		ulimits = append(ulimits, ULimit{
			Name: ulimit.Name,
			Soft: ulimit.Soft,
			Hard: ulimit.Hard,
		})
	}
	return ulimits
}

func getContainerNetworks(container dockerlib.Container) []string {
	var networks []string
	for network, _ := range container.NetworkSettings.Networks {
		// If the network is not in the default networks we add it.
		if _, ok := DEFAULT_NETWORKS[network]; !ok {
			networks = append(networks, network)
		}
	}
	return networks
}

func getAssumedDefaultNetwork(container dockerlib.Container) string {
	for k, _ := range container.NetworkSettings.Networks {
		return k
	}
	return ""
}
