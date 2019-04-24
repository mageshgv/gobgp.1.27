// Copyright (C) 2015 Nippon Telegraph and Telephone Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"fmt"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func modLogLevelServer(cmdType string, args []string) error {
	var level log.Level

	switch cmdType {
	case CMD_DEBUG:
		level = log.DebugLevel
	case CMD_ERROR:
		level = log.ErrorLevel
	case CMD_FATAL:
		level = log.FatalLevel
	case CMD_INFO:
		level = log.InfoLevel
	case CMD_PANIC:
		level = log.PanicLevel
	case CMD_WARN:
		level = log.WarnLevel
	default:
		return fmt.Errorf("wrong log level: %s", cmdType)
	}
	return client.SetLogLevel(level)
}

func NewLogLevelCmd() *cobra.Command {

	llCmd := &cobra.Command{
		Use: CMD_LOGLEVEL,
	}

	for _, w := range []string{CMD_DEBUG, CMD_ERROR, CMD_FATAL, CMD_INFO, CMD_PANIC, CMD_WARN} {
		subcmd := &cobra.Command{
			Use: w,
			Run: func(cmd *cobra.Command, args []string) {
				err := modLogLevelServer(cmd.Use, args)
				if err != nil {
					exitWithError(err)
				}
			},
		}
		llCmd.AddCommand(subcmd)
	}

	return llCmd
}
